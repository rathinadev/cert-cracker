//! Consistent local backups of a stopped coordinator's SQLite database and artifacts.
use crate::storage::{Store, no_symlink, private_file};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize)]
pub struct BackupReport {
    pub format_version: u32,
    pub database: FileEntry,
    pub artifacts: Vec<FileEntry>,
    pub note: &'static str,
}
#[derive(Serialize)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

fn digest(path: &Path, relative: String) -> Result<FileEntry> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("backup file size overflow")?;
        hasher.update(&buf[..n]);
    }
    Ok(FileEntry {
        path: relative,
        bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn validate_artifact_manifests(store: &Store, destination: &Path) -> Result<()> {
    let mut stmt = store.conn.prepare("SELECT id FROM jobs ORDER BY id")?;
    let jobs = stmt.query_map([], |r| r.get::<_, i64>(0))?;
    for job in jobs {
        let job = job?;
        let spec = store.spec(job)?;
        if spec.bsgs.is_none() {
            continue;
        }
        let Some(value) = store.engine_state(job)? else {
            let units: i64 = store.conn.query_row(
                "SELECT count(*) FROM work_units WHERE job_id=?1",
                [job],
                |r| r.get(0),
            )?;
            ensure!(
                units == 0,
                "BSGS job {job} is missing its artifact manifest"
            );
            continue;
        };
        let manifest: crate::bsgs::Manifest =
            serde_json::from_value(value).context("invalid BSGS manifest")?;
        ensure!(
            manifest.version == 1
                && manifest.spec_hash == spec.hash()?
                && matches!(manifest.stage.as_str(), "building" | "ready"),
            "invalid BSGS manifest binding"
        );
        ensure!(
            Path::new(&manifest.file_name).components().count() == 1
                && manifest.file_name.starts_with(&format!("job-{job}-"))
                && manifest.file_name.ends_with(".baby"),
            "invalid BSGS artifact name"
        );
        let path = destination.join("artifacts").join(&manifest.file_name);
        let file = File::open(&path).context("referenced BSGS artifact missing from backup")?;
        let size = file.metadata()?.len();
        ensure!(
            size >= manifest.file_bytes
                && (manifest.stage != "ready" || size == manifest.file_bytes),
            "BSGS artifact size mismatch"
        );
        let mut bytes = file.take(manifest.file_bytes);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = bytes.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        ensure!(
            hex::encode(hasher.finalize()) == manifest.sha256,
            "BSGS artifact checksum mismatch in backup"
        );
    }
    Ok(())
}

pub fn create(source: &Path, destination: &Path) -> Result<BackupReport> {
    no_symlink(source)?;
    ensure!(source.is_dir(), "state directory does not exist");
    let source = fs::canonicalize(source)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).context("backup parent directory must exist")?;
    ensure!(
        !parent.starts_with(&source),
        "backup destination cannot be inside the state directory"
    );
    let name = destination
        .file_name()
        .context("backup destination needs a directory name")?;
    let destination = parent.join(name);
    let lockpath = source.join("coordinator.lockfile");
    no_symlink(&lockpath)?;
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options.open(lockpath)?;
    lock.try_lock_exclusive()
        .context("another coordinator owns this state directory; stop it before backup")?;
    let store = Store::open(&source, false)?;
    // create_dir is atomic and refuses an existing destination.
    create_private_dir(&destination).context("creating new backup directory")?;
    sync_dir(&parent)?;
    let db = destination.join("state.sqlite");
    drop(private_file(&db)?);
    store
        .conn
        .backup(
            rusqlite::MAIN_DB,
            &db,
            None::<fn(rusqlite::backup::Progress)>,
        )
        .context("copying SQLite backup")?;
    // Windows FlushFileBuffers requires a handle opened with write access.
    OpenOptions::new()
        .write(true)
        .open(&db)
        .context("opening copied SQLite backup for sync")?
        .sync_all()
        .context("syncing copied SQLite backup")?;
    let check =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = check.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(
        integrity == "ok",
        "backup SQLite integrity check failed: {integrity}"
    );
    drop(check);
    let database = digest(&db, "state.sqlite".into())?;
    let mut artifacts = Vec::new();
    let original = source.join("artifacts");
    no_symlink(&original)?;
    if original.exists() {
        ensure!(
            original.is_dir(),
            "source artifacts path is not a directory"
        );
        let target = destination.join("artifacts");
        create_private_dir(&target)?;
        let mut entries = fs::read_dir(original)?.collect::<std::io::Result<Vec<_>>>()?;
        ensure!(entries.len() <= 100_000, "too many artifact files");
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let input = entry.path();
            let metadata = fs::symlink_metadata(&input)?;
            ensure!(
                metadata.file_type().is_file(),
                "artifact must be a regular file: {}",
                input.display()
            );
            let name = entry.file_name();
            let text = name.to_str().context("artifact file name is not UTF-8")?;
            let output: PathBuf = target.join(&name);
            let mut src = File::open(input).context("opening source artifact")?;
            let mut dst = private_file(&output)?;
            std::io::copy(&mut src, &mut dst).context("copying artifact")?;
            dst.sync_all().context("syncing copied artifact")?;
            artifacts.push(digest(&output, format!("artifacts/{text}"))?);
        }
        sync_dir(&target)?;
    }
    validate_artifact_manifests(&store, &destination)?;
    let report = BackupReport {
        format_version: 1,
        database,
        artifacts,
        note: "Contains sensitive state and may include unencrypted private keys. Restore by using this completed directory as --state. Referenced BSGS artifact checksums were verified; full structural validation occurs on resume.",
    };
    let marker = destination.join("BACKUP_COMPLETE.json");
    let mut file = tempfile::NamedTempFile::new_in(&destination)?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    writeln!(file)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&marker)
        .map_err(|e| e.error)
        .context("publishing backup completion marker")?;
    sync_dir(&destination)?;
    drop(lock);
    Ok(report)
}
