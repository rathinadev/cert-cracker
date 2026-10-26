//! Memory-bounded interval BSGS with a durable baby-step ledger and immutable ready table.
use crate::{
    crypto::{bignum, ec_order},
    import::public_key,
    model::{SearchSpec, Target, WorkUnit, number},
    planner::{self, Entry, MAX_POINT_BYTES},
    storage::{Store, no_symlink},
};
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcPoint, PointConversionForm},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MAGIC: &[u8; 8] = b"CCBSGS01";
const RECORD_BYTES: u64 = MAX_POINT_BYTES as u64 + 8;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    spec_hash: String,
    curve: String,
    point_len: usize,
    baby_steps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub spec_hash: String,
    pub stage: String,
    pub file_name: String,
    pub committed_entries: u64,
    pub file_bytes: u64,
    pub sha256: String,
}

pub struct Table {
    entries: Vec<Entry>,
    point_len: usize,
}

pub struct PrepareOptions {
    pub workers: usize,
    pub cancel: Arc<AtomicBool>,
    pub deadline: Option<Instant>,
    pub checkpoint_interval: Duration,
    pub quiet: bool,
}

impl PrepareOptions {
    fn stopped(&self) -> bool {
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        self.cancel.load(Ordering::Relaxed)
    }
}

fn domain(target: &Target) -> Result<(EcGroup, EcPoint, BigNumContext)> {
    planner::ensure_curve(target)?;
    ec_order(target)?;
    let key = public_key(target)?;
    let ec = key.ec_key()?;
    let group = EcGroup::from_curve_name(ec.group().curve_name().context("missing curve")?)?;
    let mut ctx = BigNumContext::new()?;
    let bytes =
        ec.public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let point = EcPoint::from_bytes(&group, &bytes, &mut ctx)?;
    Ok((group, point, ctx))
}

fn point_key(
    group: &EcGroup,
    point: &EcPoint,
    ctx: &mut BigNumContext,
) -> Result<[u8; MAX_POINT_BYTES]> {
    let bytes = point.to_bytes(group, PointConversionForm::COMPRESSED, ctx)?;
    ensure!(
        bytes.len() <= MAX_POINT_BYTES,
        "point encoding exceeds table format"
    );
    let mut key = [0u8; MAX_POINT_BYTES];
    key[..bytes.len()].copy_from_slice(&bytes);
    Ok(key)
}

fn header_bytes(header: &Header) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(header)?;
    ensure!(json.len() <= 4096, "table header too large");
    let mut bytes = Vec::with_capacity(12 + json.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&json);
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
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

fn artifact_dir(store: &Store) -> Result<PathBuf> {
    let parent = store.path.parent().context("state directory unavailable")?;
    let dir = parent.join("artifacts");
    no_symlink(&dir)?;
    if !dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&dir)?;
        sync_directory(parent)?;
    }
    ensure!(dir.is_dir(), "artifact path must be a directory");
    Ok(dir)
}

fn artifact_path(dir: &Path, job: i64, name: &str) -> Result<PathBuf> {
    ensure!(
        Path::new(name).components().count() == 1
            && name.starts_with(&format!("job-{job}-"))
            && name.ends_with(".baby"),
        "invalid artifact file name"
    );
    let path = dir.join(name);
    no_symlink(&path)?;
    Ok(path)
}

fn persist(temp: tempfile::NamedTempFile, dir: &Path) -> Result<PathBuf> {
    temp.as_file().sync_all()?;
    let path = temp.path().with_extension("baby");
    temp.persist_noclobber(&path).map_err(|e| e.error)?;
    sync_directory(dir)?;
    Ok(path)
}

fn save(store: &mut Store, job: i64, manifest: &Manifest) -> Result<()> {
    store.save_engine_state(job, &serde_json::to_value(manifest)?)
}

fn validate_entry(entry: &Entry, header: &Header) -> Result<()> {
    ensure!(
        entry.index < header.baby_steps,
        "baby index outside table bounds"
    );
    if entry.index == 0 {
        ensure!(
            entry.point == [0u8; MAX_POINT_BYTES],
            "invalid infinity entry"
        );
    } else {
        ensure!(
            matches!(entry.point[0], 2 | 3)
                && entry.point[header.point_len..].iter().all(|b| *b == 0),
            "invalid compressed-point record"
        );
    }
    Ok(())
}

fn load(
    path: &Path,
    header: &Header,
    manifest: &Manifest,
    entries: &mut Vec<Entry>,
    options: &PrepareOptions,
) -> Result<Option<Sha256>> {
    let expected = header_bytes(header)?;
    let count = manifest.committed_entries;
    ensure!(
        count <= header.baby_steps
            && manifest.file_bytes == expected.len() as u64 + count * RECORD_BYTES,
        "invalid artifact size/count manifest"
    );
    let file=File::open(path).context("referenced BSGS artifact is missing; restore its matching checkpoint instead of resetting coverage")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "artifact must be a regular file");
    ensure!(
        metadata.len() >= manifest.file_bytes,
        "truncated BSGS artifact"
    );
    if manifest.stage == "ready" {
        ensure!(
            metadata.len() == manifest.file_bytes && count == header.baby_steps,
            "ready table has unexpected size"
        );
    }
    let mut reader = BufReader::new(file);
    let mut hash = Sha256::new();
    let mut actual = vec![0u8; expected.len()];
    reader.read_exact(&mut actual)?;
    ensure!(actual == expected, "BSGS table binding/header mismatch");
    hash.update(&actual);
    let mut seen = vec![];
    if manifest.stage == "ready" {
        let len = usize::try_from(count.div_ceil(8))?;
        seen.try_reserve_exact(len)?;
        seen.resize(len, 0u8);
    }
    for index in 0..count {
        if index.is_multiple_of(1024) && options.stopped() {
            return Ok(None);
        }
        let mut point = [0u8; MAX_POINT_BYTES];
        let mut encoded = [0u8; 8];
        reader.read_exact(&mut point)?;
        reader.read_exact(&mut encoded)?;
        hash.update(point);
        hash.update(encoded);
        let entry = Entry {
            point,
            index: u64::from_le_bytes(encoded),
        };
        validate_entry(&entry, header)?;
        if manifest.stage == "building" {
            ensure!(entry.index == index, "building ledger index mismatch");
        } else {
            let byte = usize::try_from(entry.index / 8)?;
            let mask = 1u8 << (entry.index % 8);
            ensure!(seen[byte] & mask == 0, "duplicate baby-step index");
            seen[byte] |= mask;
            if let Some(last) = entries.last() {
                ensure!(
                    last.point < entry.point,
                    "ready table is unsorted or has duplicate points"
                );
            }
        }
        entries.push(entry);
    }
    ensure!(
        hex::encode(hash.clone().finalize()) == manifest.sha256,
        "BSGS artifact checksum mismatch; checkpoint left unchanged"
    );
    Ok(Some(hash))
}

/// Build/load exactly one shared table. Unacknowledged appended tails are safely replayed.
pub fn prepare(
    store: &mut Store,
    job: i64,
    spec: &SearchSpec,
    target: &Target,
    options: &PrepareOptions,
) -> Result<Option<Arc<Table>>> {
    planner::preflight(spec, options.workers)?;
    let config = spec.bsgs.as_ref().context("missing BSGS config")?;
    let (group, _, mut ctx) = domain(target)?;
    let point_len = (group.degree() as usize).div_ceil(8) + 1;
    ensure!(point_len <= MAX_POINT_BYTES, "unsupported point length");
    let header = Header {
        version: 1,
        spec_hash: spec.hash()?,
        curve: target.curve.clone().context("missing curve")?,
        point_len,
        baby_steps: config.baby_steps,
    };
    let encoded_header = header_bytes(&header)?;
    let dir = artifact_dir(store)?;
    let mut manifest = if let Some(state) = store.engine_state(job)? {
        let manifest: Manifest =
            serde_json::from_value(state).context("invalid BSGS checkpoint manifest")?;
        ensure!(
            manifest.version == 1
                && manifest.spec_hash == header.spec_hash
                && matches!(manifest.stage.as_str(), "building" | "ready"),
            "incompatible BSGS checkpoint"
        );
        manifest
    } else {
        // Work cannot be trusted if its associated table manifest disappeared.
        let units: i64 = store.conn.query_row(
            "SELECT count(*) FROM work_units WHERE job_id=?1",
            [job],
            |r| r.get(0),
        )?;
        ensure!(
            units == 0,
            "BSGS table manifest missing for existing work; restore the matching checkpoint"
        );
        let mut temp = tempfile::Builder::new()
            .prefix(&format!("job-{job}-build-"))
            .suffix(".pending")
            .tempfile_in(&dir)?;
        temp.write_all(&encoded_header)?;
        let path = persist(temp, &dir)?;
        let manifest = Manifest {
            version: 1,
            spec_hash: header.spec_hash.clone(),
            stage: "building".into(),
            file_name: path.file_name().unwrap().to_string_lossy().into_owned(),
            committed_entries: 0,
            file_bytes: encoded_header.len() as u64,
            sha256: hex::encode(Sha256::digest(&encoded_header)),
        };
        save(store, job, &manifest)?;
        manifest
    };
    let path = artifact_path(&dir, job, &manifest.file_name)?;
    let mut entries = vec![];
    entries
        .try_reserve_exact(usize::try_from(config.baby_steps)?)
        .context("unable to reserve BSGS table memory")?;
    let Some(mut hash) = load(&path, &header, &manifest, &mut entries, options)? else {
        return Ok(None);
    };
    if options.stopped() {
        return Ok(None);
    }
    if manifest.stage == "ready" {
        return Ok(Some(Arc::new(Table { entries, point_len })));
    }
    let additional = (config.baby_steps - manifest.committed_entries) * RECORD_BYTES
        + config.baby_steps * RECORD_BYTES
        + encoded_header.len() as u64
        + 8 * 1024 * 1024;
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    // Only truncate after validating the entire committed prefix.
    file.set_len(manifest.file_bytes)?;
    file.seek(SeekFrom::Start(manifest.file_bytes))?;
    file.sync_all()?;
    ensure!(
        fs2::available_space(&dir)? >= additional,
        "insufficient free space for the building ledger, ready table and database margin"
    );
    let mut writer = BufWriter::with_capacity(65536, file);
    let mut point = EcPoint::new(&group)?;
    let start = bignum(&BigUint::from(manifest.committed_entries))?;
    point.mul_generator2(&group, &start, &mut ctx)?;
    let mut scratch = EcPoint::new(&group)?;
    let mut count = manifest.committed_entries;
    let mut checkpoint = Instant::now();
    while count < config.baby_steps {
        if count.is_multiple_of(128) && options.stopped() {
            break;
        }
        let entry = Entry {
            point: point_key(&group, &point, &mut ctx)?,
            index: count,
        };
        writer.write_all(&entry.point)?;
        writer.write_all(&entry.index.to_le_bytes())?;
        hash.update(entry.point);
        hash.update(entry.index.to_le_bytes());
        entries.push(entry);
        count += 1;
        scratch.add(
            &group,
            &point,
            group.generator_opt().context("missing generator")?,
            &mut ctx,
        )?;
        std::mem::swap(&mut point, &mut scratch);
        if count.is_multiple_of(1024) && checkpoint.elapsed() >= options.checkpoint_interval {
            commit_build(
                store,
                job,
                &mut writer,
                &mut manifest,
                count,
                &hash,
                encoded_header.len() as u64,
            )?;
            if !options.quiet {
                eprintln!(
                    "job {job}: {count}/{} baby steps durable",
                    config.baby_steps
                );
            }
            checkpoint = Instant::now();
        }
    }
    commit_build(
        store,
        job,
        &mut writer,
        &mut manifest,
        count,
        &hash,
        encoded_header.len() as u64,
    )?;
    drop(writer);
    if count < config.baby_steps || options.stopped() {
        return Ok(None);
    }
    entries.sort_unstable_by(|a, b| a.point.as_slice().cmp(b.point.as_slice()));
    if options.stopped() {
        return Ok(None);
    }
    let mut temp = tempfile::Builder::new()
        .prefix(&format!("job-{job}-ready-"))
        .suffix(".pending")
        .tempfile_in(&dir)?;
    temp.write_all(&encoded_header)?;
    let mut ready_hash = Sha256::new();
    ready_hash.update(&encoded_header);
    {
        let mut output = BufWriter::with_capacity(65536, temp.as_file_mut());
        for (i, entry) in entries.iter().enumerate() {
            if i.is_multiple_of(1024) && options.stopped() {
                return Ok(None);
            }
            output.write_all(&entry.point)?;
            output.write_all(&entry.index.to_le_bytes())?;
            ready_hash.update(entry.point);
            ready_hash.update(entry.index.to_le_bytes());
        }
        output.flush()?;
    }
    let ready_path = persist(temp, &dir)?;
    manifest.stage = "ready".into();
    manifest.file_name = ready_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    manifest.sha256 = hex::encode(ready_hash.finalize());
    save(store, job, &manifest)?;
    // The new file and its DB reference are durable before the old ledger is removed.
    let _ = fs::remove_file(path);
    Ok(Some(Arc::new(Table { entries, point_len })))
}

fn commit_build(
    store: &mut Store,
    job: i64,
    writer: &mut BufWriter<File>,
    manifest: &mut Manifest,
    count: u64,
    hash: &Sha256,
    header_len: u64,
) -> Result<()> {
    writer.flush()?;
    writer.get_ref().sync_all()?;
    manifest.committed_entries = count;
    manifest.file_bytes = header_len + count * RECORD_BYTES;
    manifest.sha256 = hex::encode(hash.clone().finalize());
    save(store, job, manifest)
}

pub struct Worker {
    group: EcGroup,
    target: EcPoint,
    step: EcPoint,
    ctx: BigNumContext,
    base: BigUint,
    end: BigUint,
    m: BigUint,
    table: Arc<Table>,
}

impl Worker {
    pub fn new(target: &Target, spec: &SearchSpec, table: Arc<Table>) -> Result<Self> {
        let (group, target, mut ctx) = domain(target)?;
        let m = BigUint::from(
            spec.bsgs
                .as_ref()
                .context("missing BSGS parameters")?
                .baby_steps,
        );
        let mut step = EcPoint::new(&group)?;
        let scalar = bignum(&m)?;
        step.mul_generator2(&group, &scalar, &mut ctx)?;
        step.invert2(&group, &mut ctx)?;
        Ok(Self {
            group,
            target,
            step,
            ctx,
            base: number(&spec.start)?,
            end: number(&spec.end)?,
            m,
            table,
        })
    }
    pub fn search(
        &mut self,
        unit: &WorkUnit,
        cancel: &Arc<AtomicBool>,
        interval: Duration,
        mut progress: impl FnMut(&BigUint) -> Result<()>,
    ) -> Result<(BigUint, Option<BigUint>)> {
        let mut next = unit.next.clone();
        let first = &self.base + &next * &self.m;
        let mut offset = EcPoint::new(&self.group)?;
        let scalar = bignum(&first)?;
        offset.mul_generator2(&self.group, &scalar, &mut self.ctx)?;
        offset.invert2(&self.group, &mut self.ctx)?;
        let mut point = EcPoint::new(&self.group)?;
        point.add(&self.group, &self.target, &offset, &mut self.ctx)?;
        let mut scratch = EcPoint::new(&self.group)?;
        let mut checked = 0u32;
        let mut checkpoint = Instant::now();
        while next < unit.end {
            if checked.is_multiple_of(64) {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                if checkpoint.elapsed() >= interval {
                    progress(&next)?;
                    checkpoint = Instant::now();
                }
            }
            let key = point_key(&self.group, &point, &mut self.ctx)?;
            debug_assert!(self.table.point_len <= MAX_POINT_BYTES);
            if let Ok(index) = self
                .table
                .entries
                .binary_search_by(|entry| entry.point.cmp(&key))
            {
                let candidate =
                    &self.base + &next * &self.m + BigUint::from(self.table.entries[index].index);
                if candidate < self.end {
                    let mut verified = EcPoint::new(&self.group)?;
                    let secret = bignum(&candidate)?;
                    verified.mul_generator2(&self.group, &secret, &mut self.ctx)?;
                    ensure!(
                        verified.eq(&self.group, &self.target, &mut self.ctx)?,
                        "BSGS lookup failed full public-key verification"
                    );
                    next += 1u8;
                    return Ok((next, Some(candidate)));
                }
            }
            next += 1u8;
            scratch.add(&self.group, &point, &self.step, &mut self.ctx)?;
            std::mem::swap(&mut point, &mut scratch);
            checked = checked.wrapping_add(1);
        }
        Ok((next, None))
    }
}
