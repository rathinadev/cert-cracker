use cert_cracker::{
    backup, crypto, import,
    model::SearchSpec,
    search::{self, RunOptions},
    storage::Store,
};
use openssl::pkey::PKey;
use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
const PASSWORD: &[u8] = b"correct horse laboratory battery";
fn target() -> (cert_cracker::model::Target, Vec<u8>) {
    let key = crypto::lab_key("P-256", &42u8.into()).unwrap();
    let public = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    (
        import::target_from_key(&public, "test").unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}
#[test]
fn encrypted_findings_unlock_export_backup_and_detect_tampering() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let saved = root.path().join("backup");
    let (target, pem) = target();
    let id;
    {
        let mut store = Store::open(&state, true).unwrap();
        store.import(target.clone()).unwrap();
        store.initialize_vault(PASSWORD).unwrap();
        id = store.record_recovery(&target, None, "test", &pem).unwrap();
        let stored: Vec<u8> = store
            .conn
            .query_row("SELECT private_pem FROM findings WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            !stored
                .windows(b"PRIVATE KEY".len())
                .any(|w| w == b"PRIVATE KEY")
        );
        assert!(!stored.windows(pem.len()).any(|w| w == pem));
    }
    for name in ["state.sqlite", "state.sqlite-wal"] {
        if let Ok(data) = fs::read(state.join(name)) {
            assert!(!data.windows(pem.len()).any(|w| w == pem));
        }
    }
    backup::create(&state, &saved).unwrap();
    {
        let mut store = Store::open(&saved, true).unwrap();
        assert!(store.unlock_vault(b"wrong password for vault").is_err());
        assert!(
            store
                .export_key(id, &root.path().join("locked.pem"))
                .is_err()
        );
        store.unlock_vault(PASSWORD).unwrap();
        let path = root.path().join("unlocked.pem");
        store.export_key(id, &path).unwrap();
        crypto::verify_private(&target, &fs::read(&path).unwrap()).unwrap();
        let mut blob: Vec<u8> = store
            .conn
            .query_row("SELECT private_pem FROM findings WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        blob[0] ^= 1;
        store
            .conn
            .execute(
                "UPDATE findings SET private_pem=?1 WHERE id=?2",
                rusqlite::params![blob, id],
            )
            .unwrap();
        assert!(
            store
                .export_key(id, &root.path().join("tampered.pem"))
                .is_err()
        );
        assert!(!root.path().join("tampered.pem").exists());
    }
}
#[test]
fn locked_vault_stops_search_before_job_progress_and_plaintext_migration_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let (target, pem) = target();
    let job;
    {
        let mut store = Store::open(&state, true).unwrap();
        let id = store.import(target.clone()).unwrap();
        job = store
            .create_job(&SearchSpec::sequential(id, "1", "100", 10).unwrap())
            .unwrap();
        store.initialize_vault(PASSWORD).unwrap();
    }
    {
        let mut store = Store::open(&state, true).unwrap();
        let result = search::run(
            &mut store,
            job,
            RunOptions {
                workers: 1,
                checkpoint_interval: Duration::from_millis(5),
                time_limit: None,
                cancel: Arc::new(AtomicBool::new(false)),
                quiet: true,
            },
        );
        assert!(result.unwrap_err().to_string().contains("vault is locked"));
        assert_eq!(store.report(job).unwrap()["tested_candidates"], "0");
    }
    let other = root.path().join("other");
    let mut store = Store::open(&other, true).unwrap();
    store.import(target.clone()).unwrap();
    store.record_recovery(&target, None, "test", &pem).unwrap();
    assert!(
        store
            .initialize_vault(PASSWORD)
            .unwrap_err()
            .to_string()
            .contains("no existing findings")
    );
}

#[test]
fn cli_vault_init_search_and_export_require_password_file() {
    use std::process::Command;
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let pass = root.path().join("password");
    fs::write(&pass, PASSWORD).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (cert, _) = crypto::lab_certificate("P-256", &42u8.into()).unwrap();
    let input = root.path().join("cert.pem");
    fs::write(&input, cert).unwrap();
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let init = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .arg("--vault-password-file")
        .arg(&pass)
        .arg("vault-init")
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let locked = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .arg("search")
        .arg("--input")
        .arg(&input)
        .args(["--end", "100", "--method", "sequential", "--quiet"])
        .output()
        .unwrap();
    assert!(!locked.status.success());
    assert!(String::from_utf8_lossy(&locked.stderr).contains("vault is locked"));
    let recovered = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .arg("--vault-password-file")
        .arg(&pass)
        .arg("search")
        .arg("--input")
        .arg(&input)
        .args(["--end", "100", "--method", "sequential", "--quiet"])
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    let id = report["finding_id"].as_i64().unwrap().to_string();
    let out = root.path().join("export.pem");
    let export = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .arg("--vault-password-file")
        .arg(&pass)
        .arg("export-key")
        .arg(id)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(out.is_file());
}
