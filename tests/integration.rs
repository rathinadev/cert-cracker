use cert_cracker::{
    analysis, crypto, import,
    model::{SearchSpec, number},
    search::{self, RunOptions},
    storage::Store,
};
use num_bigint::BigUint;
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
#[cfg(unix)]
use std::{process::Stdio, time::Instant};

fn fixture(dir: &Path, curve: &str, scalar: &BigUint) -> std::path::PathBuf {
    let (cert, public) = crypto::lab_certificate(curve, scalar).unwrap();
    let path = dir.join(format!("{curve}-{}.pem", scalar.to_str_radix(16)));
    fs::write(&path, cert).unwrap();
    fs::write(path.with_extension("pub.pem"), public).unwrap();
    path
}
fn options(workers: usize, seconds: Option<f64>) -> RunOptions {
    RunOptions {
        workers,
        checkpoint_interval: Duration::from_millis(5),
        time_limit: seconds.map(Duration::from_secs_f64),
        cancel: Arc::new(AtomicBool::new(false)),
        quiet: true,
    }
}

#[test]
fn four_curves_recover_verify_and_export_without_leaking() {
    for curve in ["P-256", "P-384", "P-521", "secp256k1"] {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), curve, &4u8.into());
        let target = import::load(&path).unwrap().remove(0);
        let public = import::load(&path.with_extension("pub.pem"))
            .unwrap()
            .remove(0);
        assert_eq!(target.id, public.id);
        let mut store = Store::open(&dir.path().join("state"), true).unwrap();
        let id = store.import(target.clone()).unwrap();
        store.import(public).unwrap();
        assert_eq!(store.targets().unwrap().len(), 1);
        let spec = SearchSpec::sequential(id, "1", "32", 3).unwrap();
        let job = store.create_job(&spec).unwrap();
        assert_eq!(job, store.create_job(&spec).unwrap());
        let report = search::run(&mut store, job, options(3, None)).unwrap();
        assert_eq!(report["outcome"], "verified_recovery");
        let json = report.to_string();
        assert!(!json.contains("PRIVATE KEY"));
        assert!(!json.contains("private_pem"));
        let finding = report["finding_id"].as_i64().unwrap();
        let output = dir.path().join("recovered.pem");
        store.export_key(finding, &output).unwrap();
        crypto::verify_private(&target, &fs::read(&output).unwrap()).unwrap();
        assert!(store.export_key(finding, &output).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn p521_search_above_machine_integer_limit() {
    let dir = tempfile::tempdir().unwrap();
    let start = BigUint::from(1u8) << 200usize;
    let scalar = &start + 3u8;
    let target = import::load(&fixture(dir.path(), "P-521", &scalar))
        .unwrap()
        .remove(0);
    let mut store = Store::open(&dir.path().join("state"), true).unwrap();
    let id = store.import(target).unwrap();
    let spec = SearchSpec::sequential(
        id,
        &start.to_str_radix(10),
        &(&start + 10u8).to_str_radix(10),
        2,
    )
    .unwrap();
    let job = store.create_job(&spec).unwrap();
    assert_eq!(
        search::run(&mut store, job, options(2, None)).unwrap()["outcome"],
        "verified_recovery"
    );
}

#[test]
fn partial_units_stale_updates_and_resume_preserve_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let target = import::load(&fixture(dir.path(), "P-256", &99999u32.into()))
        .unwrap()
        .remove(0);
    let mut store = Store::open(&dir.path().join("state"), true).unwrap();
    let id = store.import(target).unwrap();
    let job = store
        .create_job(&SearchSpec::sequential(id, "1", "258", 64).unwrap())
        .unwrap();
    store.begin_run(job).unwrap();
    let a = store.allocate(job).unwrap().unwrap();
    let b = store.allocate(job).unwrap().unwrap();
    store
        .progress(job, b.id, b.generation, &b.end, true)
        .unwrap();
    store
        .progress(job, a.id, a.generation, &10u8.into(), false)
        .unwrap();
    assert!(
        store
            .progress(job, a.id, a.generation, &5u8.into(), false)
            .is_err()
    );
    assert!(
        store
            .progress(job, a.id, a.generation + 1, &12u8.into(), false)
            .is_err()
    );
    assert_eq!(
        store.report(job).unwrap()["coverage"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    store.begin_run(job).unwrap();
    let resumed = store.allocate(job).unwrap().unwrap();
    assert_eq!(resumed.next, BigUint::from(10u8));
    assert!(resumed.generation > a.generation);
    assert!(
        store
            .progress(job, a.id, a.generation, &20u8.into(), false)
            .is_err()
    );
    let report = search::run(&mut store, job, options(4, None)).unwrap();
    assert_eq!(report["outcome"], "range_exhausted");
    assert_eq!(report["tested_candidates"], "257");
    assert_eq!(
        report["coverage"],
        serde_json::json!([{"start":"0x1","end":"0x102"}])
    );
}

#[test]
fn pause_inside_last_allocated_chunk_is_not_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    let target = import::load(&fixture(dir.path(), "P-256", &999999u32.into()))
        .unwrap()
        .remove(0);
    let mut store = Store::open(&dir.path().join("state"), true).unwrap();
    let id = store.import(target).unwrap();
    let job = store
        .create_job(&SearchSpec::sequential(id, "1", "20000", 20000).unwrap())
        .unwrap();
    assert_eq!(
        search::run(&mut store, job, options(2, Some(0.001))).unwrap()["status"],
        "paused"
    );
    let report = search::run(&mut store, job, options(3, None)).unwrap();
    assert_eq!(report["tested_candidates"], "19999");
    assert_eq!(report["status"], "exhausted");
}

#[test]
fn rejected_bounds_and_modified_specification() {
    let dir = tempfile::tempdir().unwrap();
    let target = import::load(&fixture(dir.path(), "P-256", &4u8.into()))
        .unwrap()
        .remove(0);
    let mut store = Store::open(&dir.path().join("state"), true).unwrap();
    let id = store.import(target.clone()).unwrap();
    let order = crypto::ec_order(&target).unwrap();
    let job = store
        .create_job(&SearchSpec::sequential(id, "1", &(&order + 1u8).to_str_radix(10), 64).unwrap())
        .unwrap();
    assert!(search::run(&mut store, job, options(1, None)).is_err());
    store
        .conn
        .execute("UPDATE jobs SET spec_hash='modified' WHERE id=?1", [job])
        .unwrap();
    assert!(store.spec(job).is_err());
}

#[cfg(unix)]
#[test]
fn real_process_sigkill_then_resume_with_different_workers() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path(), "P-256", &999999u32.into());
    let state = dir.path().join("state");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let mut child = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["search", "--input"])
        .arg(path)
        .args([
            "--end",
            "50000",
            "--chunk-size",
            "256",
            "--workers",
            "2",
            "--checkpoint-interval-ms",
            "5",
            "--method",
            "sequential",
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let mut observed = false;
    while started.elapsed() < Duration::from_secs(10) {
        if let Ok(store) = Store::open(&state, false)
            && let Ok(report) = store.report(1)
            && number(report["tested_candidates"].as_str().unwrap()).unwrap() > BigUint::from(100u8)
        {
            observed = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(observed, "child never committed measurable progress");
    let before = Store::open(&state, false).unwrap().report(1).unwrap();
    assert!(
        number(before["tested_candidates"].as_str().unwrap()).unwrap() < BigUint::from(49999u32)
    );
    let output = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["resume", "1", "--workers", "3", "--quiet"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "exhausted");
    assert_eq!(report["tested_candidates"], "49999");
    assert_eq!(
        report["coverage"],
        serde_json::json!([{"start":"0x1","end":"0xc350"}])
    );
}

#[test]
fn rsa_shared_prime_recovery_and_no_secret_in_report() {
    use openssl::{bn::BigNum, pkey::PKey, rsa::Rsa};
    let mut p = BigNum::new().unwrap();
    p.generate_prime(512, false, None, None).unwrap();
    let mut q = BigNum::new().unwrap();
    q.generate_prime(512, false, None, None).unwrap();
    let mut r = BigNum::new().unwrap();
    r.generate_prime(512, false, None, None).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let mut targets = vec![];
    for other in [&q, &r] {
        let mut n = BigNum::new().unwrap();
        n.checked_mul(&p, other, &mut ctx).unwrap();
        let key = PKey::from_rsa(
            Rsa::from_public_components(n, BigNum::from_u32(65537).unwrap()).unwrap(),
        )
        .unwrap();
        targets.push(import::target_from_key(&key, "test").unwrap());
    }
    let results = analysis::analyze(&targets, 0, 0).unwrap();
    for (result, target) in results.iter().zip(&targets) {
        assert_eq!(result.outcome, "verified_recovery");
        crypto::verify_private(target, result.private_pem.as_ref().unwrap()).unwrap();
    }
    let report = serde_json::to_string(&results).unwrap();
    assert!(!report.contains("PRIVATE KEY"));
    assert!(!report.contains("private_pem"));
    let duplicates = analysis::analyze(&[targets[0].clone(), targets[0].clone()], 0, 0).unwrap();
    assert!(duplicates.iter().all(|r| r.private_pem.is_none()));
}

#[test]
fn input_limits_der_trailing_data_bundles_and_ed25519() {
    use openssl::{pkey::PKey, x509::X509};
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path(), "P-256", &4u8.into());
    let cert = fs::read(&path).unwrap();
    let mut bundle = cert.clone();
    bundle.extend_from_slice(&cert);
    let bundle_path = dir.path().join("bundle.pem");
    fs::write(&bundle_path, &bundle).unwrap();
    let targets = import::load(&bundle_path).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].certificates.len(), 1);
    let der = X509::from_pem(&cert).unwrap().to_der().unwrap();
    let der_path = dir.path().join("certificate.der");
    fs::write(&der_path, &der).unwrap();
    assert_eq!(import::load(&der_path).unwrap()[0].id, targets[0].id);
    let mut trailing = der;
    trailing.push(0);
    fs::write(&der_path, trailing).unwrap();
    assert!(import::load(&der_path).is_err());
    fs::write(&der_path, [0x30, 0xff, 0xff, 0xff]).unwrap();
    assert!(import::load(&der_path).is_err());
    let empty = dir.path().join("empty");
    fs::write(&empty, []).unwrap();
    assert!(import::load(&empty).is_err());
    let oversized = dir.path().join("large");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert!(import::load(&oversized).is_err());
    let key = PKey::generate_ed25519().unwrap();
    let ed = dir.path().join("ed.pem");
    fs::write(&ed, key.public_key_to_pem().unwrap()).unwrap();
    let target = import::load(&ed).unwrap().remove(0);
    assert_eq!(target.algorithm, "Ed25519");
    assert!(crypto::ec_order(&target).is_err());
    fs::write(&ed, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    assert!(import::load(&ed).is_err());
}

#[test]
fn range_boundaries_false_matches_and_durable_discovery() {
    for scalar in [1u32, 31, 32, 33, 64, 65, 127, 128] {
        let dir = tempfile::tempdir().unwrap();
        let target = import::load(&fixture(dir.path(), "P-256", &scalar.into()))
            .unwrap()
            .remove(0);
        assert!(crypto::recover_ec(&target, &BigUint::from(scalar + 1)).is_err());
        let mut store = Store::open(&dir.path().join("state"), true).unwrap();
        let id = store.import(target).unwrap();
        let job = store
            .create_job(&SearchSpec::sequential(id, "1", "128", 32).unwrap())
            .unwrap();
        let result = search::run(&mut store, job, options(3, None)).unwrap();
        assert_eq!(
            result["status"],
            if scalar < 128 {
                "recovered"
            } else {
                "exhausted"
            }
        );
        if scalar == 128 {
            assert_eq!(result["tested_candidates"], "127");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let target = import::load(&fixture(dir.path(), "P-256", &4u8.into()))
        .unwrap()
        .remove(0);
    let mut store = Store::open(&dir.path().join("state"), true).unwrap();
    let id = store.import(target.clone()).unwrap();
    let job = store
        .create_job(&SearchSpec::sequential(id, "1", "32", 8).unwrap())
        .unwrap();
    store.begin_run(job).unwrap();
    let _unit = store.allocate(job).unwrap().unwrap();
    let private = crypto::recover_ec(&target, &4u8.into()).unwrap();
    store
        .record_recovery(&target, Some(job), "ec-sequential", &private)
        .unwrap();
    // Simulate termination after persisting a recovery but before advancing the unit cursor.
    let report = search::run(&mut store, job, options(2, None)).unwrap();
    assert_eq!(report["status"], "recovered");
    assert!(report["finding_id"].is_i64());
}

#[test]
fn persisted_negative_audit_and_database_schema_migration() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    {
        let store = Store::open(&state, true).unwrap();
        store
            .conn
            .execute_batch(
                "DROP TABLE engine_states; DROP TABLE kangaroo_states; DROP TABLE audit_runs; PRAGMA user_version=1;",
            )
            .unwrap();
    }
    let store = Store::open(&state, true).unwrap();
    let record =
        serde_json::json!({"outcome":"no_weakness_detected_by_completed_checks","budget":100});
    store.save_audit(&record).unwrap();
    assert_eq!(store.audits().unwrap()[0]["report"], record);
    assert_eq!(
        store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
}

#[test]
fn tiny_rsa_trial_and_fermat_have_verified_private_keys() {
    use openssl::{bn::BigNum, pkey::PKey, rsa::Rsa};
    for (p, q, trial, fermat, method) in [
        (101u32, 1009u32, 103, 0, "trial_division"),
        (1009, 1013, 0, 1, "fermat"),
    ] {
        let key = PKey::from_rsa(
            Rsa::from_public_components(
                BigNum::from_u32(p * q).unwrap(),
                BigNum::from_u32(65537).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let target = import::target_from_key(&key, "tiny-rsa-lab").unwrap();
        let result = analysis::analyze(std::slice::from_ref(&target), trial, fermat)
            .unwrap()
            .remove(0);
        assert_eq!(result.outcome, "verified_recovery");
        assert_eq!(result.method.as_deref(), Some(method));
        crypto::verify_private(&target, result.private_pem.as_ref().unwrap()).unwrap();
    }
}

#[test]
fn cli_keeps_successful_imports_when_other_paths_are_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path(), "P-256", &4u8.into());
    let state = dir.path().join("state");
    let output = Command::new(env!("CARGO_BIN_EXE_cert-cracker"))
        .arg("--state")
        .arg(&state)
        .args(["targets", "import"])
        .arg(&path)
        .arg(dir.path().join("missing.pem"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["target_ids"].as_array().unwrap().len(), 1);
    assert_eq!(report["errors"].as_array().unwrap().len(), 1);
    assert_eq!(
        Store::open(&state, false).unwrap().targets().unwrap().len(),
        1
    );
}
