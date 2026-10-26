use anyhow::Result;
use cert_cracker::{
    bsgs::{self, Manifest, PrepareOptions},
    crypto, import,
    model::{BsgsConfig, SearchSpec, number},
    planner::{self, PlanOptions},
    search::{self, RunOptions},
    storage::Store,
};
use num_bigint::BigUint;
use openssl::pkey::PKey;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

fn target(curve: &str, scalar: BigUint) -> cert_cracker::model::Target {
    let private = crypto::lab_key(curve, &scalar).unwrap();
    let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
    import::target_from_key(&public, "BSGS laboratory").unwrap()
}
fn opts(workers: usize) -> RunOptions {
    RunOptions {
        workers,
        checkpoint_interval: Duration::from_millis(1),
        time_limit: None,
        cancel: Arc::new(AtomicBool::new(false)),
        quiet: true,
    }
}
fn config(m: u64) -> BsgsConfig {
    BsgsConfig {
        baby_steps: m,
        memory_budget_bytes: 32 * 1024 * 1024,
        table_format_version: 1,
    }
}
fn make(store: &Store, id: String, a: &str, b: &str, m: u64) -> i64 {
    store
        .create_job(&SearchSpec::bsgs(id, a, b, 3, config(m)).unwrap())
        .unwrap()
}
fn prepare(store: &mut Store, job: i64, cancel: bool) -> Result<()> {
    let spec = store.spec(job)?;
    let target = store.target(&spec.target_id)?;
    bsgs::prepare(
        store,
        job,
        &spec,
        &target,
        &PrepareOptions {
            workers: 2,
            cancel: Arc::new(AtomicBool::new(cancel)),
            deadline: None,
            checkpoint_interval: Duration::from_millis(1),
            quiet: true,
        },
    )?;
    Ok(())
}
fn artifact(store: &Store, job: i64) -> (Manifest, std::path::PathBuf) {
    let m: Manifest = serde_json::from_value(store.engine_state(job).unwrap().unwrap()).unwrap();
    let path = store
        .path
        .parent()
        .unwrap()
        .join("artifacts")
        .join(&m.file_name);
    (m, path)
}

#[test]
fn differential_four_curves_nonsquare_interval_and_infinity() {
    for curve in ["P-256", "P-384", "P-521", "secp256k1"] {
        for scalar in [4u32, 5, 6, 15, 16, 115, 118, 119, 120] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::open(dir.path(), true).unwrap();
            let id = store.import(target(curve, scalar.into())).unwrap();
            let bsgs = make(&store, id.clone(), "5", "119", 11);
            let sequential = store
                .create_job(&SearchSpec::sequential(id, "5", "119", 13).unwrap())
                .unwrap();
            let a = search::run(&mut store, bsgs, opts(3)).unwrap();
            let b = search::run(&mut store, sequential, opts(2)).unwrap();
            assert_eq!(a["outcome"], b["outcome"], "{curve} scalar {scalar}");
            assert!(a["tested_candidates"].is_null());
            assert!(a["giant_steps_completed"].is_string());
            if scalar == 119 {
                assert_eq!(a["covered_candidates"], "114");
                assert_eq!(a["coverage"], json!([{"start":"0x5","end":"0x77"}]));
            }
        }
    }
}

#[test]
fn table_sizes_one_and_whole_interval_and_large_scalar() {
    for m in [1, 32] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), true).unwrap();
        let id = store.import(target("P-256", 32u8.into())).unwrap();
        let job = make(&store, id, "1", "33", m);
        assert_eq!(
            search::run(&mut store, job, opts(2)).unwrap()["status"],
            "recovered"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let start = BigUint::from(1u8) << 200usize;
    let mut store = Store::open(dir.path(), true).unwrap();
    let id = store.import(target("P-521", &start + 102u8)).unwrap();
    let job = make(
        &store,
        id,
        &start.to_str_radix(10),
        &(&start + 103u8).to_str_radix(10),
        11,
    );
    assert_eq!(
        search::run(&mut store, job, opts(3)).unwrap()["status"],
        "recovered"
    );
}

#[test]
fn planner_memory_constraints_and_automatic_selection() {
    let t = target("P-256", 4u8.into());
    let mut options = PlanOptions {
        start: "1",
        end: "1000000000001",
        chunk_size: 64,
        method: "auto",
        memory_mib: 16,
        baby_steps: None,
        workers: 4,
    };
    let (spec, estimate) = planner::plan(&t, options).unwrap();
    assert_eq!(spec.method, "ec-bsgs");
    assert_eq!(estimate["bsgs"]["balanced_sqrt_table"], false);
    assert!(
        planner::memory_required(spec.bsgs.as_ref().unwrap().baby_steps, 4).unwrap()
            <= 16 * 1024 * 1024
    );
    options.end = "16";
    assert_eq!(
        planner::plan(&t, options).unwrap().0.method,
        "ec-sequential"
    );
    options.method = "bsgs";
    options.memory_mib = 1;
    assert!(planner::plan(&t, options).is_err());
    options.memory_mib = 16;
    options.baby_steps = Some(999999);
    assert!(planner::plan(&t, options).is_err());
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let id = store.import(t).unwrap();
    let spec = SearchSpec::bsgs(
        id,
        "1",
        "1000001",
        64,
        BsgsConfig {
            baby_steps: 1000,
            memory_budget_bytes: 4 * 1024 * 1024,
            table_format_version: 1,
        },
    )
    .unwrap();
    let job = store.create_job(&spec).unwrap();
    assert!(search::run(&mut store, job, opts(8)).is_err());
    assert_eq!(store.status(job).unwrap(), "queued");
    assert!(store.engine_state(job).unwrap().is_none());
}

#[test]
fn interrupted_build_discards_unacknowledged_tail_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let id = store.import(target("P-384", 77u8.into())).unwrap();
    let job = make(&store, id, "1", "1000", 64);
    prepare(&mut store, job, true).unwrap();
    let (before, path) = artifact(&store, job);
    assert_eq!(before.stage, "building");
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"uncommitted torn tail")
        .unwrap();
    let report = search::run(&mut store, job, opts(4)).unwrap();
    assert_eq!(report["status"], "recovered");
    assert_eq!(artifact(&store, job).0.stage, "ready");
    assert!(!path.exists());
}

#[test]
fn ready_table_is_reused_and_corruption_is_rejected() {
    for corruption in ["checksum", "truncate", "append", "binding"] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), true).unwrap();
        let id = store.import(target("P-256", 9999u32.into())).unwrap();
        let job = make(&store, id, "1", "1000", 32);
        prepare(&mut store, job, false).unwrap();
        let (manifest, path) = artifact(&store, job);
        prepare(&mut store, job, false).unwrap();
        assert_eq!(artifact(&store, job).0.file_name, manifest.file_name);
        match corruption {
            "checksum" => {
                let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                file.seek(SeekFrom::End(-1)).unwrap();
                file.write_all(&[0xff]).unwrap();
            }
            "truncate" => {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(manifest.file_bytes - 1)
                    .unwrap();
            }
            "append" => {
                OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(&[0])
                    .unwrap();
            }
            _ => {
                let mut m = serde_json::to_value(&manifest).unwrap();
                m["spec_hash"] = json!("wrong");
                store.save_engine_state(job, &m).unwrap();
            }
        }
        assert!(search::run(&mut store, job, opts(2)).is_err());
        assert!(store.findings().unwrap().is_empty());
        assert_eq!(store.report(job).unwrap()["covered_candidates"], "0");
    }
}

#[test]
fn missing_manifest_does_not_reset_existing_giant_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let id = store.import(target("P-256", 9999u32.into())).unwrap();
    let job = make(&store, id, "1", "1000", 32);
    prepare(&mut store, job, false).unwrap();
    store.begin_run(job).unwrap();
    store.allocate(job).unwrap();
    store
        .conn
        .execute("DELETE FROM engine_states WHERE job_id=?1", [job])
        .unwrap();
    assert!(search::run(&mut store, job, opts(2)).is_err());
}

#[test]
fn legacy_sequential_hash_and_v2_database_migrate() {
    let dir = tempfile::tempdir().unwrap();
    let id;
    let job;
    let old;
    {
        let store = Store::open(dir.path(), true).unwrap();
        id = store.import(target("P-256", 4u8.into())).unwrap();
        let spec = SearchSpec::sequential(id, "1", "32", 8).unwrap();
        old = serde_json::to_string(&spec).unwrap();
        assert!(!old.contains("bsgs"));
        job = store.create_job(&spec).unwrap();
        store
            .conn
            .execute_batch("DROP TABLE engine_states; PRAGMA user_version=2;")
            .unwrap();
    }
    let mut store = Store::open(dir.path(), true).unwrap();
    assert_eq!(
        serde_json::to_string(&store.spec(job).unwrap()).unwrap(),
        old
    );
    assert_eq!(
        search::run(&mut store, job, opts(2)).unwrap()["status"],
        "recovered"
    );
}

#[test]
fn subgroup_boundary_and_outside_wrapped_candidate() {
    for curve in ["P-256", "P-521"] {
        let reference = target(curve, 1u8.into());
        let order = crypto::ec_order(&reference).unwrap();
        let start = &order - 103u8;
        for scalar in [&order - 1u8, BigUint::from(1u8)] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::open(dir.path(), true).unwrap();
            let expected = scalar != BigUint::from(1u8);
            let id = store.import(target(curve, scalar)).unwrap();
            let job = make(
                &store,
                id,
                &start.to_str_radix(10),
                &order.to_str_radix(10),
                11,
            );
            let report = search::run(&mut store, job, opts(3)).unwrap();
            assert_eq!(
                report["status"],
                if expected { "recovered" } else { "exhausted" }
            );
        }
    }
}

#[test]
fn estimate_is_readonly_and_giant_chunks_expose_parallel_work() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _) = crypto::lab_certificate("P-256", &4u8.into()).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, cert).unwrap();
    let state = dir.path().join("must-not-exist");
    let result = Command::new(env!("CARGO_BIN_EXE_cert-cracker"))
        .arg("--state")
        .arg(&state)
        .args(["estimate", "--input"])
        .arg(&input)
        .args([
            "--end",
            "100000001",
            "--method",
            "bsgs",
            "--memory-mib",
            "16",
            "--workers",
            "4",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!state.exists());
    let estimate: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(estimate["planning"]["selected_method"], "ec-bsgs");
    let spec: SearchSpec = serde_json::from_value(estimate["spec"].clone()).unwrap();
    let (_, giants) = spec.work_bounds().unwrap();
    assert!(BigUint::from(spec.chunk_size) < giants);
}

#[test]
fn cancellation_during_table_validation_preserves_ready_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let id = store.import(target("P-256", 77u8.into())).unwrap();
    let job = make(&store, id, "1", "1000", 64);
    prepare(&mut store, job, false).unwrap();
    let before = artifact(&store, job).0;
    let cancelled = opts(2);
    cancelled
        .cancel
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        search::run(&mut store, job, cancelled).unwrap()["status"],
        "paused"
    );
    assert_eq!(artifact(&store, job).0.sha256, before.sha256);
    assert_eq!(
        search::run(&mut store, job, opts(3)).unwrap()["status"],
        "recovered"
    );
}

#[cfg(unix)]
fn kill_at_stage(state: &Path, stage: &str, child: &mut std::process::Child) -> Value {
    let started = Instant::now();
    let mut observed = None;
    while started.elapsed() < Duration::from_secs(20) {
        if let Ok(store) = Store::open(state, false)
            && let Ok(report) = store.report(1)
        {
            let built = report["engine_state"]["committed_entries"]
                .as_u64()
                .unwrap_or(0);
            let giant = report["giant_steps_completed"]
                .as_str()
                .and_then(|s| number(s).ok())
                .unwrap_or_default();
            if report["engine_state"]["stage"] == stage
                && (stage == "building" && built > 0
                    || stage == "ready" && giant > BigUint::from(0u8))
            {
                observed = Some(report);
                break;
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let _ = child.kill();
    child.wait().unwrap();
    observed.expect("never observed durable progress in requested BSGS stage")
}

#[cfg(unix)]
#[test]
fn real_sigkill_during_table_build_then_changed_worker_resume() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _) = crypto::lab_certificate("P-256", &BigUint::from(2_000_000_000u64)).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, cert).unwrap();
    let state = dir.path().join("state");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let mut child = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["search", "--input"])
        .arg(input)
        .args([
            "--method",
            "bsgs",
            "--end",
            "1000000001",
            "--baby-steps",
            "200000",
            "--memory-mib",
            "64",
            "--workers",
            "2",
            "--checkpoint-interval-ms",
            "1",
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let before = kill_at_stage(&state, "building", &mut child);
    assert!(
        before["engine_state"]["committed_entries"]
            .as_u64()
            .unwrap()
            < 200000
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
    assert_eq!(report["covered_candidates"], "1000000000");
    assert_eq!(report["giant_steps_completed"], "5000");
}

#[cfg(unix)]
#[test]
fn real_sigkill_during_giant_search_reuses_ready_table() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _) = crypto::lab_certificate("P-256", &BigUint::from(3_000_000u64)).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, cert).unwrap();
    let state = dir.path().join("state");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let mut child = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["search", "--input"])
        .arg(input)
        .args([
            "--method",
            "bsgs",
            "--end",
            "2000001",
            "--baby-steps",
            "8",
            "--chunk-size",
            "256",
            "--memory-mib",
            "16",
            "--workers",
            "2",
            "--checkpoint-interval-ms",
            "1",
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let before = kill_at_stage(&state, "ready", &mut child);
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
    assert_eq!(report["covered_candidates"], "2000000");
    assert_eq!(
        report["engine_state"]["file_name"],
        before["engine_state"]["file_name"]
    );
    assert_eq!(
        report["engine_state"]["sha256"],
        before["engine_state"]["sha256"]
    );
}
