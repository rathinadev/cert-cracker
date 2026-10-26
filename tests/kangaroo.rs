use cert_cracker::{
    crypto, import, kangaroo,
    model::{SearchSpec, Target, fingerprint, number},
    planner::{self, KangarooOptions, PlanOptions},
    search::{self, RunOptions},
    storage::Store,
};
use num_bigint::BigUint;
use openssl::pkey::PKey;
use serde_json::{Value, json};
use std::{
    fs,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
#[cfg(unix)]
use std::{process::Stdio, time::Instant};

fn target(curve: &str, scalar: BigUint) -> Target {
    let private = crypto::lab_key(curve, &scalar).unwrap();
    let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
    import::target_from_key(&public, "kangaroo laboratory").unwrap()
}
fn options(workers: usize) -> RunOptions {
    RunOptions {
        workers,
        checkpoint_interval: Duration::from_millis(2),
        time_limit: None,
        cancel: Arc::new(AtomicBool::new(false)),
        quiet: true,
    }
}
fn plan(
    t: &Target,
    start: &str,
    end: &str,
    k: &KangarooOptions,
    workers: usize,
    memory_mib: u64,
) -> anyhow::Result<SearchSpec> {
    Ok(planner::plan(
        t,
        PlanOptions {
            start,
            end,
            chunk_size: 16384,
            method: "kangaroo",
            memory_mib,
            baby_steps: None,
            workers,
            kangaroo: Some(k),
        },
    )?
    .0)
}
fn config() -> KangarooOptions {
    KangarooOptions {
        attempts: Some(8),
        distinguished_bits: Some(0),
        max_points: Some(256),
        ..Default::default()
    }
}

#[test]
fn differential_four_curves_and_interval_boundaries() {
    for curve in ["P-256", "P-384", "P-521", "secp256k1"] {
        for scalar in [4u32, 5, 6, 15, 65, 117, 118, 119] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::open(dir.path(), true).unwrap();
            let t = target(curve, scalar.into());
            let spec = plan(&t, "5", "119", &config(), 3, 32).unwrap();
            store.import(t.clone()).unwrap();
            let job = store.create_job(&spec).unwrap();
            let sequential = store
                .create_job(&SearchSpec::sequential(t.id.clone(), "5", "119", 16).unwrap())
                .unwrap();
            let reference = search::run(&mut store, sequential, options(2)).unwrap();
            let report = search::run(&mut store, job, options(3)).unwrap();
            assert_eq!(
                report["status"] == "recovered",
                reference["status"] == "recovered",
                "{curve} {scalar}"
            );
            assert!(report["coverage"].is_null());
            assert!(report["covered_candidates"].is_null());
            assert!(report["tested_candidates"].is_null());
            if report["status"] == "recovered" {
                let key = dir.path().join("recovered.private.pem");
                store
                    .export_key(report["finding_id"].as_i64().unwrap(), &key)
                    .unwrap();
                crypto::verify_private(&t, &fs::read(key).unwrap()).unwrap();
            } else {
                assert_eq!(report["outcome"], "probabilistic_budget_exhausted");
                assert_eq!(report["attempts_completed"], 8);
            }
            assert!(!report.to_string().contains("PRIVATE KEY"));
        }
    }
}

#[test]
fn arbitrary_offsets_singleton_and_subgroup_wrap() {
    let offset = BigUint::from(1u8) << 200usize;
    for (start, end, scalar, recovered) in [
        (offset.clone(), &offset + 103u8, &offset + 31u8, true),
        (offset.clone(), &offset + 1u8, offset.clone(), true),
        (offset.clone(), &offset + 1u8, &offset + 1u8, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), true).unwrap();
        let t = target("P-521", scalar);
        let spec = plan(
            &t,
            &start.to_str_radix(10),
            &end.to_str_radix(10),
            &config(),
            2,
            32,
        )
        .unwrap();
        store.import(t).unwrap();
        let job = store.create_job(&spec).unwrap();
        assert_eq!(
            search::run(&mut store, job, options(2)).unwrap()["status"] == "recovered",
            recovered
        );
    }
    for curve in ["P-256", "P-521"] {
        let order = crypto::ec_order(&target(curve, 1u8.into())).unwrap();
        for (scalar, expected) in [
            (&order - 1u8, true),
            (&order - 103u8, true),
            (1u8.into(), false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::open(dir.path(), true).unwrap();
            let t = target(curve, scalar);
            let spec = plan(
                &t,
                &(&order - 103u8).to_str_radix(10),
                &order.to_str_radix(10),
                &config(),
                2,
                32,
            )
            .unwrap();
            store.import(t).unwrap();
            let job = store.create_job(&spec).unwrap();
            assert_eq!(
                search::run(&mut store, job, options(2)).unwrap()["status"] == "recovered",
                expected
            );
        }
    }
}

#[test]
fn insufficient_budget_never_claims_exhaustive_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let t = target("P-256", 17u8.into());
    let k = KangarooOptions {
        steps_per_phase: Some(1),
        attempts: Some(2),
        ..config()
    };
    let spec = plan(&t, "1", "1000001", &k, 2, 32).unwrap();
    store.import(t).unwrap();
    let job = store.create_job(&spec).unwrap();
    let report = search::run(&mut store, job, options(2)).unwrap();
    assert_eq!(report["status"], "budget_exhausted");
    assert_eq!(report["outcome"], "probabilistic_budget_exhausted");
    assert_eq!(report["walk_steps_completed"], "4");
    assert!(report["coverage"].is_null());
    let resumed = search::run(&mut store, job, options(1)).unwrap();
    assert_eq!(report, resumed);
    let mut changed = spec.clone();
    changed.kangaroo.as_mut().unwrap().seed = "01".repeat(32);
    assert_ne!(store.create_job(&changed).unwrap(), job);
}

#[test]
fn saturated_table_stays_bounded_and_reports_saturation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let t = target("P-256", 2_000_000u32.into());
    let k = KangarooOptions {
        attempts: Some(2),
        max_points: Some(16),
        steps_per_phase: Some(1000),
        distinguished_bits: Some(0),
        ..Default::default()
    };
    let spec = plan(&t, "1", "1000001", &k, 2, 16).unwrap();
    store.import(t).unwrap();
    let job = store.create_job(&spec).unwrap();
    let report = search::run(&mut store, job, options(2)).unwrap();
    assert_eq!(report["status"], "budget_exhausted");
    for walk in report["walks"].as_array().unwrap() {
        assert_eq!(walk["table_saturated"], true);
        assert_eq!(walk["distinguished_points"], 16);
    }
}

fn states(store: &Store, job: i64) -> Vec<String> {
    store
        .conn
        .prepare("SELECT record FROM kangaroo_states WHERE job_id=?1 ORDER BY unit_id")
        .unwrap()
        .query_map([job], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn pause_and_changed_worker_resume_preserve_exact_walk_results() {
    let t = target("P-256", 2_000_000_000_000u64.into());
    let k = KangarooOptions {
        attempts: Some(3),
        steps_per_phase: Some(3000),
        max_points: Some(128),
        ..Default::default()
    };
    let spec = plan(&t, "1", "1000000000001", &k, 1, 32).unwrap();
    let mut records = vec![];
    for pause in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), true).unwrap();
        store.import(t.clone()).unwrap();
        let job = store.create_job(&spec).unwrap();
        if pause {
            let mut opts = options(1);
            opts.time_limit = Some(Duration::from_millis(15));
            assert_eq!(
                search::run(&mut store, job, opts).unwrap()["status"],
                "paused"
            );
            assert!(
                number(
                    store.report(job).unwrap()["walk_steps_completed"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
                    > 0u8.into()
            );
        }
        let report = search::run(&mut store, job, options(if pause { 3 } else { 1 })).unwrap();
        assert_eq!(report["status"], "budget_exhausted");
        records.push(states(&store, job));
    }
    assert_eq!(records[0], records[1]);
}

#[test]
fn corrupt_missing_and_rebound_checkpoints_are_rejected() {
    for corruption in ["checksum", "missing", "manifest", "position", "binding"] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), true).unwrap();
        let t = target("P-256", 2_000_000u32.into());
        let spec = plan(&t, "1", "1000001", &config(), 2, 32).unwrap();
        store.import(t.clone()).unwrap();
        let job = store.create_job(&spec).unwrap();
        store
            .initialize_kangaroo(job, &spec, &kangaroo::initial_snapshot(&t, &spec).unwrap())
            .unwrap();
        match corruption {
            "checksum" => {
                store
                    .conn
                    .execute(
                        "UPDATE kangaroo_states SET checksum='bad' WHERE job_id=?1",
                        [job],
                    )
                    .unwrap();
            }
            "missing" => {
                store.conn.execute("DELETE FROM kangaroo_states WHERE unit_id=(SELECT MIN(unit_id) FROM kangaroo_states)",[]).unwrap();
            }
            "manifest" => {
                store
                    .conn
                    .execute("DELETE FROM engine_states WHERE job_id=?1", [job])
                    .unwrap();
            }
            _ => {
                let mut record: Value = serde_json::from_str(&states(&store, job)[0]).unwrap();
                if corruption == "position" {
                    record["point"] = json!("00");
                } else {
                    record["spec_hash"] = json!("bad");
                }
                let record = record.to_string();
                store.conn.execute("UPDATE kangaroo_states SET record=?1,checksum=?2 WHERE unit_id=(SELECT MIN(unit_id) FROM kangaroo_states)",rusqlite::params![record,fingerprint(record.as_bytes())]).unwrap();
            }
        }
        assert!(
            search::run(&mut store, job, options(2)).is_err(),
            "{corruption}"
        );
    }
}

#[test]
fn planner_parameters_and_resume_resources_are_validated() {
    let t = target("P-256", 4u8.into());
    let mut k = config();
    for invalid in ["seed", "attempts", "steps", "bits", "capacity"] {
        let mut bad = k.clone();
        match invalid {
            "seed" => bad.seed = Some("BAD".into()),
            "attempts" => bad.attempts = Some(0),
            "steps" => bad.steps_per_phase = Some(0),
            "bits" => bad.distinguished_bits = Some(41),
            _ => bad.max_points = Some(15),
        }
        assert!(plan(&t, "1", "1000", &bad, 2, 32).is_err(), "{invalid}");
    }
    assert!(plan(&t, "1", "1000", &k, 2, 1).is_err());
    k.max_points = Some(256);
    let spec = plan(&t, "1", "1000", &k, 1, 6).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    store.import(t).unwrap();
    let job = store.create_job(&spec).unwrap();
    assert!(search::run(&mut store, job, options(4)).is_err());
    assert_eq!(store.status(job).unwrap(), "queued");
    assert!(store.engine_state(job).unwrap().is_none());
}

#[test]
fn stale_updates_and_phase_regressions_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    let t = target("P-256", 4u8.into());
    let spec = plan(&t, "1", "1000", &config(), 2, 32).unwrap();
    store.import(t.clone()).unwrap();
    let job = store.create_job(&spec).unwrap();
    let state = kangaroo::initial_snapshot(&t, &spec).unwrap();
    store.initialize_kangaroo(job, &spec, &state).unwrap();
    store.begin_run(job).unwrap();
    let stale = store.allocate(job).unwrap().unwrap();
    store
        .save_kangaroo_state(job, &stale, &spec, &state, false)
        .unwrap();
    store.begin_run(job).unwrap();
    let current = store.allocate(job).unwrap().unwrap();
    assert!(
        store
            .save_kangaroo_state(job, &stale, &spec, &state, false)
            .is_err()
    );
    let mut advanced = state.clone();
    advanced.phase = "wild".into();
    store
        .save_kangaroo_state(job, &current, &spec, &advanced, false)
        .unwrap();
    assert!(
        store
            .save_kangaroo_state(job, &current, &spec, &state, false)
            .is_err()
    );
}

#[test]
fn readonly_cli_estimate_and_unknown_configuration_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, _) = crypto::lab_certificate("P-384", &4u8.into()).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, certificate).unwrap();
    let state = dir.path().join("no-state");
    let output = Command::new(env!("CARGO_BIN_EXE_cert-cracker"))
        .arg("--state")
        .arg(&state)
        .args(["estimate", "--input"])
        .arg(&input)
        .args([
            "--end",
            "1000001",
            "--method",
            "kangaroo",
            "--workers",
            "2",
            "--memory-mib",
            "16",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.exists());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["planning"]["selected_method"], "ec-kangaroo");
    assert!(result["planning"]["estimated_success_probability"].is_null());
    let mut spec = result["spec"].clone();
    spec["kangaroo"]["unknown_field"] = json!(1);
    assert!(serde_json::from_value::<SearchSpec>(spec).is_err());
}

#[test]
fn schema_three_bsgs_artifact_and_hash_survive_migration() {
    let dir = tempfile::tempdir().unwrap();
    let job;
    let hash;
    let manifest;
    {
        let mut store = Store::open(dir.path(), true).unwrap();
        let t = target("P-384", 77u8.into());
        let id = store.import(t.clone()).unwrap();
        let spec = SearchSpec::bsgs(
            id,
            "1",
            "1000",
            3,
            cert_cracker::model::BsgsConfig {
                baby_steps: 32,
                memory_budget_bytes: 16 * 1024 * 1024,
                table_format_version: 1,
            },
        )
        .unwrap();
        assert!(!serde_json::to_string(&spec).unwrap().contains("kangaroo"));
        hash = spec.hash().unwrap();
        job = store.create_job(&spec).unwrap();
        cert_cracker::bsgs::prepare(
            &mut store,
            job,
            &spec,
            &t,
            &cert_cracker::bsgs::PrepareOptions {
                workers: 2,
                cancel: Arc::new(AtomicBool::new(false)),
                deadline: None,
                checkpoint_interval: Duration::from_millis(1),
                quiet: true,
            },
        )
        .unwrap();
        manifest = store.engine_state(job).unwrap();
        store
            .conn
            .execute_batch("DROP TABLE kangaroo_states; PRAGMA user_version=3;")
            .unwrap();
    }
    let mut store = Store::open(dir.path(), true).unwrap();
    assert_eq!(store.spec(job).unwrap().hash().unwrap(), hash);
    assert_eq!(store.engine_state(job).unwrap(), manifest);
    assert_eq!(
        search::run(&mut store, job, options(2)).unwrap()["status"],
        "recovered"
    );
    assert_eq!(store.engine_state(job).unwrap(), manifest);
}

#[cfg(unix)]
fn killed_walk(phase: &str) {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, _) = crypto::lab_certificate("P-256", &2_000_000_000_000u64.into()).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, certificate).unwrap();
    let state = dir.path().join("state");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let mut child = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["search", "--input"])
        .arg(&input)
        .args([
            "--end",
            "1000000000001",
            "--method",
            "kangaroo",
            "--kangaroo-attempts",
            "2",
            "--kangaroo-steps",
            "20000",
            "--kangaroo-max-points",
            "128",
            "--memory-mib",
            "32",
            "--workers",
            "1",
            "--checkpoint-interval-ms",
            "2",
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let mut observed = None;
    while started.elapsed() < Duration::from_secs(20) {
        if let Ok(store) = Store::open(&state, false)
            && let Ok(report) = store.report(1)
            && let Some(walk) = report["walks"].as_array().and_then(|a| a.first())
            && walk["phase"] == phase
            && walk[if phase == "tame" {
                "tame_steps"
            } else {
                "wild_steps"
            }]
            .as_u64()
            .unwrap_or(0)
                > 0
        {
            observed = Some(states(&store, 1));
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let _ = child.kill();
    child.wait().unwrap();
    let observed = observed.expect("never observed requested durable walk phase");
    let output = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["resume", "1", "--workers", "2", "--quiet"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "budget_exhausted");
    assert!(report["coverage"].is_null());
    let store = Store::open(&state, false).unwrap();
    let after = states(&store, 1);
    for (old, new) in observed.iter().zip(&after) {
        let old: kangaroo::Snapshot = serde_json::from_str(old).unwrap();
        let new: kangaroo::Snapshot = serde_json::from_str(new).unwrap();
        assert!(old.tame_steps <= new.tame_steps && old.wild_steps <= new.wild_steps);
        assert!(old.points.iter().all(|(p, d)| new.points.get(p) == Some(d)));
    }
}

#[cfg(unix)]
#[test]
fn real_sigkill_tame_phase_and_changed_worker_resume() {
    killed_walk("tame");
}

#[cfg(unix)]
#[test]
fn real_sigkill_wild_phase_and_changed_worker_resume() {
    killed_walk("wild");
}
