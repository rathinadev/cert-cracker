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
#[cfg(unix)]
use std::process::Stdio;
use std::{
    fs,
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

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
fn cooperative_collisions_survive_restart_for_both_checkpoint_orders() {
    for reverse in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let t = target("P-256", 14u8.into());
        let k = KangarooOptions {
            cooperative: true,
            attempts: Some(2),
            steps_per_phase: Some(1),
            max_points: Some(16),
            distinguished_bits: Some(0),
            ..Default::default()
        };
        let spec = plan(&t, "1", "17", &k, 2, 16).unwrap();
        let job;
        {
            let mut store = Store::open(dir.path(), true).unwrap();
            store.import(t.clone()).unwrap();
            job = store.create_job(&spec).unwrap();
            let initial = kangaroo::initial_snapshot(&t, &spec).unwrap();
            store.initialize_kangaroo(job, &spec, &initial).unwrap();
            store.begin_run(job).unwrap();
            let first = store.allocate(job).unwrap().unwrap();
            let second = store.allocate(job).unwrap().unwrap();
            let mut tame = store.kangaroo_state(job, &first, &spec).unwrap().unwrap();
            let mut wild = store.kangaroo_state(job, &second, &spec).unwrap().unwrap();
            // Upper=16 and wild scalar=14 plus attempt-1 offset=2 meet at 16G.
            let point = tame.point.clone();
            tame.points.insert(point.clone(), "0x0".into());
            wild.phase = "wild".into();
            wild.point = point.clone();
            wild.wild_points.insert(point, "0x0".into());
            let entries = if reverse {
                vec![(&second, &wild), (&first, &tame)]
            } else {
                vec![(&first, &tame), (&second, &wild)]
            };
            for (unit, state) in entries {
                store
                    .save_kangaroo_state(job, unit, &spec, state, false)
                    .unwrap();
            }
        }
        // Simulate a termination between persisted checkpoint updates and a result.
        // A concurrently spawning child on Unix can briefly inherit the lock
        // before exec closes inherited descriptors. Bound the wait so a real
        // lock leak still fails the test.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut store = loop {
            match Store::open(dir.path(), true) {
                Ok(store) => break store,
                Err(error)
                    if error.to_string().contains("another coordinator")
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("could not reopen checkpoint: {error:#}"),
            }
        };
        let report = search::run(&mut store, job, options(2)).unwrap();
        assert_eq!(report["status"], "recovered");
        assert_eq!(
            store.findings().unwrap()[0]["method"],
            "ec-kangaroo-cooperative"
        );
        let key = dir.path().join("cross.private.pem");
        store
            .export_key(report["finding_id"].as_i64().unwrap(), &key)
            .unwrap();
        crypto::verify_private(&t, &fs::read(key).unwrap()).unwrap();
    }
}

#[test]
fn cooperative_walks_match_reference_and_respect_resource_limits() {
    for curve in ["P-256", "P-384", "P-521", "secp256k1"] {
        for (scalar, recovered) in [
            (4u32, false),
            (5, true),
            (67, true),
            (118, true),
            (119, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::open(dir.path(), true).unwrap();
            let t = target(curve, scalar.into());
            let k = KangarooOptions {
                cooperative: true,
                ..config()
            };
            let spec = plan(&t, "5", "119", &k, 3, 32).unwrap();
            store.import(t).unwrap();
            let job = store.create_job(&spec).unwrap();
            let report = search::run(&mut store, job, options(3)).unwrap();
            assert_eq!(
                report["status"] == "recovered",
                recovered,
                "{curve}: {scalar}"
            );
            assert!(report["covered_candidates"].is_null());
            if !recovered {
                assert_eq!(report["outcome"], "probabilistic_budget_exhausted");
            }
            assert!(
                report["walks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|w| w["wild_distinguished_points"].is_number())
            );
        }
    }
    let t = target("P-256", 4u8.into());
    let k = KangarooOptions {
        cooperative: true,
        attempts: Some(4),
        max_points: Some(128),
        ..Default::default()
    };
    let spec = plan(&t, "1", "1000", &k, 1, 10).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), true).unwrap();
    store.import(t).unwrap();
    let job = store.create_job(&spec).unwrap();
    assert!(search::run(&mut store, job, options(2)).is_err());
    assert_eq!(store.status(job).unwrap(), "queued");
}

#[test]
fn independent_checkpoint_and_spec_remain_version_one() {
    let t = target("P-256", 4u8.into());
    let spec = plan(&t, "1", "1000", &config(), 2, 32).unwrap();
    assert_eq!(spec.kangaroo.as_ref().unwrap().state_version, 1);
    let state = kangaroo::initial_snapshot(&t, &spec).unwrap();
    let json = serde_json::to_string(&state).unwrap();
    assert!(!json.contains("wild_points"));
    assert!(!json.contains("wild_table_saturated"));
    let parsed: kangaroo::Snapshot = serde_json::from_str(&json).unwrap();
    parsed.validate(&spec, 0).unwrap();
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
    let spec = store.spec(job).unwrap();
    let mut stmt = store
        .conn
        .prepare("SELECT id,start,end,next,generation FROM work_units WHERE job_id=?1 ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([job], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .unwrap();
    rows.map(|row| {
        let (id, start, end, next, generation) = row.unwrap();
        let unit = cert_cracker::model::WorkUnit {
            id,
            generation,
            start: number(&start).unwrap(),
            end: number(&end).unwrap(),
            next: number(&next).unwrap(),
        };
        serde_json::to_string(&store.kangaroo_state(job, &unit, &spec).unwrap().unwrap()).unwrap()
    })
    .collect()
}

#[test]
fn schema_four_walk_migrates_lazily_and_point_corruption_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let t = target("P-256", 1234u32.into());
    let k = KangarooOptions {
        attempts: Some(1),
        max_points: Some(16),
        ..Default::default()
    };
    let spec = plan(&t, "1", "1001", &k, 1, 16).unwrap();
    let job;
    let expected;
    {
        let mut store = Store::open(dir.path(), true).unwrap();
        store.import(t.clone()).unwrap();
        job = store.create_job(&spec).unwrap();
        let initial = kangaroo::initial_snapshot(&t, &spec).unwrap();
        store.initialize_kangaroo(job, &spec, &initial).unwrap();
        store.begin_run(job).unwrap();
        let unit = store.allocate(job).unwrap().unwrap();
        let mut state = store.kangaroo_state(job, &unit, &spec).unwrap().unwrap();
        state.points.insert(state.point.clone(), "0x0".into());
        store
            .save_kangaroo_state(job, &unit, &spec, &state, false)
            .unwrap();
        expected = serde_json::to_string(&state).unwrap();
        store
            .conn
            .execute(
                "UPDATE kangaroo_states SET record=?1,checksum=?2",
                rusqlite::params![expected, fingerprint(expected.as_bytes())],
            )
            .unwrap();
        store.conn.execute_batch("DROP TABLE vault_config; DROP TABLE kangaroo_points; ALTER TABLE kangaroo_states DROP COLUMN storage_format; PRAGMA user_version=4;").unwrap();
    }
    {
        let reader = Store::open(dir.path(), false).unwrap();
        assert_eq!(states(&reader, job), vec![expected.clone()]);
    }
    {
        let mut store = Store::open(dir.path(), true).unwrap();
        assert_eq!(states(&store, job), vec![expected.clone()]);
        store.begin_run(job).unwrap();
        let unit = store.allocate(job).unwrap().unwrap();
        let state = store.kangaroo_state(job, &unit, &spec).unwrap().unwrap();
        store
            .save_kangaroo_state(job, &unit, &spec, &state, false)
            .unwrap();
        let (format, count): (i64, i64) = store
            .conn
            .query_row(
                "SELECT storage_format,(SELECT count(*) FROM kangaroo_points) FROM kangaroo_states",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((format, count), (2, 1));
        assert_eq!(states(&store, job), vec![expected]);
        store.conn.execute_batch("CREATE TRIGGER forbid_point_rewrite BEFORE UPDATE ON kangaroo_points BEGIN SELECT RAISE(ABORT,'point was rewritten'); END;").unwrap();
        store
            .save_kangaroo_state(job, &unit, &spec, &state, false)
            .unwrap();
        store.conn.execute_batch("CREATE TRIGGER fail_new_point BEFORE INSERT ON kangaroo_points BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END;").unwrap();
        let mut next = state.clone();
        next.points.insert("00".into(), "0x0".into());
        assert!(
            store
                .save_kangaroo_state(job, &unit, &spec, &next, false)
                .is_err()
        );
        assert_eq!(
            store.kangaroo_state(job, &unit, &spec).unwrap().unwrap(),
            state
        );
        store
            .conn
            .execute_batch("DROP TRIGGER fail_new_point; DROP TRIGGER forbid_point_rewrite;")
            .unwrap();
        store
            .conn
            .execute("UPDATE kangaroo_points SET distance='0x1'", [])
            .unwrap();
        assert!(
            store
                .kangaroo_state(job, &unit, &spec)
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
    }
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
            // Slow filesystem/crypto setup can consume a short time limit before any
            // work starts. Synchronize cancellation with an observed FULL checkpoint.
            let cancel = opts.cancel.clone();
            let monitor_cancel = cancel.clone();
            let ready = Arc::new(Barrier::new(2));
            let monitor_ready = ready.clone();
            let path = dir.path().to_owned();
            let monitor = std::thread::spawn(move || {
                monitor_ready.wait();
                let started = Instant::now();
                while !monitor_cancel.load(Ordering::Relaxed) {
                    if let Ok(reader) = Store::open(&path, false)
                        && let Ok(report) = reader.report(job)
                        && let Some(steps) = report["walk_steps_completed"].as_str()
                        && number(steps).unwrap() > 0u8.into()
                    {
                        monitor_cancel.store(true, Ordering::Relaxed);
                        return true;
                    }
                    if started.elapsed() >= Duration::from_secs(30) {
                        monitor_cancel.store(true, Ordering::Relaxed);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                false
            });
            opts.time_limit = Some(Duration::from_secs(30));
            ready.wait();
            let paused = search::run(&mut store, job, opts);
            cancel.store(true, Ordering::Relaxed);
            assert!(
                monitor.join().unwrap(),
                "no durable walk progress observed before cancellation"
            );
            assert_eq!(paused.unwrap()["status"], "paused");
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
            .execute_batch(
                "DROP TABLE vault_config; DROP TABLE kangaroo_points; DROP TABLE kangaroo_states; PRAGMA user_version=3;",
            )
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
fn killed_walk(phase: &str, cooperative: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, _) = crypto::lab_certificate("P-256", &2_000_000_000_000u64.into()).unwrap();
    let input = dir.path().join("cert.pem");
    fs::write(&input, certificate).unwrap();
    let state = dir.path().join("state");
    let stderr_path = dir.path().join("child-stderr.txt");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let mut command = Command::new(bin);
    command
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
            if cooperative && phase == "wild" {
                "200000"
            } else {
                "20000"
            },
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
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()));
    if cooperative {
        command.arg("--kangaroo-cooperative");
    }
    let mut child = command.spawn().unwrap();
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
    let observed = observed.unwrap_or_else(|| {
        panic!(
            "never observed requested durable walk phase; child stderr: {}",
            fs::read_to_string(&stderr_path).unwrap_or_default()
        )
    });
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
        assert!(
            old.wild_points
                .iter()
                .all(|(p, d)| new.wild_points.get(p) == Some(d))
        );
    }
}

#[cfg(unix)]
#[test]
fn real_sigkill_tame_phase_and_changed_worker_resume() {
    killed_walk("tame", false);
}

#[cfg(unix)]
#[test]
fn real_sigkill_wild_phase_and_changed_worker_resume() {
    killed_walk("wild", false);
}

#[cfg(unix)]
#[test]
fn cooperative_sigkill_tame_phase_and_changed_worker_resume() {
    killed_walk("tame", true);
}

#[cfg(unix)]
#[test]
fn cooperative_sigkill_wild_phase_and_changed_worker_resume() {
    killed_walk("wild", true);
}
