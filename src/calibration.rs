//! Optional local, bounded benchmark profiles for advisory planning estimates.
use crate::{
    crypto, import,
    model::{SearchSpec, Target, number},
    planner::{self, KangarooOptions, PlanOptions},
    search::{self, RunOptions},
    storage::Store,
};
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

const MAX_PROFILE_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub seconds: f64,
    pub operations: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format_version: u32,
    pub software_version: String,
    pub os: String,
    pub architecture: String,
    pub logical_cpus: usize,
    pub openssl: String,
    pub sqlite: String,
    pub curve: String,
    pub workers: usize,
    pub memory_mib: u64,
    pub candidates: u64,
    pub repetitions: u32,
    pub sequential: Sample,
    pub bsgs: Sample,
    pub kangaroo_independent: Sample,
    pub kangaroo_cooperative: Sample,
}

fn logical_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

fn measure(
    target: &Target,
    width: u64,
    workers: usize,
    memory_mib: u64,
    method: &str,
    cooperative: bool,
) -> Result<Sample> {
    let temp = tempfile::tempdir()?;
    let mut store = Store::open(temp.path(), true)?;
    store.import(target.clone())?;
    let k = KangarooOptions {
        attempts: Some(4),
        max_points: Some(64),
        cooperative,
        ..Default::default()
    };
    let end = (width + 1).to_string();
    let (spec, _) = planner::plan(
        target,
        PlanOptions {
            start: "1",
            end: &end,
            chunk_size: 16384,
            method,
            memory_mib,
            baby_steps: None,
            workers,
            kangaroo: if method == "kangaroo" { Some(&k) } else { None },
        },
    )?;
    let job = store.create_job(&spec)?;
    let started = Instant::now();
    let report = search::run(
        &mut store,
        job,
        RunOptions {
            workers,
            checkpoint_interval: Duration::from_secs(1),
            time_limit: None,
            cancel: Arc::new(AtomicBool::new(false)),
            quiet: true,
        },
    )?;
    let seconds = started.elapsed().as_secs_f64();
    let operations = match method {
        "sequential" => {
            ensure!(
                report["status"] == "exhausted"
                    && report["covered_candidates"]
                        .as_str()
                        .and_then(|v| v.parse::<u64>().ok())
                        == Some(width),
                "sequential calibration did not cover the sample"
            );
            width
        }
        "bsgs" => {
            ensure!(
                report["status"] == "exhausted"
                    && report["covered_candidates"]
                        .as_str()
                        .and_then(|v| v.parse::<u64>().ok())
                        == Some(width),
                "BSGS calibration did not cover the sample"
            );
            let giants = report["giant_steps_completed"]
                .as_str()
                .context("missing giant-step count")?
                .parse::<u64>()?;
            spec.bsgs
                .context("missing BSGS configuration")?
                .baby_steps
                .checked_add(giants)
                .context("calibration work overflow")?
        }
        "kangaroo" => {
            ensure!(
                report["status"] == "budget_exhausted" && report["coverage"].is_null(),
                "kangaroo calibration did not finish its walk budget"
            );
            report["walk_steps_completed"]
                .as_str()
                .context("missing walk count")?
                .parse::<u64>()?
        }
        _ => anyhow::bail!("unsupported calibration method"),
    };
    ensure!(
        seconds.is_finite() && seconds > 0.0 && operations > 0,
        "invalid calibration measurement"
    );
    Ok(Sample {
        seconds,
        operations,
    })
}

fn median(mut samples: Vec<Sample>) -> Sample {
    samples.sort_by(|a, b| {
        (a.seconds / a.operations as f64).total_cmp(&(b.seconds / b.operations as f64))
    });
    samples.remove(samples.len() / 2)
}

pub fn calibrate(
    curve: &str,
    candidates: u64,
    workers: usize,
    memory_mib: u64,
    repetitions: u32,
) -> Result<Profile> {
    ensure!(
        (100..=1_000_000).contains(&candidates),
        "calibration candidates must be 100..1000000"
    );
    ensure!((1..=256).contains(&workers), "worker count must be 1..256");
    ensure!(
        (1..=5).contains(&repetitions),
        "calibration repetitions must be 1..5"
    );
    ensure!(
        (1..=65536).contains(&memory_mib),
        "memory budget must be 1..65536 MiB"
    );
    let private = crypto::lab_key(curve, &BigUint::from(candidates + 2))?;
    let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
    let target = import::target_from_key(&public, "local calibration fixture")?;
    let mut results: Vec<Vec<Sample>> = vec![vec![], vec![], vec![], vec![]];
    for _ in 0..repetitions {
        for (index, (method, cooperative)) in [
            ("sequential", false),
            ("bsgs", false),
            ("kangaroo", false),
            ("kangaroo", true),
        ]
        .into_iter()
        .enumerate()
        {
            results[index].push(measure(
                &target,
                candidates,
                workers,
                memory_mib,
                method,
                cooperative,
            )?);
        }
    }
    let [sequential, bsgs, kangaroo_independent, kangaroo_cooperative]: [Vec<Sample>; 4] = results
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid calibration result"))?;
    let profile = Profile {
        format_version: 1,
        software_version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        logical_cpus: logical_cpus(),
        openssl: openssl::version::version().into(),
        sqlite: rusqlite::version().into(),
        curve: target.curve.context("calibration target has no curve")?,
        workers,
        memory_mib,
        candidates,
        repetitions,
        sequential: median(sequential),
        bsgs: median(bsgs),
        kangaroo_independent: median(kangaroo_independent),
        kangaroo_cooperative: median(kangaroo_cooperative),
    };
    profile.validate()?;
    Ok(profile)
}

impl Profile {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == 1,
            "unsupported calibration profile version"
        );
        ensure!(
            (100..=1_000_000).contains(&self.candidates) && (1..=5).contains(&self.repetitions),
            "invalid calibration sample parameters"
        );
        ensure!(
            (1..=256).contains(&self.workers) && (1..=65536).contains(&self.memory_mib),
            "invalid calibration resource parameters"
        );
        for sample in [
            &self.sequential,
            &self.bsgs,
            &self.kangaroo_independent,
            &self.kangaroo_cooperative,
        ] {
            ensure!(
                sample.seconds.is_finite()
                    && sample.seconds > 0.0
                    && sample.seconds <= 31_536_000.0
                    && sample.operations > 0,
                "invalid calibration measurement"
            );
        }
        ensure!(
            self.sequential.operations == self.candidates,
            "calibration sequential count does not match sample interval"
        );
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("opening calibration profile {}", path.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "calibration profile must be a regular file"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_PROFILE_BYTES,
            "calibration profile exceeds 256 KiB"
        );
        let profile: Self =
            serde_json::from_slice(&bytes).context("invalid calibration profile")?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn estimate(
        &self,
        target: &Target,
        spec: &SearchSpec,
        planning: &Value,
        workers: usize,
        memory_mib: u64,
    ) -> Result<Value> {
        self.validate()?;
        ensure!(
            self.software_version == env!("CARGO_PKG_VERSION")
                && self.os == std::env::consts::OS
                && self.architecture == std::env::consts::ARCH
                && self.logical_cpus == logical_cpus()
                && self.openssl == openssl::version::version()
                && self.sqlite == rusqlite::version(),
            "calibration environment does not match this executable/system; recalibrate"
        );
        ensure!(
            target.curve.as_deref() == Some(self.curve.as_str()),
            "calibration curve does not match target"
        );
        ensure!(
            self.workers == workers && self.memory_mib == memory_mib,
            "calibration workers or memory budget differ; recalibrate or use matching values"
        );
        let width = (number(&spec.end)? - number(&spec.start)?)
            .to_f64()
            .context("interval is too large for advisory estimate")?;
        let scale = |operations: f64, s: &Sample| -> Result<f64> {
            let seconds = (operations / s.operations as f64) * s.seconds;
            ensure!(
                seconds.is_finite() && seconds >= 0.0,
                "calibration estimate overflow"
            );
            Ok(seconds)
        };
        let sequential = scale(width, &self.sequential)?;
        let bsgs = planning
            .get("bsgs")
            .and_then(|v| v.get("estimated_group_steps"))
            .and_then(Value::as_str)
            .map(|v| -> Result<f64> {
                scale(
                    number(v)?.to_f64().context("BSGS work is too large")?,
                    &self.bsgs,
                )
            })
            .transpose()?;
        let kangaroo = if let Some(c) = spec.kangaroo.as_ref() {
            let max = BigUint::from(c.steps_per_phase) * 2u8 * c.attempts;
            Some(scale(
                max.to_f64().context("kangaroo work is too large")?,
                if c.state_version == 2 {
                    &self.kangaroo_cooperative
                } else {
                    &self.kangaroo_independent
                },
            )?)
        } else {
            None
        };
        let preference = bsgs.map(|b| if b < sequential { "bsgs" } else { "sequential" });
        Ok(
            json!({"sample_candidates":self.candidates,"sample_repetitions":self.repetitions,"environment_fields_match":true,"sequential_seconds":sequential,"bsgs_seconds":bsgs,"kangaroo_maximum_step_budget_seconds":kangaroo,"calibrated_comparison":preference,"interval_extrapolation_factor":width/self.candidates as f64,"note":"Coarse linear scaling of one local sample, including its setup and checkpoints; not a guarantee, confidence interval or success probability. CPU model, current load, table size, disk speed and checkpoint frequency can change results. Kangaroo value scales its maximum configured additions and may finish sooner or take longer. Automatic method selection is not changed."}),
        )
    }
}
