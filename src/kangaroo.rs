//! Bounded, independent two-walk Pollard lambda attempts. No exhaustive coverage is implied.
use crate::{
    crypto::{bignum, ec_order, recover_ec},
    import::public_key,
    model::{KangarooConfig, SearchSpec, Target, WorkUnit, canonical, fingerprint, number},
    search::RunOptions,
    storage::Store,
};
use anyhow::{Context, Result, ensure};
use crossbeam_channel::{Receiver, Sender, bounded};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcPoint, PointConversionForm},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const BASE_BYTES: u64 = 2 * 1024 * 1024;
pub const WORKER_BYTES: u64 = 2 * 1024 * 1024;
// Conservative allowance for map nodes, serialized checkpoint, clones and channel handoff.
pub const POINT_BYTES: u64 = 4096;

pub fn memory_required(points: u32, workers: usize, attempts: u32) -> u64 {
    BASE_BYTES
        + workers.min(attempts as usize) as u64 * (WORKER_BYTES + u64::from(points) * POINT_BYTES)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub spec_hash: String,
    pub attempt: u32,
    pub phase: String,
    pub tame_steps: u64,
    pub wild_steps: u64,
    pub tame_distance: String,
    pub wild_distance: String,
    pub point: String,
    pub points: BTreeMap<String, String>,
    pub table_saturated: bool,
    pub termination: Option<String>,
}

impl Snapshot {
    pub fn operations(&self) -> u64 {
        self.tame_steps + self.wild_steps
    }

    pub fn validate(&self, spec: &SearchSpec, attempt: u32) -> Result<()> {
        let c = spec
            .kangaroo
            .as_ref()
            .context("missing kangaroo configuration")?;
        ensure!(
            self.version == 1
                && self.spec_hash == spec.hash()?
                && self.attempt == attempt
                && attempt < c.attempts,
            "kangaroo checkpoint binding mismatch"
        );
        ensure!(
            matches!(self.phase.as_str(), "tame" | "wild" | "done"),
            "invalid kangaroo phase"
        );
        ensure!(
            self.tame_steps <= c.steps_per_phase && self.wild_steps <= c.steps_per_phase,
            "kangaroo steps exceed immutable budget"
        );
        ensure!(
            self.points.len() <= c.max_points as usize,
            "kangaroo point table exceeds immutable capacity"
        );
        ensure!(
            self.phase != "tame"
                || (self.wild_steps == 0 && number(&self.wild_distance)?.is_zero()),
            "wild progress in tame phase"
        );
        ensure!(
            (self.phase == "done") == self.termination.is_some(),
            "invalid kangaroo termination state"
        );
        ensure!(
            self.termination
                .as_deref()
                .is_none_or(|s| matches!(s, "walk_budget_exhausted" | "collision")),
            "unknown kangaroo termination"
        );
        for distance in [&self.tame_distance, &self.wild_distance]
            .into_iter()
            .chain(self.points.values())
        {
            ensure!(
                distance.len() <= 270 && canonical(&number(distance)?) == *distance,
                "invalid kangaroo distance"
            );
        }
        for point in std::iter::once(&self.point).chain(self.points.keys()) {
            ensure!(
                (point == "00"
                    || (matches!(point.len(), 66 | 98 | 134)
                        && (point.starts_with("02") || point.starts_with("03"))))
                    && hex::encode(hex::decode(point)?) == *point,
                "invalid kangaroo point encoding"
            );
        }
        Ok(())
    }
}

struct Walk {
    group: EcGroup,
    ctx: BigNumContext,
    target: EcPoint,
    point: EcPoint,
    scratch: EcPoint,
    jumps: Vec<(BigUint, EcPoint)>,
    salt: Vec<u8>,
    order: BigUint,
    upper: BigUint,
    start: BigUint,
    wild_limit: BigUint,
    config: KangarooConfig,
    state: Snapshot,
}

impl Walk {
    fn new(
        target: &Target,
        spec: &SearchSpec,
        attempt: u32,
        saved: Option<Snapshot>,
    ) -> Result<Self> {
        let order = ec_order(target)?;
        let key = public_key(target)?;
        let ec = key.ec_key()?;
        let group = EcGroup::from_curve_name(ec.group().curve_name().context("unnamed EC group")?)?;
        let mut ctx = BigNumContext::new()?;
        let bytes =
            ec.public_key()
                .to_bytes(ec.group(), PointConversionForm::COMPRESSED, &mut ctx)?;
        let target_point = EcPoint::from_bytes(&group, &bytes, &mut ctx)?;
        let start = number(&spec.start)?;
        let upper = number(&spec.end)? - 1u8;
        let width = &upper - &start + 1u8;
        let root = width.sqrt().max(1u8.into());
        let mean = (&root / 2u8).max(1u8.into());
        let mut count = 1usize;
        while ((BigUint::from(1u8) << count) - 1u8) < &mean * count {
            count += 1;
        }
        ensure!(count <= 512, "kangaroo jump table exceeds supported size");
        let mut jumps = Vec::with_capacity(count);
        for i in 0..count {
            let distance = BigUint::from(1u8) << i;
            let mut p = EcPoint::new(&group)?;
            p.mul_generator2(&group, bignum(&distance)?.as_ref(), &mut ctx)?;
            jumps.push((distance, p));
        }
        let config = spec
            .kangaroo
            .clone()
            .context("missing kangaroo configuration")?;
        let mut salt = hex::decode(&config.seed)?;
        salt.extend_from_slice(&attempt.to_le_bytes());
        salt.extend_from_slice(b"cert-cracker-kangaroo-v1");
        let mut point = EcPoint::new(&group)?;
        let mut state = if let Some(state) = saved {
            state.validate(spec, attempt)?;
            state
        } else {
            Snapshot {
                version: 1,
                spec_hash: spec.hash()?,
                attempt,
                phase: "tame".into(),
                tame_steps: 0,
                wild_steps: 0,
                tame_distance: "0x0".into(),
                wild_distance: "0x0".into(),
                point: String::new(),
                points: BTreeMap::new(),
                table_saturated: false,
                termination: None,
            }
        };
        if state.phase == "tame" {
            point.mul_generator2(
                &group,
                bignum(&(&upper + number(&state.tame_distance)?))?.as_ref(),
                &mut ctx,
            )?;
        } else {
            let mut offset = EcPoint::new(&group)?;
            offset.mul_generator2(
                &group,
                bignum(&number(&state.wild_distance)?)?.as_ref(),
                &mut ctx,
            )?;
            point.add(&group, &target_point, &offset, &mut ctx)?;
        }
        let encoded =
            hex::encode(point.to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?);
        ensure!(
            state.point.is_empty() || state.point == encoded,
            "kangaroo saved position does not match its distance"
        );
        state.point = encoded;
        let wild_limit = &width - 1u8 + number(&state.tame_distance)?;
        let scratch = EcPoint::new(&group)?;
        Ok(Self {
            group,
            ctx,
            target: target_point,
            point,
            scratch,
            jumps,
            salt,
            order,
            upper,
            start,
            wild_limit,
            config,
            state,
        })
    }

    fn switch_to_wild(&mut self) -> Result<()> {
        self.state.phase = "wild".into();
        self.point = self.target.to_owned(&self.group)?;
        self.state.point = hex::encode(self.point.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.ctx,
        )?);
        self.wild_limit = &self.upper - &self.start + number(&self.state.tame_distance)?;
        Ok(())
    }

    fn step(&mut self) -> Result<Option<BigUint>> {
        let bytes =
            self.point
                .to_bytes(&self.group, PointConversionForm::COMPRESSED, &mut self.ctx)?;
        let point_key = hex::encode(&bytes);
        let mut hash = Sha256::new();
        hash.update(&self.salt);
        hash.update(&bytes);
        let digest = hash.finalize();
        let selector =
            (u64::from_le_bytes(digest[..8].try_into()?) % self.jumps.len() as u64) as usize;
        if self.state.phase == "tame" {
            let distinguished = u64::from_le_bytes(digest[8..16].try_into()?)
                & ((1u64 << self.config.distinguished_bits) - 1)
                == 0;
            let endpoint = self.state.tame_steps == self.config.steps_per_phase;
            if distinguished || endpoint || self.state.tame_steps == 0 {
                if self.state.points.len() >= self.config.max_points as usize
                    && !self.state.points.contains_key(&point_key)
                {
                    self.state.table_saturated = true;
                    self.switch_to_wild()?;
                    return Ok(None);
                }
                self.state
                    .points
                    .entry(point_key)
                    .or_insert_with(|| self.state.tame_distance.clone());
            }
            if endpoint {
                self.switch_to_wild()?;
                return Ok(None);
            }
        } else {
            if let Some(tame) = self.state.points.get(&point_key) {
                let lhs = (&self.upper + number(tame)?) % &self.order;
                let rhs = number(&self.state.wild_distance)? % &self.order;
                let candidate = (lhs + &self.order - rhs) % &self.order;
                if self.start <= candidate && candidate <= self.upper {
                    self.state.phase = "done".into();
                    self.state.termination = Some("collision".into());
                    return Ok(Some(candidate));
                }
            }
            if self.state.wild_steps == self.config.steps_per_phase
                || number(&self.state.wild_distance)? > self.wild_limit
            {
                self.state.phase = "done".into();
                self.state.termination = Some("walk_budget_exhausted".into());
                return Ok(None);
            }
        }
        let (distance, jump) = &self.jumps[selector];
        self.scratch
            .add(&self.group, &self.point, jump, &mut self.ctx)?;
        std::mem::swap(&mut self.point, &mut self.scratch);
        if self.state.phase == "tame" {
            self.state.tame_steps += 1;
            self.state.tame_distance = canonical(&(number(&self.state.tame_distance)? + distance));
        } else {
            self.state.wild_steps += 1;
            self.state.wild_distance = canonical(&(number(&self.state.wild_distance)? + distance));
        }
        self.state.point = hex::encode(self.point.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.ctx,
        )?);
        Ok(None)
    }
}

struct Task {
    unit: WorkUnit,
    saved: Option<Snapshot>,
}
enum Event {
    Checkpoint {
        unit: WorkUnit,
        state: Box<Snapshot>,
        candidate: Option<BigUint>,
        finished: bool,
        ack: Sender<std::result::Result<(), String>>,
    },
    Failed(String),
    Stopped,
}

fn worker(
    target: Target,
    spec: SearchSpec,
    tasks: Receiver<Task>,
    events: Sender<Event>,
    cancel: Arc<AtomicBool>,
    interval: Duration,
) {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        while let Ok(task) = tasks.recv() {
            let attempt = task.unit.start.to_u32().context("invalid attempt index")?;
            let mut walk = Walk::new(&target, &spec, attempt, task.saved)?;
            let mut checkpoint = Instant::now();
            loop {
                let cancelled = cancel.load(Ordering::Relaxed);
                let candidate = if cancelled { None } else { walk.step()? };
                let done = walk.state.phase == "done";
                if let Some(candidate) = &candidate {
                    recover_ec(&target, candidate)?;
                }
                if cancelled || done || checkpoint.elapsed() >= interval {
                    let (ack, response) = bounded(1);
                    events.send(Event::Checkpoint {
                        unit: task.unit.clone(),
                        state: Box::new(walk.state.clone()),
                        candidate,
                        finished: cancelled || done,
                        ack,
                    })?;
                    response.recv()?.map_err(anyhow::Error::msg)?;
                    checkpoint = Instant::now();
                }
                if cancelled || done {
                    break;
                }
            }
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }
        Ok(())
    }));
    match result {
        Ok(Err(e)) => {
            let _ = events.send(Event::Failed(format!("{e:#}")));
        }
        Err(_) => {
            let _ = events.send(Event::Failed(
                "kangaroo worker panicked; committed walks remain resumable".into(),
            ));
        }
        _ => {}
    }
    let _ = events.send(Event::Stopped);
}

pub fn run(store: &mut Store, job: i64, options: RunOptions) -> Result<Value> {
    let started = Instant::now();
    let spec = store.spec(job)?;
    let config = spec
        .kangaroo
        .as_ref()
        .context("missing kangaroo configuration")?;
    crate::planner::preflight(&spec, options.workers)?;
    ensure!(
        !options.checkpoint_interval.is_zero(),
        "checkpoint interval must be positive"
    );
    let target = store.target(&spec.target_id)?;
    crate::planner::ensure_curve(&target)?;
    ensure!(
        number(&spec.end)? <= ec_order(&target)?,
        "exclusive end exceeds subgroup order"
    );
    if matches!(
        store.status(job)?.as_str(),
        "recovered" | "budget_exhausted"
    ) {
        return store.report(job);
    }
    let initial = initial_snapshot(&target, &spec)?;
    store.initialize_kangaroo(job, &spec, &initial)?;
    // A logical attempt is independent of the number of OS threads executing it.
    let workers = options.workers.min(config.attempts as usize);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|i| format!("kangaroo-{i}"))
        .build()?;
    store.begin_run(job)?;
    let (tasks_tx, tasks_rx) = bounded::<Task>(workers);
    let (events_tx, events_rx) = bounded::<Event>(workers);
    for _ in 0..workers {
        let (target, spec, tasks, events, cancel) = (
            target.clone(),
            spec.clone(),
            tasks_rx.clone(),
            events_tx.clone(),
            options.cancel.clone(),
        );
        let interval = options.checkpoint_interval;
        pool.spawn(move || worker(target, spec, tasks, events, cancel, interval));
    }
    drop(tasks_rx);
    drop(events_tx);
    let mut sender = Some(tasks_tx);
    let mut outstanding = 0usize;
    let mut stopped = 0usize;
    let mut allocated = false;
    let mut failure = None;
    let mut recovered = false;
    let mut last_display = Instant::now();
    while stopped < workers {
        if options.time_limit.is_some_and(|t| started.elapsed() >= t) {
            options.cancel.store(true, Ordering::Relaxed);
        }
        if options.cancel.load(Ordering::Relaxed) || failure.is_some() {
            options.cancel.store(true, Ordering::Relaxed);
            sender.take();
        }
        while outstanding < workers && !allocated {
            let Some(tx) = sender.as_ref() else {
                break;
            };
            let result = (|| -> Result<bool> {
                if let Some(unit) = store.allocate(job)? {
                    let saved = store.kangaroo_state(job, &unit, &spec)?;
                    tx.send(Task { unit, saved })?;
                    outstanding += 1;
                    Ok(true)
                } else {
                    Ok(false)
                }
            })();
            match result {
                Ok(true) => {}
                Ok(false) => allocated = true,
                Err(e) => {
                    failure = Some(format!("kangaroo allocation error: {e:#}"));
                    break;
                }
            }
        }
        if allocated && outstanding == 0 {
            sender.take();
        }
        match events_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Event::Checkpoint {
                unit,
                state,
                candidate,
                finished,
                ack,
            }) => {
                let result = (|| -> Result<()> {
                    if let Some(candidate) = candidate {
                        let key = recover_ec(&target, &candidate)?;
                        store.record_recovery(&target, Some(job), &spec.method, &key)?;
                        recovered = true;
                        options.cancel.store(true, Ordering::Relaxed);
                    }
                    store.save_kangaroo_state(job, &unit, &spec, &state, finished)?;
                    if finished {
                        outstanding = outstanding.saturating_sub(1);
                    }
                    Ok(())
                })();
                match result {
                    Ok(()) => {
                        let _ = ack.send(Ok(()));
                    }
                    Err(e) => {
                        let error = format!("kangaroo checkpoint error: {e:#}");
                        let _ = ack.send(Err(error.clone()));
                        failure = Some(error);
                    }
                }
            }
            Ok(Event::Failed(error)) => {
                failure = Some(error);
            }
            Ok(Event::Stopped) => {
                stopped += 1;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                failure = Some("kangaroo workers disconnected unexpectedly".into());
                break;
            }
        }
        if !options.quiet && last_display.elapsed() >= Duration::from_secs(1) {
            if let Ok(report) = store.report(job) {
                eprintln!(
                    "job {job}: {} durable walk steps; no exhaustive coverage percentage",
                    report["walk_steps_completed"].as_str().unwrap_or("?")
                );
            }
            last_display = Instant::now();
        }
    }
    options.cancel.store(true, Ordering::Relaxed);
    drop(sender);
    drop(pool);
    let complete =
        store.report(job)?["attempts_completed"].as_u64() == Some(config.attempts as u64);
    let status = if recovered {
        "recovered"
    } else if failure.is_some() {
        "failed"
    } else if complete {
        "budget_exhausted"
    } else {
        "paused"
    };
    store.finish(job, status, started.elapsed(), failure.as_deref())?;
    if let Some(error) = failure {
        anyhow::bail!("{error}; committed walks remain resumable in job {job}");
    }
    store.report(job)
}

pub fn initial_snapshot(target: &Target, spec: &SearchSpec) -> Result<Snapshot> {
    let key = public_key(target)?;
    let ec = key.ec_key()?;
    let mut ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(ec.group())?;
    point.mul_generator2(
        ec.group(),
        bignum(&(number(&spec.end)? - 1u8))?.as_ref(),
        &mut ctx,
    )?;
    Ok(Snapshot {
        version: 1,
        spec_hash: spec.hash()?,
        attempt: 0,
        phase: "tame".into(),
        tame_steps: 0,
        wild_steps: 0,
        tame_distance: "0x0".into(),
        wild_distance: "0x0".into(),
        point: hex::encode(point.to_bytes(
            ec.group(),
            PointConversionForm::COMPRESSED,
            &mut ctx,
        )?),
        points: BTreeMap::new(),
        table_saturated: false,
        termination: None,
    })
}

pub fn report(store: &Store, job: i64) -> Result<Value> {
    let mut stmt = store
        .conn
        .prepare("SELECT record,checksum FROM kangaroo_states WHERE job_id=?1 ORDER BY unit_id")?;
    let rows = stmt.query_map([job], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let spec = store.spec(job)?;
    let mut steps = BigUint::zero();
    let mut complete = 0u32;
    let mut walks = Vec::new();
    for row in rows {
        let (record, hash) = row?;
        ensure!(
            fingerprint(record.as_bytes()) == hash,
            "kangaroo checkpoint checksum mismatch"
        );
        let state: Snapshot = serde_json::from_str(&record)?;
        state.validate(&spec, state.attempt)?;
        steps += state.operations();
        if state.phase == "done" {
            complete += 1;
        }
        walks.push(json!({"attempt":state.attempt,"phase":state.phase,"tame_steps":state.tame_steps,"wild_steps":state.wild_steps,"distinguished_points":state.points.len(),"table_saturated":state.table_saturated,"termination":state.termination}));
    }
    Ok(
        json!({"walk_steps_completed":steps.to_str_radix(10),"attempts_completed":complete,"walks":walks,"coverage_note":"Probabilistic walk attempts; no exhaustive scalar coverage or success probability is claimed. Budget exhaustion does not exclude a key inside the interval."}),
    )
}
