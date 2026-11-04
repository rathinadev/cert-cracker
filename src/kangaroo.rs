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
    memory_required_for(points, workers, attempts, false)
}

pub fn memory_required_for(points: u32, workers: usize, attempts: u32, cooperative: bool) -> u64 {
    let active = workers.min(attempts as usize) as u64;
    let maps = if cooperative {
        2 * (active + u64::from(attempts))
    } else {
        active
    };
    BASE_BYTES + active * WORKER_BYTES + maps * u64::from(points) * POINT_BYTES
}

fn is_false(value: &bool) -> bool {
    !value
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wild_points: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub wild_table_saturated: bool,
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
            self.version == c.state_version
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
            self.wild_points.len() <= c.max_points as usize,
            "kangaroo wild point table exceeds immutable capacity"
        );
        ensure!(
            c.state_version == 2 || (self.wild_points.is_empty() && !self.wild_table_saturated),
            "independent walk cannot contain cooperative points"
        );
        ensure!(
            self.phase != "tame"
                || (self.wild_steps == 0 && number(&self.wild_distance)?.is_zero()),
            "wild progress in tame phase"
        );
        ensure!(
            self.phase != "tame" || (self.wild_points.is_empty() && !self.wild_table_saturated),
            "wild points in tame phase"
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
            .chain(self.wild_points.values())
        {
            ensure!(
                distance.len() <= 270 && canonical(&number(distance)?) == *distance,
                "invalid kangaroo distance"
            );
        }
        for point in std::iter::once(&self.point)
            .chain(self.points.keys())
            .chain(self.wild_points.keys())
        {
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

fn offset(spec: &SearchSpec, attempt: u32) -> Result<BigUint> {
    let config = spec
        .kangaroo
        .as_ref()
        .context("missing kangaroo configuration")?;
    if config.state_version == 1 {
        return Ok(BigUint::zero());
    }
    let width = number(&spec.end)? - number(&spec.start)?;
    Ok((width.sqrt() / 2u8).max(1u8.into()) * attempt)
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
    pending: PointDelta,
}

#[derive(Default)]
struct PointDelta {
    tame: BTreeMap<String, String>,
    wild: BTreeMap<String, String>,
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
        if config.state_version == 1 {
            salt.extend_from_slice(&attempt.to_le_bytes());
            salt.extend_from_slice(b"cert-cracker-kangaroo-v1");
        } else {
            salt.extend_from_slice(b"cert-cracker-kangaroo-herd-v2");
        }
        let mut point = EcPoint::new(&group)?;
        let mut state = if let Some(state) = saved {
            state.validate(spec, attempt)?;
            state
        } else {
            Snapshot {
                version: config.state_version,
                spec_hash: spec.hash()?,
                attempt,
                phase: "tame".into(),
                tame_steps: 0,
                wild_steps: 0,
                tame_distance: "0x0".into(),
                wild_distance: "0x0".into(),
                point: String::new(),
                points: BTreeMap::new(),
                wild_points: BTreeMap::new(),
                wild_table_saturated: false,
                table_saturated: false,
                termination: None,
            }
        };
        if state.phase == "tame" {
            point.mul_generator2(
                &group,
                bignum(&(&upper + offset(spec, attempt)? + number(&state.tame_distance)?))?
                    .as_ref(),
                &mut ctx,
            )?;
        } else {
            let mut offset_point = EcPoint::new(&group)?;
            offset_point.mul_generator2(
                &group,
                bignum(&(offset(spec, attempt)? + number(&state.wild_distance)?))?.as_ref(),
                &mut ctx,
            )?;
            point.add(&group, &target_point, &offset_point, &mut ctx)?;
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
            pending: PointDelta::default(),
        })
    }

    fn switch_to_wild(&mut self) -> Result<()> {
        self.state.phase = "wild".into();
        let mut off = EcPoint::new(&self.group)?;
        let offset = if self.config.state_version == 2 {
            let width = &self.upper - &self.start + 1u8;
            (width.sqrt() / 2u8).max(1u8.into()) * self.state.attempt
        } else {
            BigUint::zero()
        };
        off.mul_generator2(&self.group, bignum(&offset)?.as_ref(), &mut self.ctx)?;
        self.point
            .add(&self.group, &self.target, &off, &mut self.ctx)?;
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
                if !self.state.points.contains_key(&point_key) {
                    let distance = self.state.tame_distance.clone();
                    if self.config.state_version == 2 {
                        self.pending
                            .tame
                            .insert(point_key.clone(), distance.clone());
                    }
                    self.state.points.insert(point_key, distance);
                }
            }
            if endpoint {
                self.switch_to_wild()?;
                return Ok(None);
            }
        } else {
            if self.config.state_version == 2 {
                let distinguished = u64::from_le_bytes(digest[8..16].try_into()?)
                    & ((1u64 << self.config.distinguished_bits) - 1)
                    == 0;
                if distinguished
                    || self.state.wild_steps == 0
                    || self.state.wild_steps == self.config.steps_per_phase
                {
                    if self.state.wild_points.len() < self.config.max_points as usize
                        || self.state.wild_points.contains_key(&point_key)
                    {
                        if !self.state.wild_points.contains_key(&point_key) {
                            let distance = self.state.wild_distance.clone();
                            self.pending
                                .wild
                                .insert(point_key.clone(), distance.clone());
                            self.state.wild_points.insert(point_key.clone(), distance);
                        }
                    } else {
                        self.state.wild_table_saturated = true;
                    }
                }
            }
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
                || (self.config.state_version == 1
                    && number(&self.state.wild_distance)? > self.wild_limit)
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

#[derive(Clone)]
struct Location {
    attempt: u32,
    distance: String,
}

#[derive(Default)]
struct Herd {
    tame: BTreeMap<String, Location>,
    wild: BTreeMap<String, Location>,
}

impl Herd {
    fn candidate(
        spec: &SearchSpec,
        order: &BigUint,
        tame: &Location,
        wild: &Location,
    ) -> Result<Option<BigUint>> {
        let upper = number(&spec.end)? - 1u8;
        let lhs = (upper + offset(spec, tame.attempt)? + number(&tame.distance)?) % order;
        let rhs = (offset(spec, wild.attempt)? + number(&wild.distance)?) % order;
        let candidate = (lhs + order - rhs) % order;
        if number(&spec.start)? <= candidate && candidate < number(&spec.end)? {
            Ok(Some(candidate))
        } else {
            Ok(None)
        }
    }

    // Test incoming points against committed points before publishing them. This
    // makes collision detection independent of which checkpoint arrives first.
    fn check(
        &self,
        state: &Snapshot,
        spec: &SearchSpec,
        order: &BigUint,
    ) -> Result<Option<BigUint>> {
        self.check_points(
            state.attempt,
            &state.points,
            &state.wild_points,
            spec,
            order,
        )
    }
    fn check_points(
        &self,
        attempt: u32,
        tame: &BTreeMap<String, String>,
        wild: &BTreeMap<String, String>,
        spec: &SearchSpec,
        order: &BigUint,
    ) -> Result<Option<BigUint>> {
        for (point, distance) in tame {
            if let Some(other) = self.wild.get(point)
                && other.attempt != attempt
                && let Some(candidate) = Self::candidate(
                    spec,
                    order,
                    &Location {
                        attempt,
                        distance: distance.clone(),
                    },
                    other,
                )?
            {
                return Ok(Some(candidate));
            }
        }
        for (point, distance) in wild {
            if let Some(other) = self.tame.get(point)
                && other.attempt != attempt
                && let Some(candidate) = Self::candidate(
                    spec,
                    order,
                    other,
                    &Location {
                        attempt,
                        distance: distance.clone(),
                    },
                )?
            {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    fn insert(&mut self, state: &Snapshot) {
        self.insert_points(state.attempt, &state.points, &state.wild_points);
    }
    fn insert_points(
        &mut self,
        attempt: u32,
        tame: &BTreeMap<String, String>,
        wild: &BTreeMap<String, String>,
    ) {
        for (point, distance) in tame {
            if !self.tame.contains_key(point) {
                self.tame.insert(
                    point.clone(),
                    Location {
                        attempt,
                        distance: distance.clone(),
                    },
                );
            }
        }
        for (point, distance) in wild {
            if !self.wild.contains_key(point) {
                self.wild.insert(
                    point.clone(),
                    Location {
                        attempt,
                        distance: distance.clone(),
                    },
                );
            }
        }
    }
}

fn load_herd(
    store: &Store,
    job: i64,
    spec: &SearchSpec,
    order: &BigUint,
) -> Result<(Herd, Option<BigUint>)> {
    let mut stmt = store.conn.prepare(
        "SELECT id,start,end,next,generation FROM work_units WHERE job_id=?1 ORDER BY id",
    )?;
    let rows = stmt.query_map([job], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut herd = Herd::default();
    for row in rows {
        let (id, start, end, next, generation) = row?;
        let unit = WorkUnit {
            id,
            generation,
            start: number(&start)?,
            end: number(&end)?,
            next: number(&next)?,
        };
        let state = store
            .kangaroo_state(job, &unit, spec)?
            .context("missing cooperative walk")?;
        if let Some(candidate) = herd.check(&state, spec, order)? {
            return Ok((herd, Some(candidate)));
        }
        herd.insert(&state);
    }
    Ok((herd, None))
}

enum Event {
    Checkpoint {
        unit: WorkUnit,
        state: Box<Snapshot>,
        delta: Box<PointDelta>,
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
                        delta: Box::new(std::mem::take(&mut walk.pending)),
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
    let order = ec_order(&target)?;
    ensure!(
        number(&spec.end)? <= order,
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
    let mut herd = Herd::default();
    if config.state_version == 2 {
        let (loaded, candidate) = load_herd(store, job, &spec, &order)?;
        herd = loaded;
        if let Some(candidate) = candidate {
            let key = recover_ec(&target, &candidate)?;
            store.record_recovery(&target, Some(job), "ec-kangaroo-cooperative", &key)?;
            return store.report(job);
        }
    }
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
                delta,
                candidate,
                finished,
                ack,
            }) => {
                let result = (|| -> Result<()> {
                    ensure!(
                        delta
                            .tame
                            .iter()
                            .all(|(p, d)| state.points.get(p) == Some(d))
                            && delta
                                .wild
                                .iter()
                                .all(|(p, d)| state.wild_points.get(p) == Some(d)),
                        "kangaroo collision delta does not match checkpoint"
                    );
                    let shared = if config.state_version == 2 {
                        herd.check_points(state.attempt, &delta.tame, &delta.wild, &spec, &order)?
                    } else {
                        None
                    };
                    let method = if candidate.is_none() && shared.is_some() {
                        "ec-kangaroo-cooperative"
                    } else {
                        &spec.method
                    };
                    if let Some(candidate) = candidate.or(shared)
                        && !recovered
                    {
                        store.validate_kangaroo_update(job, &unit, &spec, &state)?;
                        let key = recover_ec(&target, &candidate)?;
                        store.record_recovery(&target, Some(job), method, &key)?;
                        recovered = true;
                        options.cancel.store(true, Ordering::Relaxed);
                    }
                    store.save_kangaroo_state(job, &unit, &spec, &state, finished)?;
                    if config.state_version == 2 {
                        herd.insert_points(state.attempt, &delta.tame, &delta.wild);
                    }
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
    initial_snapshot_for_attempt(target, spec, 0)
}

pub fn initial_snapshot_for_attempt(
    target: &Target,
    spec: &SearchSpec,
    attempt: u32,
) -> Result<Snapshot> {
    let key = public_key(target)?;
    let ec = key.ec_key()?;
    let mut ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(ec.group())?;
    point.mul_generator2(
        ec.group(),
        bignum(&(number(&spec.end)? - 1u8 + offset(spec, attempt)?))?.as_ref(),
        &mut ctx,
    )?;
    Ok(Snapshot {
        version: spec
            .kangaroo
            .as_ref()
            .context("missing kangaroo configuration")?
            .state_version,
        spec_hash: spec.hash()?,
        attempt,
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
        wild_points: BTreeMap::new(),
        wild_table_saturated: false,
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
        let mut walk = json!({"attempt":state.attempt,"phase":state.phase,"tame_steps":state.tame_steps,"wild_steps":state.wild_steps,"distinguished_points":state.points.len(),"table_saturated":state.table_saturated,"termination":state.termination});
        if state.version == 2 {
            walk["wild_distinguished_points"] = json!(state.wild_points.len());
            walk["wild_table_saturated"] = json!(state.wild_table_saturated);
        }
        walks.push(walk);
    }
    let mut result = json!({"walk_steps_completed":steps.to_str_radix(10),"attempts_completed":complete,"walks":walks,"coverage_note":"Probabilistic walk attempts; no exhaustive scalar coverage or success probability is claimed. Budget exhaustion does not exclude a key inside the interval."});
    if spec.kangaroo.as_ref().is_some_and(|c| c.state_version == 2) {
        result["cooperative"] = json!(true);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, import, model::KangarooConfig};
    use openssl::pkey::PKey;
    #[test]
    fn cross_attempt_collision_is_detected_in_both_arrival_orders() {
        let private = crypto::lab_key("P-256", &14u8.into()).unwrap();
        let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
        let target = import::target_from_key(&public, "unit fixture").unwrap();
        let config = KangarooConfig {
            state_version: 2,
            seed: "00".repeat(32),
            attempts: 2,
            steps_per_phase: 1,
            distinguished_bits: 0,
            max_points: 16,
            memory_budget_bytes: 16 * 1024 * 1024,
        };
        let spec = SearchSpec::kangaroo(target.id.clone(), "1", "17", config).unwrap();
        let mut tame = initial_snapshot_for_attempt(&target, &spec, 0).unwrap();
        let mut wild = initial_snapshot_for_attempt(&target, &spec, 1).unwrap();
        let point = tame.point.clone();
        tame.points.insert(point.clone(), "0x0".into());
        wild.phase = "wild".into();
        wild.point = point.clone();
        wild.wild_points.insert(point, "0x0".into());
        let order = ec_order(&target).unwrap();
        for (first, second) in [(&tame, &wild), (&wild, &tame)] {
            let mut herd = Herd::default();
            assert!(herd.check(first, &spec, &order).unwrap().is_none());
            herd.insert(first);
            let candidate = herd.check(second, &spec, &order).unwrap().unwrap();
            assert_eq!(candidate, BigUint::from(14u8));
            recover_ec(&target, &candidate).unwrap();
        }
    }
}
