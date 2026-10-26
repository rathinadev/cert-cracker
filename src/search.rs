use crate::{
    bsgs,
    crypto::{EcWorker, ec_order, recover_ec},
    model::{SearchSpec, Target, WorkUnit, number},
    planner,
    storage::Store,
};
use anyhow::{Context, Result, ensure};
use crossbeam_channel::{Receiver, Sender, bounded};
use num_bigint::BigUint;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct RunOptions {
    pub workers: usize,
    pub checkpoint_interval: Duration,
    pub time_limit: Option<Duration>,
    pub cancel: Arc<AtomicBool>,
    pub quiet: bool,
}

enum Event {
    Progress {
        unit: i64,
        generation: i64,
        next: BigUint,
    },
    Finished {
        unit: i64,
        generation: i64,
        next: BigUint,
        candidate: Option<BigUint>,
    },
    Failed(String),
    Stopped,
}

fn worker(
    target: Target,
    spec: SearchSpec,
    table: Option<Arc<bsgs::Table>>,
    rx: Receiver<WorkUnit>,
    tx: Sender<Event>,
    cancel: Arc<AtomicBool>,
    interval: Duration,
) {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        let mut sequential = if table.is_none() {
            Some(EcWorker::new(&target)?)
        } else {
            None
        };
        let mut bsgs = table
            .map(|t| bsgs::Worker::new(&target, &spec, t))
            .transpose()?;
        while let Ok(unit) = rx.recv() {
            let mut notify = |next: &BigUint| {
                tx.send(Event::Progress {
                    unit: unit.id,
                    generation: unit.generation,
                    next: next.clone(),
                })?;
                Ok(())
            };
            let (next, candidate) = if let Some(engine) = sequential.as_mut() {
                engine.search(&unit, &cancel, interval, &mut notify)?
            } else {
                bsgs.as_mut().context("missing BSGS worker")?.search(
                    &unit,
                    &cancel,
                    interval,
                    &mut notify,
                )?
            };
            tx.send(Event::Finished {
                unit: unit.id,
                generation: unit.generation,
                next,
                candidate,
            })?;
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }
        Ok(())
    }));
    match result {
        Ok(Err(error)) => {
            let _ = tx.send(Event::Failed(format!("{error:#}")));
        }
        Err(_) => {
            let _ = tx.send(Event::Failed(
                "worker panicked; committed work is resumable".into(),
            ));
        }
        _ => {}
    }
    let _ = tx.send(Event::Stopped);
}

pub fn run(store: &mut Store, job: i64, options: RunOptions) -> Result<serde_json::Value> {
    if store.spec(job)?.kangaroo.is_some() {
        return crate::kangaroo::run(store, job, options);
    }
    let started = Instant::now();
    ensure!(
        (1..=256).contains(&options.workers),
        "worker count must be between 1 and 256"
    );
    ensure!(
        !options.checkpoint_interval.is_zero(),
        "checkpoint interval must be positive"
    );
    let spec = store.spec(job)?;
    planner::preflight(&spec, options.workers)?;
    let target = store.target(&spec.target_id)?;
    ensure!(
        number(&spec.end)? <= ec_order(&target)?,
        "exclusive range end exceeds curve subgroup order"
    );
    if matches!(store.status(job)?.as_str(), "recovered" | "exhausted") {
        return store.report(job);
    }
    store.begin_run(job)?;
    let deadline = options
        .time_limit
        .map(|d| started.checked_add(d).context("time limit overflow"))
        .transpose()?;
    let table = if spec.bsgs.is_some() {
        match bsgs::prepare(
            store,
            job,
            &spec,
            &target,
            &bsgs::PrepareOptions {
                workers: options.workers,
                cancel: options.cancel.clone(),
                deadline,
                checkpoint_interval: options.checkpoint_interval,
                quiet: options.quiet,
            },
        ) {
            Ok(Some(table)) => Some(table),
            Ok(None) => {
                store.finish(job, "paused", started.elapsed(), None)?;
                return store.report(job);
            }
            Err(e) => {
                store.finish(job, "failed", started.elapsed(), Some(&format!("{e:#}")))?;
                return Err(e.context(format!("BSGS table preparation failed for job {job}")));
            }
        }
    } else {
        None
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.workers)
        .thread_name(|i| format!("cert-worker-{i}"))
        .build()?;
    let (work_tx, work_rx) = bounded::<WorkUnit>(options.workers);
    let (event_tx, event_rx) = bounded::<Event>(options.workers * 4);
    for _ in 0..options.workers {
        let target = target.clone();
        let spec = spec.clone();
        let table = table.clone();
        let rx = work_rx.clone();
        let tx = event_tx.clone();
        let cancel = options.cancel.clone();
        let interval = options.checkpoint_interval;
        pool.spawn(move || worker(target, spec, table, rx, tx, cancel, interval));
    }
    drop(event_tx);
    drop(work_rx);
    let mut work_tx = Some(work_tx);
    let mut outstanding = 0usize;
    let mut stopped = 0usize;
    let mut all_allocated = false;
    let mut recovered = false;
    let mut failure: Option<String> = None;
    let mut last_display = Instant::now();
    while stopped < options.workers {
        if options
            .time_limit
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            options.cancel.store(true, Ordering::Relaxed);
        }
        if options.cancel.load(Ordering::Relaxed) || failure.is_some() {
            options.cancel.store(true, Ordering::Relaxed);
            work_tx.take();
        }
        while outstanding < options.workers && !all_allocated {
            let Some(sender) = work_tx.as_ref() else {
                break;
            };
            match store.allocate(job) {
                Ok(Some(unit)) => {
                    if sender.send(unit).is_err() {
                        failure = Some("all workers disconnected".into());
                        break;
                    }
                    outstanding += 1;
                }
                Ok(None) => all_allocated = true,
                Err(e) => {
                    failure = Some(format!("allocation failed: {e:#}"));
                    break;
                }
            }
        }
        if all_allocated && outstanding == 0 {
            work_tx.take();
        }
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => {
                let applied = (|| -> Result<()> {
                    match event {
                        Event::Progress {
                            unit,
                            generation,
                            next,
                        } => store.progress(job, unit, generation, &next, false)?,
                        Event::Finished {
                            unit,
                            generation,
                            next,
                            candidate,
                        } => {
                            outstanding = outstanding.saturating_sub(1);
                            // A matched candidate must be verified and stored BEFORE its cursor is advanced.
                            // Otherwise a crash could skip a discovery that had not been persisted.
                            if let Some(candidate) = candidate {
                                let key = recover_ec(&target, &candidate)?;
                                store.record_recovery(&target, Some(job), &spec.method, &key)?;
                                recovered = true;
                                options.cancel.store(true, Ordering::Relaxed);
                            }
                            store.progress(job, unit, generation, &next, true)?;
                        }
                        Event::Failed(error) => {
                            failure = Some(error);
                        }
                        Event::Stopped => stopped += 1,
                    }
                    Ok(())
                })();
                if let Err(e) = applied {
                    failure = Some(format!("checkpoint/result error: {e:#}"));
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                if stopped < options.workers {
                    failure = Some("worker event channel closed unexpectedly".into());
                }
                break;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
        if !options.quiet && last_display.elapsed() >= Duration::from_secs(1) {
            if let Ok(report) = store.report(job) {
                eprintln!(
                    "job {job}: {} scalars covered, {} active units, {:.1}s this run",
                    report["covered_candidates"].as_str().unwrap_or("?"),
                    outstanding,
                    started.elapsed().as_secs_f64()
                );
            }
            last_display = Instant::now();
        }
    }
    options.cancel.store(true, Ordering::Relaxed);
    drop(work_tx);
    drop(pool);
    let tested = number(
        store.report(job)?["covered_candidates"]
            .as_str()
            .unwrap_or("0"),
    )?;
    let complete = tested == number(&spec.end)? - number(&spec.start)?;
    let status = if recovered {
        "recovered"
    } else if failure.is_some() {
        "failed"
    } else if complete {
        "exhausted"
    } else {
        "paused"
    };
    store.finish(job, status, started.elapsed(), failure.as_deref())?;
    if let Some(error) = failure {
        anyhow::bail!("{error}; committed progress remains in job {job}");
    }
    store.report(job)
}
