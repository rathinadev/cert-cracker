use anyhow::{Context, Result, ensure};
use cert_cracker::{
    analysis, crypto, import,
    model::{Target, number},
    planner::{self, KangarooOptions, PlanOptions},
    search::{self, RunOptions},
    storage::{Store, private_file},
};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "Local public-key analysis with durable multicore bounded recovery"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".cert-cracker")]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show actual compiled capabilities; unavailable engines remain explicit.
    Capabilities,
    /// Show backend/toolchain and available logical CPU information.
    Doctor,
    /// Inspect certificate/public-key files without changing persistent state.
    Inspect {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Import, list or inspect persistent targets.
    Targets {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Create/reuse an immutable EC search job. End is exclusive.
    Plan(PlanArgs),
    /// Estimate method, work and table memory without creating persistent state.
    Estimate(EstimateArgs),
    /// Execute an existing job, or continue its last committed progress.
    Run(RunArgs),
    /// Resume a paused/interrupted job, including after SIGKILL or restart.
    Resume(RunArgs),
    /// Import one public input, create a bounded EC job, and run it.
    Search(SearchArgs),
    Jobs {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Run bounded RSA checks on imported targets or supplied files.
    Audit {
        files: Vec<PathBuf>,
        #[arg(long, default_value_t = 10000)]
        trial_limit: u64,
        #[arg(long, default_value_t = 1000)]
        fermat_steps: u64,
    },
    /// List verified findings without private material.
    Findings,
    /// List persisted bounded-audit results, including negative check coverage.
    Audits,
    /// Benchmark the actual CPU scheduler with SQLite checkpointing enabled.
    Bench {
        #[arg(long, default_value = "P-256")]
        curve: String,
        #[arg(long, default_value_t = 100000)]
        candidates: u64,
        #[arg(long, value_delimiter = ',', default_value = "1,2,4")]
        workers: Vec<usize>,
        #[command(flatten)]
        algorithm: AlgorithmArgs,
    },
    /// Emit a job report. Private material is never included.
    Report {
        job: i64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Export a verified finding's private key to a NEW private file.
    ExportKey {
        finding: i64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate deliberately weak laboratory inputs in a NEW directory.
    Lab {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "P-384")]
        curve: String,
        #[arg(long, default_value = "4")]
        scalar: String,
    },
}

#[derive(Subcommand)]
enum TargetCommand {
    Import {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        recursive: bool,
    },
    List,
    Inspect {
        id: String,
    },
}
#[derive(Subcommand)]
enum JobCommand {
    List,
    Status { job: i64 },
}

#[derive(Args)]
struct PlanArgs {
    #[arg(long)]
    target: String,
    #[arg(long, default_value = "1")]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long, default_value_t = 16384)]
    chunk_size: u64,
    #[arg(long,default_value_t=default_workers())]
    workers: usize,
    #[command(flatten)]
    algorithm: AlgorithmArgs,
}

#[derive(Args)]
struct AlgorithmArgs {
    #[arg(long,default_value="auto",value_parser=["auto","sequential","bsgs","kangaroo"])]
    method: String,
    /// Engine table/workspace budget; process runtime baseline is additional.
    #[arg(long, default_value_t = 256)]
    memory_mib: u64,
    /// Explicit baby-step count; smaller tables require more giant lookups.
    #[arg(long)]
    baby_steps: Option<u64>,
    /// Logical kangaroo attempts (default 16); stable across worker-count changes.
    #[arg(long)]
    kangaroo_attempts: Option<u32>,
    /// Maximum additions per phase per attempt (default 8*ceil(sqrt(width))).
    #[arg(long)]
    kangaroo_steps: Option<u64>,
    /// Reproducible 32-byte seed as 64 lowercase hex characters (default all zeros).
    #[arg(long)]
    kangaroo_seed: Option<String>,
    /// Distinguished-point predicate bits, 0..40 (default chosen from capacity).
    #[arg(long)]
    kangaroo_dp_bits: Option<u8>,
    /// Maximum saved tame points per logical attempt, 16..65536.
    #[arg(long)]
    kangaroo_max_points: Option<u32>,
}

impl AlgorithmArgs {
    fn kangaroo_options(&self) -> KangarooOptions {
        KangarooOptions {
            attempts: self.kangaroo_attempts,
            steps_per_phase: self.kangaroo_steps,
            seed: self.kangaroo_seed.clone(),
            distinguished_bits: self.kangaroo_dp_bits,
            max_points: self.kangaroo_max_points,
        }
    }
}

#[derive(Args)]
struct EstimateArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, default_value = "1")]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long, default_value_t = 16384)]
    chunk_size: u64,
    #[arg(long,default_value_t=default_workers())]
    workers: usize,
    #[command(flatten)]
    algorithm: AlgorithmArgs,
}
#[derive(Args)]
struct Resources {
    #[arg(long,default_value_t=default_workers())]
    workers: usize,
    #[arg(long, default_value_t = 1000)]
    checkpoint_interval_ms: u64,
    #[arg(long)]
    time_limit_secs: Option<f64>,
    #[arg(long)]
    quiet: bool,
}
#[derive(Args)]
struct RunArgs {
    job: i64,
    #[command(flatten)]
    resources: Resources,
}
#[derive(Args)]
struct SearchArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, default_value = "1")]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long, default_value_t = 16384)]
    chunk_size: u64,
    #[command(flatten)]
    resources: Resources,
    #[command(flatten)]
    algorithm: AlgorithmArgs,
}

fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).clamp(1, 256))
}
fn emit(value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn collect_files(paths: &[PathBuf], recursive: bool) -> (Vec<PathBuf>, Vec<Value>) {
    fn visit(
        path: &Path,
        recursive: bool,
        depth: usize,
        visited: &mut usize,
        files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        *visited += 1;
        ensure!(*visited <= 8192, "input traversal limited to 8192 entries");
        ensure!(files.len() < 4096, "input limited to 4096 files");
        ensure!(depth <= 64, "input directory depth exceeds 64");
        let meta =
            fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            !meta.file_type().is_symlink(),
            "input symlinks require an explicit regular-file path: {}",
            path.display()
        );
        if meta.is_dir() {
            ensure!(
                recursive,
                "{} is a directory; use --recursive",
                path.display()
            );
            let mut children = fs::read_dir(path)?
                .take(8193)
                .map(|e| e.map(|v| v.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            ensure!(children.len() <= 8192, "directory exceeds 8192 entries");
            children.sort();
            for child in children {
                visit(&child, recursive, depth + 1, visited, files)?;
            }
        } else {
            files.push(path.to_owned());
        }
        Ok(())
    }
    let mut files = vec![];
    let mut errors = vec![];
    let mut visited = 0;
    for path in paths {
        if let Err(e) = visit(path, recursive, 0, &mut visited, &mut files) {
            errors.push(json!({"path":path,"error":format!("{e:#}")}));
        }
    }
    (files, errors)
}

fn read_targets(paths: &[PathBuf]) -> (Vec<Target>, Vec<Value>) {
    let mut targets = BTreeMap::<String, Target>::new();
    let mut errors = vec![];
    for path in paths {
        match import::load(path) {
            Ok(items) => {
                for target in items {
                    if let Some(existing) = targets.get_mut(&target.id) {
                        import::merge(existing, target);
                    } else {
                        targets.insert(target.id.clone(), target);
                    }
                }
            }
            Err(e) => errors.push(json!({"path":path,"error":format!("{e:#}")})),
        }
    }
    (targets.into_values().collect(), errors)
}

fn run(store: &mut Store, job: i64, resources: Resources) -> Result<()> {
    let time_limit = if let Some(secs) = resources.time_limit_secs {
        ensure!(
            secs.is_finite() && secs > 0.0 && secs <= 31_536_000.0,
            "time limit must be positive, finite, and <= one year"
        );
        Some(Duration::from_secs_f64(secs))
    } else {
        None
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))
        .context("installing signal handler")?;
    let report = search::run(
        store,
        job,
        RunOptions {
            workers: resources.workers,
            checkpoint_interval: Duration::from_millis(resources.checkpoint_interval_ms),
            time_limit,
            cancel,
            quiet: resources.quiet,
        },
    )?;
    emit(&report)
}

fn make_plan(store: &Store, target: &str, options: PlanOptions<'_>) -> Result<(i64, Value)> {
    let (spec, estimate) = planner::plan(&store.target(target)?, options)?;
    Ok((store.create_job(&spec)?, estimate))
}

fn main_result() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Capabilities => emit(&json!({"version":env!("CARGO_PKG_VERSION"),"engines":[
            {"id":"ec-sequential","status":"implemented","hardware":"multicore CPU","checkpoint":"exact per-unit next candidate; uncommitted tails replay","curves":"named EC groups available through OpenSSL; release tests cover P-256/P-384/P-521/secp256k1","methods":["incremental point addition","independent scalar-multiplication verification"]},
            {"id":"ec-bsgs","status":"implemented","hardware":"multicore CPU with one shared immutable table","curves":["P-256","P-384","P-521","secp256k1"],"checkpoint":"durable baby-step ledger, checksummed ready table, exact giant-step cursors","memory_limit":"table/workspace budget; runtime baseline RSS excluded"},
            {"id":"ec-kangaroo","status":"experimental","hardware":"multicore CPU; independent logical two-walk attempts","curves":["P-256","P-384","P-521","secp256k1"],"checkpoint":"atomic checksummed walk positions, distances, steps and tame distinguished-point maps; worker count can change","coverage":"probabilistic budgets only; no exhaustive scalar coverage","memory_limit":"active maps and checkpoint workspace; runtime/native baseline RSS and SQLite cache excluded"},
            {"id":"rsa-audit","status":"implemented","methods":["pairwise shared-prime GCD","Wiener","bounded trial division","bounded Fermat"],"limits":{"targets":4096,"max_trial_limit":1000000,"max_fermat_iterations":1000000},"checkpoint":"short bounded audit reruns; no resumable factorization engine"}],
            "inspection":["EC","RSA","RSA-PSS","DSA","Ed25519","Ed448","DH","X25519","X448","other backend-supported public keys"],
            "not_implemented":["cooperative kangaroo herds or external adapter","GPU kernels","signature nonce recovery","EdDSA seed recovery","ECM/NFS adapters","distributed workers","dashboard","encrypted secret vault","certificate chain trust validation"],
            "secret_storage":"private state files; not encrypted"})),
        Command::Doctor => emit(
            &json!({"version":env!("CARGO_PKG_VERSION"),"openssl":openssl::version::version(),"sqlite":rusqlite::version(),"logical_cpus":std::thread::available_parallelism().map_or(1,|n|n.get()),"default_workers":default_workers(),"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"gpu_backend":null}),
        ),
        Command::Inspect { files } => {
            let (targets, errors) = read_targets(&files);
            emit(&json!({"targets":targets,"errors":errors}))?;
            ensure!(
                errors.is_empty(),
                "one or more files could not be inspected"
            );
            Ok(())
        }
        Command::Targets { command } => match command {
            TargetCommand::Import { files, recursive } => {
                let (files, mut errors) = collect_files(&files, recursive);
                let (targets, parse_errors) = read_targets(&files);
                errors.extend(parse_errors);
                let store = Store::open(&cli.state, true)?;
                let mut ids = vec![];
                for target in targets {
                    ids.push(store.import(target)?);
                }
                emit(&json!({"target_ids":ids,"errors":errors}))?;
                ensure!(
                    errors.is_empty(),
                    "some files failed; successfully imported targets were preserved"
                );
                Ok(())
            }
            TargetCommand::List => emit(&Store::open(&cli.state, false)?.targets()?),
            TargetCommand::Inspect { id } => emit(&Store::open(&cli.state, false)?.target(&id)?),
        },
        Command::Plan(args) => {
            let store = Store::open(&cli.state, true)?;
            let (id, estimate) = make_plan(
                &store,
                &args.target,
                PlanOptions {
                    start: &args.start,
                    end: &args.end,
                    chunk_size: args.chunk_size,
                    method: &args.algorithm.method,
                    memory_mib: args.algorithm.memory_mib,
                    baby_steps: args.algorithm.baby_steps,
                    kangaroo: Some(&args.algorithm.kangaroo_options()),
                    workers: args.workers,
                },
            )?;
            let mut report = store.report(id)?;
            report["planning"] = estimate;
            emit(&report)
        }
        Command::Estimate(args) => {
            let targets = import::load(&args.input)?;
            ensure!(targets.len() == 1, "estimate requires one unique key");
            let (spec, estimate) = planner::plan(
                &targets[0],
                PlanOptions {
                    start: &args.start,
                    end: &args.end,
                    chunk_size: args.chunk_size,
                    method: &args.algorithm.method,
                    memory_mib: args.algorithm.memory_mib,
                    baby_steps: args.algorithm.baby_steps,
                    kangaroo: Some(&args.algorithm.kangaroo_options()),
                    workers: args.workers,
                },
            )?;
            emit(&json!({"spec":spec,"planning":estimate,"persistent_state_created":false}))
        }
        Command::Run(args) | Command::Resume(args) => run(
            &mut Store::open(&cli.state, true)?,
            args.job,
            args.resources,
        ),
        Command::Search(args) => {
            let targets = import::load(&args.input)?;
            ensure!(
                targets.len() == 1,
                "search input must contain exactly one unique key; import a bundle then select a target"
            );
            let mut store = Store::open(&cli.state, true)?;
            let target = store.import(targets.into_iter().next().unwrap())?;
            let (id, estimate) = make_plan(
                &store,
                &target,
                PlanOptions {
                    start: &args.start,
                    end: &args.end,
                    chunk_size: args.chunk_size,
                    method: &args.algorithm.method,
                    memory_mib: args.algorithm.memory_mib,
                    baby_steps: args.algorithm.baby_steps,
                    kangaroo: Some(&args.algorithm.kangaroo_options()),
                    workers: args.resources.workers,
                },
            )?;
            if !args.resources.quiet {
                eprintln!(
                    "selected {}; {}",
                    estimate["selected_method"].as_str().unwrap_or("?"),
                    estimate["reason"].as_str().unwrap_or("")
                );
            }
            eprintln!(
                "job {id}; state {}; Ctrl+C pauses and saves progress",
                cli.state.display()
            );
            run(&mut store, id, args.resources)
        }
        Command::Jobs { command } => {
            let store = Store::open(&cli.state, false)?;
            match command {
                JobCommand::List => emit(&store.jobs()?),
                JobCommand::Status { job } => emit(&store.report(job)?),
            }
        }
        Command::Audit {
            files,
            trial_limit,
            fermat_steps,
        } => {
            let mut store = Store::open(&cli.state, true)?;
            let targets = if files.is_empty() {
                store.targets()?
            } else {
                let (targets, errors) = read_targets(&files);
                ensure!(
                    errors.is_empty(),
                    "audit inputs failed: {}",
                    serde_json::to_string(&errors)?
                );
                for target in &targets {
                    store.import(target.clone())?;
                }
                targets
            };
            ensure!(!targets.is_empty(), "no targets to audit");
            let mut findings = analysis::analyze(&targets, trial_limit, fermat_steps)?;
            for analysis in &mut findings {
                if let Some(pem) = analysis.private_pem.take() {
                    let target = targets.iter().find(|t| t.id == analysis.target_id).unwrap();
                    analysis.finding_id = Some(store.record_recovery(
                        target,
                        None,
                        analysis.method.as_deref().unwrap_or("rsa-audit"),
                        &pem,
                    )?);
                }
            }
            let mut report = json!({"format_version":1,"results":findings,"budgets":{"trial_limit":trial_limit,"fermat_steps":fermat_steps},"note":"RSA checks are bounded; negative results do not establish security"});
            let audit = store.save_audit(&report)?;
            report["audit_id"] = json!(audit);
            emit(&report)
        }
        Command::Findings => emit(&Store::open(&cli.state, false)?.findings()?),
        Command::Audits => emit(&Store::open(&cli.state, false)?.audits()?),
        Command::Bench {
            curve,
            candidates,
            workers,
            algorithm,
        } => {
            ensure!(
                (1..=10_000_000).contains(&candidates),
                "benchmark candidate count must be 1..10000000"
            );
            ensure!(
                !workers.is_empty() && workers.iter().all(|n| (1..=256).contains(n)),
                "benchmark workers must be 1..256"
            );
            let secret = num_bigint::BigUint::from(candidates + 2);
            let key = crypto::lab_key(&curve, &secret)?;
            let public = openssl::pkey::PKey::public_key_from_der(&key.public_key_to_der()?)?;
            let target = import::target_from_key(&public, "benchmark laboratory target")?;
            let mut measurements = vec![];
            for workers in workers {
                let temp = tempfile::tempdir()?;
                let mut store = Store::open(temp.path(), true)?;
                let id = store.import(target.clone())?;
                let (job, _) = make_plan(
                    &store,
                    &id,
                    PlanOptions {
                        start: "1",
                        end: &(candidates + 1).to_string(),
                        chunk_size: 16384,
                        method: &algorithm.method,
                        memory_mib: algorithm.memory_mib,
                        baby_steps: algorithm.baby_steps,
                        kangaroo: Some(&algorithm.kangaroo_options()),
                        workers,
                    },
                )?;
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
                let secs = started.elapsed().as_secs_f64();
                ensure!(
                    (report["outcome"] == "probabilistic_budget_exhausted")
                        || (report["covered_candidates"]
                            .as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            == Some(candidates)
                            && report["status"] == "exhausted"),
                    "benchmark coverage verification failed"
                );
                measurements.push(json!({"workers":workers,"seconds":secs,"engine":store.spec(job)?.method,"covered_candidates":report["covered_candidates"],"walk_steps":report["walk_steps_completed"],"walk_steps_per_second":report["walk_steps_completed"].as_str().and_then(|s|s.parse::<f64>().ok()).map(|n|n/secs),"giant_lookups":report["giant_steps_completed"],"unique_candidates":report["tested_candidates"],"unique_candidates_per_second":if report["tested_candidates"].is_string() {Some(candidates as f64/secs)} else {None}}));
            }
            emit(
                &json!({"requested_method":algorithm.method,"curve":curve,"openssl":openssl::version::version(),"sqlite":rusqlite::version(),"architecture":std::env::consts::ARCH,"logical_cpus":std::thread::available_parallelism().map_or(1,|n|n.get()),"checkpointing":"SQLite synchronous FULL; includes table construction for BSGS","chunk_size":16384,"measurements":measurements,"note":"end-to-end local measurements; BSGS coverage and kangaroo walk steps are not brute-force attempt throughput"}),
            )
        }
        Command::Report { job, output } => {
            let report = Store::open(&cli.state, false)?.report(job)?;
            if let Some(path) = output {
                use std::io::Write;
                let mut file = private_file(&path)?;
                serde_json::to_writer_pretty(&mut file, &report)?;
                writeln!(file)?;
                file.sync_all()?;
                emit(&json!({"saved":path}))
            } else {
                emit(&report)
            }
        }
        Command::ExportKey { finding, output } => {
            Store::open(&cli.state, false)?.export_key(finding, &output)?;
            emit(&json!({"finding_id":finding,"saved_private_key":output}))
        }
        Command::Lab { out, curve, scalar } => {
            let scalar = number(&scalar)?;
            let (cert, public) = crypto::lab_certificate(&curve, &scalar)?;
            fs::create_dir(&out)
                .context("lab output must be a NEW directory with an existing parent")?;
            use std::io::Write;
            for (name, bytes) in [("certificate.pem", cert), ("public.pem", public)] {
                let mut file = private_file(&out.join(name))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            emit(
                &json!({"certificate":out.join("certificate.pem"),"public_key":out.join("public.pem"),"curve":curve,"purpose":"deliberately weak laboratory input"}),
            )
        }
    }
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}
