# Cert Cracker — Full Implementation Plan

**Date:** 26 October 2026
**Project:** `cert-cracker`
**Status:** Approved implementation roadmap. Version 0.2.0 delivers the CPU foundation and interval BSGS; see IMPLEMENTATION_STATUS.md for current scope.
**Primary decision:** Rust application core, established cryptographic libraries, and interchangeable native CPU/GPU recovery engines.

## 1. Intended product

Build a local certificate and public-key analysis application that identifies supported algorithms, checks known weaknesses, and runs appropriate bounded key-recovery methods. Searches use available CPU cores, save durable progress, and resume after interruption. The application grows into a desktop workbench with a CLI, local dashboard, reports, optional GPU acceleration, and optional distributed workers.

The central user experience is: import certificates, inspect their keys, choose or generate a search plan, allocate resources, run, stop, and resume without restarting completed work.

“Strongest implementation” means correct mathematics, appropriate algorithm selection, measured performance, reliable recovery after interruption, clear evidence, and maintainable integration of existing engines. Properly generated modern keys generally remain computationally infeasible to recover. A completed search reports its precise coverage and assumptions, never a general guarantee that a key is secure.

## 2. Scope and terminology

- A certificate is public data containing a subject public key and an issuer signature. The subject key and issuer signing key are separate analysis targets.
- Parsing an algorithm, validating its parameters, detecting known weaknesses, and recovering its private key are distinct capabilities.
- Every method must declare its required inputs, supported key types/curves, resource requirements, resumability, and result semantics.
- A search may target one key, multiple keys sharing a curve, or a collection of RSA moduli, depending on the method.
- “Resume” means continue from durable algorithm state. It is a next-candidate cursor for sequential searches and a richer state object for other methods.
- Start with local certificate/public-key files. Signature datasets, additional key containers, GPUs, and multiple-machine execution are later milestones.

## 3. Product requirements

### Required foundation

1. Import PEM and DER certificates, certificate bundles, and public-key files.
2. Identify key algorithms and parameters, with explicit unsupported outcomes.
3. Distinguish subject-key analysis from issuer-signature analysis.
4. Deduplicate equivalent public keys and associate multiple certificates with one target.
5. Support arbitrary-size search bounds; never truncate a key or range to a machine integer.
6. Run CPU workers with configurable concurrency and resource budgets.
7. Persist job specifications, allocated work, completed work, results, and resumable engine state.
8. Pause gracefully and recover from forced process termination.
9. Verify every recovery independently before marking it successful.
10. Produce machine-readable reports with exact scope, assumptions, and coverage.
11. Keep normal telemetry and reports free of recovered private material.
12. Ship reproducible build instructions, a locked dependency graph, tests, fixtures, and benchmarks.

### Later product capabilities

- Local dashboard, job queue controls, multi-target scheduling, and report comparison.
- Signature-set analysis, specialized algorithm engines, optional accelerated backends.
- Multiple machines sharing work through a coordinator.
- Optional private-key export, encrypted storage, and richer input formats.

## 4. Language and architecture

Use Rust for the controller, domain model, scheduler, persistence, CLI, verification, and native engine interfaces. Use established C/C++ implementations where they offer mature mathematical algorithms or better measured throughput. GPU kernels are separate hardware-specific backends. Optional Python tools run as managed child processes.

```text
CLI                         Local dashboard (later)
  \                                  /
             Application service
                      |
       Import -> Target registry -> Planner
                      |
          Scheduler / resource manager
            /          |            \
   Rust workers   C/C++ engines   GPU engines
            \          |            /
          Independent result verifier
                      |
       SQLite state + engine checkpoint files
                      |
             Reports / explicit export
```

The core contains reusable library crates; the CLI and dashboard call the same application service. UI state is never the authority for progress. Workers never update the database directly. The coordinator controls durable work accounting.

## 5. Planned repository layout

```text
cert-cracker/
  PLAN.md
  README.md
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  crates/
    core/               # IDs, targets, parameters, ranges, result types
    import/             # bounded input parsing and normalization
    crypto/             # mathematical backends and independent verification
    engines/            # native recovery/check modules
    scheduler/          # resource allocation and work lifecycle
    storage/            # migrations, transactions, checkpoints, backup
    adapters/           # managed external engines and protocol
    cli/                # executable and terminal presentation
    service/            # local dashboard API, later
  ui/                   # dashboard, later
  tests/
    integration/
    recovery/
    fixtures/
  benches/
  fuzz/
  docs/
    algorithms.md
    checkpoint-format.md
    engine-protocol.md
    benchmarks.md
    troubleshooting.md
  .github/workflows/
```

Create crates when their boundaries become useful; avoid filling the repository with empty placeholders. Generated targets, state databases, recovered secrets, engine binaries, and build output stay out of source control.

## 6. Dependency choices

| Layer | Proposed dependencies | Role / constraint |
|---|---|---|
| Crypto backend | `openssl` | EC operations, key handling, big numbers, validation and verification. Record linked OpenSSL version and provider availability. |
| Certificate parser | `x509-parser` | Inspect certificate structure, extensions and algorithm identifiers. Parsing alone is not trust validation. |
| CPU parallelism | `rayon` | Explicitly sized native worker pools; avoid nested oversubscription. |
| Persistence | `rusqlite` with bundled SQLite where practical | Transactions, migrations, work ledger and reports. |
| Serialization | `serde`, `serde_json` | Versioned plans, events, adapter messages and reports. |
| CLI | `clap`, `indicatif` | Argument validation, help and terminal progress. |
| Diagnostics | `tracing`, `tracing-subscriber` | Structured logs with secret redaction. |
| Interruption | `ctrlc` or a compatible signal abstraction | Cooperative cancellation and final checkpoint requests. |
| Integer representation | `num-bigint`, `num-traits` as needed | Exact range arithmetic and counters outside cryptographic hot loops. |
| Heavy integer arithmetic | Optional `rug` / GMP | Add for methods that benefit; measure conversion and allocation costs. |
| Locking | Platform file-lock API or a vetted wrapper | One coordinator per state directory; locks are advisory. |
| Secret handling | `zeroize` and a reviewed encrypted-storage integration | Best-effort zeroization; document native-copy limitations. |
| Testing | `tempfile`, `proptest`, Criterion, fuzz tooling | Isolated fixtures, invariant tests and reproducible measurements. |
| Dashboard | TypeScript, React, local Rust HTTP service | Added after CLI reliability; keep computation in workers. |

Choose exact versions during the dependency compatibility build, commit `Cargo.lock`, pin the compiler, and document native prerequisites. Do not treat a dependency's advertised algorithm list as tested application support. OpenSSL is a backend, not a universal key-recovery engine.

## 7. Input handling and target identity

### Initial inputs

- PEM/DER X.509 certificates, including multi-certificate PEM bundles.
- SubjectPublicKeyInfo public keys in PEM/DER.
- RSA PKCS#1 public keys where the parser supports them explicitly.
- Directories via an explicit recursive option with file-count and size limits.

### Later inputs

- Structured signature datasets containing signatures, signed messages or digests, algorithm parameters, and signer identity.
- PKCS#12 using a supplied password, SSH public keys, CSRs and other containers through dedicated import adapters.
- Provider-backed newer algorithms where available, with precise capability reporting.

Encrypted key-container password recovery is a separate problem from recovering a private key from its public key and is outside the initial scope.

### Canonical identities

- Keep the original certificate fingerprint and original SPKI fingerprint for provenance.
- Compute a normalized key identity from the mathematical algorithm, parameters, and public value.
- For EC keys, normalize equivalent point encodings and supported equivalent group representations.
- For RSA, include both modulus and public exponent in key identity; separately index modulus for shared-factor analysis.
- Never silently merge unrecognized explicit EC parameters or ambiguous encodings.
- Preserve input paths, import timestamps and parser/backend versions as provenance.
- Use exact string or byte encodings for large integers in JSON and the database.

Reject malformed inputs with file-specific errors. Invalid or missing files must not cause other valid imports to disappear. Bound parser memory, recursion, bundle length and input size; fuzz these boundaries.

## 8. Algorithm coverage policy

| Family | Initial work | Later work | Practical boundary |
|---|---|---|---|
| RSA | Parameter checks, duplicate/shared-modulus handling, shared-prime detection, bounded trial factors, bounded Fermat, Wiener | Batch GCD product/remainder trees, Pollard rho/p-1, ECM and NFS adapters | Method applicability and modulus structure determine feasibility. |
| Named prime-field EC | Parameter/public-point validation and small-scalar sequential search on P-256, P-384, P-521, secp256k1 | BSGS, interval kangaroo, additional Brainpool and other supported curves | Every engine advertises exact supported curves. |
| Legacy EC variants | Identify and report backend availability | Explicitly tested curves through compatible backends | Binary and unusual curves are separate support decisions. |
| ECDSA signatures | Recognize and associate signer information | Repeated-nonce and specific biased-nonce checks | Requires appropriate signed data from the target signing key. |
| DSA | Identification and parameter analysis | Repeated/biased-nonce analysis with supplied datasets | Legacy support; no universal recovery guarantee. |
| Ed25519 / Ed448 | Identification, supported validation and verification | Explicit weak-seed-generation hypothesis modules | Seed derivation differs from classic EC scalar enumeration. |
| DH / X25519 / X448 | Identify key-agreement keys and validate supported parameters | Specialized checks under explicit assumptions | Key agreement and certificate signing are different roles. |
| Newer / post-quantum / unknown | Preserve OID and metadata; identify supported provider capabilities | Validation and research-backed modules individually | Report unsupported recovery honestly. |

RSA-PSS and RSA PKCS#1 signature encodings do not create separate RSA key-factorization problems. SHA-256/SHA-384 identify hashing choices in a signature, not additional public-key search families. Nonce flaws concern signing operations and cannot generally be inferred from an isolated subject public key.

## 9. Recovery methods and routing

### 9.1 Fast screening

Run applicable parameter validation, supported known-weak-key checks, duplicate identification and collection-level RSA checks first. Persist both positive findings and the exact negative check coverage. A clean screening result does not prohibit an explicitly requested longer search.

### 9.2 Sequential EC search

- Accept explicit integer bounds as a half-open interval `[start, end)`.
- Restrict classic EC private scalars to `[1, subgroup_order)` and reject accidental wraparound.
- Perform one scalar multiplication at each chunk start, then advance by adding the generator where valid and measured to improve performance.
- Reuse per-worker contexts and scratch memory. Avoid parsing certificates or allocating big integers for each candidate.
- Initially match one public key; later share work across targets on the same curve using a validated target lookup.
- Store `next_candidate` as the first candidate not durably accounted for.
- Use CPU-native operations; optimize further only after differential tests and benchmarks.

### 9.3 BSGS interval search

- Use interval width and available memory to determine a bounded table size.
- Estimate real table overhead before allocating; respect the job memory cap.
- Store exact points or verify every compressed/fingerprinted-table collision against the original key.
- Handle zero/infinity representations, non-square interval widths and final partial ranges correctly.
- Persist table construction position, artifact checksum/format, and giant-step progress.
- If the configured memory budget cannot support the plan, offer a different method or report resource insufficiency.

### 9.4 Pollard kangaroo interval search

- Use only when there is a justified bounded interval hypothesis.
- Record walk state, distances, distinguished points, seeds, partitioning and collision candidates.
- Save complete resumable state rather than representing random walks as sequential range coverage.
- Report operation counts and probabilistic estimates; never display a misleading exhaustive completion percentage.
- Start by evaluating compatible existing engines. JeanLucPons/Kangaroo is secp256k1-specific and is not a P-384 backend.
- Validate changes to worker topology and engine versions before accepting old checkpoints.

### 9.5 RSA methods

- Parameter checks: modulus/exponent consistency and supported input structure.
- Shared-prime checks: begin with a correct small-dataset reference, then implement scalable batch GCD.
- Deduplicate identical moduli before batch GCD. A GCD equal to the entire modulus requires further analysis and is not itself a verified factor recovery.
- Bounded trial factors for small factors; bounded Fermat for close-prime hypotheses.
- Wiener checks for applicable small-private-exponent cases.
- Later add bounded Pollard rho, p-1 and an ECM adapter with independent attempt state.
- Evaluate NFS through a managed CADO-NFS adapter for appropriate, explicitly budgeted inputs.
- Record factors and verify their product and reconstructed public/private-key consistency.
- Treat multi-prime RSA as separate support, rather than incorrectly applying a semiprime-only reconstruction.

### 9.6 Signature and seed methods

- Verify supplied signatures and signer associations before analysis.
- Group by the actual signer key and algorithm parameters.
- Detect repeated nonces on distinct signed data where applicable; assess specific nonce biases with methods whose assumptions are documented.
- Never treat duplicate signatures alone as proof of a nonce flaw.
- Implement EdDSA seed tests only with an explicit candidate encoding/generation hypothesis; arbitrary integer enumeration is not interchangeable with Ed25519 seed derivation.
- Report insufficient evidence separately from an unsuccessful applicable test.

### Planner behavior

The planner explains why a method applies, what evidence it uses, estimated costs, resource limits and checkpoint support. Automatic mode prioritizes inexpensive applicable checks and then proposes bounded work. Expert overrides remain available and are validated. Do not automatically launch indefinite full-keyspace searches.

## 10. Engine interface

Each engine implements a versioned contract with:

- Stable ID, implementation version, checkpoint format version and backend identity.
- Supported algorithms, parameters and hardware requirements.
- Input validation and preflight resource estimation.
- Work allocation, cancellation polling and progress-event production.
- State serialization, recovery and compatibility validation.
- Candidate results plus the evidence necessary for independent verification.
- Explicit coverage semantics: deterministic ranges, independent attempts, table stages or probabilistic walks.

Use a typed Rust interface internally and versioned JSON messages plus artifact manifests for external processes. Avoid an in-process third-party binary plugin ABI initially. Execute external engines with argument arrays, never interpolated shell commands. Cap output size, track exit status, capture versions and checksums, and terminate the whole child process tree on cancellation where supported.

## 11. Multicore scheduling

- Detect usable logical CPUs and expose worker count directly.
- Default conservatively to available cores minus one, with a minimum of one; benchmark rather than promise linear scaling.
- Use a single global resource budget across jobs and external engines.
- Allocate bounded chunks dynamically to balance heterogeneous cores and varying method cost.
- Track worker leases, heartbeats and cancellation requests.
- Do not assign overlapping live deterministic ranges within one search plan.
- Allow replay of work that was computed but never durably acknowledged after a crash.
- Prefer moderate batch messages over per-candidate coordination.
- Bound the event queue and define backpressure behavior.
- Support time limits, candidate/attempt limits and memory limits at the job level.
- Separate worker-count limits from a true CPU utilization cap. Add duty-cycle or OS controls only if tested; do not label a worker cap as an exact CPU percentage.
- Reserve database and UI responsiveness under full computation load.

## 12. Durable storage design

Use SQLite with a single coordinator writer and concurrent read access where supported. For local storage, evaluate WAL with `synchronous=FULL`, bounded checkpointing and a pinned supported SQLite version. SQLite's own documentation identifies filesystem constraints and version-specific issues; validate the chosen version before release. Do not put a live WAL database on a network share.

### Logical entities

| Entity | Important fields |
|---|---|
| `targets` | key ID, normalized public data, algorithm, parameters |
| `certificates` | certificate fingerprint, target ID, issuer details, validity, provenance |
| `plans` | immutable method parameters, bounds, evidence references, config hash |
| `jobs` | plan ID, lifecycle, priority, resource budgets, timestamps |
| `work_units` | bounds/attempt descriptor, cursor, lease, durable completion state |
| `checkpoints` | engine and schema versions, manifest, generation, artifact references |
| `findings` | type, confidence, verification state, evidence and secret reference |
| `events` | ordered lifecycle/progress events with bounded retention |
| `engine_runs` | executable hash, backend version, host/device details |
| `schema_migrations` | migration versions and integrity metadata |

Store large counters and bounds losslessly as canonical strings or byte arrays. Never use SQLite's signed 64-bit integer field for a full P-521 candidate. Keep telemetry rates as approximate numbers separately from exact coverage.

## 13. Checkpoint and crash-recovery protocol

This is a release-critical feature.

1. Persist an immutable validated plan and normalized target identity before allocating work.
2. Acquire a coordinator lock for the state directory; refuse a conflicting writer.
3. Allocate a work unit transactionally, including bounds and lease generation.
4. A worker computes within that unit and sends periodic progress with a monotonic sequence number.
5. Commit its new cursor and completion state atomically; reject stale or out-of-order updates.
6. Acknowledge durable progress only after a successful commit.
7. On normal pause, stop allocation, request worker snapshots, commit them and mark paused.
8. On forced termination, resume from the latest committed state and reclaim abandoned work.
9. Verify checkpoint versions, target/config hashes, artifact checksums and cursor bounds before resuming.
10. Recompute unacknowledged work where necessary; never silently skip an uncommitted interval.

For sequential search, `next_candidate` means every earlier candidate inside that work unit is committed as tested. Out-of-order finished chunks are represented as a coverage union, not collapsed into an incorrect global last number.

For large engine artifacts, write a new generation to a temporary file, flush, atomically rename within the same filesystem, sync the directory where supported, and only then commit its reference. Retain the previous referenced generation until the new one is committed. Clean up orphaned generations on recovery. Database integrity and file checksums have different roles and do not replace each other.

Choose a default engine snapshot interval of approximately five seconds, adjustable by method and storage performance. This is a target for ordinary operation, not a guaranteed maximum replay window under stalled storage. Report the last durable checkpoint age.

Database backup uses SQLite's supported backup mechanism or a controlled quiescent snapshot; do not copy only the main file of an active WAL database. Recovery guarantees depend on operating-system/filesystem durability semantics and healthy storage. Treat detected corruption and disk-full failures as explicit errors.

## 14. Coverage reuse and multi-target behavior

- Equivalent public keys share key identity and target-level findings.
- Reuse deterministic coverage only when candidate interpretation, method parameters and target semantics match.
- Adding targets to an already completed multi-target scan does not mean those new targets were tested against historical candidates.
- A method's negative finding is scoped to its exact inputs and bounds; it cannot automatically satisfy another method.
- Reuse compatible precomputed curve tables by verified artifact identity.
- Permit sequential extension of a range without losing its prior durable coverage.
- Keep probabilistic effort metrics separate from deterministic interval coverage.

## 15. Job lifecycle and failure behavior

Lifecycle states: `queued`, `running`, `pausing`, `paused`, `verifying`, `completed`, `cancelled`, `failed`, `needs_attention`.

Result outcomes: `verified_recovery`, `range_exhausted`, `no_weakness_detected_by_checks`, `insufficient_evidence`, `unsupported`, `resource_limit_reached`, `interrupted`, `engine_failure`.

- Pause preserves intent to continue; cancel stops the job and retains prior coverage unless explicitly deleted.
- SIGINT requests a graceful stop. Document repeated-interrupt behavior.
- Worker failure preserves committed progress and can trigger a bounded retry.
- Missing adapters, incompatible state, exhausted disk, malformed artifacts and verification failure produce actionable errors.
- A candidate is not a verified recovery until independent verification succeeds.
- Verification failure preserves diagnostic evidence without exposing private values in normal logs.
- Shutdown joins or terminates managed workers and flushes accepted state.

## 16. Independent verification and private material

- Recompute an EC public point from each recovered candidate with an established verification backend.
- For RSA, verify factorization, key reconstruction, consistency with the target and a suitable round-trip signature/verification test.
- For signature-based findings, verify the recovered public key and relevant original signatures.
- Use independent implementation paths where practical; compare optimized paths against a reference backend.
- Normal reports disclose the finding and proof metadata, not recovered private values.
- Initially keep secret values in explicitly identified private state files with restrictive filesystem permissions. This is not encryption.
- Before general distribution, add a reviewed encrypted secret store or OS-backed key wrapping with an explicit unlock policy. Never invent cryptography for the vault.
- Private-key export is a separate explicit command, defaults to a new file, and fails rather than silently overwriting.
- Avoid secrets in command history, crash telemetry, filenames and ordinary debug logs.
- Document best-effort memory clearing and limits from external libraries, backups and OS behavior.

## 17. CLI design

The following is proposed syntax, not commands that already exist:

```text
cert-cracker doctor
cert-cracker capabilities --json
cert-cracker targets import ./certificates --recursive
cert-cracker targets inspect TARGET_ID
cert-cracker plan --target TARGET_ID --method ec-sequential --start 1 --end 1000001
cert-cracker run PLAN_ID --workers 8 --time-limit 30m
cert-cracker jobs list
cert-cracker jobs status JOB_ID --json
cert-cracker jobs pause JOB_ID
cert-cracker jobs resume JOB_ID --workers 4
cert-cracker jobs cancel JOB_ID
cert-cracker report JOB_ID --format json --output report.json
cert-cracker export-key FINDING_ID --output recovered-key.pem
cert-cracker bench --engine ENGINE_ID
cert-cracker lab generate --curve P-384 --scalar 4 --out ./lab
cert-cracker serve --listen 127.0.0.1
```

Document daemon versus foreground job behavior. The initial CLI can run a foreground coordinator and resume stopped jobs; live cross-process controls require an authenticated local control channel, introduced deliberately rather than implied by the first CLI.

All commands support consistent help, actionable exit codes and structured errors. JSON output goes to stdout; progress and diagnostics go to stderr. Validate intervals before creating jobs. Display bounds and explain the exclusive upper endpoint.

## 18. Dashboard design

Implement after the CLI and persistence contracts stabilize.

- Target inventory with algorithm, curve/key size, linked certificates and findings.
- Plan preview showing method, assumptions, resource estimate and expected coverage semantics.
- Job queue with priority, resource allocation, pause/resume/cancel and retry.
- Worker/device activity, measured rate, elapsed time, current stage and durable checkpoint age.
- Exact deterministic coverage visualization; probabilistic effort shown with appropriate labels.
- Findings with verification status and report/export actions.
- Capability view that distinguishes compiled, installed, available and validated backends.
- Accessible keyboard navigation, understandable error states and bounded event history.

Bind locally by default. Authenticate mutating local API requests and validate origins to prevent unrelated web pages from controlling jobs. Require explicit configuration for remote access. Keep computation and secrets out of the browser process. A dashboard does not introduce a cloud service dependency.

## 19. GPU and hardware roadmap

### CPU baseline

Support macOS ARM64 first for the current machine, then Linux x86-64 and Windows x86-64 through CI and real tests. Discover hardware at runtime; do not infer an available GPU backend from the operating system alone.

### Accelerated backends

- Evaluate existing CUDA implementations for their documented curves, operating systems and GPU architectures.
- Add an Apple Metal backend only after a prototype passes differential tests and demonstrates a benefit on actual supported hardware.
- Consider Vulkan/OpenCL portability only when a suitable validated implementation exists.
- Distinguish CPU-only, GPU-only and hybrid jobs in capabilities and reports.
- Account for GPU memory, transfers, kernel launch overhead, device loss and checkpoint staging.
- Checkpoint only acknowledged completed batches or resumable engine state.
- Define CPU/GPU fallback behavior explicitly and preserve target/range semantics.
- Maintain a hardware-tested support matrix; unsupported devices remain visible as unavailable.

No promise of a universal GPU backend or a particular speedup. GPU integration is released per engine and device family.

## 20. External engine evaluation

| Candidate | Potential use | Required evaluation |
|---|---|---|
| RsaCtfTool | Collection of RSA weakness methods | Method coverage, maintained dependencies, output parsing, timeouts, privacy of any external lookup |
| JeanLucPons/Kangaroo | secp256k1 interval recovery, CPU/CUDA and resumable state | Exact curve support, checkpoint compatibility, license and device requirements |
| Keyhunt / forks | Specialized secp256k1 search ideas | Verify real progress semantics, correctness, maintenance and license before adoption |
| Google Paranoid Crypto | Reference checks for known weaknesses | Archived project; review algorithms, dependencies, maintenance and scope individually |
| CADO-NFS / ECM engines | Advanced integer factorization | Appropriate input scale, resources, checkpoint formats, platform support and redistribution terms |

Do not enable every available third-party method indiscriminately. Some tools can make network lookups: disable those unless explicitly configured, and disclose any public data sent. Prefer managed subprocess boundaries for external executables. Review license compatibility before copying, linking or distributing upstream implementations; do not assume a process boundary resolves all licensing questions.

## 21. Distributed execution, later

- One coordinator owns the global work ledger; machines communicate through a versioned authenticated protocol.
- Lease work with unique IDs and generations; allow reissue after lease loss.
- Use at-least-once computation with idempotent result/progress handling. Do not promise exactly-once physical computation across failures.
- Verify all remote candidate results locally.
- Reconcile deterministic coverage with exact intervals; never trust an unverified scalar claim as proof of key recovery.
- Limit remote resource use and detect incompatible engine/checkpoint versions.
- Network partitions must not lose durable coordinator state.
- Do not share a SQLite WAL file across hosts; use the coordinator API.
- Treat authenticated workers as trusted for claims about completed negative work unless a separate verifiable-computation scheme is designed.

## 22. Testing strategy

### Mathematical correctness

- Known-answer tests for supported key types, curves and input encodings.
- Differential comparison between optimized workers and a reference backend.
- Small-scalar fixtures including 1, 4, chunk boundaries, end-minus-one, outside-range keys and near-order bounds.
- BSGS fixtures with non-square widths, collisions and point-at-infinity cases.
- RSA fixtures for shared primes, identical moduli, ambiguous full-modulus GCD, close primes, small private exponents, prime powers and unsupported multi-prime inputs.
- Signature fixtures with valid repeated-nonce cases, duplicate signatures, unrelated signers, invalid signatures and insufficient data.
- EdDSA fixtures generated from documented seed hypotheses.

### Scheduler and persistence

- Property tests: assigned intervals are valid; committed coverage never contains an untested gap; counters do not overflow.
- Compare single-worker and multi-worker results and coverage on deterministic fixtures.
- Deliberately reorder, duplicate, delay and drop progress messages.
- Test simultaneous coordinator startup and lock release after termination.
- Interrupt allocation, checkpoint updates, artifact renames, candidate discovery and final verification.
- Kill a child process after durable progress, resume it, and compare coverage against an uninterrupted reference run.
- Test changed worker count, target mismatch, modified configuration, corrupt artifacts, old schema, full disk and permission failures.
- Verify reports and normal logs contain no private material.

### End-to-end and platform checks

- Import -> inspect -> plan -> multicore run -> forced termination -> resume -> verified recovery -> report -> explicit key export.
- Platform CI for the actually supported compiler/backend combinations.
- Parser fuzzing, serialized-state fuzzing and bounded external-output parsing.
- GPU backend differential tests on real hardware; CPU tests cannot certify a GPU implementation.
- Sanitizer coverage for maintained native components where practical.

## 23. Benchmarking and performance acceptance

Record hardware, OS, compiler flags, engine revision, backend version, target curve/key size, search width, table sizes, worker count, warmup, repetitions and checkpoint settings.

Measure:

- Useful unique candidate throughput for sequential methods.
- Group operations and probabilistic method statistics separately from conceptual range coverage.
- Scaling at 1, 2, 4 and available higher worker counts.
- Memory per worker and per shared table.
- Startup time, precomputation time, checkpoint latency and resume latency.
- Useful throughput with checkpointing enabled versus disabled in controlled benchmarks.
- Cancellation responsiveness and replay work after forced termination.
- End-to-end duration, including table construction and transfers, for GPU comparisons.

Set performance thresholds from the first validated baseline. Do not copy upstream headline rates or compare different counting conventions as if they were equivalent. An optimization must retain correctness, memory limits and restart behavior. Use profiling to choose optimized arithmetic or adapters; language choice alone is not evidence of higher throughput.

## 24. Build, packaging and release

- Pin the tested Rust compiler and lock dependencies.
- Document C toolchain, OpenSSL, optional GMP and optional engine toolchain requirements.
- Choose vendored versus system crypto builds per release target and document the update process.
- Run formatting, linting, tests and selected regression benchmarks in CI.
- Check dependency advisories and license compatibility at release time.
- Produce per-platform archives with checksums, build metadata and third-party notices.
- Keep GPU engines optional and versioned; include exact installation and compatibility instructions.
- Avoid requiring a database server or cloud account for local operation.
- Include a migration/backup procedure and a recovery troubleshooting guide.
- Do not auto-update an active worker or silently migrate incompatible engine state.

## 25. Milestones and exit criteria

| Milestone | Deliverable | Exit criteria |
|---|---|---|
| M0: Specification and repository | This plan, architecture decisions, dependency feasibility checks | Scope and contracts documented; no claim of working engines |
| M1: Inspection foundation | Rust workspace, CLI, bounded imports, normalized target registry, capability reporting | Tested PEM/DER/bundle import, duplicate handling, explicit unknown algorithms |
| M2: Durable multicore EC baseline | P-256/P-384/P-521/secp256k1 sequential search, scheduler, SQLite ledger, pause/resume, verifier | Repeated forced-kill/resume tests recover weak fixture keys and preserve correct coverage |
| M3: RSA weakness suite | Applicable bounded methods, shared-prime analysis, verified reconstruction | Positive/negative fixtures, duplicate-modulus edge cases and resource limits pass |
| M4: Advanced search engines | BSGS and compatible kangaroo adapter, artifact manifests and preflight estimates | Validated checkpoint recovery, reference comparison, memory cap enforcement |
| M5: Signature/seed analysis | ECDSA/DSA dataset checks and explicit seed-hypothesis modules | Evidence requirements, signer association, false-positive tests and verification pass |
| M6: Local dashboard | Inventory, planner, queue, resource views, findings and reports | UI reflects authoritative durable state; local API controls tested |
| M7: Hardware acceleration | Individually validated GPU backends | Real-device correctness, recovery and end-to-end performance evidence |
| M8: Distributed workers | Authenticated coordinator/worker service | Lease recovery, duplicate handling, partition tests and local result verification pass |
| M9: General release hardening | Packaging, encrypted secret integration, migration docs and release automation | Platform test matrix, fault tests, dependency/license review and documented limits complete |

Milestones are ordered by dependencies, not fixed calendar promises. Each ships a usable increment. The initial useful release is M1–M3; full planned scope continues through M9. M4–M8 are not implied by a successful first build.

## 26. First implementation sequence

1. Establish the Rust workspace and dependency compatibility build in the requested folder.
2. Implement exact range types, target normalization and versioned result types.
3. Implement import/inspect/capabilities commands and fixture generation.
4. Implement schema migrations, coordinator locking, immutable plans and work-unit transactions.
5. Add a reference single-worker EC search and independent verification.
6. Add bounded multicore scheduling and progress events.
7. Add checkpoint snapshots, pause, forced-kill recovery and incompatible-state rejection.
8. Add reports and explicit secret export with private-file handling.
9. Add RSA checks and collection-level shared-factor analysis.
10. Benchmark, profile and strengthen native backends before expanding algorithms.
11. Expand through the remaining milestones and publish measured support/capability tables.

The first demonstration must use a deliberately weak lab certificate: start a multicore search, wait for durable progress, terminate it, resume with a different worker count, recover the key, independently verify the match, and show the exact searched coverage in a report.

## 27. Risks and decisions to revisit

| Risk / uncertainty | Response |
|---|---|
| Key recovery is infeasible for a particular target | Show assumptions and bounded coverage; report actual outcomes without a false secure badge |
| Breadth exceeds backend support | Publish per-engine capabilities and test each curve/type before enabling it |
| Checkpoint correctness differs by method | Separate engine state models and release gates |
| Existing engine is fast but unreliable or unmaintained | Keep it optional; verify independently; retain a correct reference path |
| Multi-core contention or large tables reduce scaling | Benchmark, share immutable data where suitable, enforce global budgets |
| GPU implementation does not benefit the actual machine | Retain CPU execution; release GPU support only with hardware evidence |
| Crash, full disk or corrupt state | Durable transactions, manifest generations, backups and explicit recovery errors |
| Dashboard work delays the essential engine | Stabilize the tested CLI and storage contracts first |
| Licensing constrains a preferred integration | Evaluate adapter/redistribution options and substitute compatible engines where needed |
| Secret persistence conflicts with convenience | Private-file prototype, explicit export, reviewed encryption before general distribution |
| Source folder is not a Git checkout | The inspected folder is empty and has no `.git`; create project files there, and initialize/version-control separately when appropriate |

Current defaults: local operation, Rust core, CPU-first execution, explicit bounded searches, exact work accounting, SQLite coordinator state, private-file secret handling for development, and optional adapters. Exact supported versions and measured budgets are finalized by compatibility and benchmark results.

## 28. Definition of complete

The full project is complete when the implemented capability matrix matches documented scope; each enabled engine has correctness and recovery evidence; supported platforms have reproducible packages; interfaces expose accurate coverage and result semantics; resource limits are enforced; private material has a documented storage/export lifecycle; and later-stage GPU/distributed features are explicitly either delivered or identified as deferred scope rather than silently represented as working.

The first release is complete only when M1–M3 acceptance criteria pass, including real forced-termination recovery tests. A compiling skeleton, an attractive dashboard, or a benchmark without durable resume does not meet that bar.

## 29. References informing the plan

These are references and integration candidates, not declarations that their functionality has already been incorporated.

- [OpenSSL Rust bindings and native build requirements](https://docs.rs/openssl/latest/openssl/)
- [OpenSSL EC interface and built-in groups](https://docs.rs/openssl/latest/openssl/ec/index.html)
- [x509-parser: parsing and verification capabilities](https://docs.rs/x509-parser/latest/x509_parser/)
- [Rayon: parallel computation and thread pools](https://docs.rs/rayon/latest/rayon/)
- [Rusqlite](https://docs.rs/rusqlite/latest/rusqlite/)
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
- [SQLite WAL behavior, filesystem constraints and version notes](https://www.sqlite.org/wal.html)
- [Rug / GMP-backed arithmetic](https://docs.rs/rug/latest/rug/)
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [JeanLucPons/Kangaroo: secp256k1, hardware and work-file semantics](https://github.com/JeanLucPons/Kangaroo)
- [CADO-NFS](https://cado-nfs.gitlabpages.inria.fr/)
- [Google Paranoid Crypto, archived reference implementation](https://github.com/google/paranoid_crypto)
- [Paranoid ECDSA signature-check assumptions](https://github.com/google/paranoid_crypto/blob/main/docs/ecdsa_signature_tests.md)
- [SEC 1: elliptic-curve key definitions](https://www.secg.org/sec1-v2.pdf)
- [RFC 8410: Ed25519, Ed448, X25519 and X448 in X.509](https://www.rfc-editor.org/info/rfc8410/)
- [RFC 9295: clarifications to those algorithm identifiers](https://www.rfc-editor.org/rfc/rfc9295.html)

## 30. Work completed before this plan

- Inspected the requested source folder: it was empty, with no repository instructions or Git metadata found there or in the inspected ancestors.
- Checked local tooling: Apple Clang and OpenSSL were available; Rust was initially absent.
- Installed an isolated Rust toolchain under the chat workspace's `work/toolchain` directory without modifying the global shell path.
- Wrote this specification. No application code, search engine, dashboard, or recovery test has been implemented yet.

Implementation stops at this plan until the user asks to proceed.
