# Implementation status — 26 October 2026

Version: **0.3.0 CPU development preview**.

The CPU foundation from M1–M3, BSGS and an experimental native interval-kangaroo engine are working. The complete PLAN.md roadmap remains in progress. Cooperative kangaroo herds, compatible external adapters and calibrated estimates remain additional M4 work.

## Delivered

- Rust library and CLI, with native OpenSSL cryptographic operations and Rayon workers.
- Certificate/public-key inspection and import; bounded file/directory traversal; exact DER framing; partial-import errors preserve successful targets.
- Mathematical key identity normalization and certificate provenance.
- Exact arbitrary-size half-open search bounds; persisted immutable job specifications.
- Configurable multicore sequential EC search, chunk scheduling, progress backpressure and cooperative pause/time limits.
- Read-only estimates, automatic sequential/BSGS selection and explicit method selection.
- Memory-bounded BSGS with one shared immutable baby table, parallel giant searches and arbitrary-size interval offsets.
- Durable table-building manifests, synced artifact publication, integrity validation and resume through both precomputation and searching.
- Explicit kangaroo planning, bounded independent CPU attempts, distinguished-point capacities and checksummed atomic walk checkpoints.
- Stable logical attempt identities across worker-count changes; probabilistic budget outcomes without exhaustive coverage claims.
- SQLite 3.54.1 with synchronous FULL transactions, schema migration, coordinator locking and per-work-unit generation/cursor validation.
- Crash recovery, changed worker count on resume, exact gap-aware coverage and duplicate-plan reuse.
- Independent EC candidate recomputation before durable discovery storage.
- Bounded RSA shared-prime, Wiener, trial and Fermat checks, private reconstruction and modular/signature verification as applicable.
- Persisted audit history, public reports, verified private-key export to a new file.
- Laboratory fixture generation, runtime capability reporting and an end-to-end benchmark command.
- Locked dependencies, pinned compiler, formatting/lint checks, automated tests and a CI workflow definition.
- An optimized macOS ARM64 executable in `dist/cert-cracker`, with OpenSSL statically linked. SQLite is bundled.

## Verified locally

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `cargo test --locked`: **40 tests passed** (4 unit tests, 36 integration tests).
- Actual SIGKILL of a child search followed by resume with a different worker count: passed; final coverage was exactly the configured range.
- Actual SIGKILL during BSGS table construction and giant searching: passed, including changed worker counts and ready-table reuse.
- Differential sequential/BSGS results on four curves, infinity entries, partial final blocks, subgroup-boundary exclusions and large offsets: passed.
- Corrupt/missing tables, binding mismatches, uncommitted tails, cancellation during validation, memory limits and legacy specification/schema compatibility: tested.
- Kangaroo differential recovery, deliberately insufficient budgets, saturated point tables, stale generations, phase regression and missing/corrupt/rebound snapshots: passed.
- Actual SIGKILL during both tame and wild phases followed by changed worker counts: passed.
- Uninterrupted versus paused/resumed outside-range searches produced exactly equal final logical kangaroo snapshots.
- Schema-3 BSGS artifact/hash preservation and resume after schema-4 migration: passed.
- P-256, P-384, P-521 and secp256k1 weak-key recovery: passed.
- P-521 interval above 64-bit machine integer limits: passed.
- Recovery result saved before cursor advance: tested.
- Out-of-order chunks, stale generations and regressing cursors: tested.
- Partial final chunk pause is not incorrectly reported as exhaustion: tested.
- RSA shared-prime recovery, tiny RSA trial/Fermat reconstruction and Wiener factor detection: tested.
- Recovered laboratory keys independently matched their certificates through the separate OpenSSL command-line executable on all four kangaroo curves, including a P-384 scalar 98,765,432 in a 100-million-scalar interval.
- Dynamic-library inspection found no runtime `libssl` or `libcrypto` dependency in the release binary. System macOS libraries are still required.

The bundled SQLite version was upgraded after reviewing SQLite's documented WAL-reset fix; the application rejects SQLite older than 3.51.3 for its WAL-backed state implementation.

## Benchmark evidence

Version 0.3 kangaroo: three repetitions per worker setting on P-256, interval `[1,1000001)`, target outside the interval, eight fixed logical attempts, 128 tame points per attempt and a 32 MiB engine budget. Median end-to-end time was **0.7141 seconds with one worker** and **0.1982 seconds with four workers**, about **3.60x** local scaling. This measures the same bounded walk work, not exhaustive scalar coverage. Raw data and independent four-curve recovery timings are in `docs/kangaroo-benchmark-local.json`.

Version 0.2: three end-to-end P-256 repetitions per method, four workers, interval `[1,100000001)` and target outside the interval. Measurements include process startup, planning, import, SQLite and fresh BSGS table construction.

| Method | Median seconds | Scalar interval covered |
|---|---:|---:|
| Sequential | 10.8010 | 100,000,000 |
| BSGS | 0.10964 | 100,000,000 |

This is about 98.5x faster locally. BSGS built 10,000 baby entries and completed 10,000 giant lookups; algebraic coverage is not brute-force attempt throughput. Raw data is in `docs/bsgs-benchmark-local.json`.

Earlier version-0.1 sequential scaling baseline: three repetitions per worker setting, five million P-256 candidates per repetition, 16,384-candidate work units, progress interval one second, and SQLite FULL checkpoint transactions at work-unit completion:

| CPU workers | Median unique candidates / second |
|---|---:|
| 1 | 3,041,045 |
| 2 | 5,790,347 |
| 4 | 11,294,559 |
| 8 | 13,526,809 |

Machine: macOS ARM64, 10 logical CPUs. OpenSSL 3.6.4; SQLite 3.54.1; optimized Rust release build. These are local measurements for one method and curve, not projections for other keys, algorithms or hardware. Raw measurements are in `docs/benchmark-local.json`.

## Remaining roadmap

- Calibrated planner time estimates, cooperative kangaroo herds and compatible external-engine adapters.
- Batch-GCD trees and advanced RSA factorization adapters.
- Signature nonce analysis and explicit EdDSA seed hypotheses.
- GPU kernels and actual hardware validation.
- Dashboard and authenticated live-control service.
- Distributed workers and global resource budgets.
- Encrypted secret storage, supported backup CLI, deeper fuzz/fault testing and broader platform packaging.
- Unknown-algorithm metadata preservation beyond what the linked OpenSSL backend can parse.
- Cross-plan coverage reuse, shared multi-target EC scans and a richer job queue.

CI definitions for Linux, macOS and Windows are provided. GitHub's initial version-0.2 run passed on Linux and macOS. Windows exposed a platform-specific strict-lint failure in directory creation; it and Unix-only test imports have been corrected. Version-0.3 remote results are pending; successful Windows validation is not yet claimed.

## Current operational limits

Recovered private keys are stored in a database protected with private Unix permissions; **they are not encrypted at rest**. Export refuses overwrite. RSA audits are short bounded checks and rerun after interruption; resumable long-search support applies to sequential, BSGS and kangaroo EC searches. Only one coordinator mutates a state directory at a time. A killed invocation can leave the last lifecycle status `running` and its elapsed time can be undercounted; resume reclaims its committed work.

BSGS table construction is sequential; giant searching uses multiple cores. Its memory budget covers the table and reserved workspace, not total process RSS. Kangaroo executes independent tame/wild pairs, with strict point capacities and full-map checkpoint writes; it does not implement cooperative collision sharing. Its budget exhaustion cannot exclude an in-range key. Native/runtime baseline RSS and SQLite cache are additional to the reserved kangaroo working set. Estimates do not claim calibrated wall-clock ETA or numeric kangaroo success probability.

Schema 4 preserves old sequential/BSGS specification hashes and migrates older databases transactionally; older executables cannot read schema 4. Back up the stopped database and referenced artifacts together. See `docs/BSGS.md` and `docs/KANGAROO.md` for the format and checkpoint contracts.

Full certificate-chain trust validation, browser trust changes and network collection are outside this release. Capability output explicitly distinguishes inspection from recovery and lists unavailable engines.
