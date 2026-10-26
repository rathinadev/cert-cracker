# Implementation status — 26 October 2026

Version: **0.2.0 CPU development preview**.

The CPU foundation from M1–M3 and the BSGS portion of M4 are working. The complete PLAN.md roadmap remains in progress. Interval kangaroo is still upcoming.

## Delivered

- Rust library and CLI, with native OpenSSL cryptographic operations and Rayon workers.
- Certificate/public-key inspection and import; bounded file/directory traversal; exact DER framing; partial-import errors preserve successful targets.
- Mathematical key identity normalization and certificate provenance.
- Exact arbitrary-size half-open search bounds; persisted immutable job specifications.
- Configurable multicore sequential EC search, chunk scheduling, progress backpressure and cooperative pause/time limits.
- Read-only estimates, automatic sequential/BSGS selection and explicit method selection.
- Memory-bounded BSGS with one shared immutable baby table, parallel giant searches and arbitrary-size interval offsets.
- Durable table-building manifests, synced artifact publication, integrity validation and resume through both precomputation and searching.
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
- `cargo test --locked`: **28 tests passed** (4 unit tests, 24 integration tests).
- Actual SIGKILL of a child search followed by resume with a different worker count: passed; final coverage was exactly the configured range.
- Actual SIGKILL during BSGS table construction and giant searching: passed, including changed worker counts and ready-table reuse.
- Differential sequential/BSGS results on four curves, infinity entries, partial final blocks, subgroup-boundary exclusions and large offsets: passed.
- Corrupt/missing tables, binding mismatches, uncommitted tails, cancellation during validation, memory limits and legacy specification/schema compatibility: tested.
- P-256, P-384, P-521 and secp256k1 weak-key recovery: passed.
- P-521 interval above 64-bit machine integer limits: passed.
- Recovery result saved before cursor advance: tested.
- Out-of-order chunks, stale generations and regressing cursors: tested.
- Partial final chunk pause is not incorrectly reported as exhaustion: tested.
- RSA shared-prime recovery, tiny RSA trial/Fermat reconstruction and Wiener factor detection: tested.
- Recovered P-384 lab private key's public value independently matched the certificate through the separate OpenSSL command-line executable.
- Dynamic-library inspection found no runtime `libssl` or `libcrypto` dependency in the release binary. System macOS libraries are still required.

The bundled SQLite version was upgraded after reviewing SQLite's documented WAL-reset fix; the application rejects SQLite older than 3.51.3 for its WAL-backed state implementation.

## Benchmark evidence

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

- Calibrated planner time estimates and interval kangaroo with its durable state.
- Batch-GCD trees and advanced RSA factorization adapters.
- Signature nonce analysis and explicit EdDSA seed hypotheses.
- GPU kernels and actual hardware validation.
- Dashboard and authenticated live-control service.
- Distributed workers and global resource budgets.
- Encrypted secret storage, supported backup CLI, deeper fuzz/fault testing and broader platform packaging.
- Unknown-algorithm metadata preservation beyond what the linked OpenSSL backend can parse.
- Cross-plan coverage reuse, shared multi-target EC scans and a richer job queue.

CI definitions for Linux, macOS and Windows are provided, but remote CI has not been run and those platforms are not all claimed validated.

## Current operational limits

Recovered private keys are stored in a database protected with private Unix permissions; **they are not encrypted at rest**. Export refuses overwrite. RSA audits are short bounded checks and rerun after interruption; resumable long-search support applies to sequential and BSGS EC searches. Only one coordinator mutates a state directory at a time. A killed invocation can leave the last lifecycle status `running` and its elapsed time can be undercounted; resume reclaims its committed work.

BSGS table construction is sequential; giant searching uses multiple cores. Its memory budget covers the table and reserved workspace, not total process RSS. Estimates use an operation-count heuristic and do not claim a calibrated wall-clock ETA. Schema 3 preserves old sequential specification hashes and migrates older databases transactionally; older executables cannot read schema 3. Back up the stopped database and referenced artifacts together. See `docs/BSGS.md` for the format and checkpoint contracts.

Full certificate-chain trust validation, browser trust changes and network collection are outside this release. Capability output explicitly distinguishes inspection from recovery and lists unavailable engines.
