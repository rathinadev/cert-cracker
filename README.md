# cert-cracker

A local Rust CLI for public-key inspection and bounded weak-key recovery, with native OpenSSL mathematics, multicore ECC workers, and durable SQLite checkpoints.

Version **0.3.0** adds experimental, resumable interval kangaroo to the sequential/BSGS CPU engines in [PLAN.md](PLAN.md). It is a development preview, not the complete roadmap or a claim that modern cryptography can generally be cracked.

## Implemented

- Import PEM/DER certificates, bundles, SPKI public keys, and PKCS#1 RSA public keys.
- Inspect subject keys separately from certificate issuer signature algorithms.
- Normalize supported key identities and deduplicate certificates using the same public key.
- Search explicit EC scalar ranges with native point addition and configurable CPU workers.
- Select sequential search or interval BSGS automatically, or choose the method explicitly.
- Share one BSGS baby-step table across giant-step workers; enforce a table/workspace budget and check artifact disk requirements.
- Resume table construction from a durable append-only ledger and giant searches from committed work-unit cursors. Validate ready-table bindings, checksums, record order and index uniqueness on resume.
- Test coverage includes P-256, P-384, P-521 and secp256k1, and bounds above 64 bits.
- Save exact per-work-unit next-candidate cursors in SQLite transactions; resume after Ctrl+C, time limits, restart or forced termination.
- Resume with a different worker count. Out-of-order completed chunks retain their exact coverage.
- Run independent bounded kangaroo attempts across CPU workers, with saved walk positions, distances, seeds, operation counts and distinguished points. Probabilistic attempts never claim exhaustive coverage.
- Independently recompute a matched EC public key before persisting a verified finding.
- Run bounded RSA shared-prime, Wiener, trial-division and Fermat checks. Reconstruct and verify supported semiprime private keys, including a signature round trip.
- Persist RSA audit history, including completed negative checks and their budgets.
- Export reports without private material. Export recovered private keys only through a separate explicit command to a new file.
- Benchmark the actual scheduler with SQLite checkpointing enabled.

## Build

Install Rust through the official toolchain installer and a working C compiler. The repository pins the tested Rust toolchain in `rust-toolchain.toml` and dependencies in `Cargo.lock`.

For a macOS Homebrew OpenSSL installation:

```sh
OPENSSL_DIR="$(brew --prefix openssl@3)" cargo build --release --locked
./target/release/cert-cracker doctor
mkdir -p dist
cp target/release/cert-cracker dist/cert-cracker
```

OpenSSL headers and libraries are required. On Linux, install your distribution's OpenSSL development package and `pkg-config`; on Windows, configure a supported OpenSSL toolchain. SQLite is built from its bundled source. Only macOS ARM64 has been exercised locally so far; CI defines additional platform checks but their results must be observed before claiming those platforms validated.

The examples below use `dist/cert-cracker`, created by the copy step above. A locally tested macOS ARM64 binary is installed there in the development checkout. Build artifacts are excluded from Git:

```sh
./dist/cert-cracker --help
```

## Quick laboratory demonstration

Run from this project folder. Each `lab --out` directory must be new.

```sh
./dist/cert-cracker lab --curve P-384 --scalar 4 --out ./lab
./dist/cert-cracker inspect ./lab/certificate.pem
./dist/cert-cracker --state ./.cert-cracker search \
  --input ./lab/certificate.pem --start 1 --end 256 --workers 4
./dist/cert-cracker --state ./.cert-cracker findings
./dist/cert-cracker --state ./.cert-cracker jobs list
```

Bounds are half-open: `--start 1 --end 256` tests 1 through 255. Accepts exact decimal or `0x` hexadecimal numbers. The search must stay inside the group's valid scalar domain. Generated lab certificates are self-signed, deliberately weak, and valid for seven days; the tool does not install them into a trust store.

Use the `finding_id` returned by the search to export a recovered key:

```sh
./dist/cert-cracker export-key 1 --output ./recovered.private.pem
```

The export refuses to overwrite an existing file. Unix private files use mode `0600`.

## Stop and resume

For a deliberately weak lab key at a higher scalar:

```sh
./dist/cert-cracker lab --curve P-256 --scalar 9000000 --out ./lab-long
./dist/cert-cracker --state ./state-long search \
  --input ./lab-long/certificate.pem --end 10000000 --method sequential \
  --workers 4 --chunk-size 16384 --checkpoint-interval-ms 1000 \
  --time-limit-secs 2
./dist/cert-cracker --state ./state-long jobs status 1
./dist/cert-cracker --state ./state-long resume 1 --workers 2
```

Ctrl+C requests a graceful pause. Forced termination can replay an uncommitted tail; it does not deliberately restart committed ranges. A persisted `running` status after a crash is the last recorded lifecycle, not evidence that a coordinator is still alive. `resume` reacquires the coordinator lock and reclaims abandoned work.

One coordinator can mutate a state directory at a time. Separate state directories support independent coordinators. Read-only status and report commands can run during a search. CPU workers share a native Rayon pool; `--workers` limits thread count, not an exact CPU utilization percentage.

## Separate import, planning and execution

```sh
./dist/cert-cracker targets import ./certificates --recursive
./dist/cert-cracker targets list
./dist/cert-cracker targets inspect TARGET_ID
./dist/cert-cracker plan --target TARGET_ID --start 1 --end 1000000
./dist/cert-cracker run JOB_ID --workers 4
```

Planning the identical immutable specification reuses the same job. Worker count is operational and can change on resume. Changing bounds or chunk size creates a different specification. Cross-plan interval reuse and a daemon-controlled live job queue are not implemented in this release.

## BSGS and method selection

```sh
./dist/cert-cracker estimate --input ./lab/certificate.pem \
  --start 1 --end 100000001 --method auto --memory-mib 32 --workers 4
./dist/cert-cracker --state ./state-bsgs search \
  --input ./lab/certificate.pem --start 1 --end 100000001 \
  --method bsgs --memory-mib 32 --workers 4
./dist/cert-cracker --state ./state-bsgs resume 1 --workers 2
```

`estimate` creates no persistent state. `search` and `plan` now default to `--method auto`; choose `--method sequential` to retain the earlier CLI's explicit scalar-by-scalar behavior. Existing sequential job specifications and hashes remain compatible.

BSGS tests blocks algebraically using a baby-step table and giant-step lookups. It is enabled on P-256, P-384, P-521 and secp256k1. `--baby-steps N` chooses a smaller or larger table within the configured budget; otherwise the planner selects a square-root-sized table or the largest fitting alternative. A smaller table trades memory for more giant steps.

`--memory-mib` budgets the resident table, index-validation bitmap and reserved worker buffers. It is **not a total process RSS cap**: runtime, allocator and native-library baseline allocations are additional. Raising the worker count on resume can exceed the existing job budget and is rejected before running; reduce workers or create a new plan with a larger budget. The planner reports memory and peak artifact-space estimates. Actual free space is checked before continuing table construction.

The planner uses an operation-cost heuristic, not a calibrated time forecast. BSGS work chunks may be smaller than `--chunk-size` to expose enough parallel work. Planning with different parameters can therefore produce a different immutable job; use `resume JOB_ID` to continue an existing one.

The baby table is built once by the coordinator; giant-step workers share the immutable ready table without cloning it. Building a table is currently sequential. Table reuse applies to the same job, not to unrelated targets or plans. [BSGS.md](docs/BSGS.md) documents the artifact and coverage contracts.

## Experimental interval kangaroo

```sh
./dist/cert-cracker lab --curve P-384 --scalar 98765432 --out ./lab-kangaroo
./dist/cert-cracker estimate --input ./lab-kangaroo/certificate.pem \
  --end 100000001 --method kangaroo --memory-mib 32 --workers 4
./dist/cert-cracker --state ./state-kangaroo search \
  --input ./lab-kangaroo/certificate.pem --end 100000001 \
  --method kangaroo --memory-mib 32 --workers 4 --kangaroo-attempts 8
./dist/cert-cracker --state ./state-kangaroo resume 1 --workers 2
```

`auto` continues to select sequential or BSGS. Kangaroo requires an explicit `--method kangaroo`. Its fixed logical attempts (default 16) run independently; this is a CPU reference engine, not a cooperative or GPU herd. It supports the same four tested curves as BSGS, including large scalar offsets.

Each attempt builds a bounded tame distinguished-point map, then follows a wild walk looking for a collision. `--kangaroo-steps` limits point additions per phase; the default is `8*ceil(sqrt(interval_width))`, capped at `u64::MAX/4`. `--kangaroo-dp-bits` sets the predicate rarity; `--kangaroo-max-points` caps the saved tame map. When the map fills, the attempt switches to wild searching with the committed points and reports saturation. These settings affect the chance of finding a key; budget exhaustion does not prove the interval empty.

Checkpoints atomically save the entire map and walk state in SQLite with a specification binding, checksum and work generation. Resume preserves the same seed, partition, phase, counters and next point while allowing a different worker count within the saved memory budget. The default seed is 32 zero bytes for reproducibility; use `--kangaroo-seed` with 64 lowercase hex characters to create a different immutable search. Increasing attempt/step budgets or changing the seed creates a new job.

The memory budget reserves active maps and checkpoint copies; native/runtime baseline RSS and SQLite cache are additional. Checkpoints serialize each active map, so a large map or very short interval can make checkpoint I/O expensive. See [KANGAROO.md](docs/KANGAROO.md) for the mathematics, storage contract and limits.

## RSA analysis

```sh
./dist/cert-cracker audit first.pem second.pem --trial-limit 10000 --fermat-steps 1000
./dist/cert-cracker audits
./dist/cert-cracker findings
```

With no file arguments, `audit` uses imported targets. Shared-prime analysis is a bounded reference pairwise implementation, limited to 4096 unique targets. Trial and Fermat budgets are each capped at one million. Identical moduli are not incorrectly treated as recovered factors. Full-modulus GCD and unsupported reconstruction cases remain explicit.

RSA audits are finite checks that rerun if interrupted. Durable long-search resume currently applies to the EC engines. RSA-PSS parameter restrictions are inspected, but RSA-PSS private-key reconstruction is not enabled by this audit engine. Multi-prime reconstruction and advanced factorization engines remain future work.

## Reports and benchmarks

```sh
./dist/cert-cracker report JOB_ID --output ./report.json
./dist/cert-cracker bench --curve P-256 --candidates 100000 --workers 1,2,4 --method sequential
./dist/cert-cracker bench --curve P-256 --candidates 100000 --workers 1,2,4 --method bsgs
./dist/cert-cracker bench --curve P-256 --candidates 100000 --workers 1,2,4 --method kangaroo --kangaroo-attempts 4
./dist/cert-cracker capabilities
```

JSON goes to stdout; progress and errors go to stderr. Errors exit with status 2. Report bounds and coverage are exact strings, and completed coverage is merged without filling gaps. Timing currently sums completed invocations; a killed invocation may be undercounted. The built-in benchmark reports single local measurements with metadata, not statistically rigorous cross-machine claims.

Report format version 2 adds `covered_candidates`. For BSGS, `tested_candidates` is null and `giant_steps_completed` records actual completed lookups. Algebraic coverage must not be advertised as brute-force attempt throughput. Sequential reports retain their original `tested_candidates` field.

Kangaroo reports use format 3: `coverage`, `covered_candidates` and `tested_candidates` are null. `walk_steps_completed` counts durable point additions, and `attempts_completed` counts completed attempts. `probabilistic_budget_exhausted` means the chosen walk budget ended without recovery; a key may still be inside the interval. No exhaustive completion percentage or numeric success probability is claimed.

`range_exhausted` means that the configured interval was tested without recovery. `no_weakness_detected_by_completed_checks` applies only to the recorded checks and budgets. Neither is a general security certificate.

## Storage and privacy

Each state directory contains `state.sqlite`, SQLite journal sidecars when active, and an advisory coordinator lock file. Use local storage, not a network-shared live WAL database. Keep journal sidecars with the active database; use a supported SQLite backup process rather than copying only the main file during a run.

BSGS also requires the referenced files in `artifacts/`. Preserve them with the database when backing up or moving a stopped state directory. New artifact generations are synced before their manifests are committed; an uncommitted build tail can replay after a crash. A missing or corrupt committed table is an error and never silently resets existing search coverage.

The writer upgrades schemas 1/2/3 to schema 4 transactionally. Earlier executables cannot open an upgraded database. Keep a quiescent backup before using the new version with important existing state. Existing sequential and BSGS specifications retain their hashes; migration preserves their completed work and artifacts. Kangaroo maps and walk positions are stored together inside the database.

The database includes recovered private material and uses private Unix file permissions. **It is not encrypted at rest.** Normal reports and diagnostic output omit private keys. Development preview secret storage, Windows ACL behavior, encrypted key wrapping and a complete backup CLI need further hardening before general distribution.

The application operates on local inputs. It does not upload keys, install certificates, change browser trust, or invoke third-party recovery services.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Tests cover weak-key recovery on four curves, large P-521 bounds, duplicate target normalization, stale/regressing cursors, exact gap-aware coverage, paused final chunks, corrupt specification hashes, private-file exports, RSA recovery, and an actual child process terminated with SIGKILL and resumed with a different worker count.

The expanded suite has **40 tests**, including differential results on four curves, infinity and subgroup boundaries, bounded probabilistic failures, table saturation, resource limits, checkpoint corruption, torn tails, cancellation, schema migrations, and actual SIGKILL recovery during BSGS building/searching and kangaroo tame/wild walks. An outside-range kangaroo test also checks that changing worker count after a pause produces exactly the same final logical walk states.

## Not yet implemented

Cooperative kangaroo herds and external adapters, GPU kernels, signature nonce analysis, EdDSA seed recovery, batch-GCD trees, ECM/NFS adapters, a dashboard, distributed workers, encrypted secret storage, and full certificate-chain trust validation are not included. Inspection support for a key family does not imply a recovery engine for it. Use `capabilities` for the current executable's declared scope.

The full roadmap and milestone acceptance criteria remain in [PLAN.md](PLAN.md).
