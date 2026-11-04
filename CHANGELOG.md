# Changelog

## Unreleased fixes

- Open the copied SQLite backup with write access before syncing, as required by Windows.
- Bound transient lock-reopen retries in parallel vault integration tests.

## 0.12.0 — 4 November 2026

- Add opt-in bounded product/remainder-tree batch GCD for RSA shared-factor audits, including duplicate handling and a full-modulus GCD fallback.

## 0.11.0 — 4 November 2026

- Add atomic vault password rotation, with authenticated re-encryption of existing findings and rollback on damaged ciphertext.

## 0.10.0 — 4 November 2026

- Add an optional password-unlocked vault for new findings using scrypt and AES-256-GCM. Vault initialization refuses states with existing findings, and locked searches stop before progress.

## 0.9.0 — 4 November 2026

- Add stopped-state backup using SQLite backup, private artifact copies, BSGS manifest checksum validation, and an atomic completion marker.

## 0.8.0 — 4 November 2026

- Add an opt-in, bounded single-base Pollard p-1 stage-1 RSA check, independently verifying reconstructed keys and reporting its explicit bound.

## 0.7.0 — 4 November 2026

- Add bounded ECDSA repeated-nonce audit for verified signatures on explicitly supplied digests, including flipped-s signatures and independent key verification.

## 0.6.0 — 4 November 2026

- Store newly discovered kangaroo points incrementally in atomic SQLite checkpoints, with lazy conversion of schema-4 snapshots.
- Verify reconstructed full snapshots on read; retain old specifications, crash recovery and checksum detection.

## 0.5.0 — 4 November 2026

- Add optional local throughput calibration and advisory estimates for sequential, BSGS and independent/cooperative kangaroo budgets. Profiles validate their recorded environment and resources.
- Preserve the existing kangaroo planning capacity field alongside the more explicit per-kind field.

## 0.4.0 — 4 November 2026

- Add opt-in cooperative kangaroo attempts with a shared point-dependent walk and bounded cross-attempt collision index.
- Persist version-2 tame and wild point maps and reconstruct the collision index on resume; preserve version-1 independent jobs and their specification hashes.
- Check newly added collision points at each checkpoint instead of rescanning the entire shared index. SQLite snapshots still contain full point maps.
- Test both collision arrival orders, recovery from committed points after restart, four curves, resource limits and actual forced termination in both walk phases.

## 0.3.0 — 26 October 2026

- Add an experimental multi-curve interval kangaroo engine with bounded independent tame/wild attempts across CPU workers.
- Persist atomic, checksummed walk positions, distances, operation counters, distinguished maps and termination reasons. Preserve logical attempts when the worker count changes.
- Add explicit kangaroo planning and resource parameters. Automatic method selection remains sequential/BSGS.
- Report probabilistic budget exhaustion separately from exhaustive interval coverage. Kangaroo report format 3 uses null coverage fields and durable walk-step counts.
- Migrate state schema 1/2/3 to schema 4 while preserving earlier sequential/BSGS hashes and artifacts.
- Expand local validation to 40 tests, including forced process termination in both walk phases and exact resumed-state comparisons.
- Correct Windows strict-lint portability for artifact-directory creation and Unix-only test imports.

## 0.2.0 — 26 October 2026

- Initial published milestone: Rust CLI, local certificate/key inspection, multicore sequential EC search, bounded RSA checks, durable SQLite state, verified recovery/export and reports.
- Add automatic sequential/BSGS planning, bounded shared baby tables, durable artifact manifests and parallel giant-step search.
- Include locked dependencies, CI definitions, documentation and laboratory benchmarks.
