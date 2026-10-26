# Changelog

## 0.3.0 — 26 October 2026

- Add an experimental multi-curve interval kangaroo engine with bounded independent tame/wild attempts across CPU workers.
- Persist atomic, checksummed walk positions, distances, operation counters, distinguished maps and termination reasons. Preserve logical attempts when the worker count changes.
- Add explicit kangaroo planning and resource parameters. Automatic method selection remains sequential/BSGS.
- Report probabilistic budget exhaustion separately from exhaustive interval coverage. Kangaroo report format 3 uses null coverage fields and durable walk-step counts.
- Migrate state schema 1/2/3 to schema 4 while preserving earlier sequential/BSGS hashes and artifacts.
- Expand local validation to 40 tests, including forced process termination in both walk phases and exact resumed-state comparisons.

## 0.2.0 — 26 October 2026

- Initial published milestone: Rust CLI, local certificate/key inspection, multicore sequential EC search, bounded RSA checks, durable SQLite state, verified recovery/export and reports.
- Add automatic sequential/BSGS planning, bounded shared baby tables, durable artifact manifests and parallel giant-step search.
- Include locked dependencies, CI definitions, documentation and laboratory benchmarks.
