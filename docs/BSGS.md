# Interval BSGS implementation

Version 0.2.0 introduced the BSGS portion of milestone M4. Version 0.3.0 also provides a separate experimental native [kangaroo engine](KANGAROO.md).

## Mathematics

For target public key `Q = dG` and scalar interval `[a,b)`, set `W=b-a`. Store `jG` for `0 <= j < m`. For each giant index `i`, look up `Q-(a+im)G`. A matching baby index `j` gives candidate `a+im+j`. Reject candidates at or above `b`; independently multiply the candidate by `G` before accepting it. The coordinator verifies again through the existing recovered-key path before saving a finding.

This handles non-square interval widths, a partial final block, the infinity entry `j=0`, and arbitrary-size scalar offsets. The upper bound cannot exceed the subgroup order. The same engine is tested on P-256, P-384, P-521 and secp256k1.

## Memory and parallelism

The immutable table is a sorted vector, not one hash map per worker. It is allocated once and shared through an `Arc`. Each resident entry contains a 67-byte padded compressed-point key and a u64 index; its actual Rust size is included in preflight estimates (80 bytes on the tested ARM64 build). Point infinity is encoded as an all-zero key. Native OpenSSL contexts and mutable points are per worker.

The budget includes the table, a temporary one-bit-per-index validation map, 2 MiB of base workspace and 512 KiB of reserved workspace per worker. Native-library/allocator/runtime baseline RSS is additional; the application does not claim a hard process memory cap. Reservations use fallible allocation. Changing worker count is checked against the immutable job budget before resuming.

The planner initially seeks `ceil(sqrt(W))` entries, then reduces the table if necessary to fit the budget. It can use an explicit table size. Smaller `m` increases `ceil(W/m)` giant lookups. Automatic selection compares operation counts with a conservative setup/serialization factor and avoids BSGS for tiny intervals. No uncalibrated wall-clock ETA is displayed.

Table construction is sequential in this release; giant searches are parallel. Giant work chunks are capped to expose several units per worker. Chunking becomes part of the immutable plan; operational worker count may change on resume. The ready vector is never cloned for each worker.

## Artifact format and binding

Each artifact is bound to the complete immutable specification hash and actual target identity through a versioned header. The header contains format version, specification hash, curve name, compressed-point length and baby-step count.

The binary layout is:

1. Eight-byte magic `CCBSGS01`.
2. Little-endian u32 JSON-header length, limited to 4096 bytes.
3. Header JSON.
4. Fixed 75-byte records: padded 67-byte point key and little-endian u64 baby index.

The database manifest records version, specification hash, stage, artifact basename, committed entry count, committed byte length and SHA-256. Artifact paths are confined to the state directory and symlink artifacts are rejected.

## Table-building checkpoints

The `.baby` building ledger stores records in increasing baby-index order. The writer flushes and syncs the file before committing the corresponding count, byte boundary and prefix checksum in SQLite. The ledger prefix and manifest therefore advance in that order.

On resume, the reader validates header binding, record bounds, ordered indices and the entire committed-prefix checksum. Only after validation can an uncommitted tail be truncated. An interrupted append can replay; it cannot advance durable coverage. The next point is reconstructed directly from the saved baby index rather than recomputing all earlier curve points.

Cancellation is checked during record validation, construction and ready-file serialization. Sorting is in place and is not interruptible inside the standard-library sort call. Time limits are cooperative rather than hard real-time guarantees.

## Ready-table transition

The complete vector is sorted in place. A new ready artifact is written, synced, and published under a unique name; its directory is synced on Unix. Only then is the ready manifest committed in SQLite. The old building ledger is removed only after that commit. A failure before the new manifest is committed leaves the original ledger authoritative; orphan files may remain and can be reviewed after stopping the coordinator.

When loading a ready table, verify exact file size, full checksum, header binding, strictly ordered point keys, index bounds, and a complete permutation of indices. Refuse missing or corrupt artifacts rather than silently restarting a search whose negative coverage depended on that table. Resumes load this table without regenerating its curve points or sorting it again.

Peak artifact storage temporarily includes both the building ledger and ready file, approximately `150*m` bytes plus headers. A free-space check also reserves an 8 MiB database margin. Concurrent disk consumption can still cause a later I/O failure; the checkpoint ordering preserves the previously committed state.

## Giant-step checkpoints and reports

Work-unit bounds and cursors are giant indices, not private-scalar counters. A committed span `[i0,i1)` maps to scalar coverage `[a+i0*m,min(b,a+i1*m))`. Out-of-order completed chunks remain separate until their intervals join. A found candidate is verified and durably saved before advancing its corresponding work cursor.

`covered_candidates` is the exact union of the scalar intervals covered by completed lookups. `giant_steps_completed` counts those lookups. `tested_candidates` is null for BSGS because the engine did not test every covered scalar by brute force. For sequential jobs, `tested_candidates` remains available. Report format is version 2.

## Compatibility

Schema 3 introduced the separate `engine_states` table. Version 0.3.0 upgrades to schema 4 for kangaroo state; this preserves BSGS manifests and artifacts. Sequential specifications omit optional engine configurations when serialized, preserving version-0.1 specification hashes; BSGS specifications omit the new kangaroo field and retain their hashes. Older schemas migrate transactionally, and earlier work can resume. Earlier executables intentionally refuse newer schemas.

BSGS manifests and files are format version 1. A mismatch in job hash, format, metadata, byte count or checksum is rejected. Copies of a checkpoint must preserve the database and all referenced artifact files together, with SQLite handled through its supported backup mechanism or after a clean stop.

## Evidence

- 28 total automated tests pass, including forced termination during both table construction and giant searching, followed by different worker counts on resume.
- Differential results agree with the sequential engine on four curves, including keys outside the interval, non-square widths, infinity matches and subgroup-boundary wrap cases.
- Recovered P-384 key at laboratory scalar 98,765,432 independently matched its certificate through the separate OpenSSL CLI.
- Three local end-to-end P-256 comparisons covered `[1,100000001)` with a target outside the interval: sequential median 10.8010 seconds; BSGS median 0.10964 seconds, about 98.5x faster on this machine with four workers. BSGS built 10,000 entries and performed 10,000 giant lookups. This is a bounded laboratory comparison, not a claim about practical recovery of random modern keys.
- Raw comparison data is in `bsgs-benchmark-local.json`; earlier sequential-worker scaling evidence remains in `benchmark-local.json`.
