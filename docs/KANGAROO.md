# Bounded interval kangaroo

Version 0.3.0 introduced an experimental native CPU Pollard lambda engine for P-256, P-384, P-521 and secp256k1. Version 0.4.0 adds an opt-in cooperative mode. Both use the existing OpenSSL point arithmetic and are selected explicitly; automatic planning remains sequential/BSGS. The sections below describe independent mode unless they say otherwise.

## Cooperative mode

Pass `--method kangaroo --kangaroo-cooperative` to enable version-2 state. All logical attempts use the same seeded, point-dependent jump function and distinguished-point predicate. Attempt `i` starts its tame and wild walkers with offset `i * max(1, floor(sqrt(b-a)/2))`, making their starting points deterministic across worker-count changes.

An attempt saves bounded distinguished-point maps for both tame and wild walkers. At a checkpoint, the coordinator compares newly added points against points already committed by other attempts. For a tame point from attempt `t` and a matching wild point from attempt `w`, the candidate is `(b-1 + offset_t + dt - offset_w - dw) mod n`. It must be inside the requested interval and pass independent key verification before it is persisted.

The coordinator publishes new points to its in-memory index only after the snapshot transaction commits. Workers send only new point entries for collision checking; previously committed points are not rescanned at every checkpoint. Since version 0.6, SQLite writes newly added point rows and the compact walk state atomically; it reconstructs and hashes the full snapshot when validating reads and updates. If the process stops, the index is reconstructed from checksummed committed snapshots before workers resume, and any previously committed cross-attempt match is checked again. A forced termination can replay uncommitted work.

Tame and wild maps each have the configured capacity per attempt. A full tame map starts that attempt's wild walk; a full wild map stops accepting new shared wild points while the walk continues. Both saturation cases appear in reports and can reduce the chance of recovery. Cooperative attempts stop at the configured per-phase addition budget; they do not use independent mode's early wild-distance bound. Different checkpoint arrival orders may change which attempt finds a match first.

The shared map can detect cross-attempt collisions regardless of which point was committed first, but the implementation does not claim a guaranteed speedup or a quantified success probability. In particular, short budgets, sparse distinguished points, coalescing walks and saturated tables can reduce its benefit. The version-1 independent mode remains the default for existing and new kangaroo jobs unless the flag is specified.

Three local repetitions per mode at P-256 `[1,1000001)`, an outside-range target, eight attempts and 128 points per kind per attempt produced median cooperative times of 0.730 seconds with one worker and 0.219 seconds with four workers. Independent mode measured 0.736 and 0.219 seconds respectively. Each run completed 128,000 point additions; this is a fixed-budget throughput comparison, not evidence of equal recovery probability. Raw measurements and independent OpenSSL verification on all four curves are in `cooperative-benchmark-local.json`.

## Algorithm

For `Q=dG` and half-open hypothesis `[a,b)`, an attempt starts a tame walk at `(b-1)G` and a wild walk at `Q`. Both use the same point-dependent jump function. A tame collision point at distance `dt` and a wild point at distance `dw` imply

`d = (b-1 + dt - dw) mod n`, where `n` is the subgroup order.

The candidate must lie in `[a,b)` and pass an independent full scalar multiplication, private-key construction and target-identity verification. The coordinator verifies again before persisting a recovery.

The jump set is `1,2,4,...,2^(k-1)`. Its size is the smallest positive `k` with `(2^k-1)/k >= max(1,floor(sqrt(b-a)/2))`. Including 1 avoids a shared jump divisor. The SHA-256 input is the immutable seed, logical attempt index, version-domain string and full compressed point. The first eight digest bytes select the jump modulo `k`; separate digest bytes select distinguished points. The point at infinity uses OpenSSL's canonical one-byte encoding. Jump choice does not depend on a CPU thread number.

Store the initial tame point, hash-distinguished tame points and the final tame endpoint, subject to the strict point capacity. When adding a new point would exceed the cap, stop precomputation and start wild searching with the existing map, recording saturation. The wild walk checks its current point before advancing. It stops on a verified match, its per-phase addition budget, or a distance greater than `(b-a-1)+dt_final`. Points and distances can cross the subgroup boundary; modular candidate reconstruction and interval checks reject outside-range results.

The step budget defaults to `8*ceil(sqrt(b-a))`, capped at `u64::MAX/4` additions per phase. This is a conservative heuristic, not a guaranteed-success bound or a calibrated probabilistic model. Sparse distinguished points, finite paths, table saturation and unlucky walks can miss an in-range key. The engine never declares the scalar interval exhausted.

## Parallel execution

In independent mode, logical attempts have separate point partitions derived from their attempt indices and do not share collisions. Each attempt has one tame phase followed by one wild phase. A Rayon pool executes several attempts concurrently in either mode. Additional OS workers cannot exceed the number of logical attempts.

The immutable configuration records state format, seed, logical attempt count, additions per phase, distinguished bits, point capacity and memory budget. Version 1 uses independent walks; version 2 uses cooperative walks. A resumed job retains these values and all its logical attempt indices. Only the worker count and operational checkpoint/time-limit settings may change. Worker-count changes must pass the original memory budget before lifecycle changes begin.

## Checkpoints and crash recovery

Schema 4 added `kangaroo_states`, keyed by work-unit ID. Schema 5 stores new point entries separately and records a checksum of the reconstructed full snapshot. A checksummed snapshot records specification hash, version, logical attempt index, phase, tame/wild step counts and distances, current compressed point, the tame point-to-distance map, table saturation and termination reason.

Initialization creates all logical attempt work units, genesis snapshots, allocation end and a bound engine manifest in one transaction. Missing initialized maps or manifests are errors; they are not silently replaced with new walks. The writer validates encoding, budget limits, binding, monotonic distances/steps, retained committed points, phase order and work generation. A snapshot and its work-unit status advance together in one SQLite FULL transaction. Workers wait for acknowledgment before continuing beyond each checkpoint, keeping memory and outstanding writes bounded.

An uncommitted tail may replay after a kill. Current points are reconstructed from the saved distance and compared with the saved encoding before work resumes. Committed distinguished maps are loaded from the snapshot, not regenerated. Completed attempts remain completed, and pending attempts resume under new work generations. A candidate is independently verified and its finding durably committed before its walk is finalized; a crash between those actions preserves the recovery.

The checksum detects accidental changes and corruption. It is not authentication against an owner who rewrites both the state and its checksum. No external engine checkpoint format is accepted.

## Memory and disk

Independent-mode planning reserves 2 MiB of base workspace plus, per active worker, 2 MiB of workspace and 4096 bytes per allowed tame entry. Cooperative planning reserves 2 MiB of base workspace, 2 MiB per active worker, and `2 * (active_workers + logical_attempts) * capacity * 4096` bytes for tame/wild active maps, checkpoint copies and the shared index. The entry allowance is deliberately conservative. Point capacity is 16..65536 per kind per logical attempt. Distinguished bits are 0..40, chosen by default to keep the expected tame-map occupancy below a quarter of the cap under the hash model when possible.

This is an engine working-set budget, not a hard RSS limit. Runtime, allocator/native baselines and SQLite page cache are additional. Finished/inactive maps remain on disk; cooperative mode reads their committed points to reconstruct the shared index on resume. The estimator includes a maximum checkpoint JSON payload estimate; SQLite/WAL overhead and historical free pages are additional. Disk-full errors preserve the previously committed transaction. Full maps are still read, validated and serialized for checksumming at each checkpoint, so large maps and very short intervals can substantially reduce CPU performance. Point rows already committed are not rewritten.

## Reports and compatibility

Kangaroo uses report format 3. `walk_steps_completed` counts committed point additions, excluding jump-table generator multiplications and verification work. `attempts_completed` and per-walk fields describe the attempt budget. `coverage`, `covered_candidates` and `tested_candidates` are null. The negative terminal status is `budget_exhausted`, with outcome `probabilistic_budget_exhausted`; this cannot exclude an in-range key. There is no exhaustive percentage or numeric success-probability claim. Optional calibration gives an advisory estimate of the maximum configured walk budget, not a recovery ETA.

Sequential and BSGS reports retain format 2. Earlier independent kangaroo specifications and snapshots retain their version-1 serialization and hashes. Cooperative snapshots use version 2 with additional wild-point maps and saturation state, stored in schema-5 point rows for new checkpoints. Existing schema-4 snapshots convert lazily on the next successful checkpoint. The 0.3 executable rejects a cooperative specification; keep the newer binary to resume those jobs. Schema 1–4 migrations are transactional, including preservation of old BSGS manifests/artifacts. Back up a stopped state database with its BSGS artifacts, or use SQLite's supported live backup mechanism.

## Validation and references

The automated suite checks differential recovery against the sequential engine on four curves, singleton/offset/subgroup-boundary intervals, outside-range keys, deliberately insufficient budgets, saturated maps, stale generations, phase regressions, missing/corrupt/rebound checkpoints, read-only CLI estimates and resource rejections. It checks cooperative collision arrivals in both orders and recovery of a committed cross-attempt collision after a restart. An outside-range test compares the exact final independent snapshots of uninterrupted and paused/changed-worker runs. Actual child processes are killed during both tame and wild phases in independent and cooperative modes and then resumed with changed worker counts. A schema-3 BSGS checkpoint is migrated and resumed without changing its hash or artifact manifest.

Release verification independently compared exported laboratory keys with their certificate public keys through the separate OpenSSL CLI on all four curves. This included P-384 scalar 98,765,432 in `[1,100000001)`. Three local P-256 repetitions with eight attempts, a 128-point cap and `[1,1000001)` gave median end-to-end times of 0.7141 seconds with one worker and 0.1982 seconds with four workers (3.60x). This compares fixed bounded walks with an outside-range target; it is not exhaustive interval throughput. Raw evidence is in `kangaroo-benchmark-local.json`.

Algorithm background: [Montenegro and Tetali, How long does it take to catch a wild kangaroo?](https://arxiv.org/abs/0812.0789) and [Fowler and Galbraith, Kangaroo Methods for Solving the Interval Discrete Logarithm Problem](https://arxiv.org/abs/1501.07019). Their theoretical constants are not performance guarantees for this bounded implementation.

The existing [JeanLucPons/Kangaroo](https://github.com/JeanLucPons/Kangaroo) engine was reviewed as a potential adapter. Its secp256k1-specific arithmetic does not provide the P-384/P-521 backend required here, and its work files are a separate compatibility contract. This release implements a native multi-curve reference engine; it does not incorporate or redistribute that implementation.
