# Bounded interval kangaroo

Version 0.3.0 introduces an experimental native CPU Pollard lambda engine for P-256, P-384, P-521 and secp256k1. It uses independent two-walk attempts and the existing OpenSSL point arithmetic. It is selected explicitly; automatic planning remains sequential/BSGS.

## Algorithm

For `Q=dG` and half-open hypothesis `[a,b)`, an attempt starts a tame walk at `(b-1)G` and a wild walk at `Q`. Both use the same point-dependent jump function. A tame collision point at distance `dt` and a wild point at distance `dw` imply

`d = (b-1 + dt - dw) mod n`, where `n` is the subgroup order.

The candidate must lie in `[a,b)` and pass an independent full scalar multiplication, private-key construction and target-identity verification. The coordinator verifies again before persisting a recovery.

The jump set is `1,2,4,...,2^(k-1)`. Its size is the smallest positive `k` with `(2^k-1)/k >= max(1,floor(sqrt(b-a)/2))`. Including 1 avoids a shared jump divisor. The SHA-256 input is the immutable seed, logical attempt index, version-domain string and full compressed point. The first eight digest bytes select the jump modulo `k`; separate digest bytes select distinguished points. The point at infinity uses OpenSSL's canonical one-byte encoding. Jump choice does not depend on a CPU thread number.

Store the initial tame point, hash-distinguished tame points and the final tame endpoint, subject to the strict point capacity. When adding a new point would exceed the cap, stop precomputation and start wild searching with the existing map, recording saturation. The wild walk checks its current point before advancing. It stops on a verified match, its per-phase addition budget, or a distance greater than `(b-a-1)+dt_final`. Points and distances can cross the subgroup boundary; modular candidate reconstruction and interval checks reject outside-range results.

The step budget defaults to `8*ceil(sqrt(b-a))`, capped at `u64::MAX/4` additions per phase. This is a conservative heuristic, not a guaranteed-success bound or a calibrated probabilistic model. Sparse distinguished points, finite paths, table saturation and unlucky walks can miss an in-range key. The engine never declares the scalar interval exhausted.

## Parallel execution

Logical attempts have independent point partitions derived from their attempt indices. Each attempt has one tame phase followed by one wild phase. A Rayon pool executes several attempts concurrently. This implementation does not share collisions across attempts and does not claim the scaling of a cooperative kangaroo herd. Additional OS workers cannot exceed the number of logical attempts.

The immutable configuration records state format, seed, logical attempt count, additions per phase, distinguished bits, point capacity and memory budget. A resumed job retains these values and all its logical attempt indices. Only the worker count and operational checkpoint/time-limit settings may change. Worker-count changes must pass the original memory budget before lifecycle changes begin.

## Checkpoints and crash recovery

Schema 4 adds `kangaroo_states`, keyed by the corresponding work-unit ID. A checksummed JSON snapshot records specification hash, version, logical attempt index, phase, tame/wild step counts and distances, current compressed point, the tame point-to-distance map, table saturation and termination reason.

Initialization creates all logical attempt work units, genesis snapshots, allocation end and a bound engine manifest in one transaction. Missing initialized maps or manifests are errors; they are not silently replaced with new walks. The writer validates encoding, budget limits, binding, monotonic distances/steps, retained committed points, phase order and work generation. A snapshot and its work-unit status advance together in one SQLite FULL transaction. Workers wait for acknowledgment before continuing beyond each checkpoint, keeping memory and outstanding writes bounded.

An uncommitted tail may replay after a kill. Current points are reconstructed from the saved distance and compared with the saved encoding before work resumes. Committed distinguished maps are loaded from the snapshot, not regenerated. Completed attempts remain completed, and pending attempts resume under new work generations. A candidate is independently verified and its finding durably committed before its walk is finalized; a crash between those actions preserves the recovery.

The checksum detects accidental changes and corruption. It is not authentication against an owner who rewrites both the state and its checksum. No external engine checkpoint format is accepted.

## Memory and disk

Planning reserves 2 MiB of base workspace plus, per active worker, 2 MiB of workspace and 4096 bytes per allowed tame entry. The entry allowance covers map nodes, serialized checkpoint buffers, handoff copies and validation overhead; it is deliberately conservative. Point capacity is 16..65536 per logical attempt. Distinguished bits are 0..40, chosen by default to keep the expected tame-map occupancy below a quarter of the cap under the hash model when possible.

This is an engine working-set budget, not a hard RSS limit. Runtime, allocator/native baselines and SQLite page cache are additional. Finished/inactive maps remain on disk and are loaded only when needed. The estimator includes a maximum checkpoint JSON payload estimate; SQLite/WAL overhead and historical free pages are additional. Disk-full errors preserve the previously committed transaction. Large maps are serialized at every checkpoint, so very short checkpoint intervals can substantially reduce performance. Delta checkpoints and cooperative collision sharing remain future work.

## Reports and compatibility

Kangaroo uses report format 3. `walk_steps_completed` counts committed point additions, excluding jump-table generator multiplications and verification work. `attempts_completed` and per-walk fields describe the attempt budget. `coverage`, `covered_candidates` and `tested_candidates` are null. The negative terminal status is `budget_exhausted`, with outcome `probabilistic_budget_exhausted`; this cannot exclude an in-range key. There is no exhaustive percentage, calibrated ETA or numeric success-probability claim.

Sequential and BSGS reports retain format 2. The new optional specification field is omitted for earlier methods, preserving existing specification hashes. Schema 1/2/3 migrations are transactional, including preservation of old BSGS manifests/artifacts. Older executables refuse schema 4. Back up a stopped state database with its BSGS artifacts, or use SQLite's supported live backup mechanism.

## Validation and references

The automated suite checks differential recovery against the sequential engine on four curves, singleton/offset/subgroup-boundary intervals, outside-range keys, deliberately insufficient budgets, saturated maps, stale generations, phase regressions, missing/corrupt/rebound checkpoints, read-only CLI estimates and resource rejections. An outside-range test compares the exact final snapshots of uninterrupted and paused/changed-worker runs. Actual child processes are killed during both tame and wild phases and then resumed with changed worker counts. A schema-3 BSGS checkpoint is migrated and resumed without changing its hash or artifact manifest.

Release verification independently compared exported laboratory keys with their certificate public keys through the separate OpenSSL CLI on all four curves. This included P-384 scalar 98,765,432 in `[1,100000001)`. Three local P-256 repetitions with eight attempts, a 128-point cap and `[1,1000001)` gave median end-to-end times of 0.7141 seconds with one worker and 0.1982 seconds with four workers (3.60x). This compares fixed bounded walks with an outside-range target; it is not exhaustive interval throughput. Raw evidence is in `kangaroo-benchmark-local.json`.

Algorithm background: [Montenegro and Tetali, How long does it take to catch a wild kangaroo?](https://arxiv.org/abs/0812.0789) and [Fowler and Galbraith, Kangaroo Methods for Solving the Interval Discrete Logarithm Problem](https://arxiv.org/abs/1501.07019). Their theoretical constants are not performance guarantees for this bounded implementation.

The existing [JeanLucPons/Kangaroo](https://github.com/JeanLucPons/Kangaroo) engine was reviewed as a potential adapter. Its secp256k1-specific arithmetic does not provide the P-384/P-521 backend required here, and its work files are a separate compatibility contract. This release implements a native multi-curve reference engine; it does not incorporate or redistribute that implementation.
