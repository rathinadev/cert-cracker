# GMP-ECM adapter evaluation

GMP-ECM is a candidate for an optional RSA integer-factorization adapter. It is not an EC private-scalar search engine and is not integrated into this project yet. Factor discovery is probabilistic and a completed curve cannot prove an RSA modulus secure.

## Availability and licensing

The Homebrew `gmp-ecm` formula reports version 7.0.7 and the package license as GPL-3.0-or-later AND LGPL-3.0-or-later. The CLI source identifies itself as GPL-3.0-or-later. Keep any initial integration as a separately installed executable, do not copy or redistribute upstream code as part of this project without a license review, and document the actual installation and distribution terms. [Homebrew formula](https://formulae.brew.sh/formula/gmp-ecm), [upstream CLI source mirror](https://github.com/sethtroisi/gmp-ecm/blob/main/main.c).

## Local exploration — 5 November 2026

A Homebrew 7.0.7 Apple Silicon bottle and its primesieve dependency were downloaded into a temporary directory; their SHA-256 values matched the Homebrew formula. The executables were locally relocated and ad-hoc signed for the experiment; no system-wide installation was performed. The linked GMP was version 6.3.0. This is an exploratory local test, not a claim about other builds, platforms or versions.

- `ecm -q -one -sigma 0:6 30` received the intentionally weak modulus `1028171` on standard input and returned `1009 1019`, with exit status 14. A run returning the entire input modulus used status 8. Exit status is a bit field, so a nonzero value is not automatically a subprocess failure. Candidates must be independently checked against the input modulus and recovered private key.
- `-maxmem` is documented as a stage-2 memory limit, not an overall process RSS cap. The adapter must not represent it as a total memory limit. [Upstream options](https://github.com/sethtroisi/gmp-ecm/blob/main/main.c).
- In a stage-1 test with `-param 0 -chkpnt FILE` on a 521-bit prime, sending SIGINT or SIGTERM after two seconds terminated the tested process without a checkpoint. Adding a separate `-save FILE` caused a subsequent SIGTERM test to write a checkpoint and exit with status 143; the checkpoint was accepted by a subsequent `-resume` invocation. The signal took several seconds to finish. These experiments do not establish forced-kill durability, stage-2 restart, or portability of the behavior.
- The 7.0.7 package README says stage-1 checkpoints can be written periodically and on signals, and that ECM checkpointing is implemented for `-param 0`. It also warns that a specified checkpoint path can be overwritten. The inspected source mirror installs signal handling only when a save file is configured. Validate the exact installed version instead of assuming every build behaves identically. [README checkpoint section](https://github.com/sethtroisi/gmp-ecm/blob/main/README).

## Integration requirements

1. Invoke an explicitly selected executable using an argument array; record its version and identity. Never run a shell command assembled from input.
2. Send only the selected public RSA modulus to the local child process. Bound captured output, wall time, curve count and configured stage-2 memory; make the limits and their scope visible.
3. Parse output and exit status as untrusted evidence. Accept only a nontrivial divisor of the selected modulus and pass reconstructed keys through the existing independent verification before persisting a finding. Report no factor, full-modulus results, errors, timeouts, and unsupported reconstruction separately.
4. Persist stable attempt identities and committed attempt outcomes before scheduling more work. A cancelled or killed attempt may replay unless a checkpoint has been validated and bound to the same engine version, modulus, curve parameters and job specification.
5. Treat upstream checkpoint files as untrusted and potentially overwritten. Use per-attempt private paths and an atomic publication protocol. Test forced termination, restart, corrupt/truncated artifacts, changed executable/configuration, and both supported and unsupported platforms before advertising intra-attempt resume. Distinguish stage 1 and stage 2.
6. Test against real supported versions in CI in addition to synthetic subprocess failures. Avoid claiming whole-process memory enforcement, broad platform support, or general cryptographic breakage without evidence.
