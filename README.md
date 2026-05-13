# spectre-m2

Reproducible demos for Apple M2 transient-execution experiments around
SLAP/LAP behavior and a narrower `prfm pldl1keep` transient-consumer signal.
The repository focuses on the code paths that build from the top-level
`Makefile` and on the limits of the observed cache-state disclosure.

## Claim

On the tested patched M2 system, the original SLAP-style LAP leak did not
reproduce as a secret-bearing primitive, and classical Spectre-v1 with normal
register consumers did not recover attacker-selected bytes. The surviving
signal came from changing the transient consumer to `prfm pldl1keep`: during a
bounds-check-mispredicted window, a victim gadget can compute a
secret-dependent address and issue an L1 software prefetch, leaving a cache
footprint after rollback.

This is a cache-state disclosure primitive, not an arbitrary write primitive.
The artifact does not claim a universal read from unrelated processes. The
strongest demos here are same-process and separately compiled victim-object
demos that require a reachable victim-side prefetch gadget.

## Repository Layout

```text
demos/
  minimal_prfm_signal.c             Minimal prfm-vs-nop signal check.
  same_process_page_oracle.c        Self-contained 16-way page oracle.
  same_process_two_hop_read.c       Same-process natural-byte recovery.
  separate_victim_page_oracle.c     Attacker harness for victim object oracle.
  separate_victim_fullbyte.c        Attacker harness for victim object key read.
  victim_page_oracle.c/.h           Separately compiled victim oracle module.
  victim_fullbyte.c/.h              Separately compiled victim key module.

tools/
  flush_reload_channel.c            Single-line cache timing sanity check.
  probe_array_calibration.c         Probe-array calibration harness.

scripts/
  run_separate_victim_page_oracle.sh Fresh-process page-oracle runner.
  run_separate_victim_fullbyte.sh    Fresh-process full-byte runner.
```

The repository layout is deliberately small: it includes working demos,
calibration tools, and shell drivers. Negative findings are summarized below
rather than preserved as non-working exploratory scripts.

## Requirements

- Apple Silicon M2, tested on an M2 MacBook Air.
- macOS Darwin 25.4.0 / build 25E246 was the measured environment.
- Xcode command-line tools with `clang`.
- P-core placement. The demos try to detect or retry around E-core placement,
  but scheduler state can still affect results.

The measurements use `dc civac` plus a 32 MB eviction walk. On this system,
`dc civac` alone did not clear the shared P-cluster L2.

## Build

```sh
make
```

Build artifacts are written to `build/`. Remove them with:

```sh
make clean
```

## Quick Verification

Minimal signal:

```sh
make run-minimal
```

Expected shape:

```text
verdict: prfm SIGNAL  |  nop noise
```

Single-round separated-victim page oracle:

```sh
./build/separate_victim_page_oracle --round=1 --secret=3
```

Expected shape:

```text
ROUND r=1 secret=3 guess=3 CORRECT
```

Single-nibble separated-victim full-byte check:

```sh
./build/separate_victim_fullbyte --nibble=0:lo
```

Expected shape:

```text
NIBBLE byte=0 lo expected=3 got=3 OK
```

Scripted smoke tests:

```sh
ROUNDS=1 SLEEP=0 ./scripts/run_separate_victim_page_oracle.sh
BYTES=1 SLEEP=0 ./scripts/run_separate_victim_fullbyte.sh
```

Full demos:

```sh
make run-page-oracle
make run-fullbyte
make run-two-hop
```

The full demos are slow by design: they perform L2 eviction and use fresh
process/cooldown protocols to avoid signal decay.

## Project Conclusions

- Flush+Reload-style channels work on M2 after adding the L2 eviction walk.
- The stock SLAP L1 timing detector did not reproduce on the patched system.
- L2/DRAM striding still showed timing speedups, but the leak test indicated
  that this timing effect did not carry secret values through the original LAP
  receiver.
- Classical Spectre-v1 with normal `ldr`/GPR consumers did not recover the
  requested out-of-bounds bytes.
- `prfm pldl1keep` was the surviving transient consumer in this artifact. It
  has no architectural destination register, but it can still create a
  measurable cache footprint.
- Separated-victim-object demos work when the victim contains the relevant
  bounds-checked prefetch gadget.

## Scope And Limitations

- The repository does not demonstrate architectural memory modification.
- The repository does not demonstrate arbitrary read of unrelated applications.
- The separated-victim demos are separate translation units in one process,
  not a no-shared-memory cross-process receiver.
- Results are scheduler-sensitive and strongest on P-cores.
- Low per-trial yield means thousands of trials are expected.

## License

BSD 3-Clause. See `LICENSE`.
