# PoC logs: what produced what

Every log in this directory is reproduced by the current code in `poc/` (regenerated 2026-09-23).
Build and environment: see `../README.md`.

| log | command | what it confirms |
|---|---|---|
| `msgtest.log` | `./msgtest 256` | switch output = `m + e/Δ`; message table for `m = 0..7` |
| `diag_59.log`, `diag_50.log` | `./diag 59`, `./diag 50` | switch noise is deterministic; dependence on precision |
| `direct_59.log` | `./direct 512 59 1 1` | **512/512** exact errors in a single decryption query |
| `direct_50_t1.log` | `./direct 512 50 1 1` | at the shipped `scaleMod=50`, the bare read fails |
| `direct_50_amp.log` | `./direct 512 50 1 {64,256,1024}` | admissible amplification restores it: `t=256` already gives 512/512 |
| `floodtest_fixed.log` | `./floodtest 1024 1 40 t 59 0` | fixed-magnitude flooding is bypassed by amplification (0→10→40 of 40) |
| `floodtest_tag.log` | `./floodtest 1024 1 40 t 59 1` | noise-tag flooding is NOT bypassed (0/40 at every `t`) |
| `real_flooding_sweep.log` | OpenFHE `NOISE_FLOODING_DECRYPT` sweep | the shipped countermeasure, swept to the library's ceiling, still leaves 512/512 exact |
| `swktest.log` | `./swktest` | the switching key decrypts to the secret: 1305/1305 in one query |

The headline key-recovery numbers are produced by `../solve2_direct.log` (high-precision config)
and `../solve2_default_direct.log` (the library's own `scaleMod=50` example with amplification).
