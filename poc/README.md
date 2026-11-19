# PoC: IND-CPA-D key recovery on OpenFHE FHEW→CKKS scheme switching

Reverse-direction attack (the direction ePrint 2026/285 left untested). Recovers the FHEW/LWE
secret key from a CKKS decryption oracle on switched ciphertexts.

## Build

Requires OpenFHE (commit `ed361af2`) built and installed locally.

```sh
mkdir -p build && cd build
cmake -DCMAKE_PREFIX_PATH=/path/to/openfhe-install ..
make
export DYLD_LIBRARY_PATH=/path/to/openfhe-install/lib     # Linux: LD_LIBRARY_PATH
```

The binaries write `equations.csv` / `secret.csv` to the **current working directory**, and the
Python solvers read them from the current directory, so run both from the same place (e.g. the
`build/` directory).

## Programs

- `calib` / `sweep` — show that `EvalFHEWtoCKKS` output is the normalized LWE phase (a ramp
  crossing ½ at phase Δ/2). `sweep` covers a full message period.
- `diag [scaleModSize]` — calibration + repeatability: the transform noise is deterministic, and
  at `scaleModSize=59`, after an `a=0` calibration, the error estimate is exact to ~0.03 (rounds
  to the exact integer `e`).
- `msgtest [p]` — shows the switch output is `m + e/Δ`; table for messages `m = 0..7`.
- `direct [slots] [scaleModSize] [flood] [tscale]` — the admissible attack: one decryption query
  returns `slots` exact errors.
- `attack [G] [Mct] [flood] [tscale]` — collect `Mct` exact equations (`G` ciphertexts packed per
  switch call), dump `equations.csv` and `secret.csv`. Optional `flood` (injected Gaussian
  flooding std, phase units) and `tscale` (amplification factor `t`).
- `floodtest [flood] [reps] [K] [tscale] [scaleModSize] [tagmode]` — measure the exact-`e` rate
  over `K` ciphertexts vs. flooding and amplification.
- `swktest` — shows the switching key is itself a CKKS encryption of the FHEW secret: decrypting
  it returns all 1305 coordinates in one query (the out-of-game trivial break).
- `solve.py` / `solve2.py` — modular solve (SageMath): pick `n` GF(2)-independent equations,
  Hensel-lift mod `2^28`, compare to ground truth. `solve2.py` is the fast one-echelonization
  version. Run `sage -python solve2.py`.

## Headline runs

```sh
# clean full key recovery
./attack 4 1400                 # -> 1400/1400 exact e, dumps equations.csv / secret.csv
sage -python ../solve2.py       # -> FULL KEY RECOVERY 1305/1305

# full key recovery even under injected decryption-noise flooding, via amplification
./attack 4 1400 1024 1024
sage -python ../solve2.py       # -> FULL KEY RECOVERY 1305/1305
```

Parameters (both): CKKS ring `2^13`, depth 13, `scaleModSize 59`; FHEW STD128, `n=1305`, `q=2^28`,
`p=256`, `Δ=2^20`. Only public ciphertext data and oracle outputs drive the recovery; the
ground-truth `e` and `s` are read solely to report exactness.
