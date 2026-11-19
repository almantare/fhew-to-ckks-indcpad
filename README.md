# Recovering the FHEW Secret Key from FHEW→CKKS Scheme Switching under IND-CPA-D

Artifact for the paper of the same name. It settles the **reverse** direction (FHEW→CKKS) of
OpenFHE's CKKS/FHEW scheme switching, which Santato & Zanotto (ePrint 2026/285) analyzed only in
the CKKS→FHEW direction. In the IND-CPA-D game, the full FHEW/LWE secret key is recovered from a
CKKS decryption oracle on switched ciphertexts in **three decryption queries**.

## Result in one line

OpenFHE's `EvalFHEWtoCKKS` does not round — it applies the transfer function
`out = (p/2π)·sin(2π·φ/q)`, so the CKKS plaintext it returns is `m + e/Δ`. The LWE error survives
the switch, only attenuated, inside CKKS message space. Inverting the sine recovers each
ciphertext's error exactly, giving one linear equation in the LWE secret per ciphertext. One
switch packs 512 LWE ciphertexts into CKKS slots, so three decryption queries over-determine the
`n = 1305` STD128 FHEW key.

## Layout

| path | what |
|---|---|
| `paper/` | the paper in English (`main.tex` / `main.pdf`) and a Russian translation (`main_ru.tex` / `main_ru.pdf`); shared `refs.bib` and `fig_transfer.pdf` |
| `poc/`   | C++ proof-of-concept against OpenFHE (commit `ed361af2`), the Python modular solver, and the result logs in `poc/out/` that the paper cites |
| `lean/`  | Lean 4 formalization of the algebraic core of the recovery (compiles, no `sorry`) |

## Build and run the PoC

Requires OpenFHE (commit `ed361af2`) built and installed locally, and SageMath for the solver.

```sh
cd poc
mkdir -p build && cd build
cmake -DCMAKE_PREFIX_PATH=/path/to/openfhe-install ..
make
export DYLD_LIBRARY_PATH=/path/to/openfhe-install/lib     # Linux: LD_LIBRARY_PATH

# one decryption query, high-precision config -> 512/512 errors exact
./direct 512 59 1 1

# collect the full system and recover the key
./attack 4 1400                 # writes equations.csv / secret.csv to the current directory
sage -python ../solve2.py       # -> FULL KEY RECOVERY 1305/1305

# the same under injected decryption-noise flooding, via admissible amplification
./attack 4 1400 1024 1024
sage -python ../solve2.py       # -> FULL KEY RECOVERY 1305/1305
```

Parameters (both runs): CKKS ring `2^13`, depth 13, `scaleModSize 59`; FHEW STD128, `n = 1305`,
`q = 2^28`, `p = 256`, `Δ = 2^20`. Only public ciphertext data and oracle outputs drive the
recovery; the ground-truth error `e` and secret `s` are read **solely to report exactness**, never
used by the attack. `poc/out/README.md` maps each log file to the paper claim it supports.

## Check the Lean proof

```sh
cd lean
cp .leanpath.example .leanpath          # then edit it to point at a built Mathlib
./build.sh                              # -> compiles, no sorry, 3 standard axioms
```

The formalization covers the deductive bridge "errors recovered ⇒ key recovered" (uniqueness of
the solution, the explicit `s = A⁻¹v` formula, and soundness of mod-2 pivot selection over
`ZMod (2^k)`). It does **not** formalize the measured library behavior or the game reduction; those
are empirical (`poc/`) and on-paper respectively. See `lean/README.md`.

## Notes

- The PoC generates its own keys. `secret.csv` is **synthetic test output**, not a real
  deployment's key.
- License: to be decided (MIT or Apache-2.0 are the usual choices for a research artifact).
