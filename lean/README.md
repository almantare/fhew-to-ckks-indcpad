# Lean 4 formalization — what is actually proved

`LWEKeyRecovery.lean`: 8 theorems, compiles with no errors and **no `sorry`**; every theorem
depends only on the three standard Lean axioms (`propext`, `Classical.choice`, `Quot.sound`).
Check with `./build.sh`.

## What is proved

| theorem | statement |
|---|---|
| `inner_of_lwe` | from the LWE relation `b = ⟨a,s⟩ + Δm + e` it follows that `⟨a,s⟩ = b − Δm − e`: knowing the public `a, b`, one's own `m`, and the recovered `e`, the attacker obtains one equation in the secret |
| `inner_of_lwe_zero` | the same for encryptions of zero (the attack case) |
| `secret_unique` | with an invertible matrix the system has **at most one** solution |
| `secret_eq_inv_mulVec` | the explicit recovery formula `s = A⁻¹v` |
| `key_recovery` | end to end: from `n` LWE relations and invertibility of `A`, the vector the solver returns from `v_j = b_j − e_j` **equals the secret** |
| `isUnit_iff_map_two` | in `ZMod (2^k)`, an element is a unit ⟺ its residue mod 2 is a unit (i.e. ⟺ it is odd) |
| `isUnit_det_iff_map_two` | a matrix over `ZMod (2^k)` is invertible ⟺ its entrywise reduction mod 2 is invertible |
| `key_recovery_of_mod_two` | independence of the selected rows **over GF(2)** already suffices for the system to determine the secret uniquely over `ZMod (2^k)` |

Two consequences for the paper:

1. **`secret_unique` / `key_recovery` justify the claim "the attacker knows it succeeded."** The
   check "all equations are satisfied" needs no ground truth: any solution of a system with an
   invertible matrix *is* the real key.
2. **`isUnit_det_iff_map_two` justifies the solver `poc/solve2.py`**, which selects `n` rows
   independent over GF(2) and only then inverts the system mod `2^28` (by Hensel lifting). What was
   a heuristic ("the determinant is a unit ⟺ it is odd") is now a theorem.

## What is NOT proved here (and cannot be)

- **Empirical facts.** That `EvalFHEWtoCKKS` outputs `m + e/Δ`, the noise magnitudes, the
  linearity of the ramp — these are facts about the behavior of the C++ library and floating
  point. They are not amenable to this formalization; they are measured in `poc/`.
- **The game reduction to IND-CPA-D.** That the queries are admissible in the game of §3.2 of
  ePrint 2026/285 and that the attack wins the game. This belongs in EasyCrypt/SSProve; in Lean it
  would be a separate large project. It remains an open item.
- **The negative result about noise-tag flooding.** It is statistical (σ grows with `t`) and is
  established by measurement, not by deduction.

In short: the **deductive bridge** from "errors recovered" to "key recovered" is formalized — not
the leak itself and not its absence under the countermeasure.

## Reproduction

`build.sh` reuses an already-built Mathlib **read-only** (toolchain `leanprover/lean4:v4.34.0-rc2`);
the path to its compiled libraries is read from a local `.leanpath` file (not committed — it is
machine-specific). Copy `.leanpath.example` to `.leanpath` and edit it to point at a Mathlib build
of the same toolchain, or create a normal Lake project depending on mathlib and drop
`LWEKeyRecovery.lean` into it.
