/-
Algebraic core of the FHEW→CKKS key-recovery attack, formalized.

What this file does and does NOT cover
--------------------------------------
NOT covered (not formalizable here): the empirical facts about OpenFHE — that the switch
outputs m + e/Δ, the measured noise, the ramp. Those are statements about a C++ library and
floating-point numerics. Also NOT covered: the game-based IND-CPA-D reduction (that belongs in
EasyCrypt/SSProve).

Covered: the deductive step that turns "the adversary learned each ciphertext's error" into
"the adversary holds the secret key", plus the modular-linear-algebra fact that justifies the
solver's pivot selection over GF(2).
-/
import Mathlib.Data.ZMod.Basic
import Mathlib.LinearAlgebra.Matrix.NonsingularInverse
import Mathlib.Data.Nat.GCD.Basic

open Matrix

namespace LWEAttack

variable {q n : ℕ}

/-! ### 1. From an LWE sample to a linear equation in the secret -/

/-- OpenFHE's LWE convention: `b = ⟨a,s⟩ + Δ·m + e`.  If the adversary knows the public `a, b`,
the message `m` it asked for, and has recovered the error `e`, then the inner product
`⟨a,s⟩` is determined.  This is the step the phase-probe performs for one ciphertext. -/
theorem inner_of_lwe (s a : Fin n → ZMod q) (b Δ m e : ZMod q)
    (h : b = a ⬝ᵥ s + Δ * m + e) : a ⬝ᵥ s = b - Δ * m - e := by
  rw [h]; ring

/-- Specialised to the encryptions of zero used by the attack (`m = 0`). -/
theorem inner_of_lwe_zero (s a : Fin n → ZMod q) (b e : ZMod q)
    (h : b = a ⬝ᵥ s + e) : a ⬝ᵥ s = b - e := by
  rw [h]; ring

/-! ### 2. Soundness: a solution of the collected system IS the secret -/

/-- If the coefficient matrix is invertible, the linear system has at most one solution.
Consequence for the attack: an adversary that exhibits *any* `s'` satisfying all the collected
equations has necessarily found the true secret — no ground truth is needed to be certain. -/
theorem secret_unique (A : Matrix (Fin n) (Fin n) (ZMod q)) (hA : IsUnit A.det)
    (s s' : Fin n → ZMod q) (h : A.mulVec s' = A.mulVec s) : s' = s := by
  have h1 : (A⁻¹ * A).mulVec s' = (A⁻¹ * A).mulVec s := by
    simp only [← Matrix.mulVec_mulVec, h]
  rwa [Matrix.nonsing_inv_mul A hA, Matrix.one_mulVec, Matrix.one_mulVec] at h1

/-- The explicit recovery formula: the secret is obtained from the leaked right-hand side. -/
theorem secret_eq_inv_mulVec (A : Matrix (Fin n) (Fin n) (ZMod q)) (hA : IsUnit A.det)
    (s v : Fin n → ZMod q) (h : A.mulVec s = v) : s = A⁻¹.mulVec v := by
  rw [← h, Matrix.mulVec_mulVec, Matrix.nonsing_inv_mul A hA, Matrix.one_mulVec]

/-! ### 3. End-to-end: errors recovered ⇒ key recovered -/

/-- The attack, stated abstractly.  `a j` are the public vectors, `b j` the public scalars,
`e j` the errors the phase-probe recovered, and the rows of `A` are the `a j`.  If every
sample satisfies the LWE relation with message `0`, and `A` is invertible, then the vector the
solver returns from `v j = b j - e j` is exactly the secret. -/
theorem key_recovery
    (s : Fin n → ZMod q) (A : Matrix (Fin n) (Fin n) (ZMod q)) (b e : Fin n → ZMod q)
    (hA : IsUnit A.det)
    (hlwe : ∀ j, b j = (A j) ⬝ᵥ s + e j) :
    A⁻¹.mulVec (fun j => b j - e j) = s := by
  have hv : A.mulVec s = fun j => b j - e j := by
    funext j
    show (A j) ⬝ᵥ s = b j - e j
    rw [hlwe j]; ring
  rw [← hv, Matrix.mulVec_mulVec, Matrix.nonsing_inv_mul A hA, Matrix.one_mulVec]

/-! ### 4. Why picking pivot rows over GF(2) is sound

`solve2.py` selects `n` equations whose matrix is invertible **mod 2** and then inverts mod
`2^k` (by Hensel lifting).  The justification is that over `ZMod (2^k)` invertibility is
detected entirely by the reduction mod 2 — the determinant is a unit iff it is odd. -/

section TwoAdic

variable {k : ℕ}

/-- In `ZMod (2^k)`, an element is a unit exactly when its reduction mod 2 is a unit
(equivalently: exactly when it is odd). -/
theorem isUnit_iff_map_two (hk : 0 < k) (x : ZMod (2 ^ k)) :
    IsUnit x ↔ IsUnit (ZMod.castHom (dvd_pow_self 2 hk.ne') (ZMod 2) x) := by
  have : NeZero (2 ^ k) := ⟨pow_ne_zero k two_ne_zero⟩
  have hx : ((x.val : ℕ) : ZMod (2 ^ k)) = x := ZMod.natCast_rightInverse x
  have himg : ZMod.castHom (dvd_pow_self 2 hk.ne') (ZMod 2) x = ((x.val : ℕ) : ZMod 2) := by
    conv_lhs => rw [← hx]
    rw [map_natCast]
  calc IsUnit x ↔ IsUnit ((x.val : ℕ) : ZMod (2 ^ k)) := by rw [hx]
    _ ↔ Nat.Coprime x.val (2 ^ k) := ZMod.isUnit_iff_coprime _ _
    _ ↔ Nat.Coprime x.val 2 := Nat.coprime_pow_right_iff hk _ _
    _ ↔ IsUnit ((x.val : ℕ) : ZMod 2) := (ZMod.isUnit_iff_coprime _ _).symm
    _ ↔ IsUnit (ZMod.castHom (dvd_pow_self 2 hk.ne') (ZMod 2) x) := by rw [himg]

/-- A square matrix over `ZMod (2^k)` is invertible iff its entrywise reduction mod 2 is.
This is exactly the fact the solver relies on when it chooses `n` rows independent over GF(2)
and then inverts the resulting system modulo `2^k`. -/
theorem isUnit_det_iff_map_two (hk : 0 < k) (A : Matrix (Fin n) (Fin n) (ZMod (2 ^ k))) :
    IsUnit A.det ↔
      IsUnit ((ZMod.castHom (dvd_pow_self 2 hk.ne') (ZMod 2)).mapMatrix A).det := by
  rw [← RingHom.map_det, isUnit_iff_map_two hk]

/-- Combined with `key_recovery`: mod-2 independence of the selected rows already guarantees
that the system pins the secret uniquely over `ZMod (2^k)`. -/
theorem key_recovery_of_mod_two (hk : 0 < k)
    (s : Fin n → ZMod (2 ^ k)) (A : Matrix (Fin n) (Fin n) (ZMod (2 ^ k)))
    (b e : Fin n → ZMod (2 ^ k))
    (hA2 : IsUnit ((ZMod.castHom (dvd_pow_self 2 hk.ne') (ZMod 2)).mapMatrix A).det)
    (hlwe : ∀ j, b j = (A j) ⬝ᵥ s + e j) :
    A⁻¹.mulVec (fun j => b j - e j) = s :=
  key_recovery s A b e ((isUnit_det_iff_map_two hk A).mpr hA2) hlwe

end TwoAdic

end LWEAttack
