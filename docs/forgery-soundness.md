# Forgery-soundness: testing witness-carrying verifiers

A Groth16 verifier can establish soundness in one of two ways, and the difference
decides whether the existing correctness gate actually proves it sound:

- **on-chain** — the verifier recomputes the full verification relation on-chain
  (notably the final exponentiation `e(…)^((p^k−1)/r)`). A false statement cannot
  satisfy the recomputed equation, so tampering *any* input breaks it. This is how
  the references (`nchain`, `scrypt-bn256`) and the reference `groth16.cash` work.
- **witnessed** — the verifier moves part of the relation **off-chain** into a
  computed unlocking witness, and on-chain checks only a cheap algebraic relation on
  that witness. The residue final-exponentiation verifiers (ePrint 2024/640) do this:
  instead of computing the final exp, they accept a residue witness `c` and check
  `frob(c)·c^λ == F·w`-style relations, which is dramatically cheaper on-chain.

Both genuinely verify — **when implemented correctly**. But a witnessed verifier has
a soundness surface that the correctness gate did **not** probe.

## Why the bit-flip tamper test is not enough

The harness derives invalid runs (`tamperable: true`) by flipping one bit of the
witness. For a witnessed verifier that *rejects* the flip — a bit-flipped `c` is no
longer a consistent witness — so it looks sound. But the real adversary does not flip
a bit: **they control the whole unlocking and craft a *consistent* witness for a
false statement.** The classic instance is a missing guard. Our cross-mult residue
check certifies `∃w: c² = w·F` by `Le·Fo == Fe·Lo` with `L = c²`. If `c = 0` then
`L = 0` and the check is `0 == 0` for **any** `F` — a *universal* forged proof. The
`require(c ≠ 0)` guard blocks it. A verifier that omits that one line:

- **accepts** the true statement (correctness ✓),
- **rejects** a bit-flip of `c` (`tamperable` ✓ — it passes the old gate),
- **accepts** the `c = 0` forgery of a false statement (**unsound**).

The bit-flip test cannot construct that forgery, so the loophole is invisible to it.

## How the harness checks it

An `Implementation` declares `soundnessModel: 'on-chain' | 'witnessed'` (default
`on-chain`). A **`witnessed`** scenario also carries `forgery: Step[][]` — runs for a
**false statement**, each carrying the *strongest* witness the verifier's **own honest
generator** produces for it (the adversary's best shot, e.g. the residue witness of
the false pairing product, and the degenerate `c = 0` witness). The harness
(`src/harness/benchmark.ts`):

1. runs every forgery run and requires **all** to REJECT;
2. reports `soundness.demonstrated` and folds it into `pass`: a `witnessed` verifier
   that does not reject every forgery — *or supplies none* — **fails**.

An `on-chain` verifier has no such surface: it supplies no `forgery` runs and
`demonstrated` is vacuously true.

Because the **same** generator produces the accepted `valid` / `extraValidProofs`
runs and the rejected `forgery` runs, a generator too weak to actually forge cannot
pass by shipping trivially-broken forgeries — the accepted runs pin it honest. The
`soundness` block is emitted into `results.json`
(`src/harness/export-json.ts`) for the website.

## The demonstration (a negative control)

`src/bch/forgery-demo/WitnessedResidueDemo.cash` is a minimal witness-carrying
verifier with the `c ≠ 0` guard; `WitnessedResidueDemoBroken.cash` is the same
contract with that single line removed. `src/bch/gen-forgery-demo.mjs` builds the
vectors and **asserts** on the loosened VM:

```
sound : valid ACCEPT, c=0 forgery REJECT, tamper REJECT   -> pass, forgery demonstrated
broken: valid ACCEPT, c=0 forgery ACCEPT, tamper REJECT   -> tamper passes, forgery FAILS
```

Registered as `forgery-demo-witnessed-sound` (PASS) and
`forgery-demo-witnessed-broken` (FAIL). The broken control passes the *pre-existing*
correctness gate (valid accept + tamper reject) and is caught **only** by the forgery
gate — which is exactly the point: it proves the gate is not decorative.

## Adding forgery runs to a real witnessed verifier

Mint a **false** statement (e.g. a valid proof but a changed public input, so the
pairing product is not the identity), run the verifier's own witness generator on it
to produce the strongest consistent witness, and add the resulting step-list to
`Scenario.forgery` — plus the degenerate witness the guards are meant to reject
(`c = 0`, non-canonical limbs). Each must reject. Set `soundnessModel: 'witnessed'`.
The verifier now demonstrates forgery-resistance empirically instead of asserting it.
