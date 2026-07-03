// Forgery-soundness DEMONSTRATION (docs/forgery-soundness.md) — a negative control that proves the
// new `soundnessModel: 'witnessed'` + `Scenario.forgery` gate actually discriminates.
//
// Two MINIMAL witness-carrying verifiers (src/bch/forgery-demo/WitnessedResidueDemo{,Broken}.cash)
// stand in for a residue final-exponentiation Groth16 verifier: each accepts a residue witness
// c=(ce,co) in Fp2 and checks the CHEAP cross-multiplication Le*Fo == Fe*Lo with L = c^2 (so L=0 iff
// c=0), which certifies `exists w: c^2 = w*F` — the exact shape of the real cross-mult residue check.
// The c=0 witness makes the cross-mult 0==0 for ANY public F, so it is a UNIVERSAL forged proof
// unless a c!=0 guard blocks it.
//
//   forgery-demo-witnessed-sound  : has the c!=0 guard  -> rejects the c=0 forgery  -> PASS
//   forgery-demo-witnessed-broken : omits the guard     -> accepts the c=0 forgery  -> FAIL (soundness)
//
// BOTH pass the existing tests: valid ACCEPT and bit-flip tamper REJECT (a flipped c is no longer
// parallel to F). Only the forgery gate separates them — which is the whole point: the bit-flip
// `tamperable` test cannot catch a CONSISTENT witness forged for a false statement.
//
// Vectors + self-check: src/bch/gen-forgery-demo.mjs -> src/bch/forgery-demo-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/forgery-demo-vectors.json', 'utf8')) as {
  soundLock: string;
  brokenLock: string;
  validUnlocking: string;
  forgeryUnlocking: string;
  tamperUnlocking: string;
};

const scenarioFor = (lock: string) => {
  const locking = hexToBin(lock);
  const step = (unlock: string, label: string): Step => ({ label, lockingBytecode: locking, unlockingBytecode: hexToBin(unlock) });
  return {
    // valid: F = c^2 (a TRUE statement, proven with the honest witness c=(2,3))
    valid: [step(v.validUnlocking, 'witnessed residue check: cross-mult L=c^2 parallel to F')],
    // explicit invalid: a CONSISTENT bit-flip of the witness c (c no longer parallel to F) — both
    // contracts reject this, so it does NOT distinguish them (that is exactly why it is insufficient).
    invalid: [[step(v.tamperUnlocking, 'tampered witness (flipped c)')]],
    // forgery: a FALSE statement F=(999,888) "proven" with the universal c=0 witness. The SOUND
    // contract's c!=0 guard rejects it; the BROKEN contract accepts it (0==0). This is the run the
    // bit-flip tamper test cannot construct.
    forgery: [[step(v.forgeryUnlocking, 'consistent c=0 forgery of a false statement')]],
  };
};

const common = {
  proofSystem: 'forgery-soundness demo',
  field: '-',
  structure: 'single-tx' as const,
  proofBinding: 'runtime' as const,
  soundnessModel: 'witnessed' as const,
  demo: true,
};

export const forgeryDemoSound: Implementation = {
  ...common,
  id: 'forgery-demo-witnessed-sound',
  name: 'Forgery-soundness demo: witnessed verifier WITH the c!=0 guard (rejects the c=0 forgery)',
  source:
    'Minimal witness-carrying verifier (src/bch/forgery-demo/WitnessedResidueDemo.cash): accepts a ' +
    'residue witness c in Fp2 and checks the cheap cross-mult Le*Fo==Fe*Lo with L=c^2, guarded by ' +
    'c!=0. Stands in for a residue final-exp Groth16 verifier. Accepts a true statement, rejects a ' +
    'bit-flip tamper AND the universal c=0 forgery of a false statement -> demonstrates forgery-soundness.',
  load: async () => scenarioFor(v.soundLock),
};

export const forgeryDemoBroken: Implementation = {
  ...common,
  id: 'forgery-demo-witnessed-broken',
  name: 'Forgery-soundness demo: witnessed verifier WITHOUT the guard (accepts the c=0 forgery) — NEGATIVE CONTROL',
  source:
    'The same verifier with the single c!=0 guard line removed ' +
    '(src/bch/forgery-demo/WitnessedResidueDemoBroken.cash). It still accepts the true statement and ' +
    'rejects the bit-flip tamper — so it PASSES the pre-existing correctness gate — but the c=0 witness ' +
    'makes the cross-mult 0==0 for the false statement, so it ACCEPTS the forgery. The new forgery gate ' +
    'is what catches it: it must fail `pass`. This is the negative control proving the gate discriminates.',
  load: async () => scenarioFor(v.brokenLock),
};
