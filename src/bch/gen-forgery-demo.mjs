// Generator for the forgery-soundness demonstration vectors (docs/forgery-soundness.md).
//
// Two MINIMAL witness-carrying verifiers stand in for a residue final-exponentiation Groth16
// verifier (see src/bch/forgery-demo/*.cash). Both accept a residue witness c=(ce,co) in Fp2 and
// check the cheap cross-multiplication Le*Fo == Fe*Lo with L = c^2 (L=0 iff c=0), certifying
// exists w: c^2 = w*F. WitnessedResidueDemo GUARDS c != 0; WitnessedResidueDemoBroken omits it, so
// the c=0 witness (L=0 => 0==0 for ANY F) is a UNIVERSAL forged proof.
//
// This writes forgery-demo-vectors.json and ASSERTS, on the loosened BCH 2026 VM:
//   sound : valid ACCEPT, c=0 forgery REJECT, tamper REJECT   (passes the new forgery gate)
//   broken: valid ACCEPT, c=0 forgery ACCEPT, tamper REJECT   (passes tamper, FAILS the forgery gate)
// Reproduce the hexes: cashc 0.13.1 on src/bch/forgery-demo/WitnessedResidueDemo{,Broken}.cash.
import { writeFileSync } from 'node:fs';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch, hexToBin, bigIntToVmNumber } from '@bitauth/libauth';

const SOUND_LOCK = '5279009e5479009e9b6908ffffffffffffff1f5354795579957c56795779959593789752557a567a95955279977c547a95527997537a7b957b979c';
const BROKEN_LOCK = '08ffffffffffffff1f5354795579957c56795779959593789752557a567a95955279977c547a95527997537a7b957b979c';

const HUGE = Number.MAX_SAFE_INTEGER;
const loose = { maximumOperationCost: HUGE, maximumStackDepth: HUGE, maximumStandardStackItemLength: HUGE, maximumBytecodeLength: HUGE, maximumStandardBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loose }));
const push = (n) => { const d = bigIntToVmNumber(n); if (d.length === 0) return [0]; if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return [0x50 + d[0]]; if (d.length <= 75) return [d.length, ...d]; return [0x4c, d.length, ...d]; };
// verify(Fe,Fo,ce,co): CashScript pushes args in REVERSE declaration order
const unlockHex = (args) => Buffer.from([...args].reverse().flatMap(push)).toString('hex');
const accepts = (lockHex, args) => vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: hexToBin(lockHex), unlockingBytecode: hexToBin(unlockHex(args)), valueSatoshis: 10000n })) === true;

// c=(2,3), xi=3 => L=c^2=(2^2+3*3^2, 2*2*3)=(31,12); F := L makes the statement TRUE (F parallel to c^2).
const VALID = [31n, 12n, 2n, 3n];
// FALSE statement F=(999,888) "proven" with the universal c=0 witness (L=0 => cross-mult 0==0).
const FORGERY = [999n, 888n, 0n, 0n];
// consistent tamper: flip the witness c (2 -> 3); c'^2 no longer parallel to F, so the check fails.
const TAMPER = [31n, 12n, 3n, 3n];

const check = (name, lock, exp) => {
  const got = { valid: accepts(lock, VALID), forgery: accepts(lock, FORGERY), tamper: accepts(lock, TAMPER) };
  const ok = got.valid === exp.valid && got.forgery === exp.forgery && got.tamper === exp.tamper;
  console.log(`${name}: valid=${got.valid} forgery=${got.forgery} tamper=${got.tamper}  ${ok ? 'OK' : 'MISMATCH'}`);
  if (!ok) process.exit(1);
};
check('sound ', SOUND_LOCK, { valid: true, forgery: false, tamper: false });
check('broken', BROKEN_LOCK, { valid: true, forgery: true, tamper: false });

const out = {
  description: 'Forgery-soundness demo: a witness-carrying verifier that rejects a consistent c=0 forgery (SOUND) vs one that omits the c!=0 guard and accepts it (BROKEN). Both pass the bit-flip tamper test; only the forgery gate separates them. See docs/forgery-soundness.md.',
  soundLock: SOUND_LOCK, brokenLock: BROKEN_LOCK,
  validUnlocking: unlockHex(VALID),
  forgeryUnlocking: unlockHex(FORGERY),
  tamperUnlocking: unlockHex(TAMPER),
};
writeFileSync('src/bch/forgery-demo-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/forgery-demo-vectors.json');
