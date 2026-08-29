import { describe, it, expect } from 'vitest';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { Transaction } from '@scure/btc-signer';
import { hex } from '@scure/base';

import { Psbt, createPsbt, p2wpkhScript, psbtNetworkFor } from '../src/index.js';
import { MNEMONIC } from './vectors.mjs';

/**
 * PSBT tests — fixed, hard-coded inputs; NO network. Two load-bearing properties:
 *   (a) a signed+finalized tx round-trips / validates via @scure/btc-signer;
 *   (b) given a multi-input PSBT where we own only SOME indices, we sign ONLY those
 *       (the CoinJoin-compat primitive — others stay unsigned).
 *
 * Keys are derived deterministically from the published test mnemonic (the same
 * single source of truth the other suites use); prevouts (txid + witnessUtxo) are
 * FABRICATED — we never fetch a UTXO. Litecoin has no CoinJoin ecosystem, but the
 * same spend/merge API covers it, so the properties are exercised on BTC and LTC.
 */

const seed = mnemonicToSeedSync(MNEMONIC, '');
const root = HDKey.fromMasterSeed(seed);

// Two distinct keypairs: "ours" and a stranger's (another CoinJoin participant).
const ourNode = root.derive("m/84'/0'/0'/0/0");
const strangerNode = root.derive("m/84'/0'/0'/0/1");
const OUR_PRIV = ourNode.privateKey!;
const OUR_PUB = ourNode.publicKey!;
const STRANGER_PRIV = strangerNode.privateKey!;
const STRANGER_PUB = strangerNode.publicKey!;

// Fabricated prevout txids (32 bytes each). These never touch a network.
const TXID_A = 'a'.repeat(64);
const TXID_B = 'b'.repeat(64);

function ourInput(txid: string, asset: 'BTC' | 'LTC' = 'BTC') {
  return {
    txid,
    index: 0,
    witnessUtxo: { script: p2wpkhScript(OUR_PUB, asset), amount: 100_000n },
  };
}
function strangerInput(txid: string, asset: 'BTC' | 'LTC' = 'BTC') {
  return {
    txid,
    index: 1,
    witnessUtxo: { script: p2wpkhScript(STRANGER_PUB, asset), amount: 100_000n },
  };
}

describe('PSBT — round-trip / validation via @scure/btc-signer', () => {
  it('a signed, finalized single-owner tx extracts and re-parses (round-trips) via btc-signer', () => {
    const p = createPsbt({ asset: 'BTC' });
    p.addInput(ourInput(TXID_A));
    // Send to the stranger's P2WPKH script, minus a fee.
    p.addOutput({ script: p2wpkhScript(STRANGER_PUB, 'BTC'), amount: 90_000n });

    const res = p.signOnlyOurInputs(OUR_PRIV, [0]);
    expect(res.signed).toEqual([0]);
    expect(res.skipped).toEqual([]);
    expect(p.isInputSigned(0)).toBe(true);

    // Serialize the SIGNED (not-yet-finalized) PSBT and re-parse it via btc-signer:
    // the partial signature must survive the round-trip.
    const psbtBytes = p.toPsbt();
    const reloaded = Psbt.fromPsbt(psbtBytes, { asset: 'BTC' });
    expect(reloaded.isInputSigned(0)).toBe(true);

    // Finalize + extract the raw tx, then re-parse the RAW tx via btc-signer.
    const { hex: rawHex, txid } = reloaded.finalizeAndExtract();
    expect(rawHex).toMatch(/^[0-9a-f]+$/);
    expect(txid).toMatch(/^[0-9a-f]{64}$/);

    const parsed = Transaction.fromRaw(hex.decode(rawHex));
    expect(parsed.id).toBe(txid); // txid stable across extract → re-parse
    expect(parsed.inputsLength).toBe(1);
    expect(parsed.outputsLength).toBe(1);
    // The extracted tx is FINAL: the input carries a witness.
    expect(parsed.getInput(0).finalScriptWitness).toBeTruthy();
  });

  it('the same property holds on LTC params (ltc1 network)', () => {
    expect(psbtNetworkFor('LTC').bech32).toBe('ltc');
    const p = createPsbt({ asset: 'LTC' });
    p.addInput(ourInput(TXID_A, 'LTC'));
    p.addOutput({ script: p2wpkhScript(STRANGER_PUB, 'LTC'), amount: 90_000n });
    p.signOnlyOurInputs(OUR_PRIV, [0]);
    const { hex: rawHex, txid } = p.finalizeAndExtract();
    const parsed = Transaction.fromRaw(hex.decode(rawHex));
    expect(parsed.id).toBe(txid);
    expect(parsed.getInput(0).finalScriptWitness).toBeTruthy();
  });
});

describe('PSBT — CoinJoin-compat: sign ONLY our inputs (load-bearing)', () => {
  it('with a 2-input PSBT we own only index 0, index 1 stays completely unsigned', () => {
    const p = createPsbt({ asset: 'BTC' });
    p.addInput(ourInput(TXID_A)); // index 0 — OURS
    p.addInput(strangerInput(TXID_B)); // index 1 — NOT ours
    p.addOutput({ script: p2wpkhScript(OUR_PUB, 'BTC'), amount: 180_000n });

    const res = p.signOnlyOurInputs(OUR_PRIV, [0]);
    expect(res.signed).toEqual([0]);
    expect(res.skipped).toEqual([1]);

    // ASSERTION OF THE PROPERTY: our input has exactly one partial signature;
    // the stranger's input has NONE (no partialSig, no final witness).
    expect(p.isInputSigned(0)).toBe(true);
    expect(p.tx.getInput(0).partialSig).toHaveLength(1);
    expect(p.isInputSigned(1)).toBe(false);
    expect(p.tx.getInput(1).partialSig).toBeUndefined();

    // And because input 1 is unsigned, the tx is INCOMPLETE — cannot finalize/extract.
    expect(() => p.finalizeAndExtract()).toThrow();
  });

  it('refuses to sign an input we do not actually control (claimed ownership we cannot back)', () => {
    const p = createPsbt({ asset: 'BTC' });
    p.addInput(ourInput(TXID_A)); // index 0 — ours
    p.addInput(strangerInput(TXID_B)); // index 1 — stranger's script
    p.addOutput({ script: p2wpkhScript(OUR_PUB, 'BTC'), amount: 180_000n });

    // Declaring ownership of index 1 but signing with OUR key must throw, not silently mis-sign.
    expect(() => p.signOnlyOurInputs(OUR_PRIV, [1])).toThrow(/could not sign/);
    // Nothing was signed as a side effect of the failed attempt on index 1.
    expect(p.isInputSigned(1)).toBe(false);
  });

  it('rejects out-of-range and duplicate indices before touching any input', () => {
    const p = createPsbt({ asset: 'BTC' });
    p.addInput(ourInput(TXID_A));
    p.addOutput({ script: p2wpkhScript(OUR_PUB, 'BTC'), amount: 90_000n });
    expect(() => p.signOnlyOurInputs(OUR_PRIV, [5])).toThrow(/out of range/);
    expect(() => p.signOnlyOurInputs(OUR_PRIV, [0, 0])).toThrow(/more than once/);
  });
});

describe('PSBT — merge external inputs/outputs (participant flow, no coordinator)', () => {
  it('two participants each sign only their own input, then combine into one finalizable tx', () => {
    // A coordinator would build this shared tx (both inputs + the output) and hand
    // each participant the SAME unsigned PSBT bytes. We only ever sign our own part.
    const shared = createPsbt({ asset: 'BTC' });
    shared.addInput(ourInput(TXID_A)); // index 0 — party A (us)
    shared.addInput(strangerInput(TXID_B)); // index 1 — party B
    shared.addOutput({ script: p2wpkhScript(OUR_PUB, 'BTC'), amount: 90_000n });
    shared.addOutput({ script: p2wpkhScript(STRANGER_PUB, 'BTC'), amount: 90_000n });
    const unsigned = shared.toPsbt();

    // Party A: load the shared PSBT, sign ONLY index 0.
    const partyA = Psbt.fromPsbt(unsigned, { asset: 'BTC' });
    expect(partyA.signOnlyOurInputs(OUR_PRIV, [0])).toEqual({ signed: [0], skipped: [1] });

    // Party B: load the SAME shared PSBT, sign ONLY index 1.
    const partyB = Psbt.fromPsbt(unsigned, { asset: 'BTC' });
    expect(partyB.signOnlyOurInputs(STRANGER_PRIV, [1])).toEqual({ signed: [1], skipped: [0] });

    // Merge B's partial signature into A's PSBT → now complete → finalize + extract.
    partyA.combine(partyB.toPsbt());
    expect(partyA.isInputSigned(0)).toBe(true);
    expect(partyA.isInputSigned(1)).toBe(true);

    const { hex: rawHex, txid } = partyA.finalizeAndExtract();
    const parsed = Transaction.fromRaw(hex.decode(rawHex));
    expect(parsed.id).toBe(txid);
    expect(parsed.inputsLength).toBe(2);
    expect(parsed.outputsLength).toBe(2);
    expect(parsed.getInput(0).finalScriptWitness).toBeTruthy();
    expect(parsed.getInput(1).finalScriptWitness).toBeTruthy();
  });
});
