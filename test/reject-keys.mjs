/**
 * Builders for the private-key REJECT fixtures — real, well-formed private material
 * (not dummy strings), constructed at runtime from the BIP84 test seed so every
 * fixture is a genuine serialization the guard must refuse.
 *
 * Shared by `test/guards.test.ts` and `scripts/smoke.mjs` so the unit tests and the
 * built-artifact smoke exercise the identical adversarial inputs.
 *
 * This file uses `@scure/*` only to MINT valid private serializations for the test —
 * it is not part of the shipped library.
 */
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { base58check, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';

import { MNEMONIC, PRIVATE_VERSION_HEX, ZPUB_VERSION_HEX } from './vectors.mjs';

const b58check = base58check(sha256);

/** Re-serialize any 78-byte extended key under different version bytes. */
function reVersion(extendedKey, versionHex) {
  const raw = b58check.decode(extendedKey);
  const out = new Uint8Array(raw);
  out.set(hex.decode(versionHex), 0);
  return b58check.encode(out);
}

/**
 * Every extended-PRIVATE reject fixture, plus the two non-extended shapes and the
 * re-versioned trap. Returns `[{ label, key }]`.
 *
 * The account-level private extended key (m/84'/0'/0') is minted once from the test
 * seed; @scure emits it under the registered `xprv` version, which we then swap to
 * each SLIP-132 private version byte to produce a structurally valid `zprv`, `Ltpv`,
 * etc. The final `zprv→zpub` entry swaps a real `zprv` to the PUBLIC `zpub` version
 * byte: it passes a prefix check but its decoded key byte is still 0x00.
 */
export function buildRejects() {
  const seed = mnemonicToSeedSync(MNEMONIC, '');
  const account = HDKey.fromMasterSeed(seed).derive("m/84'/0'/0'");
  const xprv = account.privateExtendedKey; // registered xprv version

  const rejects = [];
  for (const [label, versionHex] of Object.entries(PRIVATE_VERSION_HEX)) {
    rejects.push({ label, key: reVersion(xprv, versionHex) });
  }

  // A real zprv re-serialized to wear the zpub PUBLIC prefix. Prefix says "zpub…",
  // decoded key byte is 0x00 → must still be rejected.
  const zprv = reVersion(xprv, PRIVATE_VERSION_HEX.zprv);
  rejects.push({ label: 'zprv-reversioned-as-zpub', key: reVersion(zprv, ZPUB_VERSION_HEX) });

  // Non-extended private shapes.
  rejects.push({ label: 'raw-64-hex-scalar', key: hex.encode(account.privateKey) });
  rejects.push({ label: 'mnemonic-seed-phrase', key: MNEMONIC });

  return rejects;
}
