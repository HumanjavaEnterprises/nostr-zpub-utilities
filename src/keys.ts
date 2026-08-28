/**
 * SEED-SIDE logic — enclave/client ONLY, never a server.
 *
 * ⛔ Every export in this file TOUCHES THE SEED. A BIP39 mnemonic (or a raw seed)
 * is private material. These functions MUST run only where the seed is allowed to
 * live — a browser, a hardware enclave, an offline signer — and NEVER on a shared
 * server, a receiving rail, or anywhere the seed shouldn't be. This is the exact
 * inverse of the public side (`derive.ts`), which is watch-only and never sees a
 * seed.
 *
 * These functions output ONLY PUBLIC material — an account-level `zpub`/`Ltub` and
 * its fingerprint. They never return, log, persist, or transmit the seed, the
 * mnemonic, or any private/extended-private key bytes. The seed exists only as a
 * local variable for the duration of the call and is never surfaced.
 *
 * @packageDocumentation
 */

import { HDKey } from '@scure/bip32';
import { base58check, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { outputVersionHex, type ChainAsset, type ChainNetwork } from './versions.js';
import type { ZpubOptions, ZpubResult } from './types.js';

const b58check = base58check(sha256);

/** SLIP-44 mainnet coin_type per asset. BTC = 0, LTC = 2. */
const MAINNET_COIN_TYPE: Record<ChainAsset, number> = { BTC: 0, LTC: 2 };

/**
 * SLIP-44 coin_type for the BIP84 account path, NETWORK-AWARE.
 *
 * On mainnet each coin has its own type (BTC 0, LTC 2). On TESTNET, SLIP-44
 * registers a single shared type — coin 1, "Testnet (all coins)" — so EVERY coin's
 * testnet account lives at `m/84'/1'/…`. This is what Sparrow/Electrum and testnet
 * faucets derive against; using the mainnet coin type on testnet produces addresses
 * no real testnet wallet is watching.
 */
function coinFor(asset: ChainAsset, network: ChainNetwork): number {
  return network === 'testnet' ? 1 : MAINNET_COIN_TYPE[asset];
}

/**
 * Re-serialize an extended key (as produced by @scure/bip32, which emits the
 * registered `xpub` version) under a different SLIP-132 version byte. This is the
 * inverse of the public side's neutral re-serialization, so a `zpub` this produces
 * decodes to the identical key `derive.ts` reads.
 */
function reSerializeVersion(extendedKey: string, versionHex: string): string {
  const raw = b58check.decode(extendedKey);
  const out = new Uint8Array(raw);
  out.set(hex.decode(versionHex), 0);
  return b58check.encode(out);
}

/**
 * SEED-SIDE — enclave/client only, never a server.
 *
 * Derive the account-level BIP84 extended PUBLIC key from a raw BIP39 seed.
 * Path: `m/84'/coin'/account'` — mainnet coin is BTC 0 / LTC 2; TESTNET coin is 1
 * for BOTH (SLIP-44 "Testnet (all coins)"), so a testnet account is `m/84'/1'/0'`
 * and serializes as a `vpub` (`tb1…`/`tltc1…` addresses). Returns PUBLIC material
 * only: the `zpub`/`Ltub`/`vpub`, its path, asset, and fingerprint.
 *
 * @param seed - the BIP39 seed bytes (private material — keep in the enclave)
 * @param opts - asset / account / ltcLabel / network
 */
export function seedToZpub(seed: Uint8Array, opts: ZpubOptions = {}): ZpubResult {
  if (!(seed instanceof Uint8Array) || seed.length < 16) {
    throw new Error('seedToZpub: seed must be a Uint8Array of at least 16 bytes');
  }
  const asset: ChainAsset = opts.asset ?? 'BTC';
  const account = opts.account ?? 0;
  if (!Number.isInteger(account) || account < 0 || account >= 0x80000000) {
    throw new Error(`seedToZpub: account must be an integer in [0, 2^31), got ${account}`);
  }
  const network = opts.network ?? 'mainnet';
  const coin = coinFor(asset, network);
  const path = `m/84'/${coin}'/${account}'`;

  const master = HDKey.fromMasterSeed(seed);
  const node = master.derive(path);
  if (!node.publicKey) {
    throw new Error('seedToZpub: derivation did not yield a public key');
  }
  // @scure/bip32 serializes under the registered xpub version; swap to the SLIP-132
  // output version (zpub / Ltub / vpub) WITHOUT ever serializing a private key.
  const xpub = node.publicExtendedKey;
  const versionHex = outputVersionHex(asset, network, opts.ltcLabel);
  const zpub = reSerializeVersion(xpub, versionHex);

  const fingerprint = hex.encode(
    new Uint8Array([
      (node.fingerprint >>> 24) & 0xff,
      (node.fingerprint >>> 16) & 0xff,
      (node.fingerprint >>> 8) & 0xff,
      node.fingerprint & 0xff,
    ]),
  );

  // NOTE: `master`, `node`, and `seed` hold private material; NONE of them leaves
  // this function. Only PUBLIC fields are returned.
  return { zpub, path, asset, fingerprint };
}

/**
 * SEED-SIDE — enclave/client only, never a server.
 *
 * Derive the account-level BIP84 `zpub`/`Ltub` from a BIP39 mnemonic. Validates the
 * mnemonic against the English wordlist, expands it to a seed
 * (`@scure/bip39` `mnemonicToSeedSync`, with the optional passphrase), and hands off
 * to {@link seedToZpub}. Returns PUBLIC material only.
 *
 * @param mnemonic - the BIP39 mnemonic (private material — keep in the enclave)
 * @param opts - asset / account / passphrase / ltcLabel / network
 */
export function mnemonicToZpub(mnemonic: string, opts: ZpubOptions = {}): ZpubResult {
  if (typeof mnemonic !== 'string' || mnemonic.trim() === '') {
    throw new Error('mnemonicToZpub: mnemonic must be a non-empty string');
  }
  const m = mnemonic.trim();
  if (!validateMnemonic(m, wordlist)) {
    // Deliberately do NOT echo the mnemonic back in the error.
    throw new Error('mnemonicToZpub: invalid BIP39 mnemonic (checksum/wordlist failed)');
  }
  const seed = mnemonicToSeedSync(m, opts.passphrase ?? '');
  return seedToZpub(seed, opts);
}
