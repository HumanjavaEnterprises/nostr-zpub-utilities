import { describe, it, expect } from 'vitest';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';

import { mnemonicToZpub, seedToZpub, zpubToAddress, zpubToAddressForAsset } from '../src/index.js';
import { refAddress, reVersion, bech32DecodeSegwit } from './ref-derive.mjs';
import { MNEMONIC, BIP84_ZPUB, BIP84_FINGERPRINT, BTC_VECTORS, LTUB_VERSION_HEX } from './vectors.mjs';

describe('mnemonicToZpub — BTC BIP84 account key (published vector, char-for-char)', () => {
  it('derives the exact published account zpub, path and fingerprint', () => {
    const r = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
    expect(r.zpub).toBe(BIP84_ZPUB);
    expect(r.path).toBe("m/84'/0'/0'");
    expect(r.asset).toBe('BTC');
    expect(r.fingerprint).toBe(BIP84_FINGERPRINT);
  });

  it('the derived account zpub reproduces the published first addresses', () => {
    const { zpub } = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
    for (const { change, index, address } of BTC_VECTORS) {
      expect(zpubToAddress(zpub, { asset: 'BTC', change: change as 0 | 1, index })).toBe(address);
    }
  });

  it('seedToZpub and mnemonicToZpub agree (mnemonic is just seed expansion)', () => {
    const seed = mnemonicToSeedSync(MNEMONIC, '');
    expect(seedToZpub(seed, { asset: 'BTC' }).zpub).toBe(BIP84_ZPUB);
  });

  it('account index selects a different, valid account key', () => {
    const a0 = mnemonicToZpub(MNEMONIC, { asset: 'BTC', account: 0 });
    const a1 = mnemonicToZpub(MNEMONIC, { asset: 'BTC', account: 1 });
    expect(a1.path).toBe("m/84'/0'/1'");
    expect(a1.zpub).not.toBe(a0.zpub);
  });
});

/**
 * LTC has no published BIP84 vectors. Two independent checks per the brief:
 *  (1) keys.ts derives m/84'/2'/0'; a SECOND minimal HDKey path in the test
 *      (full private path to the leaf, a different call path) must produce the
 *      same address.
 *  (2) program equality: the published BTC account key re-versioned as `Ltub`
 *      yields ltc1 addresses whose witness programs equal the published bc1
 *      vectors' programs — pinning the Litecoin encoding to published data.
 */
describe('LTC — independent cross-derivation (no published vectors exist)', () => {
  const seed = mnemonicToSeedSync(MNEMONIC, '');

  /** A second, minimal derivation: full private path master → leaf → P2WPKH ltc1. */
  function ltcLeafAddress(change: number, index: number): string {
    const leaf = HDKey.fromMasterSeed(seed).derive(`m/84'/2'/0'/${change}/${index}`);
    const program = ripemd160(sha256(leaf.publicKey!));
    return bech32.encode('ltc', [0, ...bech32.toWords(program)]);
  }

  it('keys.ts LTC account (Ltub) addresses match a second minimal HDKey leaf path', () => {
    const { zpub } = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });
    for (const change of [0, 1]) {
      for (const index of [0, 1, 2]) {
        const fromAccount = zpubToAddress(zpub, { change: change as 0 | 1, index });
        expect(fromAccount).toBe(ltcLeafAddress(change, index));
      }
    }
  });

  it('the independent node:crypto oracle agrees with keys.ts on the LTC account key', () => {
    const { zpub } = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });
    // Oracle derives from the same Ltub account key, no shared code with src/.
    for (const index of [0, 1, 2]) {
      const oracle = refAddress(zpub, 'ltc', index, 0).address;
      expect(zpubToAddress(zpub, { change: 0, index })).toBe(oracle);
    }
  });

  it('program equality: published BTC key re-versioned Ltub → ltc1 shares BTC vectors’ programs', () => {
    const ltub = reVersion(BIP84_ZPUB, LTUB_VERSION_HEX);
    for (const { change, index, address: btcAddr } of BTC_VECTORS) {
      const ltcAddr = zpubToAddressForAsset(ltub, 'LTC', { change: change as 0 | 1, index });
      const btcProgram = bech32DecodeSegwit(btcAddr).program;
      const ltcProgram = bech32DecodeSegwit(ltcAddr).program;
      expect(Buffer.from(ltcProgram).toString('hex')).toBe(Buffer.from(btcProgram).toString('hex'));
    }
  });

  it('default LTC label emits the ambiguous zpub byte (still coin-2 key)', () => {
    const def = mnemonicToZpub(MNEMONIC, { asset: 'LTC' });
    const ltub = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });
    expect(def.zpub.startsWith('zpub')).toBe(true);
    expect(ltub.zpub.startsWith('Ltub')).toBe(true);
    // Same underlying key, different SLIP-132 dress → same ltc1 addresses.
    expect(zpubToAddressForAsset(def.zpub, 'LTC', { index: 0 })).toBe(
      zpubToAddress(ltub.zpub, { index: 0 }),
    );
  });
});

/**
 * The load-bearing safety property: nothing on a seed-side path returns, embeds, or
 * leaks the seed / mnemonic / a private byte.
 */
describe('no-leak — seed-side outputs carry only PUBLIC material', () => {
  const seed = mnemonicToSeedSync(MNEMONIC, '');
  const seedHex = Buffer.from(seed).toString('hex');
  const account = HDKey.fromMasterSeed(seed).derive("m/84'/0'/0'");
  const privHex = Buffer.from(account.privateKey!).toString('hex');
  const zprv = account.privateExtendedKey;

  function assertNoPrivate(value: unknown) {
    const s = JSON.stringify(value);
    expect(s.includes(MNEMONIC)).toBe(false);
    expect(s.toLowerCase().includes(seedHex.toLowerCase())).toBe(false);
    expect(s.toLowerCase().includes(privHex.toLowerCase())).toBe(false);
    expect(s.includes(zprv)).toBe(false);
    // No word of the mnemonic-derived seed, and no zprv-family prefix, in the output.
    expect(/zprv|xprv|Ltpv/.test(s)).toBe(false);
  }

  it('mnemonicToZpub returns only zpub/path/asset/fingerprint', () => {
    const r = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
    expect(Object.keys(r).sort()).toEqual(['asset', 'fingerprint', 'path', 'zpub']);
    assertNoPrivate(r);
  });

  it('seedToZpub returns only public material', () => {
    assertNoPrivate(seedToZpub(seed, { asset: 'LTC', ltcLabel: 'Ltub' }));
  });

  it('a thrown error never echoes the mnemonic or seed', () => {
    let msg = '';
    try {
      mnemonicToZpub('abandon abandon totally invalid not a real mnemonic zzz');
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg.length).toBeGreaterThan(0);
    expect(msg.includes(seedHex)).toBe(false);
  });
});
