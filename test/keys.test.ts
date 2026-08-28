import { describe, it, expect } from 'vitest';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';

import {
  mnemonicToZpub,
  seedToZpub,
  zpubToAddress,
  zpubToAddressForAsset,
  inspectZpub,
} from '../src/index.js';
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
 * Testnet uses SLIP-44 coin_type 1 for EVERY coin (`m/84'/1'/0'`), not the mainnet
 * coin type — otherwise a Sparrow/Electrum testnet wallet (which derives against
 * coin 1) would never see these addresses. No single canonical published BIP84
 * testnet vector exists, so pin to an independent HDKey derivation.
 */
describe('testnet — network-aware coin_type (m/84\'/1\'/0\', SLIP-44 coin 1)', () => {
  const seed = mnemonicToSeedSync(MNEMONIC, '');

  /** Independent leaf derivation for a full testnet path → P2WPKH on the given HRP. */
  function leafAddress(path: string, hrp: string): string {
    const leaf = HDKey.fromMasterSeed(seed).derive(path);
    const program = ripemd160(sha256(leaf.publicKey!));
    return bech32.encode(hrp, [0, ...bech32.toWords(program)]);
  }

  it('BTC testnet derives at m/84\'/1\'/0\' as a vpub (NOT m/84\'/0\'/0\')', () => {
    const r = mnemonicToZpub(MNEMONIC, { asset: 'BTC', network: 'testnet' });
    expect(r.path).toBe("m/84'/1'/0'");
    const info = inspectZpub(r.zpub);
    expect(info.label).toBe('vpub');
    expect(info.network).toBe('testnet');
    expect(info.purpose).toBe('bip84');
    expect(info.depth).toBe(3);
  });

  it('BTC testnet address0 matches an independent HDKey m/84\'/1\'/0\'/0/0 derivation (tb1)', () => {
    const { zpub } = mnemonicToZpub(MNEMONIC, { asset: 'BTC', network: 'testnet' });
    const fromApi = zpubToAddress(zpub, { asset: 'BTC', change: 0, index: 0 });
    expect(fromApi.startsWith('tb1')).toBe(true);
    expect(fromApi).toBe(leafAddress("m/84'/1'/0'/0/0", 'tb'));
    // And NOT the mainnet-coin-path address (the bug would have produced this).
    expect(fromApi).not.toBe(leafAddress("m/84'/0'/0'/0/0", 'tb'));
  });

  it('LTC testnet also uses coin 1 and yields tltc1 via zpubToAddressForAsset', () => {
    const { zpub, path } = mnemonicToZpub(MNEMONIC, { asset: 'LTC', network: 'testnet' });
    expect(path).toBe("m/84'/1'/0'");
    const addr = zpubToAddressForAsset(zpub, 'LTC', { change: 0, index: 0 });
    expect(addr.startsWith('tltc1')).toBe(true);
    expect(addr).toBe(leafAddress("m/84'/1'/0'/0/0", 'tltc'));
  });

  it('BTC and LTC testnet share the coin-1 key (both m/84\'/1\'/0\') — same underlying node', () => {
    const btc = mnemonicToZpub(MNEMONIC, { asset: 'BTC', network: 'testnet' });
    const ltc = mnemonicToZpub(MNEMONIC, { asset: 'LTC', network: 'testnet' });
    // Same path, same vpub serialization (coin 1 collapses both onto one testnet key).
    expect(btc.fingerprint).toBe(ltc.fingerprint);
    // tb1 vs tltc1 differ only by HRP — same witness program body.
    const tb = zpubToAddressForAsset(btc.zpub, 'BTC', { index: 0 });
    const tltc = zpubToAddressForAsset(ltc.zpub, 'LTC', { index: 0 });
    expect(tb.slice(tb.indexOf('1') + 1, -6)).toBe(tltc.slice(tltc.indexOf('1') + 1, -6));
  });
});

/** Guard: the network-aware fix must NOT have moved the mainnet account paths. */
describe('mainnet paths are unchanged by the testnet fix', () => {
  it('BTC mainnet is still m/84\'/0\'/0\' and LTC mainnet still m/84\'/2\'/0\'', () => {
    expect(mnemonicToZpub(MNEMONIC, { asset: 'BTC' }).path).toBe("m/84'/0'/0'");
    expect(mnemonicToZpub(MNEMONIC, { asset: 'BTC', network: 'mainnet' }).path).toBe("m/84'/0'/0'");
    expect(mnemonicToZpub(MNEMONIC, { asset: 'LTC' }).path).toBe("m/84'/2'/0'");
    expect(mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' }).path).toBe("m/84'/2'/0'");
  });

  it('the mainnet BTC account zpub is byte-for-byte the published vector', () => {
    expect(mnemonicToZpub(MNEMONIC, { asset: 'BTC' }).zpub).toBe(BIP84_ZPUB);
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
