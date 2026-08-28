import { describe, it, expect } from 'vitest';
import {
  zpubToAddress,
  zpubToAddressForAsset,
  inspectZpub,
  mnemonicToZpub,
  AmbiguousAssetError,
} from '../src/index.js';
// The INDEPENDENT oracle (node:crypto only, shares no code with src/) — the
// round-trip pin. hj-pay's own tests use this exact implementation, so agreeing
// with it pins this library to hj-pay byte-for-byte.
import { refAddress } from './ref-derive.mjs';
import { MNEMONIC, BIP84_ZPUB, BIP84_FINGERPRINT, BTC_VECTORS } from './vectors.mjs';

describe('zpubToAddress — published BIP84 Bitcoin vectors (char-for-char)', () => {
  it.each(BTC_VECTORS)('$path -> $address', ({ change, index, address }) => {
    expect(zpubToAddress(BIP84_ZPUB, { asset: 'BTC', change: change as 0 | 1, index })).toBe(address);
  });

  it('round-trip pin: matches the independent node:crypto oracle (== hj-pay)', () => {
    for (const { change, index, address } of BTC_VECTORS) {
      const oracle = refAddress(BIP84_ZPUB, 'bc', index, change).address;
      expect(oracle).toBe(address); // oracle reproduces the published vector
      expect(zpubToAddress(BIP84_ZPUB, { asset: 'BTC', change: change as 0 | 1, index })).toBe(oracle);
    }
  });
});

describe('inspectZpub', () => {
  it('reads the account key without deriving', () => {
    const info = inspectZpub(BIP84_ZPUB);
    expect(info.label).toBe('zpub');
    expect(info.purpose).toBe('bip84');
    expect(info.network).toBe('mainnet');
    expect(info.depth).toBe(3);
    expect(info.fingerprint).toBe(BIP84_FINGERPRINT);
    // zpub is an ambiguous BTC/LTC prefix — no single asset is pinned.
    expect(info.assets).toEqual(['BTC', 'LTC']);
    expect(info.asset).toBeNull();
  });
});

/**
 * Regression — the LTC ambiguity footgun (MEDIUM, real money). An LTC account
 * exported under the shared `zpub` version byte must NEVER silently yield a `bc1`
 * Bitcoin address through the primary API. The safe path is the default; the
 * dangerous default is impossible.
 */
describe('zpubToAddress — no silent wrong-chain default (LTC footgun)', () => {
  it('an ambiguous zpub with NO asset throws AmbiguousAssetError (never guesses BTC)', () => {
    expect(() => zpubToAddress(BIP84_ZPUB, { index: 0 })).toThrow(AmbiguousAssetError);
  });

  it('an LTC-derived default (ambiguous) zpub does NOT silently produce a bc1 address', () => {
    // A real Litecoin account, exported under the shared `zpub` prefix (the footgun input).
    const ltcDefault = mnemonicToZpub(MNEMONIC, { asset: 'LTC' });
    expect(ltcDefault.zpub.startsWith('zpub')).toBe(true);
    // Primary API with no asset: must refuse, not hand out an unwatched bc1 address.
    expect(() => zpubToAddress(ltcDefault.zpub, { index: 0 })).toThrow(AmbiguousAssetError);
    // Named as LTC, it yields the correct ltc1 address.
    const addr = zpubToAddress(ltcDefault.zpub, { asset: 'LTC', index: 0 });
    expect(addr.startsWith('ltc1')).toBe(true);
    expect(addr.startsWith('bc1')).toBe(false);
  });

  it('a chain-definite prefix still needs no asset (Ltub → ltc1)', () => {
    const ltub = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });
    expect(zpubToAddress(ltub.zpub, { index: 0 }).startsWith('ltc1')).toBe(true);
  });

  it('a conflicting explicit asset on a definite prefix is rejected', () => {
    const ltub = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });
    expect(() => zpubToAddress(ltub.zpub, { asset: 'BTC', index: 0 })).toThrow(/mismatch/);
  });
});

describe('zpubToAddressForAsset', () => {
  it('an ambiguous zpub, read as LTC, gives ltc1 with the SAME witness program as bc1', () => {
    const btc = zpubToAddress(BIP84_ZPUB, { asset: 'BTC', change: 0, index: 0 });
    const ltc = zpubToAddressForAsset(BIP84_ZPUB, 'LTC', { change: 0, index: 0 });
    expect(btc.startsWith('bc1')).toBe(true);
    expect(ltc.startsWith('ltc1')).toBe(true);
    // Same account key, same pubkey → identical witness program body, different HRP.
    const btcBody = btc.slice(btc.indexOf('1') + 1, -6);
    const ltcBody = ltc.slice(ltc.indexOf('1') + 1, -6);
    expect(ltcBody).toBe(btcBody);
  });
});
