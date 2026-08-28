import { describe, it, expect } from 'vitest';
import { base58check, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';

import { checkXpub, assertDistinctXpubs, mnemonicToZpub } from '../src/index.js';
import { MNEMONIC, BIP84_ZPUB } from './vectors.mjs';

const b58check = base58check(sha256);

/** Re-serialize an extended key with a different version and/or depth byte. */
function tweak(extendedKey: string, { versionHex, depth }: { versionHex?: string; depth?: number }) {
  const raw = b58check.decode(extendedKey);
  const out = new Uint8Array(raw);
  if (versionHex) out.set(hex.decode(versionHex), 0);
  if (depth !== undefined) out[4] = depth;
  return b58check.encode(out);
}

describe('checkXpub — go-live preflight (mirrors hj-pay)', () => {
  it('passes a correct BIP84 BTC account key (ok, no errors)', () => {
    // A proper depth-3 BIP84 zpub. The only warning is the intrinsic SLIP-132
    // ambiguity note (the `zpub` byte is shared by BTC/LTC) — depth and purpose
    // are correct, so no other warning fires.
    const res = checkXpub(BIP84_ZPUB, 'BTC');
    expect(res.ok).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.info?.depth).toBe(3);
    expect(res.warnings.every((w) => w.includes('does not pin a chain'))).toBe(true);
    expect(res.warnings.some((w) => w.includes('depth'))).toBe(false);
    expect(res.warnings.some((w) => w.includes('implies'))).toBe(false);
  });

  it('flags a wrong depth (depth ≠ 3)', () => {
    const badDepth = tweak(BIP84_ZPUB, { depth: 99 });
    const res = checkXpub(badDepth, 'BTC');
    expect(res.info?.depth).toBe(99);
    expect(res.warnings.some((w) => w.includes('depth is 99'))).toBe(true);
    expect(res.ok).toBe(true); // a warning, not a hard error
  });

  it('flags a non-BIP84 purpose byte (a bip44 xpub)', () => {
    const asXpub = tweak(BIP84_ZPUB, { versionHex: '0488b21e' }); // xpub → purpose bip44
    const res = checkXpub(asXpub, 'BTC');
    expect(res.warnings.some((w) => w.includes('bip44'))).toBe(true);
  });

  it('errors when the prefix cannot be the configured asset (ypub is BTC-only, asked as LTC)', () => {
    const asYpub = tweak(BIP84_ZPUB, { versionHex: '049d7cb2' }); // ypub → BTC only
    const res = checkXpub(asYpub, 'LTC');
    expect(res.ok).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
  });

  it('never throws — a malformed key returns { ok:false } with the error captured', () => {
    const res = checkXpub('not-a-key', 'BTC');
    expect(res.ok).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
  });
});

describe('assertDistinctXpubs — catch the same key on both chains', () => {
  it('throws when BTC and LTC are configured with the identical key', () => {
    expect(() => assertDistinctXpubs(BIP84_ZPUB, BIP84_ZPUB)).toThrow(/SAME key/);
  });

  it('passes when the two account keys genuinely differ (BTC coin 0 vs LTC coin 2)', () => {
    const btc = mnemonicToZpub(MNEMONIC, { asset: 'BTC' }).zpub;
    const ltc = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' }).zpub;
    expect(() => assertDistinctXpubs(btc, ltc)).not.toThrow();
  });
});
