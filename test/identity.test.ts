import { describe, it, expect } from 'vitest';
import { mnemonicToIdentity, mnemonicToZpub } from '../src/index.js';
import { MNEMONIC } from './vectors.mjs';

describe('mnemonicToIdentity — one root, PUBLIC anchors only', () => {
  it('returns npub + the two receiving zpubs, and nothing else', async () => {
    const id = await mnemonicToIdentity(MNEMONIC);
    expect(Object.keys(id).sort()).toEqual(['npub', 'zpubBTC', 'zpubLTC']);
    expect(id.npub.startsWith('npub1')).toBe(true);
    expect(id.zpubBTC).toBe(mnemonicToZpub(MNEMONIC, { asset: 'BTC' }).zpub);
    expect(id.zpubLTC).toBe(mnemonicToZpub(MNEMONIC, { asset: 'LTC' }).zpub);
  });

  it('never surfaces an nsec, seed, or private byte', async () => {
    const id = await mnemonicToIdentity(MNEMONIC);
    const s = JSON.stringify(id);
    expect(s.includes('nsec')).toBe(false);
    expect(s.includes(MNEMONIC)).toBe(false);
    expect(/zprv|xprv/.test(s)).toBe(false);
  });

  it('rejects an empty mnemonic before touching the optional dep', async () => {
    await expect(mnemonicToIdentity('')).rejects.toThrow(/non-empty/);
  });
});
