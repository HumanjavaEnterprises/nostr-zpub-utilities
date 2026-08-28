import { describe, it, expect } from 'vitest';
import {
  assertPublicOnly,
  zpubToAddress,
  zpubToAddressForAsset,
  inspectZpub,
  PrivateKeyMaterialError,
} from '../src/index.js';
import { buildRejects } from './reject-keys.mjs';
import { BIP84_ZPUB } from './vectors.mjs';

const rejects = buildRejects();

describe('assertPublicOnly rejects every private-key shape', () => {
  it.each(rejects)('rejects $label', ({ key }) => {
    expect(() => assertPublicOnly(key)).toThrow();
  });

  it('the zprv re-versioned to wear a zpub prefix is caught by the decoded key byte', () => {
    const trap = rejects.find((r) => r.label === 'zprv-reversioned-as-zpub');
    expect(trap).toBeDefined();
    expect(trap!.key.startsWith('zpub')).toBe(true); // looks public…
    expect(() => assertPublicOnly(trap!.key)).toThrow(PrivateKeyMaterialError); // …but is refused
  });

  it('accepts a genuine public zpub', () => {
    expect(() => assertPublicOnly(BIP84_ZPUB)).not.toThrow();
  });
});

describe('every public-path function also rejects private material', () => {
  const fns: Array<{ name: string; call: (k: string) => unknown }> = [
    { name: 'zpubToAddress', call: (k) => zpubToAddress(k, { index: 0 }) },
    { name: 'zpubToAddressForAsset', call: (k) => zpubToAddressForAsset(k, 'BTC', { index: 0 }) },
    { name: 'inspectZpub', call: (k) => inspectZpub(k) },
  ];

  for (const { name, call } of fns) {
    it.each(rejects)(`${name} rejects $label`, ({ key }) => {
      expect(() => call(key)).toThrow();
    });
  }
});

describe('the guard error never echoes the private input', () => {
  it('does not include the raw 64-hex scalar in the message', () => {
    const scalar = rejects.find((r) => r.label === 'raw-64-hex-scalar')!.key;
    let msg = '';
    try {
      assertPublicOnly(scalar);
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg.includes(scalar)).toBe(false);
  });
});
