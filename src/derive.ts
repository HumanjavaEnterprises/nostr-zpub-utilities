/**
 * PUBLIC-SIDE (watch-only) logic — safe to run anywhere, INCLUDING a server.
 *
 * This module never sees a seed. It accepts EXTENDED PUBLIC KEYS ONLY and reads
 * addresses off them. Its address derivation MIRRORS hj-pay
 * (`colabrelay.sdk.src/src/pay/derive.ts`) byte-for-byte — same decode, same
 * neutral re-serialization for @scure/bip32, same BIP84 P2WPKH bech32 encoding —
 * so the two libraries can never disagree about which address a `zpub` produces.
 *
 * Any input carrying private key material (xprv/yprv/zprv/tprv/uprv/vprv/Ltpv/
 * Mtpv/ttpv, an `nsec`, a WIF, a mnemonic, a raw 32-byte scalar) is rejected —
 * twice: once on the human-readable prefix / known private version byte, once on
 * the decoded serialization's key byte (a BIP32 extended PRIVATE key has 0x00
 * where a public key has 0x02/0x03). Re-versioning a `zprv` to wear a `zpub`
 * prefix does NOT get past the second check.
 *
 * @packageDocumentation
 */

import { HDKey } from '@scure/bip32';
import { base58check, bech32, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

import {
  PUBLIC_VERSIONS,
  PRIVATE_VERSIONS,
  PRIVATE_PREFIXES,
  HRP,
  XPUB_VERSION,
  type ChainAsset,
} from './versions.js';
import type { ZpubInfo, AddressOptions } from './types.js';

const b58check = base58check(sha256);
const HARDENED = 0x80000000;

/** Thrown whenever an input smells like private key material. */
export class PrivateKeyMaterialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PrivateKeyMaterialError';
  }
}

/**
 * Throw if `value` looks like PRIVATE key material — before any decode. Mirrors
 * hj-pay's `assertNoPrivateKeyMaterial`: rejects known private prefixes, a raw
 * 64-hex scalar, and anything that looks like a ≥12-word seed phrase.
 *
 * @param value - the string to screen
 * @param label - a name for the value, used in the error message
 */
export function assertNoPrivateKeyMaterial(value: string, label = 'value'): void {
  const v = (value ?? '').trim();
  if (!v) return;
  for (const p of PRIVATE_PREFIXES) {
    if (v.startsWith(p)) {
      throw new PrivateKeyMaterialError(
        `${label} looks like PRIVATE key material ("${p}…"). ` +
          'This library is watch-only on the public side and must never receive a private key. ' +
          'Supply the extended PUBLIC key (zpub/xpub/Ltub).',
      );
    }
  }
  // A bare 12/24-word mnemonic or a 64-hex scalar has no business here either.
  if (/^[0-9a-fA-F]{64}$/.test(v)) {
    throw new PrivateKeyMaterialError(
      `${label} is 64 hex chars — that is a raw key/seed, not a zpub. Refusing.`,
    );
  }
  if (v.split(/\s+/).length >= 12) {
    throw new PrivateKeyMaterialError(
      `${label} looks like a seed phrase. Refusing — the public side never handles seeds.`,
    );
  }
}

interface Decoded {
  info: ZpubInfo;
  /** The same key re-serialized under the plain xpub version, for @scure/bip32. */
  neutral: string;
}

function decodeZpub(zpub: string, label = 'zpub'): Decoded {
  if (typeof zpub !== 'string' || zpub.trim() === '') {
    throw new Error(`${label} is empty`);
  }
  const s = zpub.trim();
  assertNoPrivateKeyMaterial(s, label);

  let raw: Uint8Array;
  try {
    raw = b58check.decode(s);
  } catch {
    throw new Error(`${label} is not valid base58check`);
  }
  if (raw.length !== 78) {
    throw new Error(`${label} is not a 78-byte BIP32 serialization (got ${raw.length})`);
  }

  const version = hex.encode(raw.slice(0, 4));

  // Guard #1 (naming): a known extended-private version byte.
  const privLabel = PRIVATE_VERSIONS[version];
  if (privLabel) {
    throw new PrivateKeyMaterialError(
      `${label} decodes to an extended PRIVATE key (${privLabel}). Refusing — this side is watch-only.`,
    );
  }
  // Guard #2 (exhaustive): byte 45 is 0x00 for every extended PRIVATE key and
  // 0x02/0x03 for every extended PUBLIC key, WHATEVER the version bytes claim.
  // This is what catches a zprv re-versioned to wear a zpub prefix.
  const keyByte = raw[45];
  if (keyByte !== 0x02 && keyByte !== 0x03) {
    throw new PrivateKeyMaterialError(
      `${label} does not carry a compressed PUBLIC key (key byte 0x${keyByte
        .toString(16)
        .padStart(2, '0')}). Refusing — this is private key material or corrupt.`,
    );
  }

  const row = PUBLIC_VERSIONS[version];
  if (!row) {
    throw new Error(
      `${label} has unknown version bytes 0x${version}. Supported: ` +
        Object.values(PUBLIC_VERSIONS)
          .map((r) => r.label)
          .join(', '),
    );
  }

  const neutralBytes = new Uint8Array(raw);
  neutralBytes.set(XPUB_VERSION, 0);

  const identifier = ripemd160(sha256(raw.slice(45, 78)));

  return {
    info: {
      label: row.label,
      assets: row.assets,
      asset: row.assets.length === 1 ? row.assets[0] : null,
      network: row.network,
      purpose: row.purpose,
      depth: raw[4],
      parentFingerprint: hex.encode(raw.slice(5, 9)),
      fingerprint: hex.encode(identifier.slice(0, 4)),
    },
    neutral: b58check.encode(neutralBytes),
  };
}

/**
 * The hard guard on the public path — throws on ANY private-key shape.
 *
 * Rejects, in order: known private prefixes / raw scalar / seed phrase (string
 * screen), then a known extended-private version byte, then — the exhaustive one —
 * a decoded key byte that is not 0x02/0x03. A real `zprv` re-serialized under the
 * `zpub` version byte passes the prefix check but fails the key-byte check.
 *
 * @param key - the string to assert is public-only
 * @param label - a name for the value, used in the error message
 */
export function assertPublicOnly(key: string, label = 'key'): void {
  // decodeZpub runs every guard (prefix + private version + 0x00 key byte) and
  // throws on anything that is not a well-formed extended PUBLIC key.
  decodeZpub(key, label);
}

/**
 * Inspect an extended PUBLIC key without deriving anything. Throws on private material.
 *
 * @param zpub - the extended public key
 * @param label - a name used in any error message
 */
export function inspectZpub(zpub: string, label = 'zpub'): ZpubInfo {
  return decodeZpub(zpub, label).info;
}

/**
 * Derive a BIP84 P2WPKH receive address from an account-level extended PUBLIC key.
 *
 * MIRRORS hj-pay's `deriveAddress`: neutral-versioned key → `HDKey.fromExtendedKey`
 * → `deriveChild(change).deriveChild(index)` → hash160(pubkey) → witness-v0 bech32.
 * Deterministic: same (zpub, index, change) → same address, forever.
 *
 * @param zpub - the account-level extended public key (depth 3)
 * @param opts - `index` (default 0), `change` (0 receive / 1 change), `network`
 * @returns a `bc1…` (BTC) or `ltc1…` (LTC) native-segwit address
 */
export function zpubToAddress(zpub: string, opts: AddressOptions = {}): string {
  const index = opts.index ?? 0;
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
    throw new Error(`derivation index must be an integer in [0, 2^31), got ${index}`);
  }
  const change = opts.change ?? 0;
  if (change !== 0 && change !== 1) {
    throw new Error(`change must be 0 or 1, got ${change}`);
  }

  const { info, neutral } = decodeZpub(zpub, 'zpub');
  if (opts.network && opts.network !== info.network) {
    throw new Error(
      `network mismatch — ${info.label} is ${info.network}, ${opts.network} was requested`,
    );
  }
  // Ambiguous prefix (xpub/zpub) → default to BTC HRP; a Litecoin-definite prefix
  // (Ltub/Mtub/ttub) pins LTC. This matches hj-pay's asset resolution.
  const asset: ChainAsset = info.asset ?? 'BTC';

  const hd = HDKey.fromExtendedKey(neutral);
  const child = hd.deriveChild(change).deriveChild(index);
  const pub = child.publicKey;
  if (!pub || pub.length !== 33) {
    throw new Error('derivation did not produce a compressed public key');
  }

  const program = ripemd160(sha256(pub));
  const hrp = HRP[asset][info.network];
  // witness v0 + 20-byte program = P2WPKH (BIP84 / BIP173).
  return bech32.encode(hrp, [0, ...bech32.toWords(program)]);
}

/**
 * Same as {@link zpubToAddress}, but pins the chain explicitly (for the ambiguous
 * `xpub`/`zpub` prefixes that both BTC and LTC wallets emit). The HRP is taken
 * from `asset`; the version's own network still governs mainnet vs testnet.
 */
export function zpubToAddressForAsset(
  zpub: string,
  asset: ChainAsset,
  opts: AddressOptions = {},
): string {
  const info = inspectZpub(zpub);
  if (info.asset && info.asset !== asset) {
    throw new Error(
      `asset mismatch — a ${info.label} is a ${info.assets.join('/')} key, but ${asset} was requested`,
    );
  }
  const index = opts.index ?? 0;
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
    throw new Error(`derivation index must be an integer in [0, 2^31), got ${index}`);
  }
  const change = opts.change ?? 0;
  if (change !== 0 && change !== 1) {
    throw new Error(`change must be 0 or 1, got ${change}`);
  }
  const { neutral } = decodeZpub(zpub, 'zpub');
  const hd = HDKey.fromExtendedKey(neutral);
  const child = hd.deriveChild(change).deriveChild(index);
  const pub = child.publicKey;
  if (!pub || pub.length !== 33) {
    throw new Error('derivation did not produce a compressed public key');
  }
  const program = ripemd160(sha256(pub));
  const hrp = HRP[asset][info.network];
  return bech32.encode(hrp, [0, ...bech32.toWords(program)]);
}
