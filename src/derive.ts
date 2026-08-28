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
 * Thrown when a caller asks for an address off an AMBIGUOUS-prefix key (`xpub`/
 * `zpub`/`tpub`/`vpub` — version bytes both BTC and LTC wallets emit) without
 * naming the chain. Defaulting silently to BTC would hand out `bc1…` addresses for
 * a Litecoin account (and vice versa) that no wallet is watching — a real-money
 * footgun. The chain MUST be explicit for these prefixes.
 */
export class AmbiguousAssetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AmbiguousAssetError';
  }
}

/**
 * Resolve which chain to encode for. A Litecoin-definite prefix (`Ltub`/`Mtub`/
 * `ttub`) pins LTC; a Bitcoin-definite prefix (`ypub`/`upub`) pins BTC. For an
 * AMBIGUOUS prefix the caller MUST name `asset` — otherwise we throw rather than
 * guess. A caller-supplied `asset` is validated against any definite prefix.
 */
function resolveAsset(info: ZpubInfo, requested?: ChainAsset): ChainAsset {
  if (info.asset) {
    // Definite prefix. A conflicting explicit asset is a hard error.
    if (requested && requested !== info.asset) {
      throw new Error(
        `asset mismatch — a ${info.label} is a ${info.assets.join('/')} key, but ${requested} was requested`,
      );
    }
    return info.asset;
  }
  // Ambiguous prefix (xpub/zpub/tpub/vpub — shared by BTC and LTC).
  if (!requested) {
    throw new AmbiguousAssetError(
      `a ${info.label} prefix is shared by BTC and LTC and does not pin a chain — ` +
        'refusing to guess (defaulting to BTC would hand out an unwatched wrong-chain address). ' +
        "Pass { asset: 'BTC' | 'LTC' }, or use zpubToAddressForAsset(zpub, asset).",
    );
  }
  if (!info.assets.includes(requested)) {
    throw new Error(
      `asset mismatch — a ${info.label} is a ${info.assets.join('/')} key, but ${requested} was requested`,
    );
  }
  return requested;
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
  // SAFE BY DEFAULT: a definite prefix pins the chain; an AMBIGUOUS prefix forces
  // the caller to name `asset` (throws otherwise). We never silently guess BTC.
  const asset = resolveAsset(info, opts.asset);
  return encodeP2wpkh(neutral, asset, info.network, change, index);
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
  const resolved = resolveAsset(info, asset);
  return encodeP2wpkh(neutral, resolved, info.network, change, index);
}

export interface ZpubCheck {
  ok: boolean;
  info?: ZpubInfo;
  errors: string[];
  warnings: string[];
}

/**
 * Go-live preflight for a supplied account key — mirrors hj-pay's `checkXpub`.
 * Never throws; returns findings so a caller (e.g. a /health probe) can surface
 * them without crashing.
 *
 * The load-bearing checks: this library ALWAYS emits BIP84 P2WPKH. If a caller
 * hands in a BIP44 `Ltub`/`xpub` (from an m/44' account), or a key at the wrong
 * depth, the `bc1`/`ltc1` addresses are derived from the right chain of keys but
 * will NOT appear in a wallet that is only watching its legacy/other script type.
 * The ambiguous-prefix case is flagged too — the exact wrong-chain footgun the
 * primary derivation API now refuses outright.
 *
 * @param zpub - the extended public key to check
 * @param asset - the chain it is configured for
 * @param label - a name used in messages
 */
export function checkXpub(zpub: string, asset: ChainAsset, label = 'zpub'): ZpubCheck {
  const errors: string[] = [];
  const warnings: string[] = [];
  let info: ZpubInfo | undefined;
  try {
    info = inspectZpub(zpub, label);
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
    return { ok: false, errors, warnings };
  }
  if (!info.assets.includes(asset)) {
    errors.push(
      `${label}: a ${info.label} is a ${info.assets.join('/')} key, but it is configured as ${asset}`,
    );
  } else if (info.asset === null) {
    warnings.push(
      `${label}: prefix "${info.label}" does not pin a chain (Litecoin has no registered BIP84 version byte). ` +
        `It will be treated as ${asset} — confirm this is the ${asset} account key, because the two chains ` +
        'derive different addresses from the same key and only one wallet will be watching.',
    );
  }
  if (info.depth !== 3) {
    warnings.push(
      `${label}: BIP32 depth is ${info.depth}, expected 3 (an ACCOUNT key, m/84'/coin'/0'). ` +
        'Addresses will be derived as <key>/<change>/<index> — confirm that matches your wallet.',
    );
  }
  if (info.purpose !== 'bip84') {
    warnings.push(
      `${label}: prefix "${info.label}" implies ${info.purpose}, but this library always emits BIP84 ` +
        'P2WPKH. Export the NATIVE SEGWIT account key from your wallet so it watches these addresses.',
    );
  }
  return { ok: errors.length === 0, info, errors, warnings };
}

/**
 * Go-live guard — mirrors hj-pay's `assertDistinctXpubs`. The BTC and LTC account
 * keys MUST be different keys. Pasting the same key into both is the single most
 * likely mistake, and because `xpub`/`zpub` are ambiguous prefixes nothing else
 * would catch it — the two chains would derive different addresses from the same
 * key and only one wallet would ever see the money.
 *
 * @param zpubBtc - the key configured for BTC
 * @param zpubLtc - the key configured for LTC
 */
export function assertDistinctXpubs(zpubBtc: string, zpubLtc: string): void {
  const a = inspectZpub(zpubBtc, 'zpubBTC');
  const b = inspectZpub(zpubLtc, 'zpubLTC');
  if (a.fingerprint === b.fingerprint) {
    throw new Error(
      `zpubBTC and zpubLTC are the SAME key (fingerprint ${a.fingerprint}). ` +
        'Derive/export a separate native-segwit account key per chain (BTC coin 0, LTC coin 2).',
    );
  }
}

/** The shared, verified derivation core: neutral xpub → BIP84 P2WPKH bech32. */
function encodeP2wpkh(
  neutral: string,
  asset: ChainAsset,
  network: ZpubInfo['network'],
  change: 0 | 1,
  index: number,
): string {
  const hd = HDKey.fromExtendedKey(neutral);
  const child = hd.deriveChild(change).deriveChild(index);
  const pub = child.publicKey;
  if (!pub || pub.length !== 33) {
    throw new Error('derivation did not produce a compressed public key');
  }
  const program = ripemd160(sha256(pub));
  const hrp = HRP[asset][network];
  // witness v0 + 20-byte program = P2WPKH (BIP84 / BIP173).
  return bech32.encode(hrp, [0, ...bech32.toWords(program)]);
}
