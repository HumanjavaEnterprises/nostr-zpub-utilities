/**
 * Public types for nostr-zpub-utilities.
 *
 * The library derives PUBLIC receiving keys (a `zpub`/`Ltub` and the addresses under
 * it) from the same BIP39 seed root that yields a Nostr identity. Every shape here
 * describes PUBLIC material only — there is no type in this library that carries a
 * seed, an `nsec`, or a private scalar, by design (see SPEC "The one hard boundary").
 *
 * @packageDocumentation
 */

import type { ChainAsset, ChainNetwork, PurposeHint } from './versions.js';

export type { ChainAsset, ChainNetwork, PurposeHint } from './versions.js';

/** What {@link inspectZpub} reports about an extended PUBLIC key — no derivation. */
export interface ZpubInfo {
  /** SLIP-132 label of the supplied prefix (xpub/zpub/Ltub/…). */
  label: string;
  /** Assets this prefix may belong to. Length 2 = ambiguous (Litecoin has no BIP84 byte). */
  assets: ChainAsset[];
  /** The asset the prefix PINS, or null when the prefix is ambiguous. */
  asset: ChainAsset | null;
  network: ChainNetwork;
  /** What the prefix IMPLIES. This library always emits BIP84 P2WPKH anyway. */
  purpose: PurposeHint;
  /** BIP32 depth. A correct account-level key (m/84'/coin'/a') has depth 3. */
  depth: number;
  /** 4-byte parent fingerprint, hex. */
  parentFingerprint: string;
  /** 4-byte fingerprint of THIS key, hex — the stable identifier of the account. */
  fingerprint: string;
}

/** Options for the seed-side zpub derivation. */
export interface ZpubOptions {
  /** Chain to derive for — `'BTC'` (coin 0) or `'LTC'` (coin 2). Default `'BTC'`. */
  asset?: ChainAsset;
  /** BIP84 account index (the hardened depth-3 level). Default `0`. */
  account?: number;
  /** BIP39 passphrase (the "25th word"). Default `''`. */
  passphrase?: string;
  /** For LTC only: emit the registered `zpub` byte (default) or the Litecoin-definite `Ltub`. */
  ltcLabel?: 'zpub' | 'Ltub';
  /** Network. Default `'mainnet'`. */
  network?: ChainNetwork;
}

/** The PUBLIC result of a seed-side derivation. Carries no private material. */
export interface ZpubResult {
  /** The account-level extended PUBLIC key (BIP84 P2WPKH), depth 3. */
  zpub: string;
  /** The derivation path that produced it, e.g. `m/84'/0'/0'`. */
  path: string;
  /** The asset this account is for. */
  asset: ChainAsset;
  /** 4-byte fingerprint of the account key, hex. */
  fingerprint: string;
}

/** Options for reading a receive address off a public zpub. */
export interface AddressOptions {
  /** Address index on the chosen chain. Default `0`. */
  index?: number;
  /** 0 = external/receive chain (default), 1 = change/internal. */
  change?: 0 | 1;
  /**
   * The chain to encode for. REQUIRED when the key's prefix is ambiguous
   * (`xpub`/`zpub`/`tpub`/`vpub` — shared by BTC and LTC): omitting it throws an
   * {@link AmbiguousAssetError} rather than silently guessing BTC. Optional for a
   * chain-definite prefix (`Ltub`/`Mtub`/`ttub`/`ypub`/`upub`), where it is
   * validated against the prefix if given.
   */
  asset?: ChainAsset;
  /** Assert the key's network. Throws on mismatch. */
  network?: ChainNetwork;
}

/**
 * The one-root tie-in: the PUBLIC anchors derived from a single BIP39 mnemonic.
 * Returns `npub` + the two receiving `zpub`s — never an `nsec` or a seed.
 */
export interface Identity {
  /** NIP-06 Nostr public key (bech32), m/44'/1237'/0'/0/0. */
  npub: string;
  /** BTC BIP84 account zpub, m/84'/0'/0'. */
  zpubBTC: string;
  /** LTC BIP84 account zpub, m/84'/2'/0'. */
  zpubLTC: string;
}
