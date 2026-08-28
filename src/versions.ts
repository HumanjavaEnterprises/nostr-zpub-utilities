/**
 * SLIP-132 extended-key version bytes — the byte-for-byte shared vocabulary with
 * `hj-pay` (colabrelay.sdk `src/pay/derive.ts`).
 *
 * `PUBLIC_VERSIONS` is COPIED from hj-pay so the two libraries can never disagree
 * about what a given extended PUBLIC key means. `PRIVATE_VERSIONS` is the reject
 * set — every extended PRIVATE key version — used by {@link assertPublicOnly} so a
 * `zprv`/`Ltpv`/… (or a private key re-versioned to *wear* a public prefix) is
 * refused. The exhaustive guard is not the version table, though: it is the
 * decoded key byte (0x00 = private, 0x02/0x03 = public), which no re-versioning
 * can fake.
 *
 * @packageDocumentation
 */

/** Assets that settle on a chain and therefore have an address. */
export type ChainAsset = 'BTC' | 'LTC';
export type ChainNetwork = 'mainnet' | 'testnet';
/** BIP purpose the SLIP-132 version prefix implies. This library only EMITS bip84. */
export type PurposeHint = 'bip44' | 'bip49' | 'bip84';

export interface VersionRow {
  /**
   * Which assets this prefix may legitimately belong to. Litecoin never got its own
   * registered BIP84 version byte — Electrum-LTC and friends hand out a plain `zpub`
   * (and older wallets an `xpub`) for a Litecoin native-segwit account. So those
   * prefixes are AMBIGUOUS by construction and we accept them for either chain;
   * `Ltub`/`Mtub`/`ttub` are Litecoin-definite.
   */
  assets: ChainAsset[];
  network: ChainNetwork;
  label: string;
  purpose: PurposeHint;
}

/**
 * SLIP-132 extended PUBLIC key version bytes we accept.
 *
 * ⚠️ COPIED VERBATIM from hj-pay (`colabrelay.sdk.src/src/pay/derive.ts`
 * `PUBLIC_VERSIONS`). Keep the two in lockstep — a divergence here means the two
 * libraries would derive different addresses (or accept/reject differently) for the
 * same key.
 */
export const PUBLIC_VERSIONS: Record<string, VersionRow> = {
  // Bitcoin-registered mainnet (xpub/zpub also used by Litecoin wallets)
  '0488b21e': { assets: ['BTC', 'LTC'], network: 'mainnet', label: 'xpub', purpose: 'bip44' },
  '049d7cb2': { assets: ['BTC'], network: 'mainnet', label: 'ypub', purpose: 'bip49' },
  '04b24746': { assets: ['BTC', 'LTC'], network: 'mainnet', label: 'zpub', purpose: 'bip84' },
  // Bitcoin-registered testnet
  '043587cf': { assets: ['BTC', 'LTC'], network: 'testnet', label: 'tpub', purpose: 'bip44' },
  '044a5262': { assets: ['BTC'], network: 'testnet', label: 'upub', purpose: 'bip49' },
  '045f1cf6': { assets: ['BTC', 'LTC'], network: 'testnet', label: 'vpub', purpose: 'bip84' },
  // Litecoin-definite mainnet
  '019da462': { assets: ['LTC'], network: 'mainnet', label: 'Ltub', purpose: 'bip44' },
  '01b26ef6': { assets: ['LTC'], network: 'mainnet', label: 'Mtub', purpose: 'bip49' },
  // Litecoin-definite testnet
  '0436f6e1': { assets: ['LTC'], network: 'testnet', label: 'ttub', purpose: 'bip44' },
};

/**
 * Extended PRIVATE key versions — listed so an error can name what was handed in.
 * COPIED from hj-pay's `PRIVATE_VERSIONS`. The 0x00 key-byte check in
 * {@link assertPublicOnly} is the real, exhaustive guard.
 */
export const PRIVATE_VERSIONS: Record<string, string> = {
  '0488ade4': 'xprv',
  '049d7878': 'yprv',
  '04b2430c': 'zprv',
  '04358394': 'tprv',
  '044a4e28': 'uprv',
  '045f18bc': 'vprv',
  '019d9cfe': 'Ltpv',
  '01b26792': 'Mtpv',
  '0436ef7d': 'ttpv',
};

/** Human-readable prefixes that mean "this string can move money". COPIED from hj-pay. */
export const PRIVATE_PREFIXES = [
  'xprv',
  'yprv',
  'zprv',
  'tprv',
  'uprv',
  'vprv',
  'Ltpv',
  'Mtpv',
  'ttpv',
  'nsec', // Nostr private key — also never ours to hold
];

/** bech32 human-readable parts, per asset + network. COPIED from hj-pay's `HRP`. */
export const HRP: Record<ChainAsset, Record<ChainNetwork, string>> = {
  BTC: { mainnet: 'bc', testnet: 'tb' },
  LTC: { mainnet: 'ltc', testnet: 'tltc' },
};

/** The neutral xpub version — every accepted key is re-serialized to this for @scure/bip32. */
export const XPUB_VERSION = new Uint8Array([0x04, 0x88, 0xb2, 0x1e]);

/**
 * The extended PUBLIC version byte this library EMITS for a given asset / network /
 * label choice. BTC and (default) LTC native-segwit accounts serialize under the
 * registered `zpub` byte; Litecoin callers may opt into the Litecoin-definite `Ltub`.
 */
export function outputVersionHex(
  asset: ChainAsset,
  network: ChainNetwork,
  ltcLabel: 'zpub' | 'Ltub' = 'zpub',
): string {
  if (network === 'testnet') return '045f1cf6'; // vpub — BIP84 testnet public
  if (asset === 'LTC' && ltcLabel === 'Ltub') return '019da462'; // Ltub (BIP44 SLIP-132; Litecoin-definite)
  return '04b24746'; // zpub — BIP84 mainnet public
}
