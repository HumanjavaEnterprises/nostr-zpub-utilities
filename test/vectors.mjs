/**
 * Shared test vectors — the ONE source of truth for the vitest suites
 * (`test/*.test.ts`) and the built-artifact smoke test (`scripts/smoke.mjs`).
 *
 * Authored as plain `.mjs` (not `.ts`) for the same reason the sibling repo's
 * `fixtures.mjs` is: the smoke test must import the BUILT `dist` and run under node
 * with zero transpile, so both consumers load the identical objects natively.
 *
 * The Bitcoin values are the PUBLISHED BIP-0084 "Test vectors" for the canonical
 * `abandon … about` mnemonic, account 0. If any of these change, derivation is wrong.
 */

/** The canonical BIP39 test mnemonic (BIP-0084 test vectors). */
export const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** The published account-level (m/84'/0'/0') extended PUBLIC key. Char-for-char. */
export const BIP84_ZPUB =
  'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs';

/** The account key's own 4-byte fingerprint (hex). */
export const BIP84_FINGERPRINT = 'fd13aac9';

/** Published BIP84 receive/change addresses for the account above. Char-for-char. */
export const BTC_VECTORS = [
  { path: "m/84'/0'/0'/0/0", change: 0, index: 0, address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' },
  { path: "m/84'/0'/0'/0/1", change: 0, index: 1, address: 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g' },
  { path: "m/84'/0'/0'/1/0", change: 1, index: 0, address: 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el' },
];

/** Litecoin SLIP-132 version bytes. */
export const LTUB_VERSION_HEX = '019da462';

/** SLIP-132 extended-PRIVATE version bytes, by label — used to build reject fixtures. */
export const PRIVATE_VERSION_HEX = {
  xprv: '0488ade4',
  yprv: '049d7878',
  zprv: '04b2430c',
  tprv: '04358394',
  uprv: '044a4e28',
  vprv: '045f18bc',
  Ltpv: '019d9cfe',
  Mtpv: '01b26792',
  ttpv: '0436ef7d',
};

/** The registered `zpub` public version byte — used to build the re-versioned-private trap. */
export const ZPUB_VERSION_HEX = '04b24746';
