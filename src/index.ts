/**
 * nostr-zpub-utilities — derive Bitcoin/Litecoin receiving keys from a Nostr identity root.
 *
 * One BIP39 mnemonic, two lives: the `npub` (who you are) and the `zpub` (where you
 * get paid), derived from the same seed on the same curve. The authoritative spec is
 * SPEC.md — read it first.
 *
 * THE ONE HARD BOUNDARY: seed-touching functions (`mnemonicToZpub`, `seedToZpub`,
 * `mnemonicToIdentity`) are ENCLAVE/CLIENT-ONLY and output PUBLIC material only. The
 * public side (`zpubToAddress`, `inspectZpub`, `assertPublicOnly`) is watch-only,
 * mirrors hj-pay byte-for-byte, and rejects every private-key shape.
 *
 * @packageDocumentation
 */

// ── Types ────────────────────────────────────────────────────────────────────
export type {
  ChainAsset,
  ChainNetwork,
  PurposeHint,
  ZpubInfo,
  ZpubOptions,
  ZpubResult,
  AddressOptions,
  Identity,
} from './types.js';

// ── Version vocabulary (SLIP-132) ─────────────────────────────────────────────
export {
  PUBLIC_VERSIONS,
  PRIVATE_VERSIONS,
  PRIVATE_PREFIXES,
  HRP,
  outputVersionHex,
  type VersionRow,
} from './versions.js';

// ── SEED-SIDE (enclave/client only) ───────────────────────────────────────────
export { seedToZpub, mnemonicToZpub } from './keys.js';
export { mnemonicToIdentity } from './identity.js';

// ── PUBLIC-SIDE (watch-only, safe anywhere; mirrors hj-pay) ────────────────────
export {
  zpubToAddress,
  zpubToAddressForAsset,
  inspectZpub,
  checkXpub,
  assertDistinctXpubs,
  assertPublicOnly,
  assertNoPrivateKeyMaterial,
  PrivateKeyMaterialError,
  AmbiguousAssetError,
  type ZpubCheck,
} from './derive.js';
