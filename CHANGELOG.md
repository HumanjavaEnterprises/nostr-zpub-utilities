# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-28

Initial draft release — derive Bitcoin/Litecoin receiving keys from a Nostr identity root.

### Added
- **[SPEC.md](SPEC.md)** — the authoritative spec: one mnemonic → both a Nostr identity and a BIP84
  receiving hierarchy; the one hard boundary (seed-side is enclave-only, outputs public material only);
  what it derives; the correctness gates; the non-goals.
- **Seed-side (enclave/client only)**:
  - `mnemonicToZpub(mnemonic, opts)` / `seedToZpub(seed, opts)` — derive the BIP84 account-level
    `zpub`/`Ltub` at `m/84'/coin'/account'` (BTC coin 0, LTC coin 2). Returns PUBLIC material only
    (`{ zpub, path, asset, fingerprint }`).
  - `mnemonicToIdentity(mnemonic)` — the one-root tie-in: NIP-06 `npub` + BTC/LTC `zpub`s from a single
    mnemonic. Returns PUBLIC anchors only — never an `nsec` or seed. Uses the OPTIONAL peer
    `nostr-nsec-seedphrase`; throws a clear install hint if absent.
- **Public-side (watch-only, safe anywhere; mirrors `hj-pay` byte-for-byte)**:
  - `zpubToAddress` / `zpubToAddressForAsset` — BIP84 P2WPKH `bc1…`/`ltc1…` addresses from a public account
    key.
  - `inspectZpub` — asset/network/purpose/label/depth/fingerprint, no derivation.
  - `assertPublicOnly` / `assertNoPrivateKeyMaterial` — the hard guard: rejects every private-key shape on
    a prefix check AND the decoded key byte (catches a `zprv` re-versioned to wear a `zpub` prefix).
- **`versions.ts`** — the SLIP-132 version-byte map, `PUBLIC_VERSIONS` COPIED verbatim from `hj-pay` so the
  two libraries never disagree, plus the `PRIVATE_VERSIONS` reject set.
- **Tests (vitest)** — the published BIP84 vectors (char-for-char), the round-trip pin to an independent
  `node:crypto`-only oracle (== hj-pay), the LTC independent cross-derivation + program-equality check, the
  full guard-rejection matrix, and the no-leak assertion. Plus a built-artifact smoke test over ESM + CJS.
- Dual ESM + CommonJS build with `.d.ts` and a browser IIFE bundle. Runtime deps pinned exact to the audited
  stack (`@scure/bip32` 2.3.0, `@scure/bip39` 2.3.0, `@scure/base` 2.3.0, `@noble/hashes` 2.3.0).

### Notes
- This library **never spends, signs a spend, or persists/logs/transmits private material.** It derives
  public receiving keys from a seed (enclave-side) and reads addresses from a `zpub` (watch-only) — nothing
  else. See [SECURITY.md](SECURITY.md).
