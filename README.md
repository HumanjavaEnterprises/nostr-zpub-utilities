# nostr-zpub-utilities

<div align="center">

[![npm version](https://img.shields.io/npm/v/nostr-zpub-utilities.svg)](https://www.npmjs.com/package/nostr-zpub-utilities)
[![npm downloads](https://img.shields.io/npm/dm/nostr-zpub-utilities.svg)](https://www.npmjs.com/package/nostr-zpub-utilities)
[![License](https://img.shields.io/npm/l/nostr-zpub-utilities.svg)](https://github.com/humanjavaenterprises/nostr-zpub-utilities/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Status](https://img.shields.io/github/actions/workflow/status/humanjavaenterprises/nostr-zpub-utilities/ci.yml?branch=main&label=tests)](https://github.com/humanjavaenterprises/nostr-zpub-utilities/actions)
[![Code Style](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://prettier.io/)

</div>

**One mnemonic, two lives: your `npub` (who you are) and your `zpub` (where you get paid) — derived from
the same seed, on the same curve.**

Nostr keys and Bitcoin keys are the same curve (secp256k1), so a single BIP39 mnemonic yields *both* a Nostr
identity (NIP-06 `m/44'/1237'/0'/0/0` → `npub`) and a hierarchy of receiving keys (BIP84 `m/84'/coin'/0'` →
`zpub` → addresses). Where [`nostr-agentic-identity`](https://github.com/humanjavaenterprises/nostr-agentic-identity)
defines *who an agent is*, this defines *where value reaches it* — Bitcoin and Litecoin.

> Status: **DRAFT 0.1** · Read **[SPEC.md](SPEC.md)** first — it is authoritative; the code here is a thin,
> audited-stack expression of it. Prior art it composes: `@scure/bip32` + `@scure/bip39` (audited HD
> derivation), SLIP-132, BIP84/44, and `nostr-nsec-seedphrase` (BIP39 ↔ Nostr keys, optional).

> ### ⚠️ One seed is one root, not one wallet — read this before shipping
> This mnemonic is **both the agent's voice and its treasury.** The same seed derives the `npub`
> that signs its words (NIP-06, `m/44'/1237'/0'/0/0`) and the receiving keys that hold its money
> (BIP84, `m/84'/coin'/0'`). Those are **sibling derivation paths, not the same key** — but they
> share one root. So:
> - **Losing the seed loses both** the business identity and the coin inbox. Back it up like money.
> - **Compromising the seed compromises both.** Consider a dedicated account index (or a separate
>   seed) for agent spend vs. human funds, so a hot agent key is not your cold treasury.
> - The library **never guesses a chain.** A definite-prefix key resolves its asset; an ambiguous
>   one makes you pass `asset` or it throws. It will not silently hand you a BTC address for an LTC
>   key. Keep it that way in your own call sites.

## The one hard boundary (the whole safety of the library)

**Deriving a zpub touches the SEED. The seed is private material.** So the library has two clearly-separated
sides:

- 🔒 **Seed-side — enclave/client ONLY** (`mnemonicToZpub`, `seedToZpub`, `mnemonicToIdentity`). These touch
  the seed and MUST run only where the seed is allowed to live (a browser, a hardware enclave, an offline
  signer) — **never a shared server**. They **output PUBLIC material only** — a `zpub`/`Ltub`, an `npub` — and
  never return, log, persist, or transmit the seed, the mnemonic, or any private byte.
- 👁️ **Public-side — watch-only, safe anywhere** (`zpubToAddress`, `inspectZpub`, `assertPublicOnly`). Reads
  addresses off a public `zpub`. This side **mirrors [`hj-pay`](https://github.com/humanjavaenterprises)
  byte-for-byte** — same decode, same BIP84 P2WPKH bech32 — so the two libraries never disagree about which
  address a `zpub` produces. It **rejects every private-key shape** (`xprv`/`zprv`/`Ltpv`/…, a raw scalar, a
  seed phrase, *and a `zprv` re-versioned to wear a `zpub` prefix*) on a prefix check AND on the decoded key
  byte.

A conforming caller keeps the seed in the enclave, calls a derive function, and hands the resulting `zpub` to
the watch-only world. If a design needs the seed on a server to work, it is using this library wrong.

## What it derives

| Input | Path | Output |
|---|---|---|
| BIP39 mnemonic (+ optional passphrase) | BTC BIP84 `m/84'/0'/account'` | `zpub…` |
| BIP39 mnemonic | LTC BIP84 `m/84'/2'/account'` | `zpub…` (default) or `Ltub…` |
| a `zpub`/`Ltub` (public) | `.../change/index` | a receive address (`bc1…`/`ltc1…`) |
| a `zpub` | — | inspect: asset, network, purpose, SLIP-132 label, fingerprint |

Account level (depth 3) is the export unit — the shape `hj-pay` expects.

## Installation

```bash
npm install nostr-zpub-utilities
# optional — only needed for mnemonicToIdentity's npub derivation:
npm install nostr-nsec-seedphrase
```

Runtime deps are limited to the estate's audited stack (pinned exact): `@scure/bip32`, `@scure/bip39`,
`@scure/base`, `@noble/hashes`. `nostr-nsec-seedphrase` is an **optional peer** used only by
`mnemonicToIdentity`; the core zpub derivation has no Nostr dependency.

## Quick Start

### Seed-side — derive receiving keys (ENCLAVE/CLIENT ONLY)

```typescript
import { mnemonicToZpub, mnemonicToIdentity } from 'nostr-zpub-utilities';

// A BTC BIP84 account key from the seed root:
const { zpub, path, fingerprint } = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
// zpub → hand to the watch-only world; the seed never leaves this enclave.

// A Litecoin account, Litecoin-definite Ltub prefix:
const ltc = mnemonicToZpub(MNEMONIC, { asset: 'LTC', ltcLabel: 'Ltub' });

// The one-root tie-in — PUBLIC anchors only (no nsec, ever):
const { npub, zpubBTC, zpubLTC } = await mnemonicToIdentity(MNEMONIC);
```

### Public-side — read addresses off a zpub (safe anywhere, incl. a server)

```typescript
import { zpubToAddress, inspectZpub, assertPublicOnly, checkXpub, assertDistinctXpubs } from 'nostr-zpub-utilities';

assertPublicOnly(zpub);                                    // throws on ANY private-key shape
inspectZpub(zpub);                                         // { label, asset, network, purpose, depth, fingerprint }
zpubToAddress(zpub, { asset: 'BTC', index: 0, change: 0 }); // 'bc1q…'
zpubToAddress(ltubKey, { index: 0 });                      // 'ltc1…' — a chain-definite prefix needs no asset

// Preflight before going live:
checkXpub(zpub, 'BTC');                        // { ok, info, errors, warnings } — never throws
assertDistinctXpubs(zpubBTC, zpubLTC);         // throws if the same key is configured for both chains
```

> **The chain must be explicit for shared prefixes.** `xpub`/`zpub`/`tpub`/`vpub` are used by *both*
> Bitcoin and Litecoin wallets — the version byte does not pin a chain. Calling `zpubToAddress` on such a key
> **without `asset`** throws `AmbiguousAssetError` rather than silently defaulting to `bc1…` and handing out an
> address no wallet is watching. A chain-definite prefix (`Ltub`/`Mtub`/`ttub`/`ypub`/`upub`) needs no
> `asset`. Use `zpubToAddressForAsset(zpub, asset)` when you want to name the chain positionally.

## Correctness gates (in the test suite)

- **BIP84 published vectors** — the `abandon … about` mnemonic derives the canonical account
  `zpub6rFR7y4Q2Aij…` and its first addresses `bc1qcr8te4…` (0/0), `bc1qnjg0jd8…` (0/1), `bc1q8c6fshw…`
  (1/0), character for character.
- **Round-trip pin to hj-pay** — `zpubToAddress` is checked against an independent `node:crypto`-only
  reference implementation (the same oracle hj-pay's own tests use), pinning the two libraries together.
- **LTC cross-check** — no published BIP84 LTC vectors exist, so a second minimal HDKey path and an
  independent oracle must agree with `keys.ts`, and the `ltc1…` witness programs must equal the published
  BTC vectors' programs (via the re-versioned account key).
- **Guard** — every private-key shape (`xprv/yprv/zprv/tprv/uprv/vprv/Ltpv/Mtpv/ttpv`, a raw scalar, a seed
  phrase, and a `zprv` re-versioned to wear a `zpub` prefix) is rejected by `assertPublicOnly` and by every
  public-path function.
- **No leakage** — no seed/mnemonic/private byte appears in any return value or thrown error.

## Module Support

Dual ESM + CommonJS, with a browser bundle and full type declarations.

### ESM (recommended)
```typescript
import { mnemonicToZpub } from 'nostr-zpub-utilities';
```

### CommonJS
```javascript
const { mnemonicToZpub } = require('nostr-zpub-utilities');
```

## Non-goals

Not a wallet, not a signer, not a coin-selection/PSBT builder, not custody, not a relay client. It derives
public receiving keys from a seed and reads addresses from a `zpub` — nothing that spends. Spending stays in
the enclave/hardware where the seed lives.

## Security

See [SECURITY.md](SECURITY.md). The load-bearing rule is the seed boundary above: the seed-side functions are
enclave-only and emit public material only; the public side is watch-only and rejects private material twice.

## License

MIT License — see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
