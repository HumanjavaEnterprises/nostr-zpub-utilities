# nostr-zpub-utilities — deriving receiving keys from a Nostr identity root

**One mnemonic, two lives: your `npub` (who you are) and your `zpub` (where you get
paid) — derived from the same seed, on the same curve.** Where `nostr-agentic-identity`
defines *who an agent is*, this defines *where value reaches it*. Bitcoin and Litecoin.

> Status: **DRAFT 0.1** · License: MIT · Prior art it composes: `nostr-nsec-seedphrase`
> (BIP39 ↔ Nostr keys), `@scure/bip32` + `@scure/bip39` (audited HD derivation),
> SLIP-132, BIP84/44. Sibling standard: `nostr-agentic-identity`.

## Why

Nostr keys and Bitcoin keys are the **same curve** (secp256k1). So a single BIP39
mnemonic can yield *both* a Nostr identity (NIP-06: `m/44'/1237'/0'/0/0` → `nsec`/`npub`)
*and* a hierarchy of receiving keys (BIP84: `m/84'/coin'/0'` → `zpub` → addresses). The
estate already mints identities from seeds; this library derives the **receiving side**
from that same root, so "your keys are your identity are your wallet" is literally one
seed — no separate wallet, no custody, deterministic and recoverable.

## The one hard boundary (the whole safety of the library)

**Deriving a zpub touches the SEED. The seed is private material.** Therefore:

- Seed-touching functions (`mnemonicToZpub`, `seedToZpub`, `mnemonicToIdentity`) are
  **client-side / enclave-side ONLY** (browser, NSE hardware enclave, an offline signer).
  They MUST NOT run on a shared server, a receiving rail, or anywhere the seed shouldn't
  live. This is the exact inverse of `hj-pay`, which is watch-only and never sees a seed.
- The library **outputs only PUBLIC material** — a `zpub` (or `Ltub`), or addresses.
  From that point on, everything is watch-only: `hj-pay` takes the `zpub` and derives
  addresses to receive. The seed never leaves the enclave.
- The library **never persists, logs, or transmits** seed/mnemonic/private bytes, and
  **rejects private extended keys** (`xprv`/`zprv`/`Ltpv`/…) on any public-path input —
  the same hard guard `hj-pay/derive.ts` uses (prefix AND decoded-version-byte).

A conforming caller keeps the seed in the enclave, calls a derive function, and hands
the resulting `zpub` to the watch-only world. If a design needs the seed on a server to
work, it is using this library wrong.

## What it derives

| Input | Path | Output |
|---|---|---|
| BIP39 mnemonic (+ optional passphrase) | BTC BIP84 `m/84'/0'/account'` | `zpub…` |
| BIP39 mnemonic | LTC BIP84 `m/84'/2'/account'` | `zpub…` (default) or `Ltub…` |
| a `zpub`/`Ltub` (public) | `.../change/index` | a receive address (`bc1…`/`ltc1…`) |
| a `zpub` | — | inspect: asset, network, purpose, SLIP-132 label |

Account level (depth 3) is the export unit — the same shape `hj-pay` expects. Address
derivation from a public `zpub` mirrors `hj-pay/derive.ts` byte-for-byte (shared logic,
BIP84 bech32, verified against published vectors) so the two libraries never disagree
about which address a `zpub` produces.

## API (surface; the builder keeps discretion on packaging)

```ts
// SEED-SIDE (enclave only) — produce public receiving keys from the identity root
mnemonicToZpub(mnemonic: string, opts?: { asset?: 'BTC'|'LTC'; account?: number;
              passphrase?: string; ltcLabel?: 'zpub'|'Ltub'; network?: 'mainnet'|'testnet' }): {
  zpub: string; path: string; asset: 'BTC'|'LTC'; fingerprint: string }
seedToZpub(seed: Uint8Array, opts?): { … }            // lower level, same shape
mnemonicToIdentity(mnemonic: string): {               // the tie-in, one root:
  npub: string; zpubBTC: string; zpubLTC: string }    // ⚠️ derives via nostr-nsec-seedphrase;
                                                      //    returns PUBLIC anchors only (no nsec)

// PUBLIC-SIDE (safe anywhere) — watch-only, mirrors hj-pay
zpubToAddress(zpub: string, opts?: { index?: number; change?: 0|1 }): string
inspectZpub(zpub: string): { asset; network; purpose; label; fingerprint }
assertPublicOnly(key: string): void                   // throws on any xprv/zprv/Ltpv/seed shape
```

## Correctness gates (non-negotiable, in the test suite)

- **BIP84 published vectors:** the `abandon…about` mnemonic MUST derive the canonical
  account `zpub` and its first addresses `bc1qcr8te4…`, `bc1qnjg0jd8…`, change
  `bc1q8c6fshw…` — character for character.
- **LTC cross-check:** no published BIP84 LTC vectors exist, so a second independent
  derivation path in the tests must agree, and the `ltc1…` witness programs must match
  the published BTC vectors' programs (Litecoin uses the same bech32 body).
- **Round-trip:** `mnemonicToZpub` → `zpubToAddress` equals the same address `hj-pay`
  derives from that `zpub` (the two libraries are pinned to each other by a shared vector).
- **Guard:** every private-key shape (`xprv/yprv/zprv/tprv/uprv/vprv/Ltpv/Mtpv/ttpv`,
  raw 32-byte hex, a `zprv` re-versioned to wear a `zpub` prefix) is rejected by
  `assertPublicOnly` and by every public-path function.
- **No leakage:** a test asserts no seed/mnemonic/private byte appears in any return
  value, thrown error, or (if any) log line.

## Conventions (match `nostr-agentic-identity`)

MIT · dual ESM/CJS + browser build · vitest · eslint/prettier · typedoc · `scripts/
smoke.mjs`. Runtime deps limited to the audited set: `@scure/bip32`, `@scure/bip39`,
`@scure/base`, `@noble/hashes` (pinned exact; the same stack `hj-pay` passed two
security rounds on). `nostr-nsec-seedphrase` is an **optional peer** used only by
`mnemonicToIdentity` — the core zpub derivation has no Nostr dependency.

## Non-goals

Not a wallet, not a signer, not a coin-selection/PSBT builder, not custody, not a relay
client. It derives public receiving keys from a seed and reads addresses from a zpub —
nothing that spends. Spending stays in the enclave/hardware where the seed lives.
