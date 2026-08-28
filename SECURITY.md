# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| CVSS v3.0 | Supported Versions                        |
| --------- | ---------------------------------------- |
| 9.0-10.0  | Releases within the last 6 months        |
| 4.0-8.9   | Most recent release                      |

## Threat model — the seed boundary is the whole safety of this library

`nostr-zpub-utilities` derives PUBLIC receiving keys from a BIP39 seed. Its safety rests on one boundary:

- **Seed-side functions (`mnemonicToZpub`, `seedToZpub`, `mnemonicToIdentity`) are ENCLAVE/CLIENT-ONLY.**
  They touch the seed and MUST run only where the seed is allowed to live — a browser, a hardware enclave,
  an offline signer — **never on a shared server, a receiving rail, or any host the seed shouldn't reach.**
  They output PUBLIC material only (`zpub`/`Ltub`/`npub`) and never return, log, persist, or transmit the
  seed, the mnemonic, or any private/extended-private key byte. A conforming caller keeps the seed in the
  enclave and hands only the resulting `zpub` to the outside world.

- **The public side is watch-only and rejects private material twice.** `assertPublicOnly`, `inspectZpub`,
  `zpubToAddress`, and `zpubToAddressForAsset` accept extended PUBLIC keys only. Any input carrying private
  key material (`xprv`/`yprv`/`zprv`/`tprv`/`uprv`/`vprv`/`Ltpv`/`Mtpv`/`ttpv`, an `nsec`, a WIF, a mnemonic,
  a raw 32-byte scalar) is refused — once on the human-readable prefix / known private version byte, and once
  on the decoded serialization's key byte (a BIP32 extended PRIVATE key has `0x00` where a public key has
  `0x02`/`0x03`). This second, exhaustive check is what catches a real `zprv` re-serialized to *wear* a
  `zpub` prefix: the string looks public, the decoded key byte does not.

- **This library never spends.** It is not a wallet, signer, or PSBT builder. There is no code path that
  signs a chain transaction or moves funds.

## Audited stack

Runtime dependencies are limited to the estate's audited set, pinned exact: `@scure/bip32`, `@scure/bip39`,
`@scure/base`, `@noble/hashes`. `nostr-nsec-seedphrase` is an optional peer used only by
`mnemonicToIdentity`; the core derivation has no Nostr dependency. The public-side address derivation mirrors
`hj-pay` byte-for-byte and is pinned to it (and to the published BIP84 vectors) by the test suite.

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub's Security Advisory feature at [https://github.com/humanjavaenterprises/nostr-zpub-utilities/security/advisories/new](https://github.com/humanjavaenterprises/nostr-zpub-utilities/security/advisories/new).

The team will acknowledge your report within 48 hours, and will send a more detailed response within 72 hours indicating the next steps in handling your report.

After the initial reply to your report, the security team will endeavor to keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

## Disclosure Policy

When the security team receives a security bug report, they will assign it to a primary handler. This person will coordinate the fix and release process.

## Comments on this Policy

If you have suggestions on how this process could be improved please submit a pull request.
