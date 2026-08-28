/**
 * SEED-SIDE logic — enclave/client ONLY, never a server.
 *
 * The one-root tie-in: from a SINGLE BIP39 mnemonic, produce the PUBLIC anchors of
 * an identity — its Nostr `npub` (NIP-06, `m/44'/1237'/0'/0/0`) and its two BIP84
 * receiving `zpub`s (BTC `m/84'/0'/0'`, LTC `m/84'/2'/0'`). "Your keys are your
 * identity are your wallet" is literally one seed.
 *
 * ⛔ TOUCHES THE SEED. Run only in an enclave/client. Returns PUBLIC anchors ONLY —
 * `npub` + the two `zpub`s. It NEVER returns, logs, or transmits the `nsec`, the
 * seed, or the mnemonic.
 *
 * The Nostr derivation is delegated to `nostr-nsec-seedphrase`, an OPTIONAL
 * dependency. The core zpub derivation (`keys.ts`) has no Nostr dependency and works
 * with it absent; only this function needs it, and it throws a clear install hint if
 * it is missing.
 *
 * @packageDocumentation
 */

import { mnemonicToZpub } from './keys.js';
import type { Identity } from './types.js';

/** Minimal shape of the part of `nostr-nsec-seedphrase` we consume. */
interface SeedphraseModule {
  seedPhraseToKeyPair: (mnemonic: string) => Promise<{ npub: string }>;
}

/**
 * A real, un-downleveled dynamic import. `nostr-nsec-seedphrase` is ESM-only.
 * TypeScript's CommonJS emit rewrites a plain `import()` to `require()`, which
 * throws `ERR_REQUIRE_ESM` on an ESM package — so the CJS build needs a genuine
 * `import()`, which routing through a `Function` preserves. The ESM build (and the
 * test runner) use the plain `import()` below and never reach this.
 */
const preservedImport = new Function('specifier', 'return import(specifier);') as (
  specifier: string,
) => Promise<unknown>;

async function loadSeedphrase(): Promise<SeedphraseModule> {
  try {
    let mod: SeedphraseModule;
    try {
      // Preferred path — the plain dynamic import the ESM build + test runner resolve.
      mod = (await import('nostr-nsec-seedphrase')) as unknown as SeedphraseModule;
    } catch {
      // CJS fallback — tsc downleveled the above to require(); use a genuine import().
      mod = (await preservedImport('nostr-nsec-seedphrase')) as SeedphraseModule;
    }
    if (typeof mod.seedPhraseToKeyPair !== 'function') {
      throw new Error('export seedPhraseToKeyPair not found');
    }
    return mod;
  } catch {
    throw new Error(
      'mnemonicToIdentity requires the optional dependency "nostr-nsec-seedphrase". ' +
        'Install it (npm install nostr-nsec-seedphrase) to derive the npub, or use ' +
        'mnemonicToZpub for the receiving keys alone.',
    );
  }
}

/**
 * SEED-SIDE — enclave/client only, never a server.
 *
 * From ONE mnemonic, derive the PUBLIC anchors: NIP-06 `npub` + BTC/LTC BIP84
 * `zpub`s. Returns PUBLIC material only — never the `nsec` or the seed.
 *
 * @param mnemonic - the BIP39 mnemonic (private material — keep in the enclave)
 * @returns `{ npub, zpubBTC, zpubLTC }`
 */
export async function mnemonicToIdentity(mnemonic: string): Promise<Identity> {
  if (typeof mnemonic !== 'string' || mnemonic.trim() === '') {
    throw new Error('mnemonicToIdentity: mnemonic must be a non-empty string');
  }
  const m = mnemonic.trim();

  const { seedPhraseToKeyPair } = await loadSeedphrase();
  // Only `npub` is read off the keypair — the nsec/privateKey are deliberately
  // dropped and never surfaced.
  const { npub } = await seedPhraseToKeyPair(m);

  const zpubBTC = mnemonicToZpub(m, { asset: 'BTC' }).zpub;
  const zpubLTC = mnemonicToZpub(m, { asset: 'LTC' }).zpub;

  return { npub, zpubBTC, zpubLTC };
}
