/**
 * Smoke test — proves the SHIPPED artifact (dist), not the source, is correct.
 *
 * Loads BOTH built entry points and asserts, over each:
 *   - the published BIP84 Bitcoin vectors (account zpub → first addresses),
 *   - the round-trip pin (zpubToAddress == the independent node:crypto oracle),
 *   - assertPublicOnly rejects every private-key shape, INCLUDING a zprv
 *     re-versioned to wear a zpub prefix,
 *   - no seed/mnemonic/private byte appears in a seed-side return value.
 *
 * Targets:
 *   - `dist/cjs/index.js`  loaded via `require(...)`  (the CommonJS artifact)
 *   - `dist/index.js`      loaded via `import(...)`    (the ESM artifact)
 *
 * Vectors and reject fixtures come from `test/` — the same single source of truth
 * the vitest suites consume — so tests and smoke can never drift. Dev-only; `test/`
 * never ships. Exit code is non-zero on any mismatch.
 */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const require = createRequire(import.meta.url);
const root = resolve(new URL('..', import.meta.url).pathname);

const cjs = require(resolve(root, 'dist/cjs/index.js'));
const esm = await import(pathToFileURL(resolve(root, 'dist/index.js')).href);

const vectorsUrl = pathToFileURL(resolve(root, 'test/vectors.mjs')).href;
const { MNEMONIC, BIP84_ZPUB, BTC_VECTORS } = await import(vectorsUrl);
const { refAddress } = await import(pathToFileURL(resolve(root, 'test/ref-derive.mjs')).href);
const { buildRejects } = await import(pathToFileURL(resolve(root, 'test/reject-keys.mjs')).href);

const rejects = buildRejects();

const targets = [
  { label: 'cjs (require dist/cjs/index.js)', api: cjs },
  { label: 'esm (import dist/index.js)', api: esm },
];

let passed = 0;
let failed = 0;
const failures = [];

function check(label, description, actual, expected) {
  if (actual === expected) passed += 1;
  else {
    failed += 1;
    failures.push(`  ✗ [${label}] ${description}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function checkThrows(label, description, fn) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  check(label, description, threw, true);
}

console.log('nostr-zpub-utilities — smoke test over the BUILT dist');
console.log(`  targets: ${targets.map((t) => t.label.split(' ')[0]).join(', ')}  ·  reject fixtures: ${rejects.length}`);
console.log('');

for (const { label, api } of targets) {
  const { mnemonicToZpub, zpubToAddress, assertPublicOnly } = api;
  if (typeof mnemonicToZpub !== 'function' || typeof zpubToAddress !== 'function' || typeof assertPublicOnly !== 'function') {
    failed += 1;
    failures.push(`  ✗ [${label}] missing expected exports`);
    continue;
  }

  // Seed-side: canonical account zpub.
  const acct = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
  check(label, 'account zpub matches published vector', acct.zpub, BIP84_ZPUB);

  // Public-side vectors + round-trip pin against the independent oracle.
  // asset:'BTC' is REQUIRED — the account key wears the ambiguous `zpub` prefix and
  // the primary API refuses to guess a chain (the LTC-footgun fix).
  for (const { change, index, address } of BTC_VECTORS) {
    const got = zpubToAddress(acct.zpub, { asset: 'BTC', change, index });
    check(label, `addr ${change}/${index} matches vector`, got, address);
    check(label, `addr ${change}/${index} matches oracle`, got, refAddress(acct.zpub, 'bc', index, change).address);
  }

  // Footgun guard: the ambiguous zpub with NO asset must be refused, not defaulted.
  checkThrows(label, 'ambiguous zpub without asset is refused', () => zpubToAddress(acct.zpub, { index: 0 }));

  // No-leak: the seed-side return value carries no mnemonic/private bytes.
  check(label, 'seed-side return has no mnemonic', JSON.stringify(acct).includes(MNEMONIC), false);
  check(label, 'seed-side return has no zprv/xprv', /zprv|xprv/.test(JSON.stringify(acct)), false);

  // Guard: every private shape is rejected, including the re-versioned trap.
  for (const { label: rl, key } of rejects) {
    checkThrows(label, `assertPublicOnly rejects ${rl}`, () => assertPublicOnly(key));
    checkThrows(label, `zpubToAddress rejects ${rl}`, () => zpubToAddress(key, { index: 0 }));
  }

  // Sanity: a genuine zpub is accepted (must NOT throw).
  let accepted = true;
  try {
    assertPublicOnly(BIP84_ZPUB);
  } catch {
    accepted = false;
  }
  check(label, 'assertPublicOnly accepts a real zpub', accepted, true);
}

console.log(`Checks: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('');
  console.log('FAIL — the built artifact did not match expectations:');
  console.log(failures.join('\n'));
  console.log('');
  console.log('SMOKE: FAIL');
  process.exit(1);
}

console.log('');
console.log('SMOKE: PASS — the shipped package derives the published vectors and guards the seed boundary.');
process.exit(0);
