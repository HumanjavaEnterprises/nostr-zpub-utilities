/**
 * qa/synthetic.mjs — OFFLINE synthetic-data QA harness (NO NETWORK).
 *
 * Exercises the full offline derive+sign pipeline of the BUILT `dist/` artifact for
 * both assets (BTC / LTC) over a set of FIXED regression vectors plus N seeded-random
 * cases, asserting the load-bearing invariants on each:
 *
 *   DERIVATION — the published BIP84 "abandon…about" account key and its first
 *   receive/change addresses (char-for-char), plus N random seeds whose derived
 *   addresses must be valid native-segwit, deterministic, and refuse the ambiguous
 *   wrong-chain default.
 *
 *   PSBT (the safety property) — a 2-input PSBT where we own ONLY index 0:
 *   `signOnlyOurInputs([0])` signs input 0 and leaves input 1 UNTOUCHED; declaring an
 *   unowned index THROWS (never silent-signs); `finalizeAndExtract` refuses while the
 *   tx is incomplete; a fully-owned PSBT finalizes and the raw hex round-trips through
 *   the package's `Psbt.fromPsbt` and `@scure/btc-signer`'s `Transaction.fromRaw`.
 *   No private-key material ever appears in any output.
 *
 * This harness NEVER touches the network: the package has no network layer at all (it
 * never fetches a UTXO and never broadcasts — a signed PSBT is handed off externally).
 * The testnet, env-gated companion lives in qa/testnet.mjs.
 *
 * Determinism: all "random" data comes from a seeded PRNG (sha256 counter stream), so
 * a given --seed reproduces byte-for-byte across runs.
 *
 * Run:
 *   node qa/synthetic.mjs [--count N] [--seed S] [--chain btc|ltc] [--json]
 * Exit code: 0 = all pass, 1 = any failure, 2 = malformed --count.
 */
import {
  seedToZpub,
  mnemonicToZpub,
  zpubToAddress,
  zpubToAddressForAsset,
  inspectZpub,
  createPsbt,
  Psbt,
  p2wpkhScript,
} from '../dist/index.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32, hex } from '@scure/base';
import { Transaction } from '@scure/btc-signer';

// ── Published BIP-0084 regression vectors (the canonical abandon…about mnemonic) ──
const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const BIP84_ZPUB =
  'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs';
const BTC_VECTORS = [
  { change: 0, index: 0, address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' },
  { change: 0, index: 1, address: 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g' },
  { change: 1, index: 0, address: 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el' },
];

// ── seeded PRNG (deterministic sha256 counter stream) ────────────────────────
function makeRng(seed) {
  const seedBytes = sha256(new TextEncoder().encode('zpub-qa:' + String(seed)));
  let counter = 0;
  let pool = new Uint8Array(0);
  let pi = 0;
  const refill = () => {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, counter++, false);
    const buf = new Uint8Array(seedBytes.length + 4);
    buf.set(seedBytes, 0);
    buf.set(ctr, seedBytes.length);
    pool = sha256(buf);
    pi = 0;
  };
  const bytes = (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      if (pi >= pool.length) refill();
      out[i] = pool[pi++];
    }
    return out;
  };
  const float = () => {
    const b = bytes(6);
    let v = 0;
    for (const x of b) v = v * 256 + x;
    return v / 2 ** 48;
  };
  const int = (min, max) => min + Math.floor(float() * (max - min + 1));
  const big = (nbytes) => {
    let v = 0n;
    for (const x of bytes(nbytes)) v = v * 256n + BigInt(x);
    return v;
  };
  return { bytes, float, int, big };
}

/** Deterministically draw a valid secp256k1 keypair (retries the ~2^-128 out-of-range case). */
function drawSecpKey(rng) {
  for (;;) {
    const priv = rng.bytes(32);
    try {
      const pub = secp256k1.getPublicKey(priv, true); // throws if 0 or >= curve order
      return { priv, pub };
    } catch {
      /* draw again */
    }
  }
}

/** Validate a native-segwit (witness-v0 P2WPKH) address for the expected HRP. */
function isValidSegwit(addr, expectedHrp) {
  try {
    const { prefix, words } = bech32.decode(addr);
    if (prefix !== expectedHrp) return false;
    if (words[0] !== 0) return false; // witness version 0
    const program = bech32.fromWords(words.slice(1));
    return program.length === 20; // P2WPKH = 20-byte key hash
  } catch {
    return false;
  }
}

// ── tiny assertion collector ─────────────────────────────────────────────────
function makeCollector() {
  const failures = [];
  const check = (name, cond, detail) => {
    if (!cond) failures.push({ assertion: name, detail: detail ?? '' });
  };
  return { failures, check };
}

// ── PSBT invariants (the load-bearing safety property) ───────────────────────
function runPsbtInvariants(asset, rng, check) {
  const our = drawSecpKey(rng);
  const stranger = drawSecpKey(rng);
  const ourScript = p2wpkhScript(our.pub, asset);
  const strangerScript = p2wpkhScript(stranger.pub, asset);
  const txidA = hex.encode(rng.bytes(32));
  const txidB = hex.encode(rng.bytes(32));
  const amtA = 100_000n + (rng.big(4) % 400_000n);
  const amtB = 100_000n + (rng.big(4) % 400_000n);

  // 2-input PSBT where we own ONLY index 0.
  const p = createPsbt({ asset });
  p.addInput({ txid: txidA, index: 0, witnessUtxo: { script: ourScript, amount: amtA } });
  p.addInput({ txid: txidB, index: 1, witnessUtxo: { script: strangerScript, amount: amtB } });
  p.addOutput({ script: ourScript, amount: amtA + amtB - 2000n });

  const res = p.signOnlyOurInputs(our.priv, [0]);
  check(`${asset}.psbt.signed===[0]`, JSON.stringify(res.signed) === '[0]', `signed=${JSON.stringify(res.signed)}`);
  check(`${asset}.psbt.skipped===[1]`, JSON.stringify(res.skipped) === '[1]', `skipped=${JSON.stringify(res.skipped)}`);
  check(`${asset}.psbt.input0.signed`, p.isInputSigned(0) === true);
  // THE PROPERTY: input 1 (the stranger's) is completely UNTOUCHED.
  check(`${asset}.psbt.input1.untouched`, p.isInputSigned(1) === false);
  check(`${asset}.psbt.input1.noPartialSig`, p.tx.getInput(1).partialSig === undefined);

  // finalizeAndExtract must REFUSE while the tx is incomplete (input 1 unsigned).
  let incompleteThrew = false;
  try {
    p.finalizeAndExtract();
  } catch {
    incompleteThrew = true;
  }
  check(`${asset}.psbt.finalizeRefusesIncomplete`, incompleteThrew === true);

  // Declaring an index we do NOT control must THROW — never silent-sign.
  const p2 = createPsbt({ asset });
  p2.addInput({ txid: txidA, index: 0, witnessUtxo: { script: ourScript, amount: amtA } });
  p2.addInput({ txid: txidB, index: 1, witnessUtxo: { script: strangerScript, amount: amtB } });
  p2.addOutput({ script: ourScript, amount: amtA + amtB - 2000n });
  let unownedThrew = false;
  let unownedMsg = '';
  try {
    p2.signOnlyOurInputs(our.priv, [1]); // we don't own input 1
  } catch (e) {
    unownedThrew = true;
    unownedMsg = e instanceof Error ? e.message : String(e);
  }
  check(`${asset}.psbt.declaringUnownedThrows`, unownedThrew && /could not sign/.test(unownedMsg), unownedMsg);
  check(`${asset}.psbt.declaringUnownedLeavesUnsigned`, p2.isInputSigned(1) === false);

  // Out-of-range and duplicate indices are rejected before any input is touched.
  let oorThrew = false;
  try {
    p2.signOnlyOurInputs(our.priv, [9]);
  } catch {
    oorThrew = true;
  }
  check(`${asset}.psbt.outOfRangeThrows`, oorThrew === true);
  let dupThrew = false;
  try {
    p2.signOnlyOurInputs(our.priv, [0, 0]);
  } catch {
    dupThrew = true;
  }
  check(`${asset}.psbt.duplicateThrows`, dupThrew === true);

  // A FULLY-owned PSBT finalizes; the raw hex round-trips via the package's parse and
  // @scure/btc-signer's Transaction.fromRaw.
  const full = createPsbt({ asset });
  full.addInput({ txid: txidA, index: 0, witnessUtxo: { script: ourScript, amount: amtA } });
  full.addOutput({ script: strangerScript, amount: amtA - 2000n });
  const fres = full.signOnlyOurInputs(our.priv, [0]);
  check(`${asset}.psbt.full.signed===[0]`, JSON.stringify(fres.signed) === '[0]', `signed=${JSON.stringify(fres.signed)}`);

  const signedPsbtBytes = full.toPsbt();
  const reloaded = Psbt.fromPsbt(signedPsbtBytes, { asset }); // package parse round-trip
  check(`${asset}.psbt.full.reloadedSignaturePreserved`, reloaded.isInputSigned(0) === true);

  const { hex: rawHex, txid } = reloaded.finalizeAndExtract();
  check(`${asset}.psbt.full.rawHexShape`, /^[0-9a-f]+$/.test(rawHex));
  check(`${asset}.psbt.full.txidShape`, /^[0-9a-f]{64}$/.test(txid));

  const parsed = Transaction.fromRaw(hex.decode(rawHex)); // btc-signer parse round-trip
  check(`${asset}.psbt.full.txidStable`, parsed.id === txid, `parsed=${parsed.id} txid=${txid}`);
  check(`${asset}.psbt.full.inputsLength`, parsed.inputsLength === 1, `got=${parsed.inputsLength}`);
  check(`${asset}.psbt.full.outputsLength`, parsed.outputsLength === 1, `got=${parsed.outputsLength}`);
  check(`${asset}.psbt.full.finalWitness`, Boolean(parsed.getInput(0).finalScriptWitness));

  // NO private-key material appears in ANY output the harness would hand off.
  const privHexOur = hex.encode(our.priv);
  const privHexStranger = hex.encode(stranger.priv);
  const haystack = [
    rawHex,
    txid,
    hex.encode(signedPsbtBytes),
    JSON.stringify(res),
    JSON.stringify(fres),
  ].join(' ');
  check(
    `${asset}.psbt.noPrivKeyLeak`,
    !haystack.includes(privHexOur) && !haystack.includes(privHexStranger),
    'private scalar hex found in a produced output',
  );
}

// ── one case: derivation invariants + PSBT invariants for an asset ───────────
function runAssetCase(asset, { fixed, seed, rng }) {
  const { failures, check } = makeCollector();
  const hrp = asset === 'BTC' ? 'bc' : 'ltc';

  if (fixed) {
    if (asset === 'BTC') {
      // Seed-side pin: the account zpub matches the PUBLISHED BIP84 vector.
      const acct = mnemonicToZpub(MNEMONIC, { asset: 'BTC' });
      check('BTC.vector.accountZpub', acct.zpub === BIP84_ZPUB, `got=${acct.zpub}`);
      // Public-side pin: first receive/change addresses, char-for-char.
      for (const v of BTC_VECTORS) {
        const got = zpubToAddress(BIP84_ZPUB, { asset: 'BTC', change: v.change, index: v.index });
        check(`BTC.vector.addr[${v.change}/${v.index}]`, got === v.address, `got=${got} want=${v.address}`);
      }
    } else {
      // LTC pin: the SAME account key read as LTC yields ltc1 addresses with the
      // IDENTICAL witness-program body as the published bc1 vectors (only the HRP
      // differs). This reuses the externally-published BTC vectors as the anchor.
      for (const v of BTC_VECTORS) {
        const ltc = zpubToAddressForAsset(BIP84_ZPUB, 'LTC', { change: v.change, index: v.index });
        check(`LTC.vector.addr[${v.change}/${v.index}].prefix`, ltc.startsWith('ltc1'), `got=${ltc}`);
        check(`LTC.vector.addr[${v.change}/${v.index}].valid`, isValidSegwit(ltc, 'ltc'), ltc);
        const btcBody = v.address.slice(v.address.indexOf('1') + 1, -6);
        const ltcBody = ltc.slice(ltc.indexOf('1') + 1, -6);
        check(`LTC.vector.addr[${v.change}/${v.index}].bodyMatchesBTC`, ltcBody === btcBody, `ltc=${ltc}`);
      }
      // Seed-side: a real LTC account (coin 2) derives a valid ltc1 address.
      const acctLtc = mnemonicToZpub(MNEMONIC, { asset: 'LTC' });
      const addrLtc = zpubToAddress(acctLtc.zpub, { asset: 'LTC', index: 0 });
      check('LTC.vector.seedDerivesLtc1', isValidSegwit(addrLtc, 'ltc'), addrLtc);
    }
  } else {
    // Seeded-random derivation case.
    const zr = seedToZpub(seed, { asset });
    const info = inspectZpub(zr.zpub);
    check(`${asset}.random.inspect.network`, info.network === 'mainnet', `net=${info.network}`);
    check(`${asset}.random.inspect.purpose`, info.purpose === 'bip84', `purpose=${info.purpose}`);
    check(`${asset}.random.inspect.depth`, info.depth === 3, `depth=${info.depth}`);

    const index = rng.int(0, 5_000_000);
    const change = rng.int(0, 1);
    const a1 = zpubToAddress(zr.zpub, { asset, change, index });
    const a2 = zpubToAddress(zr.zpub, { asset, change, index });
    check(`${asset}.random.addr.valid`, isValidSegwit(a1, hrp), a1);
    check(`${asset}.random.addr.deterministic`, a1 === a2, `${a1} vs ${a2}`);

    // Footgun guard: the ambiguous zpub prefix must REFUSE without an explicit asset.
    let refused = false;
    try {
      zpubToAddress(zr.zpub, { index });
    } catch {
      refused = true;
    }
    check(`${asset}.random.ambiguousRefusesWithoutAsset`, refused === true);
  }

  // PSBT invariants run on every case (keys are drawn from the shared seeded RNG).
  runPsbtInvariants(asset, rng, check);
  return failures;
}

// ── orchestration ────────────────────────────────────────────────────────────
export function main(opts = {}) {
  const count = opts.count ?? 25;
  if (!Number.isInteger(count) || count < 0) {
    console.error(`qa: --count must be a non-negative integer (got ${JSON.stringify(opts.count)})`);
    process.exit(2);
  }
  const seed = opts.seed ?? 'default';
  const assetFilter = opts.chain ?? opts.asset ?? 'all';
  const want = (a) => assetFilter === 'all' || assetFilter === a;

  const rng = makeRng(seed);
  const perAsset = { btc: { passed: 0, failed: 0 }, ltc: { passed: 0, failed: 0 } };
  const failures = [];

  const tally = (assetKey, caseLabel, fails) => {
    if (fails.length === 0) perAsset[assetKey].passed++;
    else {
      perAsset[assetKey].failed++;
      for (const f of fails) failures.push({ asset: assetKey, case: caseLabel, ...f });
    }
  };

  // Fixed regression vectors.
  if (want('btc')) tally('btc', 'fixed:bip84-abandon', runAssetCase('BTC', { fixed: true, rng }));
  if (want('ltc')) tally('ltc', 'fixed:bip84-abandon', runAssetCase('LTC', { fixed: true, rng }));

  // Seeded-random cases.
  for (let i = 0; i < count; i++) {
    const label = `random#${i}`;
    if (want('btc')) tally('btc', label, runAssetCase('BTC', { seed: rng.bytes(64), rng }));
    if (want('ltc')) tally('ltc', label, runAssetCase('LTC', { seed: rng.bytes(64), rng }));
  }

  const passed = perAsset.btc.passed + perAsset.ltc.passed;
  const failed = perAsset.btc.failed + perAsset.ltc.failed;
  const total = passed + failed;

  return { ok: failed === 0, total, passed, failed, seed: String(seed), count, asset: assetFilter, perAsset, failures };
}

function printHuman(r) {
  console.log('nostr-zpub-utils — OFFLINE synthetic QA (no network)');
  console.log(`  seed=${r.seed}  random-count=${r.count}  asset=${r.asset}`);
  console.log('');
  const line = (a) => {
    if (r.asset !== 'all' && r.asset !== a) return;
    const p = r.perAsset[a];
    const mark = p.failed === 0 ? '✔' : '✘';
    console.log(`  ${mark} ${a.padEnd(4)} passed=${p.passed} failed=${p.failed}`);
  };
  line('btc');
  line('ltc');
  console.log('');
  console.log(`  TOTAL (asset,case) pairs: ${r.total}  passed=${r.passed}  failed=${r.failed}`);
  if (r.failures.length) {
    console.log('\n  FAILURES:');
    for (const f of r.failures) console.log(`    [${f.asset}] ${f.case}: ${f.assertion}${f.detail ? ' — ' + f.detail : ''}`);
  }
  console.log(r.ok ? '\nSYNTHETIC: PASS' : '\nSYNTHETIC: FAIL');
}

// ── direct-run arg parsing ───────────────────────────────────────────────────
function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--count') {
      const raw = argv[++i];
      if (!/^\d+$/.test(raw ?? '')) {
        console.error(`qa: --count must be a non-negative integer (got ${JSON.stringify(raw)})`);
        process.exit(2);
      }
      o.count = parseInt(raw, 10);
    } else if (a === '--seed') o.seed = argv[++i];
    else if (a === '--chain' || a === '--asset') o.chain = argv[++i];
  }
  return o;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const opts = parseArgs(process.argv.slice(2));
  const r = main(opts);
  if (opts.json) console.log(JSON.stringify(r));
  else printHuman(r);
  process.exit(r.ok ? 0 : 1);
}
