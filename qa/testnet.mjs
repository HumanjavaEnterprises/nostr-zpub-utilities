/**
 * qa/testnet.mjs — GATED, network QA harness.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ ⚠️  REQUIRES ENV + FUNDED TESTNET COINS. NOT RUN IN CI / SANDBOX.          │
 * │     This harness reads a testnet indexer over the network and SIGNS a real │
 * │     testnet spend. It MOVES REAL TESTNET VALUE once the operator           │
 * │     broadcasts the hex it prints. Never point it at mainnet. Never         │
 * │     hardcode a key or mnemonic — every secret comes from the environment.  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * IMPORTANT: nostr-zpub-utils does NOT broadcast. A signed PSBT is handed off. So
 * this harness stops at the raw signed tx — it prints the hex + txid + an explorer
 * hint and the OPERATOR broadcasts it EXTERNALLY (e.g. an indexer sendtx endpoint,
 * a wallet, or a block explorer's push-tx form). Nothing here ever calls a network
 * WRITE endpoint.
 *
 * Per asset (env-gated), it runs:
 *   derive testnet receive address (seed/mnemonic -> vpub -> tb1…/tltc1…)
 *     -> watch-only READ: query balance + UTXOs from a Blockbook-style indexer
 *     -> build + sign a PSBT from a fetched-or-supplied UTXO
 *     -> OUTPUT raw signed tx hex + txid + explorer hint (operator broadcasts)
 *
 * If a chain's required env is missing, that chain is SKIPPED (never failed).
 *
 * Run:
 *   node qa/testnet.mjs [--chain btc|ltc] [--json]
 *
 * ── Environment variables ────────────────────────────────────────────────────
 *   BTC (testnet3 / signet):
 *     BTC_TESTNET_INDEXER_URL   Blockbook-v2 base URL (BTC testnet). REQUIRED.
 *     BTC_TESTNET_MNEMONIC      BIP39 mnemonic (private — enclave only). *or*
 *     BTC_TESTNET_SEED          64-byte BIP39 seed, hex (0x optional). One is REQUIRED.
 *     BTC_TESTNET_UTXO          optional override "<txid>:<vout>:<amountSats>".
 *     BTC_TO                    optional recipient address (defaults to self).
 *   LTC (testnet):
 *     LTC_TESTNET_INDEXER_URL   Blockbook-v2 base URL (LTC testnet). REQUIRED.
 *     LTC_TESTNET_MNEMONIC      BIP39 mnemonic (private — enclave only). *or*
 *     LTC_TESTNET_SEED          64-byte BIP39 seed, hex (0x optional). One is REQUIRED.
 *     LTC_TESTNET_UTXO          optional override "<txid>:<vout>:<amountSats>".
 *     LTC_TO                    optional recipient address (defaults to self).
 *
 * NOTE: this file is dev/QA only. It is NEVER imported or run by the test suite or CI,
 * and it is excluded from the published npm tarball.
 */
import {
  seedToZpub,
  zpubToAddress,
  createPsbt,
  p2wpkhScript,
} from '../dist/index.js';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { bech32, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

const BANNER =
  '⚠️  qa/testnet.mjs — GATED harness: requires env + funded TESTNET coins; SIGNS a real testnet spend; MOVES REAL TESTNET VALUE once you broadcast the printed hex; NOT run in CI/sandbox. zpub-utils does NOT broadcast — you broadcast externally.';

// Per-asset env prefixes + explorer/HRP metadata.
const ASSETS = {
  btc: { key: 'BTC', hrp: 'tb', explorer: 'https://mempool.space/testnet/tx/' },
  ltc: { key: 'LTC', hrp: 'tltc', explorer: 'https://litecoinspace.org/testnet/tx/' },
};

/** Resolve a 64-byte BIP39 seed from either a mnemonic or a hex seed env var. */
function resolveSeed(prefix) {
  const mnemonic = process.env[`${prefix}_TESTNET_MNEMONIC`];
  const seedHex = process.env[`${prefix}_TESTNET_SEED`];
  if (mnemonic && mnemonic.trim()) {
    const m = mnemonic.trim();
    if (!validateMnemonic(m, wordlist)) {
      throw new Error(`${prefix}_TESTNET_MNEMONIC is not a valid BIP39 mnemonic`);
    }
    return mnemonicToSeedSync(m, process.env[`${prefix}_TESTNET_PASSPHRASE`] ?? '');
  }
  if (seedHex && seedHex.trim()) {
    const h = seedHex.trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]+$/.test(h) || h.length < 32) {
      throw new Error(`${prefix}_TESTNET_SEED must be a hex BIP39 seed (>= 16 bytes)`);
    }
    return hex.decode(h.toLowerCase());
  }
  return null; // neither supplied -> caller SKIPs
}

/** hash160(pubkey) — the 20-byte witness program for a P2WPKH. */
function hash160(pub) {
  return ripemd160(sha256(pub));
}

/** Decode the 20-byte witness program from a bech32 P2WPKH address (to cross-check). */
function witnessProgram(addr) {
  const { words } = bech32.decode(addr);
  return bech32.fromWords(words.slice(1));
}

function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.json();
}

// ── one asset's testnet pipeline ─────────────────────────────────────────────
async function runAsset(assetKey, log) {
  const meta = ASSETS[assetKey];
  const prefix = meta.key;
  const indexer = process.env[`${prefix}_TESTNET_INDEXER_URL`];
  const seed = resolveSeed(prefix);

  if (!indexer || !seed) {
    return {
      asset: assetKey,
      skipped: true,
      reason: `${prefix}_TESTNET_INDEXER_URL and ${prefix}_TESTNET_MNEMONIC (or ${prefix}_TESTNET_SEED) required`,
    };
  }
  const base = indexer.replace(/\/$/, '');

  // 1) Derive the testnet receive address via the PUBLIC (watch-only) path…
  const asset = meta.key; // 'BTC' | 'LTC'
  const { zpub: vpub } = seedToZpub(seed, { asset, network: 'testnet' });
  const address = process.env[`${prefix}_TO`] || zpubToAddress(vpub, { asset, network: 'testnet', index: 0 });
  const receiveAddr = zpubToAddress(vpub, { asset, network: 'testnet', index: 0 });
  log(`${assetKey}  receive address (m/84'/1'/0'/0/0) = ${receiveAddr}`);
  log(`${assetKey}  send-to = ${address}`);

  // …and independently derive the SIGNING key for index 0 (enclave context).
  const node = HDKey.fromMasterSeed(seed).derive("m/84'/1'/0'/0/0");
  if (!node.privateKey || !node.publicKey) throw new Error('derivation did not yield a keypair');
  const ourScript = p2wpkhScript(node.publicKey, asset, 'testnet');
  // Cross-check: the watch-only receive address IS spendable by this key.
  if (!eqBytes(witnessProgram(receiveAddr), hash160(node.publicKey))) {
    throw new Error('receive address does not match the signing key (derivation mismatch)');
  }
  log(`${assetKey}  cross-check OK: receive address is spendable by the derived key`);

  // 2) Watch-only READ — balance + UTXOs from the Blockbook-style indexer.
  log(`${assetKey}  READ balance ${base}/api/v2/address/${receiveAddr} …`);
  const acct = await getJson(`${base}/api/v2/address/${receiveAddr}`);
  log(`${assetKey}  balance=${acct.balance ?? '0'} sat  txs=${acct.txs ?? 0}  (receive side proven)`);

  // 3) Select a UTXO — an explicit override, else the first the indexer reports.
  let utxo;
  const override = process.env[`${prefix}_TESTNET_UTXO`];
  if (override) {
    const [txid, voutStr, amtStr] = override.split(':');
    if (!/^[0-9a-fA-F]{64}$/.test(txid ?? '') || !/^\d+$/.test(voutStr ?? '') || !/^\d+$/.test(amtStr ?? '')) {
      throw new Error(`${prefix}_TESTNET_UTXO must be "<txid>:<vout>:<amountSats>"`);
    }
    utxo = { txid: txid.toLowerCase(), vout: Number(voutStr), value: BigInt(amtStr) };
    log(`${assetKey}  using UTXO override ${utxo.txid}:${utxo.vout} value=${utxo.value} sat`);
  } else {
    log(`${assetKey}  READ UTXOs ${base}/api/v2/utxo/${receiveAddr} …`);
    const utxos = await getJson(`${base}/api/v2/utxo/${receiveAddr}`);
    if (!Array.isArray(utxos) || utxos.length === 0) {
      throw new Error(`no UTXOs for ${receiveAddr} — fund it from a ${prefix} testnet faucet first (or set ${prefix}_TESTNET_UTXO)`);
    }
    const u = utxos[0];
    utxo = { txid: u.txid, vout: u.vout, value: BigInt(u.value) };
    log(`${assetKey}  spending UTXO ${utxo.txid}:${utxo.vout} value=${utxo.value} sat`);
  }

  // 4) Build + sign the PSBT (SIGHASH_ALL, single owned input).
  const fee = 1_000n; // flat 1000 sat fee
  const outAmount = utxo.value - fee;
  if (outAmount <= 0n) throw new Error(`selected UTXO (${utxo.value} sat) too small to cover the ${fee} sat fee`);

  const p = createPsbt({ asset, network: 'testnet' });
  p.addInput({ txid: utxo.txid, index: utxo.vout, witnessUtxo: { script: ourScript, amount: utxo.value } });
  p.addOutput({ address, amount: outAmount });
  const res = p.signOnlyOurInputs(node.privateKey, [0]);
  if (JSON.stringify(res.signed) !== '[0]') throw new Error(`expected to sign input 0, got ${JSON.stringify(res)}`);
  const { hex: rawHex, txid } = p.finalizeAndExtract();

  // 5) OUTPUT — the operator broadcasts EXTERNALLY. We never do.
  log(`${assetKey}  SIGNED. txid=${txid} fee=${fee} sat out=${outAmount} sat`);
  log(`${assetKey}  raw signed tx hex (broadcast EXTERNALLY):`);
  log(`${assetKey}    ${rawHex}`);
  log(`${assetKey}  explorer hint (after you broadcast): ${meta.explorer}${txid}`);
  log(`${assetKey}  broadcast hint: POST this hex to ${base}/api/v2/sendtx/ , a wallet, or an explorer push-tx form`);

  return {
    asset: assetKey,
    skipped: false,
    ok: true,
    receiveAddress: receiveAddr,
    to: address,
    utxo: `${utxo.txid}:${utxo.vout}`,
    inputValue: utxo.value.toString(),
    outputValue: outAmount.toString(),
    fee: fee.toString(),
    txid,
    rawHex,
    explorer: `${meta.explorer}${txid}`,
    broadcast: 'EXTERNAL — zpub-utils does not broadcast',
  };
}

export async function main(opts = {}) {
  const json = !!opts.json;
  const asset = opts.chain ?? opts.asset ?? 'all';
  if (!json) console.error(BANNER);

  const logs = [];
  const log = (m) => {
    logs.push(m);
    if (!json) console.log('  ' + m);
  };

  const assets = asset === 'all' ? ['btc', 'ltc'] : [asset];
  const results = [];
  for (const a of assets) {
    if (!ASSETS[a]) {
      log(`${a}  ERROR — unknown asset (use btc|ltc)`);
      results.push({ asset: a, skipped: false, ok: false, error: 'unknown asset' });
      continue;
    }
    try {
      const r = await runAsset(a, log);
      if (r.skipped) log(`${a}  SKIPPED — ${r.reason}`);
      results.push(r);
    } catch (e) {
      log(`${a}  ERROR — ${e instanceof Error ? e.message : String(e)}`);
      results.push({ asset: a, skipped: false, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  }

  const ran = results.filter((r) => !r.skipped);
  const failed = ran.filter((r) => !r.ok);
  return { ok: failed.length === 0, ran: ran.length, results, asset };
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--chain' || a === '--asset') o.chain = argv[++i];
  }
  return o;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const opts = parseArgs(process.argv.slice(2));
  main(opts)
    .then((r) => {
      if (opts.json) console.log(JSON.stringify(r));
      else console.log(r.ran === 0 ? '\nTESTNET: no chains ran (all skipped — set env vars)' : r.ok ? '\nTESTNET: PASS (signed; broadcast externally)' : '\nTESTNET: FAIL');
      // Exit 0 when nothing ran (pure skip) or all-ok; 1 only when a chain that ran failed.
      process.exit(r.ran > 0 && !r.ok ? 1 : 0);
    })
    .catch((e) => {
      console.error('TESTNET: fatal —', e instanceof Error ? e.message : String(e));
      process.exit(1);
    });
}
