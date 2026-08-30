/**
 * qa/run.mjs — QA harness dispatcher.
 *
 * Usage:
 *   node qa/run.mjs [--synthetic|--testnet] [--chain btc|ltc] [--count N] [--seed S] [--json]
 *
 * Default mode is --synthetic (OFFLINE, no network, safe for CI/agents).
 *   --synthetic   run the offline synthetic-data invariant harness (qa/synthetic.mjs)
 *   --testnet     run the GATED, env-gated, network harness (qa/testnet.mjs)
 *                 ⚠️ requires env + funded testnet coins; SIGNS a real testnet spend.
 *                 zpub-utils does NOT broadcast — you broadcast the printed hex externally.
 *
 * Exit code: 0 = pass (or testnet all-skipped), 1 = any failure, 2 = bad argument.
 */
import { main as synthetic } from './synthetic.mjs';
import { main as testnet } from './testnet.mjs';

function parseArgs(argv) {
  const o = { mode: 'synthetic' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--synthetic') o.mode = 'synthetic';
    else if (a === '--testnet') o.mode = 'testnet';
    else if (a === '--json') o.json = true;
    else if (a === '--chain' || a === '--asset') o.chain = argv[++i];
    else if (a === '--count') {
      // Strict: reject anything that is not a clean non-negative integer. Never
      // silently narrow "12abc" -> 12.
      const raw = argv[++i];
      if (!/^\d+$/.test(raw ?? '')) {
        console.error(`qa: --count must be a non-negative integer (got ${JSON.stringify(raw)})`);
        process.exit(2);
      }
      o.count = parseInt(raw, 10);
    } else if (a === '--seed') o.seed = argv[++i];
    else if (a === '--help' || a === '-h') o.help = true;
    else {
      console.error(`qa: unknown argument ${JSON.stringify(a)} (see --help)`);
      process.exit(2);
    }
  }
  if (o.chain && o.chain !== 'btc' && o.chain !== 'ltc') {
    console.error(`qa: --chain must be btc or ltc (got ${JSON.stringify(o.chain)})`);
    process.exit(2);
  }
  return o;
}

const HELP = `nostr-zpub-utils QA harness

  node qa/run.mjs [--synthetic|--testnet] [--chain btc|ltc] [--count N] [--seed S] [--json]

  --synthetic   OFFLINE invariant harness over the built dist (default; no network)
  --testnet     GATED network harness; env-gated; SIGNS a real testnet spend (see qa/README.md).
                zpub-utils does NOT broadcast — you broadcast the printed hex externally.
  --chain X     restrict to one asset (btc|ltc); default both
  --count N     synthetic: number of random cases per asset (default 25)
  --seed S      synthetic: PRNG seed for reproducible runs (default "default")
  --json        emit a machine-readable JSON result object
  --help        show this help`;

async function run() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (opts.mode === 'testnet') {
    const r = await testnet(opts);
    if (opts.json) console.log(JSON.stringify(r));
    else console.log(r.ran === 0 ? '\nTESTNET: no chains ran (all skipped — set env vars)' : r.ok ? '\nTESTNET: PASS (signed; broadcast externally)' : '\nTESTNET: FAIL');
    process.exit(r.ran > 0 && !r.ok ? 1 : 0);
  }

  // Synthetic (default).
  const r = synthetic(opts);
  if (opts.json) console.log(JSON.stringify(r));
  else {
    console.log('nostr-zpub-utils — OFFLINE synthetic QA (no network)');
    console.log(`  seed=${r.seed}  random-count=${r.count}  asset=${r.asset}`);
    console.log('');
    const line = (a) => {
      if (r.asset !== 'all' && r.asset !== a) return;
      const p = r.perAsset[a];
      console.log(`  ${p.failed === 0 ? '✔' : '✘'} ${a.padEnd(4)} passed=${p.passed} failed=${p.failed}`);
    };
    line('btc');
    line('ltc');
    console.log(`\n  TOTAL (asset,case) pairs: ${r.total}  passed=${r.passed}  failed=${r.failed}`);
    if (r.failures.length) {
      console.log('\n  FAILURES:');
      for (const f of r.failures) console.log(`    [${f.asset}] ${f.case}: ${f.assertion}${f.detail ? ' — ' + f.detail : ''}`);
    }
    console.log(r.ok ? '\nSYNTHETIC: PASS' : '\nSYNTHETIC: FAIL');
  }
  process.exit(r.ok ? 0 : 1);
}

run();
