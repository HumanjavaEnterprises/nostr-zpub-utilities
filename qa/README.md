# QA harness

Agent-runnable QA for `nostr-zpub-utils`. Two modes, one dispatcher.

Everything here runs against the **built `dist/`** artifact, so build first:

```bash
npm run build
```

---

## Modes at a glance

| Mode | Network? | Moves value? | Safe in CI / sandbox / agents? | Command |
|---|---|---|---|---|
| `--synthetic` (default) | No | No | **Yes** | `node qa/run.mjs --synthetic` |
| `--testnet` | Yes | **Yes (real testnet value, on external broadcast)** | **No** — never in CI | `node qa/run.mjs --testnet` |

Dispatcher:

```bash
node qa/run.mjs [--synthetic|--testnet] [--chain btc|ltc] [--count N] [--seed S] [--json]
node qa/run.mjs --help
```

npm scripts:

```bash
npm run qa           # -> node qa/run.mjs            (synthetic, offline)
npm run qa:testnet   # -> node qa/run.mjs --testnet  (gated, env-gated)
```

Exit codes: `0` = pass (or testnet all-skipped), `1` = any failure, `2` = bad argument
(e.g. a malformed `--count`, which ERRORs rather than silently narrowing).

---

## 1. Synthetic mode (OFFLINE, no network)

Exercises the full offline derive+sign pipeline for **both assets** (BTC / LTC) over a
set of **fixed regression vectors** plus **N seeded-random cases**, asserting the
load-bearing invariants:

- **Derivation** — the published BIP-0084 `abandon … about` account key
  (`zpub6rFR7…AGutZYs`) and its first receive/change addresses, **char-for-char**
  (`bc1qcr8te4k…`). The same account key read as LTC yields `ltc1…` addresses with the
  **identical witness-program body** as the published `bc1…` vectors. Each random seed
  derives a valid, deterministic native-segwit address and the ambiguous `zpub` prefix
  **refuses** to derive without an explicit `asset` (the wrong-chain footgun guard).
- **PSBT (the safety property)** — a 2-input PSBT where we own **only index 0**:
  `signOnlyOurInputs([0])` signs input 0 and leaves input 1 **completely untouched**
  (no partial signature); declaring an unowned index **throws** (`could not sign` — it
  never silent-signs); out-of-range / duplicate indices are rejected; `finalizeAndExtract`
  **refuses** while the tx is incomplete; a fully-owned PSBT finalizes and the raw hex
  **round-trips** through the package's `Psbt.fromPsbt` and `@scure/btc-signer`'s
  `Transaction.fromRaw` (txid stable). **No private-key material appears in any output.**

The package has no network layer at all — it never fetches a UTXO and never broadcasts
(a signed PSBT is handed off externally), so synthetic mode is inherently offline.

All "random" data comes from a seeded sha256-counter PRNG, so a given `--seed` is
byte-for-byte reproducible.

### Commands

```bash
node qa/run.mjs                              # 25 random cases/asset, seed "default"
node qa/run.mjs --synthetic --count 100      # more cases
node qa/run.mjs --synthetic --seed alpha     # reproducible run
node qa/run.mjs --synthetic --chain ltc      # one asset only
node qa/run.mjs --synthetic --json           # machine-readable
```

### Sample output

```
nostr-zpub-utils — OFFLINE synthetic QA (no network)
  seed=default  random-count=25  asset=all

  ✔ btc  passed=26 failed=0
  ✔ ltc  passed=26 failed=0

  TOTAL (asset,case) pairs: 52  passed=52  failed=0

SYNTHETIC: PASS
```

### `--json` result shape

```json
{
  "ok": true,
  "total": 52,
  "passed": 52,
  "failed": 0,
  "seed": "default",
  "count": 25,
  "asset": "all",
  "perAsset": {
    "btc": { "passed": 26, "failed": 0 },
    "ltc": { "passed": 26, "failed": 0 }
  },
  "failures": []
}
```

Each entry in `failures` is `{ asset, case, assertion, detail }`.

---

## 2. Testnet mode (GATED, NETWORK, env-gated)

> ⚠️ **This harness requires network access AND funded testnet coins. It reads a live
> testnet indexer and SIGNS a real testnet spend — it MOVES REAL TESTNET VALUE the
> moment you broadcast the hex it prints. It is NOT run in CI/sandbox and must never
> point at mainnet.**
>
> 🔑 **Supply keys via environment variables ONLY. Never commit a key or mnemonic.**

**`nostr-zpub-utils` does NOT broadcast.** A signed PSBT is handed off. So this harness
stops at the raw signed transaction: it prints the **hex + txid + an explorer hint**,
and **YOU broadcast it externally** (an indexer `sendtx` endpoint, a wallet, or an
explorer's push-tx form). Nothing here calls a network WRITE endpoint.

For each asset (driven entirely by env vars) it runs:

```
derive testnet receive address (seed/mnemonic -> vpub -> tb1…/tltc1…)
  -> watch-only READ: query balance + UTXOs from a Blockbook-style indexer
  -> build + sign a PSBT from a fetched-or-supplied UTXO
  -> OUTPUT raw signed tx hex + txid + explorer hint  (operator broadcasts)
```

If an asset's required env vars are absent, that asset is **skipped** (never failed).
Keys are read from the environment only — never hardcoded, never logged as raw bytes.

### Commands

```bash
npm run qa:testnet                 # both assets whose env is set
node qa/run.mjs --testnet --chain btc
node qa/run.mjs --testnet --json
```

### Environment variables

| Asset | Variable | Meaning |
|---|---|---|
| BTC | `BTC_TESTNET_INDEXER_URL` | Blockbook-v2 base URL (BTC testnet). **Required.** |
| BTC | `BTC_TESTNET_MNEMONIC` | BIP39 mnemonic (private — enclave only). **Never commit.** |
| BTC | `BTC_TESTNET_SEED` | 64-byte BIP39 seed, hex (`0x` optional) — alternative to the mnemonic. **Never commit.** |
| BTC | `BTC_TESTNET_PASSPHRASE` | optional BIP39 passphrase ("25th word"). |
| BTC | `BTC_TESTNET_UTXO` | optional UTXO override `"<txid>:<vout>:<amountSats>"`. |
| BTC | `BTC_TO` | optional recipient address (defaults to self). |
| LTC | `LTC_TESTNET_INDEXER_URL` | Blockbook-v2 base URL (LTC testnet). **Required.** |
| LTC | `LTC_TESTNET_MNEMONIC` | BIP39 mnemonic (private — enclave only). **Never commit.** |
| LTC | `LTC_TESTNET_SEED` | 64-byte BIP39 seed, hex (`0x` optional) — alternative to the mnemonic. **Never commit.** |
| LTC | `LTC_TESTNET_PASSPHRASE` | optional BIP39 passphrase. |
| LTC | `LTC_TESTNET_UTXO` | optional UTXO override `"<txid>:<vout>:<amountSats>"`. |
| LTC | `LTC_TO` | optional recipient address (defaults to self). |

One of `<ASSET>_TESTNET_MNEMONIC` or `<ASSET>_TESTNET_SEED` is required per asset (the
mnemonic wins if both are set). Testnet uses SLIP-44 coin type 1 for both chains, so the
account path is `m/84'/1'/0'` and receive keys are `m/84'/1'/0'/0/<index>`.

### Faucets / endpoints (hints)

- **BTC — testnet3 / signet**: point `BTC_TESTNET_INDEXER_URL` at a Blockbook-v2 BTC
  testnet indexer. Fund the printed `tb1…` address from a Bitcoin testnet3 faucet (e.g.
  a coinfaucet.eu / bitcoinfaucet.uo1.net style faucet) or a signet faucet. Explorer:
  `https://mempool.space/testnet/`.
- **LTC — testnet**: point `LTC_TESTNET_INDEXER_URL` at a Blockbook-v2 LTC testnet
  indexer. Fund the printed `tltc1…` address from a Litecoin testnet faucet. Explorer:
  `https://litecoinspace.org/testnet/`.

### Example invocation

```bash
BTC_TESTNET_INDEXER_URL="https://<your-blockbook-btc-testnet>" \
BTC_TESTNET_MNEMONIC="<your funded testnet mnemonic — from env, never committed>" \
node qa/run.mjs --testnet --chain btc
```

The command prints the derived receive address, the balance/UTXOs it read, the signed
raw tx hex + txid, and an explorer hint. **Broadcast the hex yourself** — the harness
never does.

### Sample output (shape)

```
⚠️  qa/testnet.mjs — GATED harness: … MOVES REAL TESTNET VALUE once you broadcast … zpub-utils does NOT broadcast.
  btc  receive address (m/84'/1'/0'/0/0) = tb1q…
  btc  cross-check OK: receive address is spendable by the derived key
  btc  READ balance …/api/v2/address/tb1q… -> balance=… sat  txs=…  (receive side proven)
  btc  spending UTXO <txid>:<vout> value=… sat
  btc  SIGNED. txid=<txid> fee=1000 sat out=… sat
  btc  raw signed tx hex (broadcast EXTERNALLY):
  btc    0200000000010… (raw hex)
  btc  explorer hint (after you broadcast): https://mempool.space/testnet/tx/<txid>

TESTNET: PASS (signed; broadcast externally)
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Synthetic: all invariants passed. Testnet: every asset that ran signed successfully, **or** every asset was skipped (no env). |
| `1` | Synthetic: at least one invariant failed. Testnet: an asset that ran failed to read/derive/sign, or a fatal error. |
| `2` | A bad CLI argument (e.g. a malformed `--count`, an unknown `--chain`, or an unknown flag). |

## Packaging note

`qa/` is dev/QA only and is **excluded from the npm tarball** (`package.json` `files` is
`["dist","README.md","SPEC.md","LICENSE"]`; `.npmignore` also excludes `qa/`). Verify
with `npm pack --dry-run` — no `qa/` entries should appear. The testnet harness is never
imported or run by the test suite or CI.
