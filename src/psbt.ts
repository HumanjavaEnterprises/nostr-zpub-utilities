/**
 * PSBT layer for BTC/LTC — CoinJoin-COMPATIBLE, never a coordinator.
 *
 * ⛔ ENCLAVE / CLIENT-ONLY SIGNING. {@link Psbt.signOnlyOurInputs} touches a
 * PRIVATE key. Like the seed side (`keys.ts`), it MUST run only where a private key
 * is allowed to live — a browser, a hardware enclave, an offline signer — and NEVER
 * on a shared server, a receiving rail, or a coordinator. Building, merging,
 * serializing, and finalizing a PSBT need no private material and are safe anywhere;
 * signing is the one operation gated to the enclave.
 *
 * ## What this is (and is not)
 * A thin, PURE (no network) wrapper over `@scure/btc-signer`'s `Transaction`. We
 * build a PSBT, add the inputs/outputs the CALLER supplies, and — the load-bearing
 * primitive — sign ONLY the input indices the caller declares we own. That makes
 * PARTICIPATING in a CoinJoin possible without us running a coordinator, a pool, or
 * a mixing service (see design doc, Decision 3). We are join-COMPATIBLE; we never
 * coordinate.
 *
 * We do NOT fetch UTXOs, estimate fees, or broadcast — the caller supplies each
 * input's prevout (`witnessUtxo`), and the raw tx we extract is handed to the
 * wallet/network layer to broadcast. No sighash is hand-rolled: every signature and
 * script comes from `@scure/btc-signer`.
 *
 * LTC note: Litecoin has no real CoinJoin ecosystem (MWEB is its privacy path, and
 * is out of scope here); LTC support exists so the same receive-side spend/merge API
 * covers both chains, not because an LTC join pool is expected.
 *
 * @packageDocumentation
 */

import { Transaction, NETWORK, TEST_NETWORK, p2wpkh } from '@scure/btc-signer';
import { hex } from '@scure/base';
import type { HDKey } from '@scure/bip32';

import type { ChainAsset, ChainNetwork } from './versions.js';

/**
 * The four network bytes `@scure/btc-signer` needs to encode/decode addresses.
 * Structurally identical to its internal `BTC_NETWORK`; defined here so we can add
 * Litecoin params without a deep type import.
 */
export interface PsbtNetwork {
  /** bech32 human-readable part (`bc` / `tb` / `ltc` / `tltc`). */
  bech32: string;
  /** version byte for legacy P2PKH addresses. */
  pubKeyHash: number;
  /** version byte for legacy P2SH addresses. */
  scriptHash: number;
  /** WIF private-key version byte (used only if a caller decodes a WIF; we never emit one). */
  wif: number;
}

/**
 * Litecoin network params. BTC reuses `@scure/btc-signer`'s `NETWORK`/`TEST_NETWORK`.
 * Segwit (P2WPKH) address encoding depends only on `bech32`; the legacy bytes are
 * carried for completeness / decode.
 */
const LTC_MAINNET: PsbtNetwork = { bech32: 'ltc', pubKeyHash: 0x30, scriptHash: 0x32, wif: 0xb0 };
const LTC_TESTNET: PsbtNetwork = { bech32: 'tltc', pubKeyHash: 0x6f, scriptHash: 0x3a, wif: 0xef };

/** Resolve the `@scure/btc-signer` network params for an asset + network. */
export function psbtNetworkFor(asset: ChainAsset, network: ChainNetwork = 'mainnet'): PsbtNetwork {
  if (asset === 'BTC') return network === 'testnet' ? TEST_NETWORK : NETWORK;
  return network === 'testnet' ? LTC_TESTNET : LTC_MAINNET;
}

/** A signing key: a raw 32-byte secp256k1 private scalar, or a BIP32 `HDKey`. PRIVATE — enclave only. */
export type PsbtSigningKey = Uint8Array | HDKey;

/** Which asset/network a PSBT is being built for — drives address encoding. */
export interface PsbtConfig {
  asset: ChainAsset;
  network?: ChainNetwork;
}

/** Extra construction options passed through to `@scure/btc-signer`'s `Transaction`. */
export interface PsbtOptions {
  /** Transaction version. Default: btc-signer's default (2). */
  version?: number;
  /** Global locktime. */
  lockTime?: number;
}

/**
 * One input to spend. The caller supplies the prevout being spent (`witnessUtxo`) —
 * we do NOT fetch UTXOs; that is the wallet/network layer's job.
 */
export interface PsbtInput {
  /** Prevout transaction id — 32 bytes, or a 64-char hex string. */
  txid: Uint8Array | string;
  /** Prevout output index (vout). */
  index: number;
  /** The output being spent: its `script` (e.g. a P2WPKH scriptPubKey) and `amount` in satoshis. */
  witnessUtxo: { script: Uint8Array; amount: bigint };
  /** Optional full previous transaction bytes (belt-and-suspenders for amount validation). */
  nonWitnessUtxo?: Uint8Array;
  /** Optional SIGHASH type. Default: SIGHASH_ALL (what CoinJoin participation uses). */
  sighashType?: number;
  /** Optional P2SH redeem script (for wrapped-segwit inputs). */
  redeemScript?: Uint8Array;
  /** Optional P2WSH witness script. */
  witnessScript?: Uint8Array;
  /** Optional nSequence for this input. */
  sequence?: number;
}

/** One output to create. Give an `address` (encoded for the PSBT's network) OR a raw `script`. */
export interface PsbtOutput {
  /** Destination address — encoded against the PSBT's asset/network. */
  address?: string;
  /** Raw output script (scriptPubKey), as an alternative to `address`. */
  script?: Uint8Array;
  /** Amount in satoshis. */
  amount: bigint;
}

/** What {@link Psbt.signOnlyOurInputs} did. */
export interface SignResult {
  /** Indices we were told we own and successfully signed. */
  signed: number[];
  /** Indices we did NOT touch because they are not ours (external inputs). */
  skipped: number[];
}

function txidBytes(txid: Uint8Array | string): Uint8Array {
  if (typeof txid === 'string') {
    if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
      throw new Error('Psbt: txid hex string must be exactly 64 hex chars (32 bytes)');
    }
    return hex.decode(txid.toLowerCase());
  }
  if (!(txid instanceof Uint8Array) || txid.length !== 32) {
    throw new Error('Psbt: txid must be 32 bytes (Uint8Array) or a 64-char hex string');
  }
  return txid;
}

/**
 * A PSBT under construction for one asset/network. Wraps a `@scure/btc-signer`
 * `Transaction`; the raw transaction is reachable via {@link Psbt.tx} for advanced use.
 *
 * ⛔ {@link Psbt.signOnlyOurInputs} is ENCLAVE/CLIENT-ONLY (see file header).
 */
export class Psbt {
  /** The underlying `@scure/btc-signer` `Transaction`. */
  readonly tx: Transaction;
  readonly asset: ChainAsset;
  readonly network: ChainNetwork;
  private readonly net: PsbtNetwork;

  constructor(config: PsbtConfig, opts: PsbtOptions = {}) {
    this.asset = config.asset;
    this.network = config.network ?? 'mainnet';
    this.net = psbtNetworkFor(this.asset, this.network);
    this.tx = new Transaction({ version: opts.version, lockTime: opts.lockTime });
  }

  /**
   * Accept an externally-supplied PSBT — e.g. a coordinator's join transaction that
   * already carries other participants' inputs and outputs. Deserializes with
   * `@scure/btc-signer`; you can then add YOUR input/output and sign only YOUR
   * indices before handing it back. This is the "merge external inputs+outputs into
   * a shared PSBT" half of CoinJoin participation.
   */
  static fromPsbt(psbtBytes: Uint8Array, config: PsbtConfig, opts: PsbtOptions = {}): Psbt {
    const wrapper = new Psbt(config, opts);
    // Replace the empty tx with the parsed one (readonly field set once here).
    (wrapper as { tx: Transaction }).tx = Transaction.fromPSBT(psbtBytes, {
      version: opts.version,
      lockTime: opts.lockTime,
    });
    return wrapper;
  }

  /** Number of inputs currently in the PSBT. */
  get inputsLength(): number {
    return this.tx.inputsLength;
  }

  /** Number of outputs currently in the PSBT. */
  get outputsLength(): number {
    return this.tx.outputsLength;
  }

  /** Add an input to spend (caller-supplied prevout). Returns the new input's index. */
  addInput(input: PsbtInput): number {
    return this.tx.addInput({
      txid: txidBytes(input.txid),
      index: input.index,
      witnessUtxo: input.witnessUtxo,
      ...(input.nonWitnessUtxo ? { nonWitnessUtxo: input.nonWitnessUtxo } : {}),
      ...(input.sighashType !== undefined ? { sighashType: input.sighashType } : {}),
      ...(input.redeemScript ? { redeemScript: input.redeemScript } : {}),
      ...(input.witnessScript ? { witnessScript: input.witnessScript } : {}),
      ...(input.sequence !== undefined ? { sequence: input.sequence } : {}),
    });
  }

  /** Add an output. Give `address` (encoded for this PSBT's network) OR a raw `script`. Returns its index. */
  addOutput(output: PsbtOutput): number {
    if (output.address) {
      return this.tx.addOutputAddress(output.address, output.amount, this.net);
    }
    if (output.script) {
      return this.tx.addOutput({ script: output.script, amount: output.amount });
    }
    throw new Error('Psbt.addOutput: provide either `address` or `script`');
  }

  /**
   * THE COINJOIN-COMPATIBLE PRIMITIVE — ⛔ ENCLAVE/CLIENT-ONLY.
   *
   * Sign ONLY the input indices in `ourIndices`, with `signingKey`. Every other
   * input — the ones belonging to other CoinJoin participants — is left completely
   * untouched. We never sign, and never even ATTEMPT to sign, an input we do not
   * own. (Built on `@scure/btc-signer`'s `signIdx`, which its own authors document
   * as the safe primitive for exactly this mixer/join workflow.)
   *
   * Throws if a declared-ours index is out of range, listed twice, or its script
   * does not contain our key (you claimed an input you cannot actually sign).
   *
   * @param signingKey - a 32-byte private scalar or an `HDKey`. PRIVATE material.
   * @param ourIndices - the input indices we control. REQUIRED and explicit; there
   *   is deliberately no "sign everything" default — that would defeat the property.
   */
  signOnlyOurInputs(signingKey: PsbtSigningKey, ourIndices: readonly number[]): SignResult {
    if (!Array.isArray(ourIndices)) {
      throw new Error('signOnlyOurInputs: ourIndices must be an array of input indices');
    }
    const n = this.tx.inputsLength;
    const ours = new Set<number>();
    for (const idx of ourIndices) {
      if (!Number.isInteger(idx) || idx < 0 || idx >= n) {
        throw new Error(`signOnlyOurInputs: index ${idx} is out of range [0, ${n})`);
      }
      if (ours.has(idx)) {
        throw new Error(`signOnlyOurInputs: index ${idx} listed more than once`);
      }
      ours.add(idx);
    }

    const signed: number[] = [];
    const skipped: number[] = [];
    for (let i = 0; i < n; i++) {
      if (!ours.has(i)) {
        // Not ours — NEVER touched. This is the load-bearing CoinJoin property.
        skipped.push(i);
        continue;
      }
      try {
        // btc-signer bundles its own @scure/bip32 whose HDKey types `publicKey` as
        // non-null; ours (pinned 2.3.0) types it nullable. The shapes are otherwise
        // identical, so cast to signIdx's own parameter type at this one boundary.
        this.tx.signIdx(signingKey as unknown as Parameters<Transaction['signIdx']>[0], i);
        signed.push(i);
      } catch (e) {
        const why = e instanceof Error ? e.message : String(e);
        throw new Error(
          `signOnlyOurInputs: declared ownership of input ${i} but could not sign it (${why})`,
        );
      }
    }
    return { signed, skipped };
  }

  /** Whether input `idx` carries a signature (partial or finalized). */
  isInputSigned(idx: number): boolean {
    const inp = this.tx.getInput(idx);
    return Boolean(
      (inp.partialSig && inp.partialSig.length) ||
        inp.finalScriptWitness ||
        inp.finalScriptSig ||
        inp.tapKeySig ||
        (inp.tapScriptSig && inp.tapScriptSig.length),
    );
  }

  /**
   * Merge another PSBT of the SAME transaction into this one — combining partial
   * signatures from multiple participants (each of whom signed only their own
   * inputs). Accepts a {@link Psbt} or raw PSBT bytes. Returns `this` for chaining.
   */
  combine(other: Psbt | Uint8Array): this {
    const otherTx =
      other instanceof Uint8Array ? Transaction.fromPSBT(other) : other.tx;
    this.tx.combine(otherTx);
    return this;
  }

  /** Serialize the current PSBT (with any partial signatures) to bytes, to hand to another party. */
  toPsbt(): Uint8Array {
    return this.tx.toPSBT();
  }

  /**
   * Finalize every input and extract the raw, broadcast-ready transaction. Only
   * succeeds when the PSBT is COMPLETE — every input signed. In a CoinJoin, that is
   * after all participants' partial signatures have been {@link Psbt.combine}d in;
   * before then, hand the partial PSBT back via {@link Psbt.toPsbt} instead.
   *
   * Broadcast is NOT our job — the returned hex goes to the wallet/network layer.
   *
   * @returns the raw transaction `hex` and its `txid`.
   */
  finalizeAndExtract(): { hex: string; txid: string } {
    this.tx.finalize();
    const raw = this.tx.extract();
    return { hex: hex.encode(raw), txid: this.tx.id };
  }
}

/** Convenience: a new, empty PSBT for the given asset/network. Equivalent to `new Psbt(config, opts)`. */
export function createPsbt(config: PsbtConfig, opts: PsbtOptions = {}): Psbt {
  return new Psbt(config, opts);
}

/**
 * Helper: the P2WPKH (native-segwit) scriptPubKey for a compressed public key, on
 * the PSBT's network. Handy for constructing a `witnessUtxo.script` when the caller
 * has the pubkey but not the raw prevout script. Pure; no private material.
 */
export function p2wpkhScript(
  publicKey: Uint8Array,
  asset: ChainAsset,
  network: ChainNetwork = 'mainnet',
): Uint8Array {
  const net = psbtNetworkFor(asset, network);
  const script = p2wpkh(publicKey, net).script;
  if (!script) throw new Error('p2wpkhScript: could not derive a P2WPKH script from the public key');
  return script;
}
