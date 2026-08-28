/**
 * An INDEPENDENT second implementation of BIP32 CKDpub + BIP84 P2WPKH addressing,
 * written only against the specs (BIP32 / BIP173 / base58check) and Node's own
 * `node:crypto`. It shares NO code with src/pay/derive.ts: no @scure/bip32, no
 * @scure/base, no @noble/*.
 *
 * Its job is to be the cross-check the brief asks for: the LTC vectors have no
 * published reference, so they are only trustworthy if two implementations that
 * do not share a line of code agree — and if the SAME independent implementation
 * also reproduces the PUBLISHED BIP84 Bitcoin vectors.
 *
 * Elliptic curve arithmetic here is deliberately naive BigInt affine math. It is
 * slow, it is not constant-time, and that is fine: it only ever touches PUBLIC keys
 * in a test.
 */

import { createHash, createHmac } from 'node:crypto';

// ---------- hashing (node:crypto only) ----------
const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const ripemd160 = (b) => new Uint8Array(createHash('ripemd160').update(b).digest());
const hash160 = (b) => ripemd160(sha256(b));
const hmac512 = (key, data) => new Uint8Array(createHmac('sha512', key).update(data).digest());

// ---------- secp256k1, from the curve parameters ----------
const P = 2n ** 256n - 2n ** 32n - 977n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const mod = (a, m = P) => ((a % m) + m) % m;

function invert(a, m = P) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('ref: not invertible');
  return mod(old_s, m);
}

function powMod(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const ZERO = null; // point at infinity

function pointAdd(A, B) {
  if (A === ZERO) return B;
  if (B === ZERO) return A;
  const [x1, y1] = A;
  const [x2, y2] = B;
  if (x1 === x2 && mod(y1 + y2) === 0n) return ZERO;
  const lam = x1 === x2 && y1 === y2
    ? mod(3n * x1 * x1 * invert(2n * y1))
    : mod((y2 - y1) * invert(x2 - x1));
  const x3 = mod(lam * lam - x1 - x2);
  return [x3, mod(lam * (x1 - x3) - y1)];
}

function scalarMul(k, Pt) {
  let acc = ZERO;
  let add = Pt;
  k = mod(k, N);
  while (k > 0n) {
    if (k & 1n) acc = pointAdd(acc, add);
    add = pointAdd(add, add);
    k >>= 1n;
  }
  return acc;
}

const bytesToBig = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));

function bigToBytes32(n) {
  return Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
}

function decompress(pub33) {
  if (pub33.length !== 33 || (pub33[0] !== 2 && pub33[0] !== 3)) {
    throw new Error('ref: not a compressed public key');
  }
  const x = bytesToBig(pub33.slice(1));
  const y2 = mod(x * x * x + 7n);
  let y = powMod(y2, (P + 1n) / 4n, P);
  if (mod(y * y) !== y2) throw new Error('ref: point not on curve');
  if (y % 2n !== BigInt(pub33[0] - 2)) y = P - y;
  return [x, y];
}

function compress([x, y]) {
  const out = new Uint8Array(33);
  out[0] = y % 2n === 0n ? 2 : 3;
  out.set(bigToBytes32(x), 1);
  return out;
}

// ---------- base58check (from the alphabet up) ----------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(s) {
  let num = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error(`ref: bad base58 char "${ch}"`);
    num = num * 58n + BigInt(i);
  }
  let hexs = num.toString(16);
  if (hexs.length % 2) hexs = '0' + hexs;
  let body = hexs === '0' ? [] : Array.from(Buffer.from(hexs, 'hex'));
  let zeros = 0;
  for (const ch of s) {
    if (ch === '1') zeros++;
    else break;
  }
  return Uint8Array.from([...new Array(zeros).fill(0), ...body]);
}

export function base58checkDecode(s) {
  const all = base58Decode(s);
  const payload = all.slice(0, all.length - 4);
  const check = all.slice(all.length - 4);
  const want = sha256(sha256(payload)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (check[i] !== want[i]) throw new Error('ref: base58check checksum mismatch');
  return payload;
}

// ---------- bech32 (BIP173, from the spec text) ----------
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}

export function bech32EncodeSegwit(hrp, witver, program) {
  const data = [witver, ...convertBits(Array.from(program), 8, 5, true)];
  const chk = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((chk >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((d) => CHARSET[d]).join('');
}

/** Decode a bech32 segwit address back to { hrp, witver, program } — used to prove
 *  two addresses on different chains carry the SAME witness program. */
export function bech32DecodeSegwit(addr) {
  const pos = addr.lastIndexOf('1');
  const hrp = addr.slice(0, pos);
  const data = Array.from(addr.slice(pos + 1)).map((c) => {
    const i = CHARSET.indexOf(c);
    if (i < 0) throw new Error(`ref: bad bech32 char "${c}"`);
    return i;
  });
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error('ref: bad bech32 checksum');
  const witver = data[0];
  const program = Uint8Array.from(convertBits(data.slice(1, data.length - 6), 5, 8, false));
  return { hrp, witver, program };
}

// ---------- BIP32 CKDpub ----------
function ser32(i) {
  return Uint8Array.from([(i >>> 24) & 255, (i >>> 16) & 255, (i >>> 8) & 255, i & 255]);
}

/** Parse any 78-byte extended key serialization into its parts. */
export function parseExtended(xpub) {
  const raw = base58checkDecode(xpub);
  if (raw.length !== 78) throw new Error(`ref: expected 78 bytes, got ${raw.length}`);
  return {
    version: Buffer.from(raw.slice(0, 4)).toString('hex'),
    depth: raw[4],
    chainCode: raw.slice(13, 45),
    key: raw.slice(45, 78),
    raw,
  };
}

/** BIP32 public parent → public child (non-hardened only). */
export function ckdPub(pubKey, chainCode, index) {
  if (index >= 0x80000000) throw new Error('ref: cannot derive hardened child from a public key');
  const I = hmac512(Buffer.from(chainCode), Buffer.concat([Buffer.from(pubKey), Buffer.from(ser32(index))]));
  const IL = bytesToBig(I.slice(0, 32));
  if (IL >= N) throw new Error('ref: IL >= n, retry with next index');
  const child = pointAdd(scalarMul(IL, [Gx, Gy]), decompress(pubKey));
  if (child === ZERO) throw new Error('ref: child is the point at infinity');
  return { pubKey: compress(child), chainCode: I.slice(32, 64) };
}

/**
 * Derive the BIP84 receive address at m/<change>/<index> from an account xpub.
 * `hrp` is supplied by the caller ('bc' | 'ltc' | 'tb' | 'tltc') — the reference
 * implementation makes no attempt to infer the chain from version bytes.
 */
export function refAddress(xpub, hrp, index, change = 0) {
  const ext = parseExtended(xpub);
  let node = { pubKey: ext.key, chainCode: ext.chainCode };
  node = ckdPub(node.pubKey, node.chainCode, change);
  node = ckdPub(node.pubKey, node.chainCode, index);
  return {
    pubkey_hex: Buffer.from(node.pubKey).toString('hex'),
    program: hash160(node.pubKey),
    address: bech32EncodeSegwit(hrp, 0, hash160(node.pubKey)),
  };
}

function base58checkEncode(payload) {
  const check = sha256(sha256(payload)).slice(0, 4);
  const full = Buffer.concat([Buffer.from(payload), Buffer.from(check)]);
  let num = BigInt('0x' + full.toString('hex'));
  let s = '';
  while (num > 0n) {
    s = B58[Number(num % 58n)] + s;
    num /= 58n;
  }
  for (const b of full) {
    if (b === 0) s = '1' + s;
    else break;
  }
  return s;
}

/** Re-serialize an extended public key under different version bytes. */
export function reVersion(xpub, versionHex) {
  const raw = Buffer.from(base58checkDecode(xpub));
  Buffer.from(versionHex, 'hex').copy(raw, 0);
  return base58checkEncode(raw);
}

/**
 * Build a fresh 78-byte extended PUBLIC key serialization. Used to mint a second,
 * genuinely different Litecoin account key for the distinctness test, without
 * inventing a string from memory.
 */
export function serializeExtended({ versionHex, depth, parentFingerprint, childNumber, chainCode, pubKey }) {
  const out = Buffer.alloc(78);
  Buffer.from(versionHex, 'hex').copy(out, 0);
  out[4] = depth;
  Buffer.from(parentFingerprint).copy(out, 5);
  Buffer.from(ser32(childNumber)).copy(out, 9);
  Buffer.from(chainCode).copy(out, 13);
  Buffer.from(pubKey).copy(out, 45);
  return base58checkEncode(out);
}

export { hash160, sha256 };
