// The parts of the ECML-Signer host side that need no device, so they can be tested without one.
//
// Three conversions stand between what the Ledger app returns and what the chain expects, and each is a
// place where a wrong guess costs a reverted 3.9 M gas transaction:
//
//   1. the app returns the secp256k1 *public key*, never an address. The address is keccak of the
//      uncompressed point minus its 0x04 tag, last 20 bytes;
//   2. the k1 signature comes back **DER encoded** with `v` as a bare parity bit (0 or 1), where
//      `ECDSAk1Verifier` calls `ecrecover(digest, v, r, s)` and so wants 65 bytes r||s||v with v in
//      {27, 28}. No low-s normalisation: the parity the device reports belongs to the R point as produced,
//      and flipping s without flipping v would recover a different address;
//   3. the app only knows the packed 1,952-byte ML-DSA-65 public key. The expanded 38,112-byte form the
//      verifier reads is computed here, with ETHDILITHIUM's own encoder.
import { keccak_256 } from "../../lib/ETHDILITHIUM/js/node_modules/@noble/hashes/sha3.js";
import { expandPublicKey65, encodePublicKey65 } from "../../lib/ETHDILITHIUM/js/mldsa65.js";

export const MLDSA65_PK_BYTES = 1952;
export const MLDSA65_SIG_BYTES = 3309;
export const MLDSA65_KEY_BYTES = 38112;

/** Bytes from either bytes or a 0x-string. Everything below takes both, because the device gives buffers
 *  and a file or a command line gives hex, and silently reading "0x04…" as UTF-8 is a long way to debug. */
export function toBytes(v) {
  if (typeof v === "string") {
    const s = v.replace(/^0x/, "");
    if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error("not a hexadecimal string");
    return Buffer.from(s, "hex");
  }
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) return Buffer.from(v);
  throw new Error(`expected bytes or a hex string, got ${typeof v}`);
}

export const hex = (v) => "0x" + toBytes(v).toString("hex");

/** `m/44'/60'/0'/0'/0'` -> [len, u32 BE × len]. The app forces the hardened bit on every component for the
 *  ML-DSA key but not for the secp256k1 one, so a path that is not already fully hardened gives two keys
 *  from two different trees. This refuses that rather than producing a mismatched pair. */
export function packDerivationPath(path) {
  const parts = path.replace(/^m\//, "").split("/").filter(Boolean);
  if (parts.length === 0 || parts.length > 10) throw new Error("a derivation path has 1 to 10 components");
  const out = Buffer.alloc(1 + 4 * parts.length);
  out[0] = parts.length;
  parts.forEach((p, i) => {
    const hardened = p.endsWith("'") || p.endsWith("h");
    if (!hardened) {
      throw new Error(
        `${path}: component "${p}" is not hardened. The app hardens every component of the ML-DSA path and ` +
          `none of the secp256k1 one, so only a fully hardened path gives two halves of the same key.`,
      );
    }
    const n = Number(p.replace(/['h]$/, ""));
    if (!Number.isInteger(n) || n < 0 || n >= 0x80000000) throw new Error(`bad path component "${p}"`);
    out.writeUInt32BE((n >>> 0) + 0x80000000, 1 + 4 * i);
  });
  return out;
}

/** keccak256(pubkey[1..65])[12:32], the Ethereum address of an uncompressed secp256k1 point. */
export function addressFromPubkey(uncompressed) {
  const b = toBytes(uncompressed);
  if (b.length !== 65 || b[0] !== 0x04) throw new Error(`expected a 65-byte uncompressed point, got ${b.length}`);
  const h = keccak_256(b.subarray(1));
  return "0x" + Buffer.from(h.subarray(12)).toString("hex");
}

/** DER SEQUENCE { INTEGER r, INTEGER s } -> { r, s } as 32-byte buffers. */
export function parseDer(der) {
  const b = toBytes(der);
  if (b[0] !== 0x30) throw new Error("not a DER SEQUENCE");
  if (b[1] !== b.length - 2) throw new Error("DER length does not match the buffer");
  const readInt = (off) => {
    if (b[off] !== 0x02) throw new Error("expected a DER INTEGER");
    const len = b[off + 1];
    let v = b.subarray(off + 2, off + 2 + len);
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1); // strip the sign padding
    if (v.length > 32) throw new Error("DER integer wider than 32 bytes");
    return [Buffer.concat([Buffer.alloc(32 - v.length), v]), off + 2 + len];
  };
  const [r, next] = readInt(2);
  const [s, end] = readInt(next);
  if (end !== b.length) throw new Error("trailing bytes after the DER signature");
  return { r, s };
}

/** The 65 bytes `ECDSAk1Verifier` reads: r || s || v, v in {27, 28}. `parity` is the device's `v` byte,
 *  which is the low bit of the Ledger `info` word (CX_ECCINFO_PARITY_ODD). */
export function derToRsv(der, parity) {
  const { r, s } = parseDer(der);
  const p = Number(parity);
  if (p !== 0 && p !== 1) throw new Error(`the device's v is a parity bit, got ${parity}`);
  return hex(Buffer.concat([r, s, Buffer.from([27 + p])]));
}

/** The 38,112-byte argument every verification carries, from the device's packed 1,952-byte key. */
export function expandedKey(rawPk) {
  const b = toBytes(rawPk);
  if (b.length !== MLDSA65_PK_BYTES) {
    throw new Error(`an ML-DSA-65 public key is ${MLDSA65_PK_BYTES} bytes, got ${b.length}`);
  }
  const out = encodePublicKey65(expandPublicKey65(new Uint8Array(b)));
  if ((out.length - 2) / 2 !== MLDSA65_KEY_BYTES) {
    throw new Error(`expanded key is ${(out.length - 2) / 2} bytes, expected ${MLDSA65_KEY_BYTES}`);
  }
  return out;
}

export const keccak = (v) => hex(keccak_256(toBytes(v)));

/** How many (index, length) chunk reads cover `total` bytes at the app's 255-byte stride. */
export function chunkPlan(total, stride = 255) {
  const plan = [];
  for (let off = 0; off < total; off += stride) plan.push([plan.length, Math.min(stride, total - off)]);
  return plan;
}
