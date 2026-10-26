// ML-DSA-65 (FIPS 204, category 3), the scheme ZKNOX_dilithium65 verifies. Signing is deterministic
// (rnd = 0^32), empty context, message = the 32-byte digest.
//
// The on-chain key is the expanded form the verifier reads in place, and it is not deployed: those
// 38,112 bytes travel in the calldata of every verification. One flat run, no ABI framing:
//
//   polynomial f at offset f * 1056, each as a length word of 32 then its 32 words of 8 packed
//   32-bit coefficients; f < 30 is A[f / 5][f % 5] = ExpandA(rho) in the NTT domain, f >= 30 is
//   t1[f - 30] = NTT(t1 << 13); then tr = SHAKE256(pk, 64) as a length word of 64 and its 64 bytes.
//
// test/mldsa65.test.ts checks this against ETHDILITHIUM's own js encoder and against the lengths the
// Solidity constants declare.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { genCrystals, XOF128 } from "@noble/post-quantum/_crystals";
import { shake256 } from "@noble/hashes/sha3";
import { type Hex } from "viem";

export const MLDSA65 = {
  id: "ML-DSA-65" as const,
  sigBytes: 3309,
  pkBytes: 1952,
  skBytes: 4032,
  /** the expanded key the verifier takes, and its shape */
  keyBytes: 38112,
  keyPolys: 36,
  polyBytes: 1056,
};

const N = 256, Q = 8380417, D = 13, K = 6, L = 5;
const { NTT } = genCrystals({
  N, Q, F: 8347681, ROOT_OF_UNITY: 1753,
  newPoly: (n: number) => new Int32Array(n), isKyber: false, brvBits: 8,
});

export function keygen(seed: Uint8Array) {
  if (seed.length !== 32) throw new Error("ML-DSA-65 seed must be 32 bytes");
  return ml_dsa65.keygen(seed);
}

/** FIPS 204 sign, deterministic, empty context. `digest` is the 32-byte message. */
export const sign = (secretKey: Uint8Array, digest: Uint8Array): Uint8Array => ml_dsa65.sign(secretKey, digest);
export const verify = (publicKey: Uint8Array, digest: Uint8Array, sig: Uint8Array) =>
  ml_dsa65.verify(publicKey, digest, sig);

// ---- expanded public key ------------------------------------------------------------------------

/** RejNTTPoly(rho || j || i), FIPS 204 Alg. 30. */
function rejNttPoly(xof: ReturnType<typeof XOF128>, i: number, j: number) {
  const r = new Int32Array(N);
  const get = xof.get(j, i);
  let idx = 0;
  while (idx < N) {
    const buf = get();
    for (let k = 0; idx < N && k + 2 < buf.length; k += 3) {
      const t = (buf[k] | (buf[k + 1] << 8) | (buf[k + 2] << 16)) & 0x7fffff;
      if (t < Q) r[idx++] = t;
    }
  }
  return r;
}

/** SimpleBitUnpack over 10 bits, the t1 encoding of pkDecode. */
function decode10(bytes: Uint8Array) {
  const p = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    const bit = i * 10, byte = bit >> 3, off = bit & 7;
    const v = bytes[byte] | (bytes[byte + 1] << 8) | ((bytes[byte + 2] ?? 0) << 16);
    p[i] = (v >> off) & 0x3ff;
  }
  return p;
}

/** 256 coefficients into 32 words, 8 of 32 bits each, low coefficient in the low bits. */
function pack32(coeffs: Int32Array): bigint[] {
  const words: bigint[] = [];
  for (let w = 0; w < N / 8; w++) {
    let acc = 0n;
    for (let k = 0; k < 8; k++) acc |= BigInt(coeffs[w * 8 + k] >>> 0) << BigInt(32 * k);
    words.push(acc);
  }
  return words;
}

const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
const polyHex = (words: bigint[]) => word(32) + words.map(word).join("");

/** The 36 polynomials in reading order: A row by row, then t1. */
export function flattenKeyPolys(publicKey: Uint8Array): bigint[][] {
  if (publicKey.length !== MLDSA65.pkBytes) throw new Error("bad ML-DSA-65 public key length");
  const rho = publicKey.slice(0, 32);
  const xof = XOF128(rho);
  const polys: bigint[][] = [];
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < L; j++) polys.push(pack32(rejNttPoly(xof, i, j)));
  }
  xof.clean();
  for (let i = 0; i < K; i++) {
    const p = decode10(publicKey.slice(32 + i * 320, 32 + (i + 1) * 320));
    for (let c = 0; c < N; c++) p[c] <<= D;
    NTT.encode(p);
    polys.push(pack32(p));
  }
  return polys;
}

/** The `pk` argument of every ZKNOX_dilithium65 verification, 38,112 bytes. */
export function expandedPublicKey(publicKey: Uint8Array): Hex {
  const polys = flattenKeyPolys(publicKey);
  const tr = shake256(publicKey, { dkLen: 64 });
  const body =
    polys.map(polyHex).join("") +
    word(64) +
    Array.from(tr, (b) => b.toString(16).padStart(2, "0")).join("");
  const out = `0x${body}` as Hex;
  if ((out.length - 2) / 2 !== MLDSA65.keyBytes) {
    throw new Error(`expanded key is ${(out.length - 2) / 2} bytes, expected ${MLDSA65.keyBytes}`);
  }
  return out;
}
