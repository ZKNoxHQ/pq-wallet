// ML-DSA-44 (FIPS 204), NIST variant of ETHDILITHIUM. Signing is deterministic (rnd = 0^32), empty context,
// message = the 32-byte digest. The on-chain key blob is the expanded form the verifier reads in place:
//   abi.encode(bytes aHat, bytes tr, bytes t1) with
//   aHat = abi.encode(uint256[4][4][32]) : A = ExpandA(rho) in NTT domain, 8 coefficients of 32 bits per word
//   tr   = SHAKE256(pk, 64)
//   t1   = abi.encode(uint256[4][32])    : NTT(t1 << 13), same packing
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";
import { genCrystals, XOF128 } from "@noble/post-quantum/_crystals";
import { shake256 } from "@noble/hashes/sha3";
import { encodeAbiParameters, type Hex, bytesToHex } from "viem";

export const MLDSA44 = { id: "ML-DSA-44" as const, sigBytes: 2420, pkBytes: 1312, skBytes: 2560 };

const N = 256, Q = 8380417, D = 13, K = 4, L = 4;
const { NTT } = genCrystals({ N, Q, F: 8347681, ROOT_OF_UNITY: 1753, newPoly: (n: number) => new Int32Array(n), isKyber: false, brvBits: 8 });

export function keygen(seed: Uint8Array) {
  if (seed.length !== 32) throw new Error("ML-DSA-44 seed must be 32 bytes");
  return ml_dsa44.keygen(seed);
}

/** FIPS 204 sign, deterministic, empty context. `digest` is the 32-byte message. */
export const sign = (secretKey: Uint8Array, digest: Uint8Array): Uint8Array => ml_dsa44.sign(secretKey, digest);
export const verify = (publicKey: Uint8Array, digest: Uint8Array, sig: Uint8Array) => ml_dsa44.verify(publicKey, digest, sig);

// ---- expanded public key ------------------------------------------------------------------------
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

function decode10(bytes: Uint8Array) {
  const p = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    const bit = i * 10, byte = bit >> 3, off = bit & 7;
    const v = bytes[byte] | (bytes[byte + 1] << 8) | ((bytes[byte + 2] ?? 0) << 16);
    p[i] = (v >> off) & 0x3ff;
  }
  return p;
}

function pack32(coeffs: Int32Array): bigint[] {
  const words: bigint[] = [];
  for (let w = 0; w < N / 8; w++) {
    let acc = 0n;
    for (let k = 0; k < 8; k++) acc |= BigInt(coeffs[w * 8 + k] >>> 0) << BigInt(32 * k);
    words.push(acc);
  }
  return words;
}

/** The blob given to `ZKNOX_dilithium.setKey` (stored with SSTORE2, read in place by the verifier). */
export function expandedPublicKey(publicKey: Uint8Array): Hex {
  if (publicKey.length !== MLDSA44.pkBytes) throw new Error("bad ML-DSA-44 public key length");
  const rho = publicKey.slice(0, 32);
  const xof = XOF128(rho);
  const aHat: bigint[][][] = [];
  for (let i = 0; i < K; i++) {
    const row: bigint[][] = [];
    for (let j = 0; j < L; j++) row.push(pack32(rejNttPoly(xof, i, j)));
    aHat.push(row);
  }
  xof.clean();
  const t1: bigint[][] = [];
  for (let i = 0; i < K; i++) {
    const p = decode10(publicKey.slice(32 + i * 320, 32 + (i + 1) * 320));
    for (let c = 0; c < N; c++) p[c] <<= D;
    NTT.encode(p);
    t1.push(pack32(p));
  }
  const tr = shake256(publicKey, { dkLen: 64 });
  const aHatEnc = encodeAbiParameters([{ type: "uint256[][][]" }], [aHat]);
  const t1Enc = encodeAbiParameters([{ type: "uint256[][]" }], [t1]);
  return encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }], [aHatEnc, bytesToHex(tr), t1Enc]);
}
