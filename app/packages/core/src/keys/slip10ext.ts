// SLIP-0010 extended to post-quantum schemes: the master key is
//   I = HMAC-SHA512(key = "<scheme>-v1 seed", data = BIP39 seed), IL | IR
// then hardened-only child derivation (SLIP-0010 Ed25519 mechanics, no curve reduction):
//   I = HMAC-SHA512(key = chain, data = 0x00 || key || ser32(index | 0x80000000)).
// The 32-byte IL at the end of the path is the scheme's KeyGen seed (FIPS 204 Algorithm 1 for ML-DSA).
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha2";
import { utf8ToBytes } from "@noble/hashes/utils";

export const SEED_KEYS = {
  "ML-DSA-44": "ML-DSA-44-v1 seed",
  "ML-DSA-65": "ML-DSA-65-v1 seed",
  "Falcon-512": "Falcon-512-v1 seed",
} as const;
export type SchemeId = keyof typeof SEED_KEYS;

const HARDENED = 0x80000000;

export function parsePath(path: string): number[] {
  const parts = path.replace(/^m\//, "").split("/").filter(Boolean);
  return parts.map((p) => {
    const hardened = p.endsWith("'") || p.endsWith("h");
    const n = parseInt(hardened ? p.slice(0, -1) : p, 10);
    if (!Number.isInteger(n) || n < 0 || n >= HARDENED) throw new Error(`bad path component ${p}`);
    if (!hardened) throw new Error(`SLIP-0010 post-quantum derivation requires hardened components: ${p}`);
    return (n | HARDENED) >>> 0;
  });
}

/** Default path: BIP-44 semantics, coin type = network, all levels hardened. */
export const defaultPath = (account = 0, index = 0) => `m/44'/60'/${account}'/0'/${index}'`;

export function deriveSeed(scheme: SchemeId, bip39Seed: Uint8Array, path = defaultPath()) {
  const I = hmac(sha512, utf8ToBytes(SEED_KEYS[scheme]), bip39Seed);
  let key = I.slice(0, 32);
  let chain = I.slice(32, 64);
  for (const idx of parsePath(path)) {
    const data = new Uint8Array(1 + 32 + 4);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, idx, false);
    const C = hmac(sha512, chain, data);
    key = C.slice(0, 32);
    chain = C.slice(32, 64);
  }
  return { seed: key, chainCode: chain };
}
