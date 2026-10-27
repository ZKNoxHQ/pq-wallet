// The ECML-Signer Ledger app, driven from the page instead of from a terminal.
//
// This is the browser side of `safe/scripts/ecml.mjs`, with one difference that matters: the transport is
// injected. A WebHID transport in the app, a fake one in `test/ledger.test.ts`, so the device path finally
// has coverage — until now nothing exercised it outside a hand-driven CLI.
//
// Three properties of ecml-signer v2.4.0 (CLA 0xE0) shape everything below:
//
//   - HYBRID_SIGN_HASH (0x16) returns ONLY the secp256k1 half inline, DER encoded, with `v` as a bare
//     parity bit. The ML-DSA key and signature stay in device RAM and come back through GET_PK_CHUNK
//     (0x13) and GET_SIG_CHUNK (0x12), 255 bytes at a time;
//   - GET_PUBLIC_KEY (0x05) and KEYGEN_DILITHIUM (0x11) share a union with that RAM and wipe it, so
//     nothing may run between 0x16 and the chunk reads. `sign` below therefore never reads the k1 address
//     from the device: it uses the one `readAccount` already cached;
//   - 0x16 is blind signing, off when the app is installed. Every call answers 0xB00A until it is enabled
//     in the app's settings, which is why that status word has a sentence of its own.
import { bytesToHex, keccak256, type Address, type Hex } from "viem";
import { expandedPublicKey, MLDSA65 } from "./mldsa65";
import type { PqAnswer } from "./plan";
import type { Signer } from "./signer";

export const CLA = 0xe0;
export const INS = {
  GET_PUBLIC_KEY: 0x05,
  KEYGEN_DILITHIUM: 0x11,
  GET_SIG_CHUNK: 0x12,
  GET_PK_CHUNK: 0x13,
  HYBRID_SIGN_HASH: 0x16,
} as const;
export const P2_MLDSA_65 = 0x01;
/** The app answers at most 255 bytes per chunk read. */
export const CHUNK_STRIDE = 255;

export const SW: Record<number, string> = {
  0x9000: "ok",
  0x6985: "refused on the device",
  0x6a86: "wrong P1/P2",
  0x6a87: "wrong length",
  0x6d00: "unknown instruction — ECML-Signer is not the app that answered",
  0x6e00: "wrong CLA — another app is open",
  0x6600: "the device failed to sign",
  0x6a84: "not enough memory on the device",
  0xb00a: "blind signing is disabled: turn it on in the ECML-Signer settings, then retry",
};

/** One APDU exchange. The implementation checks the status word and returns the payload without it. */
export type Apdu = (ins: number, p1: number, p2: number, data?: Uint8Array) => Promise<Uint8Array>;

export class ApduError extends Error {
  constructor(
    readonly ins: number,
    readonly sw: number,
  ) {
    super(`APDU 0x${ins.toString(16)} -> 0x${sw.toString(16)}: ${SW[sw] ?? "unexpected status"}`);
    this.name = "ApduError";
  }
}

/** The expected status words, for transports that want the list up front. */
export const STATUS_WORDS = Object.keys(SW).map(Number);

const hexOf = (b: Uint8Array): Hex => bytesToHex(b);

/** `m/44'/60'/0'/0/0` -> [len][u32 BE x len].
 *
 *  Either form is valid, and the difference is worth knowing. The app takes one path and derives each half
 *  by its own scheme's rules (`src/crypto/mldsa_derive.c`, ecml-signer at e2fee68): the secp256k1 half uses
 *  the path **raw**, while the ML-DSA half forces the hardened bit on every component, because SLIP-0010 in
 *  ed25519 mode requires it. No handler rejects a non-hardened path.
 *
 *  So the intended input is the ordinary `m/44'/60'/0'/0/x`: the k1 half is then the same account Rabby,
 *  MetaMask and `forge --ledger` derive, and the ML-DSA half comes from `m/44'/60'/0'/0'/x'`. Passing an
 *  already-hardened path is equally consistent — the ML-DSA key is identical, since both forms map to the
 *  same hardened variant — but the k1 half then sits where no standard wallet will look for it.
 *
 *  `requireHardened` is kept for callers that want the stricter form; it defaults off, because refusing the
 *  logical path refuses the app's own design. */
export function packDerivationPath(path: string, requireHardened = false): Uint8Array {
  const parts = path.replace(/^m\//, "").split("/").filter(Boolean);
  if (parts.length === 0 || parts.length > 10) throw new Error("a derivation path has 1 to 10 components");
  const out = new Uint8Array(1 + 4 * parts.length);
  const view = new DataView(out.buffer);
  out[0] = parts.length;
  parts.forEach((p, i) => {
    const hardened = p.endsWith("'") || p.endsWith("h");
    if (!hardened && requireHardened) {
      throw new Error(`${path}: component "${p}" is not hardened, and this caller asked for hardened only`);
    }
    const n = Number(p.replace(/['h]$/, ""));
    if (!Number.isInteger(n) || n < 0 || n >= 0x80000000) throw new Error(`bad path component "${p}"`);
    view.setUint32(1 + 4 * i, (n >>> 0) + (hardened ? 0x80000000 : 0), false);
  });
  return out;
}

/** How many (index, length) chunk reads cover `total` bytes at the app's stride. */
export function chunkPlan(total: number, stride = CHUNK_STRIDE): [number, number][] {
  const plan: [number, number][] = [];
  for (let off = 0; off < total; off += stride) plan.push([plan.length, Math.min(stride, total - off)]);
  return plan;
}

/** DER SEQUENCE { INTEGER r, INTEGER s } -> r and s, each left-padded to 32 bytes. */
export function parseDer(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  if (der[0] !== 0x30) throw new Error("not a DER SEQUENCE");
  if (der[1] !== der.length - 2) throw new Error("DER length does not match the buffer");
  const readInt = (off: number): [Uint8Array, number] => {
    if (der[off] !== 0x02) throw new Error("expected a DER INTEGER");
    const len = der[off + 1];
    let v = der.subarray(off + 2, off + 2 + len);
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1); // drop the sign padding
    if (v.length > 32) throw new Error("DER integer wider than 32 bytes");
    const padded = new Uint8Array(32);
    padded.set(v, 32 - v.length);
    return [padded, off + 2 + len];
  };
  const [r, next] = readInt(2);
  const [s, end] = readInt(next);
  if (end !== der.length) throw new Error("trailing bytes after the DER signature");
  return { r, s };
}

/** The 65 bytes `ECDSAk1Verifier` reads: r || s || v with v in {27, 28}.
 *
 *  `parity` is the device's `v` byte, the low bit of the Ledger `info` word (CX_ECCINFO_PARITY_ODD). No
 *  low-s normalisation: the parity belongs to the R point as produced, and flipping s without flipping v
 *  recovers a different address. */
export function derToRsv(der: Uint8Array, parity: number): Hex {
  const { r, s } = parseDer(der);
  if (parity !== 0 && parity !== 1) throw new Error(`the device's v is a parity bit, got ${parity}`);
  const out = new Uint8Array(65);
  out.set(r, 0);
  out.set(s, 32);
  out[64] = 27 + parity;
  return hexOf(out);
}

/** keccak256(point[1..65])[12:32]: the address of an uncompressed secp256k1 point. The app returns the
 *  public key and never the address, so this is ours to compute. */
export function addressFromPubkey(uncompressed: Uint8Array): Address {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error(`expected a 65-byte uncompressed point, got ${uncompressed.length}`);
  }
  return (`0x${keccak256(uncompressed.subarray(1)).slice(26)}`) as Address;
}

/** One account of the device: both halves of the hybrid key, and the two hashes a clone stores. */
export type DeviceAccount = {
  path: string;
  k1Address: Address;
  /** the 38,112-byte form the verifier reads, expanded here from the 1,952 the app holds */
  expandedKey: Hex;
  preQKeyHash: Hex;
  postQKeyHash: Hex;
};

/** Reads `total` bytes through a chunked instruction. Nothing else may run in between. */
async function fetchChunks(send: Apdu, ins: number, total: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let n = 0;
  for (const [index, length] of chunkPlan(total)) {
    const part = await send(ins, index, length);
    parts.push(part);
    n += part.length;
  }
  if (n !== total) throw new Error(`expected ${total} bytes, the device returned ${n}`);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** GET_PUBLIC_KEY answers [65][uncompressed point][32][chain code]. */
async function readK1Address(send: Apdu, path: string): Promise<Address> {
  const res = await send(INS.GET_PUBLIC_KEY, 0x00, 0x00, packDerivationPath(path));
  if (res[0] !== 65) throw new Error(`expected a 65-byte point, the device announced ${res[0]}`);
  return addressFromPubkey(res.subarray(1, 66));
}

/** Both halves at one path. Costs a KEYGEN_DILITHIUM and eight chunk reads, so the caller caches it. */
export async function readAccount(send: Apdu, path: string): Promise<DeviceAccount> {
  const k1Address = await readK1Address(send, path);
  // KEYGEN_DILITHIUM loads the key into the context without asking the holder; the chunks then read it.
  await send(INS.KEYGEN_DILITHIUM, 0x00, P2_MLDSA_65, packDerivationPath(path));
  const packed = await fetchChunks(send, INS.GET_PK_CHUNK, MLDSA65.pkBytes);
  const expandedKey = expandedPublicKey(packed);
  return {
    path,
    k1Address,
    expandedKey,
    preQKeyHash: keccak256(k1Address),
    postQKeyHash: keccak256(expandedKey),
  };
}

/** The hybrid signature over one 32-byte digest, at an account already read.
 *
 *  `account.k1Address` and `account.expandedKey` come from the caller rather than from a fresh read,
 *  because GET_PUBLIC_KEY would wipe the ML-DSA RAM that the two chunk reads below are about to drain. */
export async function signWithAccount(send: Apdu, account: DeviceAccount, owner: Address, digest: Hex): Promise<PqAnswer> {
  if ((digest.length - 2) / 2 !== 32) throw new Error(`a digest is 32 bytes, got ${(digest.length - 2) / 2}`);
  const path = packDerivationPath(account.path);
  const d = new Uint8Array(32);
  for (let i = 0; i < 32; i++) d[i] = parseInt(digest.slice(2 + i * 2, 4 + i * 2), 16);
  const payload = new Uint8Array(path.length + 32);
  payload.set(path, 0);
  payload.set(d, path.length);

  const res = await send(INS.HYBRID_SIGN_HASH, 0x00, P2_MLDSA_65, payload);
  const derLen = res[0];
  const k1Signature = derToRsv(res.subarray(1, 1 + derLen), res[1 + derLen]);
  // Still inside the window where no other instruction may run.
  const packed = await fetchChunks(send, INS.GET_PK_CHUNK, MLDSA65.pkBytes);
  const pqSignature = hexOf(await fetchChunks(send, INS.GET_SIG_CHUNK, MLDSA65.sigBytes));

  const expandedKey = expandedPublicKey(packed);
  if (expandedKey.toLowerCase() !== account.expandedKey.toLowerCase()) {
    throw new Error("the device returned a different ML-DSA-65 key than the one read at this path");
  }
  return { owner, k1Address: account.k1Address, k1Signature, expandedKey, pqSignature };
}

/** A `Signer` bound to one device account, interchangeable with the software holder of `signer.ts`. */
export function ledgerSigner(send: Apdu, account: DeviceAccount, label = "ledger"): Signer {
  return {
    id: `${label}:${account.k1Address}`,
    async keyHashes() {
      return { preQKeyHash: account.preQKeyHash, postQKeyHash: account.postQKeyHash };
    },
    sign: (owner, digest) => signWithAccount(send, account, owner, digest),
  };
}

/** The paths this app scans when looking for the account that owns a clone.
 *
 *  Two families, because both are in use and they are not interchangeable on the k1 side. `m/44'/60'/0'/0/i`
 *  is the ordinary BIP-44 account, which is what the app's own derivation expects and what every wallet
 *  shows. `m/44'/60'/0'/i'/0'` is what this repository's own clones were created from, before the app's
 *  source settled the question. Interleaved by index so the common case is found first. */
export const defaultPaths = (count = 5): string[] =>
  Array.from({ length: count }, (_, i) => [`m/44'/60'/0'/0/${i}`, `m/44'/60'/0'/${i}'/0'`]).flat();

/** Keeps the device's accounts between owners: a scan costs nine APDUs per path, and the second owner of
 *  the same arrangement is almost always another account of the same device. */
export class LedgerAccounts {
  private readonly cache = new Map<string, DeviceAccount>();

  constructor(private readonly send: Apdu) {}

  get known(): DeviceAccount[] {
    return [...this.cache.values()];
  }

  async at(path: string): Promise<DeviceAccount> {
    const hit = this.cache.get(path);
    if (hit) return hit;
    const account = await readAccount(this.send, path);
    this.cache.set(path, account);
    return account;
  }

  /** The hybrid signature for one owner, at an account this object already read. Goes through the class so
   *  the transport stays here and the caller never holds a raw APDU channel. */
  signAs(account: DeviceAccount, owner: Address, digest: Hex): Promise<PqAnswer> {
    return signWithAccount(this.send, account, owner, digest);
  }

  /** The account whose keys are the ones a clone stores, or null if none of `paths` matches.
   *
   *  Both hashes matter, and `postQKeyHash` alone is not enough: the hardened and the logical form of one
   *  account index yield the *same* ML-DSA key and different secp256k1 addresses, so matching on the
   *  post-quantum half alone can return the right key with the wrong partner. Pass `preQKeyHash` whenever
   *  the clone is known, which is always in this front. */
  async find(postQKeyHash: Hex, preQKeyHash?: Hex, paths = defaultPaths()): Promise<DeviceAccount | null> {
    const post = postQKeyHash.toLowerCase();
    const pre = preQKeyHash?.toLowerCase();
    const fits = (a: DeviceAccount) =>
      a.postQKeyHash.toLowerCase() === post && (!pre || a.preQKeyHash.toLowerCase() === pre);

    for (const a of this.cache.values()) if (fits(a)) return a;
    for (const path of paths) {
      if (this.cache.has(path)) continue;
      const a = await this.at(path);
      if (fits(a)) return a;
    }
    return null;
  }
}
