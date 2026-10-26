// A software holder, for the demo and the tests: one 32-byte seed stands in for one post-quantum owner.
//
// A real holder is the ECML-Signer Ledger app, which signs an arbitrary 32-byte digest through
// HYBRID_SIGN_HASH and returns both halves. The front treats the two identically — it hands over a digest
// and takes back a `PqAnswer` — so `PasteSigner` (the device, by copy and paste) and `SeedSigner` (this)
// are interchangeable, and the device path is never the untested one.
import { bytesToHex, hexToBytes, keccak256, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { PqAnswer } from "./plan";
import { expandedPublicKey, keygen, sign, MLDSA65 } from "./mldsa65";

export type Signer = {
  readonly id: string;
  /** what the clone's `keyHashes()` must hold for this holder to be accepted */
  keyHashes(): Promise<{ preQKeyHash: Hex; postQKeyHash: Hex }>;
  sign(owner: Address, digest: Hex): Promise<PqAnswer>;
};

/** Both halves from one seed: the k1 key is `keccak256(seed || "k1")`, the ML-DSA-65 key is the seed.
 *  Separating them keeps the two schemes independent, which is the whole point of the hybrid. */
export function seedSigner(seed: Uint8Array, label = "seed"): Signer {
  if (seed.length !== 32) throw new Error("a holder's seed is 32 bytes");
  const k1 = privateKeyToAccount(keccak256(new Uint8Array([...seed, 0x6b, 0x31])));
  const { publicKey, secretKey } = keygen(seed);
  const expandedKey = expandedPublicKey(publicKey);
  return {
    id: `${label}:${k1.address}`,
    async keyHashes() {
      return { preQKeyHash: keccak256(k1.address), postQKeyHash: keccak256(expandedKey) };
    },
    async sign(owner, digest) {
      const k1Signature = await k1.sign({ hash: digest });
      const pqSignature = bytesToHex(sign(secretKey, hexToBytes(digest)));
      return { owner, k1Address: k1.address, k1Signature, expandedKey, pqSignature };
    },
  };
}

/** What a hardware holder returns, checked for shape before it reaches the packing. The expanded key comes
 *  from the holder too: 38,112 bytes is more than a screen can show, so the front takes it as a file or a
 *  URL and only ever displays its hash — which is also the value the clone compares against. */
export function pasteAnswer(input: {
  owner: Address;
  k1Address: Address;
  k1Signature: Hex;
  expandedKey: Hex;
  pqSignature: Hex;
}): PqAnswer {
  const check = (what: string, v: Hex, expected: number) => {
    const n = (v.length - 2) / 2;
    if (!/^0x[0-9a-fA-F]*$/.test(v)) throw new Error(`${what}: not hexadecimal`);
    if (n !== expected) throw new Error(`${what}: ${n} bytes, expected ${expected}`);
  };
  check("the k1 signature", input.k1Signature, 65);
  check("the expanded ML-DSA-65 key", input.expandedKey, MLDSA65.keyBytes);
  check("the ML-DSA-65 signature", input.pqSignature, MLDSA65.sigBytes);
  return input;
}
