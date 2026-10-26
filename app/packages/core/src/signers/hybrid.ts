// Hybrid signature as ZKNOX_PQAccount7702 expects it:
//   abi.encode(bytes preQKey, bytes preQSig, bytes postQKey, bytes postQSig)
// preQKey  = the normalized pre-quantum key (20-byte address for secp256k1)
// preQSig  = r || s || v
// postQKey = the normalized post-quantum key (20-byte SSTORE2 pointer returned by verifier.setKey)
// postQSig = the raw FIPS 204 signature (cTilde || z || h)
import { encodeAbiParameters, keccak256, type Address, type Hex, bytesToHex, hexToBytes } from "viem";
import type { PrivateKeyAccount } from "viem/accounts";
import { mldsa44 } from "../keys";
import type { ProgressFn } from "../adapter/types";

export type HybridKeys = {
  ecdsa: PrivateKeyAccount; // pre-quantum key
  pqSecretKey: Uint8Array; // ML-DSA-44 secret key
  pqKeyRef: Address; // SSTORE2 pointer of the expanded public key blob
};

export const keyHash = (a: Address): Hex => keccak256(a);

export async function signHybrid(keys: HybridKeys, digest: Hex, progress?: ProgressFn): Promise<Hex> {
  progress?.("sign-ecdsa");
  const preQSig = await keys.ecdsa.sign({ hash: digest });
  progress?.("sign-pq");
  const postQSig = bytesToHex(mldsa44.sign(keys.pqSecretKey, hexToBytes(digest)));
  return encodeHybrid(keys.ecdsa.address, preQSig, keys.pqKeyRef, postQSig);
}

export const encodeHybrid = (preQKey: Address, preQSig: Hex, postQKey: Address, postQSig: Hex): Hex =>
  encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
    [preQKey, preQSig, postQKey, postQSig],
  );

/** Stub for gas estimation: a real hybrid signature over a fixed digest. Both verifiers run to their last
 *  comparison, so the estimate matches a valid signature (see the contract's `_verifyHybrid`). */
export const STUB_DIGEST: Hex = keccak256(new TextEncoder().encode("zknox.pqaccount.stub"));
export const stubSignature = (keys: HybridKeys) => signHybrid(keys, STUB_DIGEST);
