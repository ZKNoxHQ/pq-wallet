// Safe signature blobs, and the ERC-1271 payload a ZKNOX_PQAccount7702 owner validates.
//
// Port of `ZKNOX_SafePQSignatures.pack` / `.hybridPayload`; test/signatures.test.ts compares the bytes to
// the Solidity on the same inputs. Safe 1.5.0 `checkNSignatures` reads a 65-byte static record per
// signature, sorted by ascending owner address, and the dynamic payload of each contract signature is
// appended after the whole static part:
//
//   ECDSA      r (32) || s (32) || v (1)         v in {27,28}, or {31,32} when the EOA used personal_sign
//   contract   owner (32) || offset (32) || 0x00 offset points into the blob, at uint256 length || payload
//   approved   owner (32) || 0  (32)  || 0x01    owner called approveHash, or is the executor
import { concatHex, encodeAbiParameters, numberToHex, size, type Address, type Hex } from "viem";

export type OwnerSig =
  | { kind: "ecdsa"; owner: Address; rsv: Hex }
  | { kind: "contract"; owner: Address; payload: Hex }
  | { kind: "approved"; owner: Address };

const word = (v: bigint | number | Address): Hex => {
  const n = typeof v === "string" ? BigInt(v) : BigInt(v);
  return numberToHex(n, { size: 32 });
};

export const ecdsaSig = (owner: Address, rsv: Hex): OwnerSig => ({ kind: "ecdsa", owner, rsv });
export const contractSig = (owner: Address, payload: Hex): OwnerSig => ({ kind: "contract", owner, payload });
export const approvedSig = (owner: Address): OwnerSig => ({ kind: "approved", owner });

/** The `signatures` argument of `execTransaction`. Sorts by owner, as Safe requires; the input is not
 *  modified. */
export function pack(sigs: readonly OwnerSig[]): Hex {
  const sorted = [...sigs].sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : BigInt(a.owner) > BigInt(b.owner) ? 1 : 0));
  const staticLen = 65 * sorted.length;
  let head: Hex = "0x";
  let tail: Hex = "0x";
  for (const s of sorted) {
    if (s.kind === "ecdsa") {
      if (size(s.rsv) !== 65) throw new Error(`${s.owner}: an ECDSA signature is 65 bytes, got ${size(s.rsv)}`);
      head = concatHex([head, s.rsv]);
    } else if (s.kind === "approved") {
      head = concatHex([head, word(s.owner), word(0), "0x01"]);
    } else {
      head = concatHex([head, word(s.owner), word(staticLen + size(tail)), "0x00"]);
      tail = concatHex([tail, word(size(s.payload)), s.payload]);
    }
  }
  return concatHex([head, tail]);
}

/** ERC-1271 payload of ZKNOX_PQAccount7702: `abi.encode(preQKey, preQSig, postQKey, postQSig)`.
 *  `postQKey` is the 38,112-byte expanded ML-DSA-65 key — it travels in the signature, not in storage. */
export const hybridPayload = (preQKey: Hex, preQSig: Hex, postQKey: Hex, postQSig: Hex): Hex =>
  encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
    [preQKey, preQSig, postQKey, postQSig],
  );

/** r || s || v from a 65-byte signature, with v normalized to 27/28 and `ethSign` adding 4 as Safe reads it. */
export function normalizeV(rsv: Hex, ethSign = false): Hex {
  if (size(rsv) !== 65) throw new Error(`a signature is 65 bytes, got ${size(rsv)}`);
  let v = parseInt(rsv.slice(130, 132), 16);
  if (v < 27) v += 27;
  if (ethSign) v += 4;
  return (rsv.slice(0, 130) + v.toString(16).padStart(2, "0")) as Hex;
}
