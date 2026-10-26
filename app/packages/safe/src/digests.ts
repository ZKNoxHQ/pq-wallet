// The digest chain, off-chain. It mirrors safe/src/libraries/ZKNOX_SafePQSignatures.sol exactly, and
// test/digests.test.ts compares every function here to that Solidity through a forge fixture.
//
// Why compute it here rather than call the chain: the front has to show the signer the 32 bytes before the
// device does, and a digest read from an RPC the front does not control is a digest the signer cannot check.
// Everything below is derived from the Safe's own parameters; the only thing read from a chain is the nonce.
//
//   root Safe tx                     safeTxHash = EIP-712 SafeTx in the root's domain
//   owner of the root is a Safe C    C's owners sign safeMessageHash(C, safeTxHash)
//   owner of C is a PQ clone P       P signs hashWrapped(P, that)            <- nestedOwnerDigest
//
// The approveHash path is shorter and is the one the front uses by default: S_pq executes its own
// transaction `root.approveHash(rootSafeTxHash)`, so a PQ owner of S_pq signs ONE wrap of S_pq's own
// safeTxHash — not the three-layer chain. Confusing the two produces a signature Safe rejects with no
// explanation, which is the mistake this module exists to prevent.
import { concatHex, encodeAbiParameters, keccak256, type Address, type Hex } from "viem";

/** keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)") */
export const SAFE_TX_TYPEHASH: Hex = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8";
/** keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), Safe 1.3.0+ */
export const SAFE_DOMAIN_TYPEHASH: Hex = "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218";
/** keccak256("SafeMessage(bytes message)"), CompatibilityFallbackHandler */
export const SAFE_MSG_TYPEHASH: Hex = "0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca";

/** ZKNOX_PQAccount7702's EIP-712 constants. */
export const PQ_DOMAIN_TYPEHASH: Hex = "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f";
export const PQ_NAME_HASH: Hex = "0xb782b28a20ca763a844f05ede7d755c13198b3cb0a53f8278dc774b634691484";
export const PQ_VERSION_HASH: Hex = "0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6";
export const PQ_WRAPPED_TYPEHASH: Hex = "0x48ef993d23de578687c065cc519dcbd34381c9365b9628fd3a2f0e970d1df092";

export const ZERO: Address = "0x0000000000000000000000000000000000000000";

const typed = (domainSeparator: Hex, structHash: Hex): Hex =>
  keccak256(concatHex(["0x19", "0x01", domainSeparator, structHash]));

/** A Safe transaction, with the fields nobody uses defaulted to 0. */
export type SafeTx = {
  to: Address;
  value?: bigint;
  data?: Hex;
  operation?: 0 | 1; // CALL | DELEGATECALL
  safeTxGas?: bigint;
  baseGas?: bigint;
  gasPrice?: bigint;
  gasToken?: Address;
  refundReceiver?: Address;
  nonce: bigint;
};

export type FullSafeTx = Required<SafeTx>;

export const fullTx = (tx: SafeTx): FullSafeTx => ({
  to: tx.to,
  value: tx.value ?? 0n,
  data: tx.data ?? "0x",
  operation: tx.operation ?? 0,
  safeTxGas: tx.safeTxGas ?? 0n,
  baseGas: tx.baseGas ?? 0n,
  gasPrice: tx.gasPrice ?? 0n,
  gasToken: tx.gasToken ?? ZERO,
  refundReceiver: tx.refundReceiver ?? ZERO,
  nonce: tx.nonce,
});

/** Safe 1.3.0+ domain separator: chainId and the Safe's own address, no name and no version. */
export const safeDomainSeparator = (safe: Address, chainId: number): Hex =>
  keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [SAFE_DOMAIN_TYPEHASH, BigInt(chainId), safe],
    ),
  );

/** What `safe.getTransactionHash(...)` returns. Computed locally so the signer can check it. */
export function safeTxHash(safe: Address, chainId: number, tx: SafeTx): Hex {
  const t = fullTx(tx);
  const structHash = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" }, { type: "address" }, { type: "uint256" }, { type: "bytes32" },
        { type: "uint8" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" },
        { type: "address" }, { type: "address" }, { type: "uint256" },
      ],
      [
        SAFE_TX_TYPEHASH, t.to, t.value, keccak256(t.data), t.operation,
        t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver, t.nonce,
      ],
    ),
  );
  return typed(safeDomainSeparator(safe, chainId), structHash);
}

/** The hash the owners of `safe` sign so that `safe.isValidSignature(hash, sig)` holds (ERC-1271 through
 *  CompatibilityFallbackHandler): EIP-712 SafeMessage(abi.encode(hash)) in `safe`'s domain. */
export function safeMessageHash(safe: Address, chainId: number, hash: Hex): Hex {
  const structHash = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }],
      [SAFE_MSG_TYPEHASH, keccak256(encodeAbiParameters([{ type: "bytes32" }], [hash]))],
    ),
  );
  return typed(safeDomainSeparator(safe, chainId), structHash);
}

/** `clone.hashWrapped(hash)`: the 32 bytes both halves of a hybrid signature are made over. */
export function hashWrapped(pqAccount: Address, chainId: number, hash: Hex): Hex {
  const domain = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [PQ_DOMAIN_TYPEHASH, PQ_NAME_HASH, PQ_VERSION_HASH, BigInt(chainId), pqAccount],
    ),
  );
  const structHash = keccak256(
    encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [PQ_WRAPPED_TYPEHASH, hash]),
  );
  return typed(domain, structHash);
}

/** Single-transaction path (`ExecNestedTx`): the whole chain, root safeTxHash -> SafeMessage of S_pq ->
 *  EIP-712 wrap of the clone. */
export const nestedOwnerDigest = (
  sPq: Address, pqAccount: Address, chainId: number, rootSafeTxHash: Hex,
): Hex => hashWrapped(pqAccount, chainId, safeMessageHash(sPq, chainId, rootSafeTxHash));

/** approveHash path: the clone signs one wrap of S_pq's own safeTxHash, the transaction being
 *  `root.approveHash(rootSafeTxHash)`. One layer, not three. */
export const approveHashOwnerDigest = (
  pqAccount: Address, chainId: number, sPqSafeTxHash: Hex,
): Hex => hashWrapped(pqAccount, chainId, sPqSafeTxHash);

/** EIP-191 of a digest, for an EOA that signed through `personal_sign` (Safe reads it from v + 4). */
export const ethSignedHash = (hash: Hex): Hex =>
  keccak256(concatHex(["0x19457468657265756d205369676e6564204d6573736167653a0a3332", hash]));

/** Identifies a Safe transaction across reloads; the front uses it as a storage key. */
export const txKey = (safe: Address, chainId: number, tx: SafeTx): string =>
  `${chainId}:${safe.toLowerCase()}:${tx.nonce}:${safeTxHash(safe, chainId, tx)}`;
