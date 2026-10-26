// The approveHash plan: the one way a post-quantum Safe transaction fits in an ordinary Safe{Wallet} screen.
//
// A root transaction signed in one shot carries both children's payloads at once — 84 kB of signature, and
// the Safe Transaction Service refuses it twice over (a confirmation is capped at 5,000 bytes, and the
// Client Gateway mis-parses more than one contract signature in a blob). So the weight moves into the
// children instead:
//
//   1. S_ecdsa executes `root.approveHash(rootSafeTxHash)`  <- Safe{Wallet} does this by itself
//                                                              ("on-chain signature"), nothing to build here
//   2. S_pq    executes `root.approveHash(rootSafeTxHash)`  <- this is what the front is for: every PQ owner
//                                                              signs ONE wrap of S_pq's own safeTxHash
//   3. the root executes, with two 65-byte approved-hash records and nothing else
//
// Step 2 is a ~84 kB transaction sent straight to an RPC. Step 3 is 130 bytes of signature.
import { encodeFunctionData, size, type Address, type Hex } from "viem";
import { safeAbi } from "./abi";
import { approveHashOwnerDigest, fullTx, safeTxHash, type SafeTx } from "./digests";
import { approvedSig, contractSig, hybridPayload, pack, type OwnerSig } from "./signatures";
import { MLDSA65 } from "./mldsa65";

export type NestedSafe = {
  chainId: number;
  root: Address;
  sEcdsa: Address;
  sPq: Address;
  /** owners of S_pq that are post-quantum clones, and its threshold */
  pqOwners: readonly Address[];
  k: number;
};

/** One post-quantum owner's answer: both halves of the hybrid signature over the same digest. */
export type PqAnswer = {
  owner: Address;
  /** the k1 address the clone stores as its pre-quantum key */
  k1Address: Address;
  /** 65 bytes, over the digest itself (no EIP-191 wrap) */
  k1Signature: Hex;
  /** the 38,112-byte expanded ML-DSA-65 key */
  expandedKey: Hex;
  /** 3,309 bytes */
  pqSignature: Hex;
};

export const approveHashData = (hash: Hex): Hex =>
  encodeFunctionData({ abi: safeAbi, functionName: "approveHash", args: [hash] });

export type ApproveHashPlan = {
  rootSafeTxHash: Hex;
  /** the transaction S_pq executes, and the hash its own owners' signatures are checked against */
  pqTx: SafeTx;
  pqSafeTxHash: Hex;
  /** what each post-quantum owner is handed: one value per owner, 32 bytes, nothing else */
  digests: { owner: Address; digest: Hex }[];
};

/** Builds step 2 and the digests it needs. `pqNonce` is S_pq's current nonce, read from the chain. */
export function approveHashPlan(cfg: NestedSafe, rootTx: SafeTx, pqNonce: bigint): ApproveHashPlan {
  return approveHashPlanFor(cfg, safeTxHash(cfg.root, cfg.chainId, rootTx), pqNonce);
}

/** The same, from the root's `safeTxHash` alone — what you have when the transaction was proposed in
 *  Safe{Wallet} and only its hash was passed on. Everything below the root is still derived here. */
export function approveHashPlanFor(cfg: NestedSafe, rootSafeTxHash: Hex, pqNonce: bigint): ApproveHashPlan {
  const pqTx: SafeTx = { to: cfg.root, data: approveHashData(rootSafeTxHash), nonce: pqNonce };
  const pqSafeTxHash = safeTxHash(cfg.sPq, cfg.chainId, pqTx);
  return {
    rootSafeTxHash,
    pqTx,
    pqSafeTxHash,
    digests: cfg.pqOwners.map((owner) => ({
      owner,
      digest: approveHashOwnerDigest(owner, cfg.chainId, pqSafeTxHash),
    })),
  };
}

export class AnswerShapeError extends Error {}

/** The `signatures` blob of step 2: one contract signature per post-quantum owner that answered. */
export function pqChildSignature(answers: readonly PqAnswer[], k: number): Hex {
  if (answers.length < k) throw new AnswerShapeError(`${answers.length} of ${k} post-quantum signatures`);
  const sigs: OwnerSig[] = answers.map((a) => {
    if (size(a.k1Signature) !== 65) {
      throw new AnswerShapeError(`${a.owner}: k1 signature is ${size(a.k1Signature)} bytes, expected 65`);
    }
    if (size(a.expandedKey) !== MLDSA65.keyBytes) {
      throw new AnswerShapeError(`${a.owner}: expanded key is ${size(a.expandedKey)} bytes, expected ${MLDSA65.keyBytes}`);
    }
    if (size(a.pqSignature) !== MLDSA65.sigBytes) {
      throw new AnswerShapeError(`${a.owner}: ML-DSA-65 signature is ${size(a.pqSignature)} bytes, expected ${MLDSA65.sigBytes}`);
    }
    return contractSig(a.owner, hybridPayload(a.k1Address, a.k1Signature, a.expandedKey, a.pqSignature));
  });
  return pack(sigs);
}

/** Step 2 as a transaction to send to an RPC: `S_pq.execTransaction(root.approveHash(...), ...)`. */
export function pqChildTransaction(cfg: NestedSafe, plan: ApproveHashPlan, answers: readonly PqAnswer[]) {
  const t = fullTx(plan.pqTx);
  const data = encodeFunctionData({
    abi: safeAbi,
    functionName: "execTransaction",
    args: [
      t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver,
      pqChildSignature(answers, cfg.k),
    ],
  });
  return { to: cfg.sPq, data, value: 0n };
}

/** Step 3: the root's signature once both children have approved. 130 bytes, whoever relays it. */
export const rootApprovedSignature = (cfg: NestedSafe): Hex =>
  pack([approvedSig(cfg.sEcdsa), approvedSig(cfg.sPq)]);

export function rootTransaction(cfg: NestedSafe, rootTx: SafeTx) {
  const t = fullTx(rootTx);
  const data = encodeFunctionData({
    abi: safeAbi,
    functionName: "execTransaction",
    args: [
      t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver,
      rootApprovedSignature(cfg),
    ],
  });
  return { to: cfg.root, data, value: t.value };
}

// ---- what to tell the user before an 84 kB transaction leaves ----------------------------------

/** EIP-7623: a transaction pays the larger of the execution cost and a floor set by its calldata. For
 *  step 2 the floor is what binds, so this is the number worth showing. */
export function calldataGas(data: Hex) {
  const bytes = size(data);
  let zeros = 0;
  for (let i = 2; i < data.length; i += 2) if (data.slice(i, i + 2) === "00") zeros++;
  const nonzeros = bytes - zeros;
  const tokens = zeros + 4 * nonzeros;
  return {
    bytes,
    zeros,
    nonzeros,
    /** 21000 + 4/zero + 16/nonzero, the classical intrinsic cost */
    intrinsic: 21000 + 4 * zeros + 16 * nonzeros,
    /** 21000 + 10 tokens: the floor no amount of execution can go under */
    floor: 21000 + 10 * tokens,
  };
}

/** geth, reth and nethermind all refuse to relay a transaction past 128 KiB. Step 2 is the only thing in
 *  this design that comes near it, which is what caps k at 3. */
export const TXPOOL_LIMIT = 128 * 1024;

export const fitsInMempool = (data: Hex) => size(data) + 200 < TXPOOL_LIMIT;
