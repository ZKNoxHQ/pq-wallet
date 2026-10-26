// The front computes every digest itself, so the TypeScript is a second implementation of
// ZKNOX_SafePQSignatures. This rebuilds, from the same seeds, what Forge produced in
// safe/test/fixtures/front.json and compares — digests, ML-DSA-65 key expansion, hybrid payload, Safe
// packing. Regenerate the fixture with `make safe-front-fixture`.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { bytesToHex, hexToBytes, keccak256, numberToHex, size, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  approveHashOwnerDigest, hashWrapped, nestedOwnerDigest, safeDomainSeparator, safeMessageHash, safeTxHash,
} from "../src/digests";
import {
  approveHashData, approveHashPlan, calldataGas, fitsInMempool, pqChildSignature, pqChildTransaction,
  rootApprovedSignature, type NestedSafe, type PqAnswer,
} from "../src/plan";
import { hybridPayload } from "../src/signatures";
import { expandedPublicKey, keygen, sign, MLDSA65 } from "../src/mldsa65";

type Fixture = {
  chainId: number; k: number;
  root: Address; sEcdsa: Address; sPq: Address; lens: Address; pqImplementation: Address;
  txTo: Address; txValue: string; txData: Hex; txOperation: number; txNonce: number;
  rootSafeTxHash: Hex; rootDomainSeparator: Hex; sPqDomainSeparator: Hex; sPqSafeMessageHash: Hex;
  pqTxData: Hex; pqTxNonce: number; pqSafeTxHash: Hex;
  pqOwners: Address[]; approveHashDigests: Hex[]; nestedOwnerDigests: Hex[];
  seeds: string[]; k1PrivateKeys: number[];
  rootApprovedSignature: Hex;
  pqChildSignatureHash: Hex; pqChildSignatureBytes: number;
  signerOneHybridPayloadHash: Hex; signerOneHybridPayloadBytes: number;
  pqExecCalldataBytes: number; pqExecCalldataZeros: number; pqExecIntrinsic: number; pqExecFloor: number;
};

const f: Fixture = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../safe/test/fixtures/front.json"), "utf8"),
);

const cfg: NestedSafe = {
  chainId: f.chainId, root: f.root, sEcdsa: f.sEcdsa, sPq: f.sPq, pqOwners: f.pqOwners, k: f.k,
};
const rootTx = {
  to: f.txTo, value: BigInt(f.txValue), data: f.txData, operation: f.txOperation as 0 | 1,
  nonce: BigInt(f.txNonce),
};

describe("digests, against ZKNOX_SafePQSignatures", () => {
  it("the Safe domain separator is the Safe's own", () => {
    expect(safeDomainSeparator(f.root, f.chainId)).toBe(f.rootDomainSeparator);
    expect(safeDomainSeparator(f.sPq, f.chainId)).toBe(f.sPqDomainSeparator);
  });

  it("safeTxHash matches getTransactionHash, for the root and for S_pq's approveHash", () => {
    expect(safeTxHash(f.root, f.chainId, rootTx)).toBe(f.rootSafeTxHash);
    expect(approveHashData(f.rootSafeTxHash)).toBe(f.pqTxData);
    expect(safeTxHash(f.sPq, f.chainId, { to: f.root, data: f.pqTxData, nonce: BigInt(f.pqTxNonce) }))
      .toBe(f.pqSafeTxHash);
  });

  it("safeMessageHash matches the child's ERC-1271 hash", () => {
    expect(safeMessageHash(f.sPq, f.chainId, f.rootSafeTxHash)).toBe(f.sPqSafeMessageHash);
  });

  it("the approveHash digest is ONE wrap of S_pq's own safeTxHash", () => {
    for (const [i, owner] of f.pqOwners.entries()) {
      expect(approveHashOwnerDigest(owner, f.chainId, f.pqSafeTxHash)).toBe(f.approveHashDigests[i]);
      expect(hashWrapped(owner, f.chainId, f.pqSafeTxHash)).toBe(f.approveHashDigests[i]);
    }
  });

  it("the single-transaction digest is the three-layer chain, and differs from it", () => {
    for (const [i, owner] of f.pqOwners.entries()) {
      expect(nestedOwnerDigest(f.sPq, owner, f.chainId, f.rootSafeTxHash)).toBe(f.nestedOwnerDigests[i]);
      // handing a signer one where the other is expected is the mistake this pins
      expect(f.nestedOwnerDigests[i]).not.toBe(f.approveHashDigests[i]);
    }
  });

  it("approveHashPlan produces exactly that", () => {
    const plan = approveHashPlan(cfg, rootTx, BigInt(f.pqTxNonce));
    expect(plan.rootSafeTxHash).toBe(f.rootSafeTxHash);
    expect(plan.pqSafeTxHash).toBe(f.pqSafeTxHash);
    expect(plan.digests.map((d) => d.digest)).toEqual(f.approveHashDigests);
  });
});

describe("ML-DSA-65 and the signature blob", () => {
  // the holders of the fixture: seed -> expanded key, k1 private key -> pre-quantum key
  const holders = f.seeds.map((seed, i) => {
    const { publicKey, secretKey } = keygen(hexToBytes(`0x${seed}`));
    return {
      owner: f.pqOwners[i],
      expandedKey: expandedPublicKey(publicKey),
      secretKey,
      k1: privateKeyToAccount(numberToHex(BigInt(f.k1PrivateKeys[i]), { size: 32 })),
    };
  });

  it("the expanded key is 38,112 bytes in 36 polynomials plus tr", () => {
    for (const h of holders) {
      expect(size(h.expandedKey)).toBe(MLDSA65.keyBytes);
      expect(MLDSA65.keyPolys * MLDSA65.polyBytes + 32 + 64).toBe(MLDSA65.keyBytes);
    }
  });

  const answer = async (i: number): Promise<PqAnswer> => {
    const h = holders[i];
    const digest = f.approveHashDigests[i];
    return {
      owner: h.owner,
      k1Address: h.k1.address,
      k1Signature: await h.k1.sign({ hash: digest }),
      expandedKey: h.expandedKey,
      pqSignature: bytesToHex(sign(h.secretKey, hexToBytes(digest))),
    };
  };

  it("one holder's hybrid payload is the bytes the clone validates", async () => {
    const a = await answer(0);
    const payload = hybridPayload(a.k1Address, a.k1Signature, a.expandedKey, a.pqSignature);
    expect(size(payload)).toBe(f.signerOneHybridPayloadBytes);
    expect(keccak256(payload)).toBe(f.signerOneHybridPayloadHash);
  });

  it("two holders' answers pack into the blob S_pq's transaction carried", async () => {
    const sigs = pqChildSignature([await answer(0), await answer(1)], f.k);
    expect(size(sigs)).toBe(f.pqChildSignatureBytes);
    expect(keccak256(sigs)).toBe(f.pqChildSignatureHash);
  });

  it("the transaction, and the figures the front puts on screen before it leaves", async () => {
    const plan = approveHashPlan(cfg, rootTx, BigInt(f.pqTxNonce));
    const tx = pqChildTransaction(cfg, plan, [await answer(0), await answer(1)]);
    expect(tx.to).toBe(f.sPq);
    const g = calldataGas(tx.data);
    expect(g.bytes).toBe(f.pqExecCalldataBytes);
    expect(g.zeros).toBe(f.pqExecCalldataZeros);
    expect(g.intrinsic).toBe(f.pqExecIntrinsic);
    expect(g.floor).toBe(f.pqExecFloor);
    expect(fitsInMempool(tx.data)).toBe(true); // 84 kB, under the 128 KiB a node will relay
  });

  it("the root's signature is 130 bytes of approved-hash slots", () => {
    expect(rootApprovedSignature(cfg)).toBe(f.rootApprovedSignature);
    expect(size(f.rootApprovedSignature)).toBe(130);
  });
});
