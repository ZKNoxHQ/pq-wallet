// `executeWithHybridSig`, off-chain: the digest a holder signs to make the clone call something, and the
// calldata that carries the answer. Mirrors ZKNOX_PQAccount7702 line for line; the provider confirms every
// digest against the clone's own `hashExecute` before it reaches the device, and test/provider.anvil.test.ts
// compares the two on a real chain.
//
// Why recompute rather than only read `hashExecute`: same reason as ADR-011. The holder's one protection is
// comparing the 32 bytes on the page with the 32 bytes on the device, and that comparison is worth
// something only if the page did not take its value from an RPC it does not control.
import { concatHex, encodeAbiParameters, encodeFunctionData, keccak256, toHex, type Address, type Hex } from "viem";
import { PQ_DOMAIN_TYPEHASH, PQ_NAME_HASH, PQ_VERSION_HASH } from "@zknox/pq-safe";
import { pqRelayAbi } from "./abi";

/** keccak256("Execute(bytes32 callsHash,uint256 nonce,uint256 deadline)") */
export const EXECUTE_TYPEHASH: Hex = keccak256(toHex("Execute(bytes32 callsHash,uint256 nonce,uint256 deadline)"));

export type Call = { target: Address; value: bigint; data: Hex };

/** The clone's EIP-712 domain: name, version, chainId and its own address. */
export const pqDomainSeparator = (account: Address, chainId: number): Hex =>
  keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [PQ_DOMAIN_TYPEHASH, PQ_NAME_HASH, PQ_VERSION_HASH, BigInt(chainId), account],
    ),
  );

/** `_callsHash`: keccak of the packed per-call hashes, each over (target, value, keccak(data)). */
export function callsHash(calls: readonly Call[]): Hex {
  const each = calls.map((c) =>
    keccak256(
      encodeAbiParameters(
        [{ type: "address" }, { type: "uint256" }, { type: "bytes32" }],
        [c.target, c.value, keccak256(c.data)],
      ),
    ),
  );
  return keccak256(each.length === 0 ? "0x" : concatHex(each));
}

/** What `clone.hashExecute(calls, nonce, deadline)` returns: the 32 bytes both halves are made over. */
export function hashExecute(account: Address, chainId: number, calls: readonly Call[], nonce: bigint, deadline: bigint): Hex {
  const structHash = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "uint256" }],
      [EXECUTE_TYPEHASH, callsHash(calls), nonce, deadline],
    ),
  );
  return keccak256(concatHex(["0x19", "0x01", pqDomainSeparator(account, chainId), structHash]));
}

/** The calldata of the relayed transaction. `signature` is the hybrid payload of @zknox/pq-safe. */
export const executeData = (calls: readonly Call[], deadline: bigint, signature: Hex): Hex =>
  encodeFunctionData({ abi: pqRelayAbi, functionName: "executeWithHybridSig", args: [calls, deadline, signature] });
