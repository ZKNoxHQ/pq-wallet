// Where a holder's clone lives, without asking the factory. A device holds two keys; the factory derives
// the clone's address from their hashes and a salt, as an ERC-1167 clone under CREATE2. Computing it here
// lets the page name the account before anything is deployed, and the factory's `getAddress` is then a
// check rather than the source (test/provider.anvil.test.ts compares the two).
import {
  concatHex, encodeAbiParameters, encodeFunctionData, getAddress, keccak256, size, type Address, type Hex,
} from "viem";
import { MLDSA65 } from "@zknox/pq-safe";
import { pqFactoryAbi } from "./abi";

export type PqStack = {
  chainId: number;
  factory: Address;
  /** `factory.IMPLEMENTATION()`: it pins the verifier pair, and the lens recognises a clone by it */
  implementation: Address;
};

/** The pre-quantum key a clone stores is the k1 address itself, 20 bytes (`abi.encodePacked(address)`). */
export const preQuantumKey = (k1Address: Address): Hex => getAddress(k1Address).toLowerCase() as Hex;

/** `ZKNOX_PQFactory7702._salt`: keccak(abi.encode(keccak(preQ), keccak(postQ), salt)). */
export const cloneSalt = (k1Address: Address, expandedKey: Hex, salt = 0n): Hex =>
  keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }],
      [keccak256(preQuantumKey(k1Address)), keccak256(expandedKey), salt],
    ),
  );

/** OpenZeppelin `Clones.predictDeterministicAddress`: the ERC-1167 init code, then the CREATE2 formula. */
export function predictClone(stack: Omit<PqStack, "chainId">, k1Address: Address, expandedKey: Hex, salt = 0n): Address {
  if (size(expandedKey) !== MLDSA65.keyBytes) {
    throw new Error(`the expanded ML-DSA-65 key is ${MLDSA65.keyBytes} bytes, got ${size(expandedKey)}`);
  }
  const initCode = concatHex([
    "0x3d602d80600a3d3981f3363d3d373d3d3d363d73",
    stack.implementation,
    "0x5af43d82803e903d91602b57fd5bf3",
  ]);
  const digest = keccak256(concatHex(["0xff", stack.factory, cloneSalt(k1Address, expandedKey, salt), keccak256(initCode)]));
  return getAddress(`0x${digest.slice(26)}`);
}

/** The transaction that creates the clone. 38 kB of calldata: ~2.5 M gas, paid once per holder. */
export const createAccountData = (k1Address: Address, expandedKey: Hex, salt = 0n): Hex =>
  encodeFunctionData({
    abi: pqFactoryAbi,
    functionName: "createAccount",
    args: [preQuantumKey(k1Address), expandedKey, salt],
  });
