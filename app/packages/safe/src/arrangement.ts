// The NESTED arrangement, created from a page: S_ecdsa (EOA owners, threshold k), S_pq (post-quantum clones,
// threshold k) and the 2-of-2 root that owns both. A port of safe/script/CreateArrangement.s.sol, salt for
// salt, so the page and the script given the same owners land on the same three addresses, and either can
// finish what the other started.
//
// The salt of each Safe comes from its owner set and threshold, never from a timestamp: a creation that
// stops between two transactions resumes instead of building a second arrangement beside the first.
import {
  concatHex, encodeAbiParameters, encodeFunctionData, getAddress, keccak256, numberToHex, type Address, type Hex,
} from "viem";

/** Safe 1.5.0, canonical deployments (safe/src/libraries/ZKNOX_SafeDeployments.sol). */
export const SAFE_150 = {
  singleton: "0xFf51A5898e281Db6DfC7855790607438dF2ca44b",
  singletonL2: "0xEdd160fEBBD92E350D4D398fb636302fccd67C7e",
  proxyFactory: "0x14F2982D601c9458F93bd70B218933A6f8165e7b",
  fallbackHandler: "0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4",
} as const satisfies Record<string, Address>;

export type SafeStack = { singleton: Address; proxyFactory: Address; fallbackHandler: Address };

export const proxyFactoryAbi = [
  { type: "function", name: "proxyCreationCode", stateMutability: "pure", inputs: [], outputs: [{ type: "bytes" }] },
  {
    type: "function", name: "createProxyWithNonce", stateMutability: "nonpayable",
    inputs: [{ name: "_singleton", type: "address" }, { name: "initializer", type: "bytes" }, { name: "saltNonce", type: "uint256" }],
    outputs: [{ type: "address" }],
  },
] as const;

const setupAbi = [
  {
    type: "function", name: "setup", stateMutability: "nonpayable",
    inputs: [
      { name: "_owners", type: "address[]" }, { name: "_threshold", type: "uint256" },
      { name: "to", type: "address" }, { name: "data", type: "bytes" },
      { name: "fallbackHandler", type: "address" }, { name: "paymentToken", type: "address" },
      { name: "payment", type: "uint256" }, { name: "paymentReceiver", type: "address" },
    ],
    outputs: [],
  },
] as const;

const ZERO: Address = "0x0000000000000000000000000000000000000000";

/** `setup(owners, threshold, 0, "", handler, 0, 0, 0)`: no module, no payment, the canonical handler —
 *  what the lens requires of every Safe in the arrangement. */
export const setupData = (owners: readonly Address[], threshold: bigint, fallbackHandler: Address): Hex =>
  encodeFunctionData({
    abi: setupAbi,
    functionName: "setup",
    args: [owners, threshold, ZERO, "0x", fallbackHandler, ZERO, 0n, ZERO],
  });

/** `uint256(keccak256(abi.encode(owners, threshold, saltNonce, "zknox.nested")))`, as the script derives it. */
export const nestedSaltNonce = (owners: readonly Address[], threshold: bigint, saltNonce = 0n): bigint =>
  BigInt(
    keccak256(
      encodeAbiParameters(
        [{ type: "address[]" }, { type: "uint256" }, { type: "uint256" }, { type: "string" }],
        [owners, threshold, saltNonce, "zknox.nested"],
      ),
    ),
  );

/** `SafeProxyFactory.createProxyWithNonce`'s CREATE2 address: salt = keccak(keccak(init) || saltNonce),
 *  init code = proxyCreationCode || uint256(singleton). `proxyCreationCode` is read once from the factory. */
export function predictProxy(stack: SafeStack, proxyCreationCode: Hex, init: Hex, saltNonce: bigint): Address {
  const salt = keccak256(concatHex([keccak256(init), numberToHex(saltNonce, { size: 32 })]));
  const initCodeHash = keccak256(concatHex([proxyCreationCode, numberToHex(BigInt(stack.singleton), { size: 32 })]));
  return getAddress(`0x${keccak256(concatHex(["0xff", stack.proxyFactory, salt, initCodeHash])).slice(26)}`);
}

export type PlannedSafe = {
  label: "S_ecdsa" | "S_pq" | "root";
  owners: Address[];
  threshold: bigint;
  address: Address;
  /** the transaction to send to the proxy factory if `address` has no code yet */
  to: Address;
  data: Hex;
};

export type ArrangementInput = {
  ecdsaOwners: readonly Address[];
  pqOwners: readonly Address[];
  k: number;
  saltNonce?: bigint;
};

/** The three Safes, their addresses and the transactions that create them. Order does not matter: the root's
 *  owners are known before the children exist, and a Safe does not check that its owners have code. */
export function planArrangement(stack: SafeStack, proxyCreationCode: Hex, input: ArrangementInput): PlannedSafe[] {
  const { k } = input;
  if (!Number.isInteger(k) || k < 1) throw new Error("k is a positive integer");
  if (k > input.ecdsaOwners.length) throw new Error(`k = ${k} but only ${input.ecdsaOwners.length} ECDSA owners`);
  if (k > input.pqOwners.length) throw new Error(`k = ${k} but only ${input.pqOwners.length} post-quantum owners`);
  const all = [...input.ecdsaOwners, ...input.pqOwners].map((a) => a.toLowerCase());
  if (new Set(all).size !== all.length) throw new Error("an address appears twice among the owners");

  const one = (label: PlannedSafe["label"], owners: readonly Address[], threshold: bigint): PlannedSafe => {
    const list = owners.map((o) => getAddress(o));
    const init = setupData(list, threshold, stack.fallbackHandler);
    const nonce = nestedSaltNonce(list, threshold, input.saltNonce ?? 0n);
    return {
      label,
      owners: list,
      threshold,
      address: predictProxy(stack, proxyCreationCode, init, nonce),
      to: stack.proxyFactory,
      data: encodeFunctionData({
        abi: proxyFactoryAbi,
        functionName: "createProxyWithNonce",
        args: [stack.singleton, init, nonce],
      }),
    };
  };

  const sEcdsa = one("S_ecdsa", input.ecdsaOwners, BigInt(k));
  const sPq = one("S_pq", input.pqOwners, BigInt(k));
  const root = one("root", [sEcdsa.address, sPq.address], 2n);
  return [sEcdsa, sPq, root];
}
