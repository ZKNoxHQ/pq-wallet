// The slices of Safe 1.5.0 and ZKNOX_PQAccount7702 this package calls. Hand-written rather than generated:
// the front needs eight functions, and a generated 60-function ABI would hide which eight.
export const safeAbi = [
  { type: "function", name: "getOwners", stateMutability: "view", inputs: [], outputs: [{ type: "address[]" }] },
  { type: "function", name: "getThreshold", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "nonce", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "domainSeparator", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "VERSION", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  {
    type: "function", name: "approvedHashes", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "bytes32" }], outputs: [{ type: "uint256" }],
  },
  { type: "function", name: "approveHash", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }], outputs: [] },
  {
    type: "function", name: "getTransactionHash", stateMutability: "view",
    inputs: [
      { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" },
      { name: "operation", type: "uint8" }, { name: "safeTxGas", type: "uint256" },
      { name: "baseGas", type: "uint256" }, { name: "gasPrice", type: "uint256" },
      { name: "gasToken", type: "address" }, { name: "refundReceiver", type: "address" },
      { name: "_nonce", type: "uint256" },
    ],
    outputs: [{ type: "bytes32" }],
  },
  {
    type: "function", name: "execTransaction", stateMutability: "payable",
    inputs: [
      { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" },
      { name: "operation", type: "uint8" }, { name: "safeTxGas", type: "uint256" },
      { name: "baseGas", type: "uint256" }, { name: "gasPrice", type: "uint256" },
      { name: "gasToken", type: "address" }, { name: "refundReceiver", type: "address" },
      { name: "signatures", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function", name: "checkSignatures", stateMutability: "view",
    inputs: [{ type: "bytes32" }, { type: "bytes" }], outputs: [],
  },
] as const;

export const pqAccountAbi = [
  { type: "function", name: "hashWrapped", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "isInitialized", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  {
    type: "function", name: "keyHashes", stateMutability: "view", inputs: [],
    outputs: [{ name: "preQKeyHash", type: "bytes32" }, { name: "postQKeyHash", type: "bytes32" }],
  },
  {
    type: "function", name: "isValidSignature", stateMutability: "view",
    inputs: [{ type: "bytes32" }, { type: "bytes" }], outputs: [{ type: "bytes4" }],
  },
] as const;

/** `ZKNOX_SafePQLens`: the policy check the front runs before it lets anyone sign. `nestedViolations`
 *  returns a bitfield rather than reverting, which is what a screen wants. */
export const lensAbi = [
  {
    type: "function", name: "classify", stateMutability: "view",
    inputs: [{ name: "account", type: "address" }, { name: "pqImplementation", type: "address" }],
    outputs: [{ type: "uint8" }],
  },
  {
    type: "function", name: "nestedViolations", stateMutability: "view",
    inputs: [
      { name: "root", type: "address" }, { name: "sEcdsa", type: "address" }, { name: "sPq", type: "address" },
      { name: "k", type: "uint256" }, { name: "pqImplementation", type: "address" },
    ],
    outputs: [{ type: "uint256" }],
  },
] as const;

/** `AccountKind` of the lens, in its declaration order. */
export const ACCOUNT_KIND = [
  "EOA", "DELEGATED_7702", "PQ_CLONE", "PQ_CLONE_UNINITIALIZED", "SAFE_150", "SAFE_OTHER", "CONTRACT",
] as const;
export type AccountKind = (typeof ACCOUNT_KIND)[number];

/** Violation flags of `nestedViolations`, as labels for the screen. Child flags are shifted by 8 (S_ecdsa)
 *  and 16 (S_pq); see safe/src/ZKNOX_SafePQLens.sol. */
export const NESTED_VIOLATIONS: ReadonlyArray<{ bit: number; label: string }> = [
  { bit: 0, label: "the root is not a Safe 1.5.0 proxy" },
  { bit: 1, label: "the root's owners are not exactly {S_ecdsa, S_pq}" },
  { bit: 2, label: "the root's threshold is not 2" },
  { bit: 3, label: "the root has a module enabled" },
  { bit: 4, label: "the root's fallback handler is neither canonical nor absent" },
  { bit: 8, label: "S_ecdsa is not a Safe 1.5.0 proxy" },
  { bit: 9, label: "S_ecdsa's fallback handler is not the canonical one" },
  { bit: 10, label: "S_ecdsa's threshold is not k" },
  { bit: 11, label: "S_ecdsa has an owner that is not a plain EOA" },
  { bit: 12, label: "S_ecdsa has a module enabled" },
  { bit: 16, label: "S_pq is not a Safe 1.5.0 proxy" },
  { bit: 17, label: "S_pq's fallback handler is not the canonical one" },
  { bit: 18, label: "S_pq's threshold is not k" },
  { bit: 19, label: "S_pq has an owner that is not an initialized post-quantum clone" },
  { bit: 20, label: "S_pq has a module enabled" },
];

export const decodeViolations = (v: bigint): string[] =>
  NESTED_VIOLATIONS.filter(({ bit }) => (v >> BigInt(bit)) & 1n).map(({ label }) => label);
