// The slices of ZKNOX_PQAccount7702 (its relayed path) and ZKNOX_PQFactory7702 a wallet provider calls.
// Hand-written, as in @zknox/pq-safe: the provider needs seven functions, and naming them is the
// documentation. `pqRelayAbi` rather than `pqAccountAbi`, which @zknox/pq-safe already exports.
const call = {
  type: "tuple[]",
  name: "calls",
  components: [
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
} as const;

export const pqRelayAbi = [
  {
    type: "function", name: "executeWithHybridSig", stateMutability: "payable",
    inputs: [call, { name: "deadline", type: "uint256" }, { name: "signature", type: "bytes" }],
    outputs: [],
  },
  {
    type: "function", name: "hashExecute", stateMutability: "view",
    inputs: [call, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }],
    outputs: [{ type: "bytes32" }],
  },
  { type: "function", name: "pqNonce", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  {
    type: "function", name: "keyHashes", stateMutability: "view", inputs: [],
    outputs: [{ name: "preQKeyHash", type: "bytes32" }, { name: "postQKeyHash", type: "bytes32" }],
  },
  { type: "function", name: "isInitialized", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "error", name: "InvalidSignature", inputs: [] },
  { type: "error", name: "Expired", inputs: [] },
  { type: "error", name: "NotAuthorized", inputs: [] },
] as const;

export const pqFactoryAbi = [
  {
    type: "function", name: "createAccount", stateMutability: "nonpayable",
    inputs: [
      { name: "preQuantumPubKey", type: "bytes" },
      { name: "postQuantumPubKey", type: "bytes" },
      { name: "salt", type: "uint256" },
    ],
    outputs: [{ type: "address" }],
  },
  {
    type: "function", name: "getAddress", stateMutability: "view",
    inputs: [
      { name: "preQuantumPubKey", type: "bytes" },
      { name: "postQuantumPubKey", type: "bytes" },
      { name: "salt", type: "uint256" },
    ],
    outputs: [{ type: "address" }],
  },
  { type: "function", name: "IMPLEMENTATION", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
] as const;
