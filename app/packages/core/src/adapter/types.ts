import type { Address, Hex } from "viem";

export type Pot = "public" | "private" | "vault";
export type SubmitPath = "bundler" | "relay";

export type TokenBalance = { address: Address; symbol: string; decimals: number; balance: bigint };

export type WalletState = {
  chainId: number;
  eoa: {
    address: Address;
    eth: bigint;
    tokens: TokenBalance[];
    nonce: number;
    delegate: Address | null; // EIP-7702 delegation target, if any
    linked: boolean; // delegated to the satellite and pointing at the vault
    reserve: bigint; // satellite gas reserve
  };
  vault: null | {
    address: Address;
    scheme: "ML-DSA-44";
    eth: bigint;
    tokens: TokenBalance[];
    preQKeyHash: Hex;
    postQKeyHash: Hex;
    epNonce: bigint; // EntryPoint nonce (key 0)
    pqNonce: bigint; // executeWithHybridSig nonce
  };
  priv: Record<string, bigint>; // shielded pools, by name
};

export type TxResult = { hash: Hex; gasUsed: bigint; detail: string; sig?: string };
export type Call = { to: Address; value?: bigint; data?: Hex };

/** Where an action is, reported while it runs. */
export type Stage = "sign-ecdsa" | "sign-pq" | "sign-auth" | "prove" | "submit" | "confirm" | "done";
export type ProgressFn = (stage: Stage) => void;

/** One of the adapter's actions, as data: used for estimation before signing. */
export type ActionRequest =
  | { kind: "eoaSend"; to: Address; value: bigint }
  | { kind: "moveToVault"; value: bigint }
  | { kind: "link"; reserve: bigint }
  | { kind: "sweep"; tokens?: Address[] }
  | { kind: "createVault" }
  | { kind: "vaultSend"; to: Address; value: bigint; path: SubmitPath; data?: Hex }
  | { kind: "sendAsPublic"; to: Address; value: bigint; data?: Hex }
  | { kind: "moveToPublic"; value: bigint; path: SubmitPath }
  | { kind: "shield"; pool: string; from: "public" | "vault"; value: bigint }
  | { kind: "unshield"; pool: string; to: Address; value: bigint };

export type Plan = { gas: bigint; source: "estimated" | "typical" };

/** What the UI talks to. The simulation and the viem implementation share it. */
export interface WalletAdapter {
  read(): Promise<WalletState>;
  /** Gas for an action, before anything is signed. Live adapters ask the node. */
  estimate(action: ActionRequest): Promise<Plan>;
  /** Progress callback for the next actions; null to clear. */
  setProgress(cb: ProgressFn | null): void;
  // public account, secp256k1 key
  eoaSend(to: Address, value: bigint): Promise<TxResult>;
  moveToVault(value: bigint): Promise<TxResult>;
  link(reserve: bigint): Promise<TxResult>;
  sweep(tokens?: Address[]): Promise<TxResult>;
  // vault, hybrid signature
  createVault(): Promise<TxResult & { vault: Address }>;
  vaultSend(to: Address, value: bigint, path: SubmitPath, data?: Hex): Promise<TxResult>;
  sendAsPublic(to: Address, value: bigint, data?: Hex): Promise<TxResult>;
  moveToPublic(value: bigint, path: SubmitPath): Promise<TxResult>;
  /** ERC-1271 signature in the name of the vault (or of the linked EOA when `asPublic`). */
  signWrapped(hash: Hex, asPublic?: boolean): Promise<Hex>;
  /** Credits the public account: simulation, or a local chain with a funded relayer and a mintable token. */
  faucet?(value?: bigint): Promise<TxResult>;
  // shielded pools (Kohaku SDK); optional until wired
  shield?(pool: string, from: "public" | "vault", value: bigint): Promise<TxResult>;
  unshield?(pool: string, to: Address, value: bigint): Promise<TxResult>;
}
