// Real adapter: talks to the deployed contracts through viem. UserOps go to a bundler when `bundlerUrl` is
// set, otherwise they are submitted directly to the EntryPoint by `relayer` (local development, anvil).
import {
  createPublicClient, createWalletClient, encodeFunctionData, getContractAddress, keccak256, http, erc20Abi, parseAbi,
  type Address, type Chain, type Hex, type PublicClient, type Transport, type WalletClient,
} from "viem";
import type { PrivateKeyAccount } from "viem/accounts";
import { createBundlerClient, toPackedUserOperation, entryPoint08Abi, type UserOperation } from "viem/account-abstraction";
import { ZKNOX_PQAccount7702Abi, ZKNOX_PQFactory7702Abi, ZKNOX_PQSatellite7702Abi, ZKNOX_dilithiumAbi } from "../abi";
import type { Deployments } from "../deployments";
import { mldsa44 } from "../keys";
import { signHybrid, type HybridKeys } from "../signers";
import { toVaultAccount, toSatelliteAccount, wrappedTypedDataHash } from "../accounts";
import { findVault, readState, type TokenInfo } from "../state/reader";
import type { ActionRequest, Call, Plan, ProgressFn, SubmitPath, TxResult, WalletAdapter, WalletState } from "./types";

export type ViemAdapterConfig = {
  chain: Chain;
  transport: Transport;
  deployments: Deployments;
  ecdsa: PrivateKeyAccount; // the public account's key, also the vault's pre-quantum key
  pqSeed: Uint8Array; // 32 bytes, ML-DSA-44 KeyGen seed (see keys/slip10ext)
  relayer?: PrivateKeyAccount; // submits userOps through handleOps when there is no bundler
  bundlerUrl?: string;
  salt?: bigint;
  vaultAddress?: Address; // known vault; discovered from the factory event otherwise
  tokens?: TokenInfo[]; // ERC-20s to show and sweep; defaults to the deployment's test token
  /** Local chains only: the relayer funds the public account and mints the test token. */
  localFaucet?: boolean;
};

// verification: ML-DSA-44 validation measured at 1.29M; the EntryPoint refunds what is not used
const GAS = { verification: 1_600_000n, call: 400_000n, preVerification: 60_000n };
const TEST_TOKEN: Omit<TokenInfo, "address"> = { symbol: "TST", decimals: 18 };

export class ViemWalletAdapter implements WalletAdapter {
  readonly client: PublicClient;
  readonly wallet: WalletClient;
  readonly d: Deployments;
  readonly pq: { publicKey: Uint8Array; secretKey: Uint8Array; blob: Hex };
  readonly tokens: TokenInfo[];
  private vaultAddr: Address | null;
  private keyRef: Address | null = null;
  private progress: ProgressFn | null = null;

  constructor(readonly cfg: ViemAdapterConfig) {
    this.client = createPublicClient({ chain: cfg.chain, transport: cfg.transport });
    this.wallet = createWalletClient({ chain: cfg.chain, transport: cfg.transport, account: cfg.ecdsa });
    this.d = cfg.deployments;
    const kp = mldsa44.keygen(cfg.pqSeed);
    this.pq = { ...kp, blob: mldsa44.expandedPublicKey(kp.publicKey) };
    this.vaultAddr = cfg.vaultAddress ?? null;
    this.tokens = cfg.tokens ?? (cfg.deployments.testToken ? [{ address: cfg.deployments.testToken, ...TEST_TOKEN }] : []);
  }

  get eoa() { return this.cfg.ecdsa.address; }
  get salt() { return this.cfg.salt ?? 0n; }
  setProgress(cb: ProgressFn | null) { this.progress = cb; }
  private stage(s: Parameters<ProgressFn>[0]) { this.progress?.(s); }

  // ---------------------------------------------------------------- state
  async read(): Promise<WalletState> {
    if (!this.vaultAddr) this.vaultAddr = await findVault(this.client, this.d, this.eoa);
    return readState(this.client, this.d, this.eoa, this.vaultAddr, this.tokens);
  }

  /** The SSTORE2 pointer of the key blob: CREATE(verifier, n) for the n that matches the stored hash. */
  private async pqKeyRef(): Promise<Address> {
    if (this.keyRef) return this.keyRef;
    const vault = await this.requireVault();
    const [, postQHash] = await this.client.readContract({ address: vault, abi: ZKNOX_PQAccount7702Abi, functionName: "keyHashes" });
    const n = await this.client.getTransactionCount({ address: this.d.mldsaVerifier });
    for (let i = 1; i <= n; i++) {
      const a = getContractAddress({ from: this.d.mldsaVerifier, nonce: BigInt(i) });
      if (keccak256(a) === postQHash) return (this.keyRef = a);
    }
    throw new Error("post-quantum key reference not found for this vault (was it written by another verifier?)");
  }

  private async keys(): Promise<HybridKeys> {
    return { ecdsa: this.cfg.ecdsa, pqSecretKey: this.pq.secretKey, pqKeyRef: await this.pqKeyRef() };
  }

  private async requireVault(): Promise<Address> {
    if (!this.vaultAddr) this.vaultAddr = await findVault(this.client, this.d, this.eoa);
    if (!this.vaultAddr) throw new Error("no vault on this chain: create it first");
    return this.vaultAddr;
  }

  private async receipt(hash: Hex, detail: string): Promise<TxResult> {
    this.stage("confirm");
    const r = await this.client.waitForTransactionReceipt({ hash });
    if (r.status !== "success") throw new Error(`transaction reverted: ${detail}`);
    this.stage("done");
    return { hash, gasUsed: r.gasUsed, detail };
  }

  // ---------------------------------------------------------------- estimation (nothing is signed for real)
  async estimate(a: ActionRequest): Promise<Plan> {
    const est = (gas: bigint): Plan => ({ gas, source: "estimated" });
    const from = this.cfg.ecdsa;
    switch (a.kind) {
      case "eoaSend":
        return est(await this.client.estimateGas({ account: from, to: a.to, value: a.value }));
      case "moveToVault":
        return est(await this.client.estimateGas({ account: from, to: await this.requireVault(), value: a.value }));
      case "link": {
        const vault = await this.requireVault();
        const authorization = await this.wallet.signAuthorization({ account: from, contractAddress: this.d.satellite, executor: "self" });
        const data = encodeFunctionData({ abi: ZKNOX_PQSatellite7702Abi, functionName: "initialize", args: [vault, a.reserve] });
        return est(await this.client.estimateGas({ account: from, to: this.eoa, data, authorizationList: [authorization] }));
      }
      case "sweep":
        return est(await this.client.estimateContractGas({ account: this.cfg.relayer ?? from, address: this.eoa, abi: ZKNOX_PQSatellite7702Abi, functionName: "sweep", args: [a.tokens ?? this.tokens.map((t) => t.address)] }));
      case "createVault": {
        const g1 = await this.client.estimateContractGas({ account: from, address: this.d.mldsaVerifier, abi: ZKNOX_dilithiumAbi, functionName: "setKey", args: [this.pq.blob] });
        // the factory only hashes the references: any 20 bytes give the right figure
        const g2 = await this.client.estimateContractGas({ account: from, address: this.d.factoryMLDSA, abi: ZKNOX_PQFactory7702Abi, functionName: "createAccountWithKeyRefs", args: [this.eoa, this.d.satellite, this.salt] });
        return est(g1 + g2);
      }
      case "vaultSend":
        return a.path === "relay" ? est(await this.estimateRelay([{ to: a.to, value: a.value, data: a.data ?? "0x" }])) : est(await this.estimateUserOp([{ to: a.to, value: a.value, data: a.data ?? "0x" }]));
      case "moveToPublic":
        return a.path === "relay" ? est(await this.estimateRelay([{ to: this.eoa, value: a.value }])) : est(await this.estimateUserOp([{ to: this.eoa, value: a.value }]));
      case "sendAsPublic":
        return est(await this.estimateUserOp(this.asPublicCalls(a.to, a.value, a.data ?? "0x")));
      case "shield":
      case "unshield":
        throw new Error("shielded pools are not wired on this network yet");
    }
  }

  // ---------------------------------------------------------------- public account
  async eoaSend(to: Address, value: bigint) {
    this.stage("sign-ecdsa");
    const hash = await this.wallet.sendTransaction({ account: this.cfg.ecdsa, chain: this.cfg.chain, to, value });
    return this.receipt(hash, "Signed with the secp256k1 key");
  }

  async moveToVault(value: bigint) {
    const vault = await this.requireVault();
    this.stage("sign-ecdsa");
    const hash = await this.wallet.sendTransaction({ account: this.cfg.ecdsa, chain: this.cfg.chain, to: vault, value });
    return this.receipt(hash, "Plain transfer to the vault, secp256k1 key");
  }

  async link(reserve: bigint) {
    const vault = await this.requireVault();
    this.stage("sign-auth");
    const authorization = await this.wallet.signAuthorization({ account: this.cfg.ecdsa, contractAddress: this.d.satellite, executor: "self" });
    this.stage("submit");
    const hash = await this.wallet.sendTransaction({
      account: this.cfg.ecdsa, chain: this.cfg.chain, to: this.eoa,
      data: encodeFunctionData({ abi: ZKNOX_PQSatellite7702Abi, functionName: "initialize", args: [vault, reserve] }),
      authorizationList: [authorization],
    });
    return this.receipt(hash, "Type-4 transaction: delegate to the satellite, initialize(vault, reserve)");
  }

  async sweep(tokens: Address[] = this.tokens.map((t) => t.address)) {
    const submitter = this.cfg.relayer ?? this.cfg.ecdsa;
    this.stage("submit");
    const hash = await this.wallet.writeContract({ account: submitter, chain: this.cfg.chain, address: this.eoa, abi: ZKNOX_PQSatellite7702Abi, functionName: "sweep", args: [tokens] });
    return this.receipt(hash, "sweep(), submitted by " + (this.cfg.relayer ? "a relayer" : "the public account") + ", no signature");
  }

  // ---------------------------------------------------------------- vault
  async createVault() {
    if (this.vaultAddr) return { hash: "0x" as Hex, gasUsed: 0n, detail: "already created", vault: this.vaultAddr };
    // 1. key blob, written once by the verifier (SSTORE2)
    this.stage("submit");
    const { result: ref, request } = await this.client.simulateContract({ account: this.cfg.ecdsa, address: this.d.mldsaVerifier, abi: ZKNOX_dilithiumAbi, functionName: "setKey", args: [this.pq.blob] });
    const h1 = await this.wallet.writeContract(request);
    const r1 = await this.client.waitForTransactionReceipt({ hash: h1 });
    if (r1.status !== "success") throw new Error("setKey reverted");
    this.keyRef = ("0x" + ref.slice(2, 42)) as Address;
    // 2. the clone, initialized with the two key references
    const { result: vault, request: req2 } = await this.client.simulateContract({
      account: this.cfg.ecdsa, address: this.d.factoryMLDSA, abi: ZKNOX_PQFactory7702Abi, functionName: "createAccountWithKeyRefs", args: [this.eoa, this.keyRef, this.salt],
    });
    const h2 = await this.wallet.writeContract(req2);
    const r2 = await this.receipt(h2, `Key blob written (${(this.pq.blob.length - 2) / 2} bytes), clone created and initialized`);
    this.vaultAddr = vault;
    return { ...r2, gasUsed: r1.gasUsed + r2.gasUsed, vault };
  }

  async vaultSend(to: Address, value: bigint, path: SubmitPath, data: Hex = "0x") {
    const calls: Call[] = [{ to, value, data }];
    return path === "relay" ? this.relay(calls) : this.userOp(calls);
  }

  async moveToPublic(value: bigint, path: SubmitPath) {
    return this.vaultSend(this.eoa, value, path);
  }

  private asPublicCalls(to: Address, value: bigint, data: Hex): Call[] {
    const inner = encodeFunctionData({ abi: ZKNOX_PQSatellite7702Abi, functionName: "execute", args: [to, value, data] });
    return [{ to: this.eoa, value }, { to: this.eoa, value: 0n, data: inner }];
  }

  /** One hybrid signature: the vault pushes funds to the public account and executes through it. */
  async sendAsPublic(to: Address, value: bigint, data: Hex = "0x") {
    return this.userOp(this.asPublicCalls(to, value, data), "vault acting as the public account");
  }

  async signWrapped(hash: Hex, asPublic = false) {
    const vault = await this.requireVault();
    if (asPublic) {
      const digest = await this.client.readContract({ address: this.eoa, abi: ZKNOX_PQSatellite7702Abi, functionName: "hashWrapped", args: [hash] });
      return signHybrid(await this.keys(), digest, this.progress ?? undefined); // satellite.hashWrapped already returns the vault digest
    }
    return signHybrid(await this.keys(), wrappedTypedDataHash(this.d.chainId, vault, hash), this.progress ?? undefined);
  }

  /** Local chains: 1 ETH from the relayer and 100 test tokens to the public account. */
  async faucet(value = 1_000000000000000000n): Promise<TxResult> {
    if (!this.cfg.localFaucet || !this.cfg.relayer) throw new Error("no faucet on this network");
    this.stage("submit");
    const h = await this.wallet.sendTransaction({ account: this.cfg.relayer, chain: this.cfg.chain, to: this.eoa, value });
    if (this.d.testToken) {
      const h2 = await this.wallet.writeContract({ account: this.cfg.relayer, chain: this.cfg.chain, address: this.d.testToken, abi: parseAbi(["function mint(address,uint256)"]), functionName: "mint", args: [this.eoa, 100n * 10n ** 18n] });
      await this.client.waitForTransactionReceipt({ hash: h2 });
    }
    return this.receipt(h, "Local faucet: ETH from the relayer" + (this.d.testToken ? ", test tokens minted" : ""));
  }

  // ---------------------------------------------------------------- submission paths
  private async relayArgs(calls: Call[]) {
    const vault = await this.requireVault();
    const c = calls.map((x) => ({ target: x.to, value: x.value ?? 0n, data: x.data ?? ("0x" as Hex) }));
    const nonce = await this.client.readContract({ address: vault, abi: ZKNOX_PQAccount7702Abi, functionName: "pqNonce" });
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const digest = await this.client.readContract({ address: vault, abi: ZKNOX_PQAccount7702Abi, functionName: "hashExecute", args: [c, nonce, deadline] });
    return { vault, c, deadline, digest };
  }

  private async estimateRelay(calls: Call[]) {
    const { vault, c, deadline, digest } = await this.relayArgs(calls);
    const sig = await signHybrid(await this.keys(), digest); // a real signature is needed for a real estimate; it is not broadcast
    return this.client.estimateContractGas({ account: this.cfg.ecdsa, address: vault, abi: ZKNOX_PQAccount7702Abi, functionName: "executeWithHybridSig", args: [c, deadline, sig] });
  }

  /** executeWithHybridSig, submitted and paid for by the public account. */
  private async relay(calls: Call[]): Promise<TxResult> {
    const { vault, c, deadline, digest } = await this.relayArgs(calls);
    const sig = await signHybrid(await this.keys(), digest, this.progress ?? undefined);
    this.stage("submit");
    const hash = await this.wallet.writeContract({ account: this.cfg.ecdsa, chain: this.cfg.chain, address: vault, abi: ZKNOX_PQAccount7702Abi, functionName: "executeWithHybridSig", args: [c, deadline, sig] });
    return this.receipt(hash, "executeWithHybridSig, relayed by the public account, hybrid signature");
  }

  private async buildUserOp(calls: Call[], progress?: ProgressFn) {
    const vault = await this.requireVault();
    const keys = await this.keys();
    const account = await toVaultAccount({ client: this.client, address: vault, entryPoint: this.d.entryPoint, keys, progress });
    const fees = await this.client.estimateFeesPerGas();
    const uo: UserOperation<"0.8"> = {
      sender: vault,
      nonce: await account.getNonce({ key: 0n }),
      callData: await account.encodeCalls(calls),
      callGasLimit: GAS.call, verificationGasLimit: GAS.verification, preVerificationGas: GAS.preVerification,
      maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      signature: "0x",
    };
    uo.signature = await account.signUserOperation({ ...uo, chainId: this.d.chainId });
    return { account, uo };
  }

  private async estimateUserOp(calls: Call[]) {
    if (this.cfg.bundlerUrl) {
      const vault = await this.requireVault();
      const account = await toVaultAccount({ client: this.client, address: vault, entryPoint: this.d.entryPoint, keys: await this.keys() });
      const bundler = createBundlerClient({ account, client: this.client, transport: http(this.cfg.bundlerUrl) });
      const g = await bundler.estimateUserOperationGas({ calls });
      return g.callGasLimit + g.verificationGasLimit + g.preVerificationGas;
    }
    if (!this.cfg.relayer) throw new Error("no bundlerUrl and no relayer");
    const { uo } = await this.buildUserOp(calls);
    return this.client.estimateContractGas({ account: this.cfg.relayer, address: this.d.entryPoint, abi: entryPoint08Abi, functionName: "handleOps", args: [[toPackedUserOperation(uo)], this.cfg.relayer.address] });
  }

  /** UserOperation from the vault: bundler if configured, otherwise handleOps from the relayer. */
  private async userOp(calls: Call[], label = "hybrid signature"): Promise<TxResult> {
    if (this.cfg.bundlerUrl) {
      const vault = await this.requireVault();
      const account = await toVaultAccount({ client: this.client, address: vault, entryPoint: this.d.entryPoint, keys: await this.keys(), progress: this.progress ?? undefined });
      const bundler = createBundlerClient({ account, client: this.client, transport: http(this.cfg.bundlerUrl) });
      const uoHash = await bundler.sendUserOperation({ calls });
      this.stage("confirm");
      const r = await bundler.waitForUserOperationReceipt({ hash: uoHash });
      this.stage("done");
      return { hash: r.receipt.transactionHash, gasUsed: r.actualGasUsed, detail: `UserOperation through the bundler, ${label}` };
    }
    if (!this.cfg.relayer) throw new Error("no bundlerUrl and no relayer: cannot submit a UserOperation");
    const { uo } = await this.buildUserOp(calls, this.progress ?? undefined);
    this.stage("submit");
    const hash = await this.wallet.writeContract({
      account: this.cfg.relayer, chain: this.cfg.chain, address: this.d.entryPoint, abi: entryPoint08Abi, functionName: "handleOps", args: [[toPackedUserOperation(uo)], this.cfg.relayer.address], gas: 4_000_000n,
    });
    return this.receipt(hash, `UserOperation via handleOps (local relayer), ${label}`);
  }
}

export const satelliteAccount = (a: ViemWalletAdapter): ReturnType<typeof toSatelliteAccount> =>
  toSatelliteAccount({ client: a.client, owner: a.cfg.ecdsa, entryPoint: a.d.entryPoint, delegate: a.d.satellite });
