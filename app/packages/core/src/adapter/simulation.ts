// In-memory implementation of WalletAdapter with the same rules as the contracts and the gas figures
// measured by the Forge tests. Used by the demo without a network, and by the UI tests.
import { keccak256, type Address, type Hex, toHex } from "viem";
import type { ActionRequest, Plan, ProgressFn, Stage, SubmitPath, TokenBalance, TxResult, WalletAdapter, WalletState } from "./types";

export const SIM_GAS = {
  eoaSend: 21000, delegate: 61000, createVault: 138000, sweep: 58000,
  mldsa: { userOp: 1431642, relayed: 1377543, asEoa: 1501489, sig: 2420, pk: 1312 },
};
export const SIM_POOLS: Record<string, { shield: number; unshield: number; note: string; unit?: bigint }> = {
  Railgun: { shield: 380000, unshield: 1250000, note: "any amount, unshield relayed by the 4337 mempool" },
  "Privacy Pools": { shield: 260000, unshield: 640000, note: "any amount, association-set proof on withdrawal" },
  "Tornado Cash": { shield: 1050000, unshield: 360000, note: "fixed 0.1 ETH notes, withdrawal via the paymaster", unit: 100000000000000000n },
};

const hex = (n: number, seed: number) => { let s = "", x = seed; for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; s += (x % 16).toString(16); } return s; };
const addr = (seed: number) => ("0x" + hex(40, seed)) as Address;
let txCounter = 1;
const fakeHash = (): Hex => keccak256(toHex(txCounter++));

export type SimulationOptions = { chainId: number; eoa?: Address; eth?: bigint; vaultAddress?: Address };

export class SimulationAdapter implements WalletAdapter {
  readonly chainId: number;
  readonly eoa: Address;
  private eth: bigint;
  private nonce = 12;
  private linked = false;
  private reserve = 50000000000000000n;
  private vault: null | { address: Address; eth: bigint; epNonce: bigint; pqNonce: bigint; preQKeyHash: Hex; postQKeyHash: Hex } = null;
  private readonly vaultAddress: Address;
  private priv: Record<string, bigint> = { Railgun: 0n, "Privacy Pools": 0n, "Tornado Cash": 0n };
  private tst = 500n * 10n ** 18n;
  private vaultTst = 0n;
  private progress: ProgressFn | null = null;
  private readonly TST = addr(5);

  constructor(o: SimulationOptions) {
    this.chainId = o.chainId;
    this.eoa = o.eoa ?? addr(7);
    this.eth = o.eth ?? 2500000000000000000n;
    this.vaultAddress = o.vaultAddress ?? addr(90 + (o.chainId % 7));
  }

  async read(): Promise<WalletState> {
    return {
      chainId: this.chainId,
      eoa: { address: this.eoa, eth: this.eth, tokens: this.tok(this.tst), nonce: this.nonce, delegate: this.linked ? addr(3) : null, linked: this.linked && !!this.vault, reserve: this.reserve },
      vault: this.vault ? { address: this.vault.address, scheme: "ML-DSA-44", eth: this.vault.eth, tokens: this.tok(this.vaultTst), preQKeyHash: this.vault.preQKeyHash, postQKeyHash: this.vault.postQKeyHash, epNonce: this.vault.epNonce, pqNonce: this.vault.pqNonce } : null,
      priv: { ...this.priv },
    };
  }

  private tok(balance: bigint): TokenBalance[] { return [{ address: this.TST, symbol: "TST", decimals: 18, balance }]; }
  setProgress(cb: ProgressFn | null) { this.progress = cb; }
  private async stages(list: Stage[]) { for (const s of list) { this.progress?.(s); await new Promise((r) => setTimeout(r, s.startsWith("sign") || s === "prove" ? 260 : 120)); } }

  async estimate(a: ActionRequest): Promise<Plan> {
    const typical = (gas: number): Plan => ({ gas: BigInt(gas), source: "typical" });
    switch (a.kind) {
      case "eoaSend": case "moveToVault": return typical(SIM_GAS.eoaSend);
      case "link": return typical(SIM_GAS.delegate);
      case "sweep": return typical(SIM_GAS.sweep);
      case "createVault": return typical(SIM_GAS.createVault);
      case "vaultSend": case "moveToPublic": return typical(a.path === "relay" ? SIM_GAS.mldsa.relayed : SIM_GAS.mldsa.userOp);
      case "sendAsPublic": return typical(SIM_GAS.mldsa.asEoa);
      case "shield": return typical(SIM_POOLS[a.pool].shield + (a.from === "vault" ? SIM_GAS.mldsa.userOp : 0));
      case "unshield": return typical(SIM_POOLS[a.pool].unshield);
    }
  }

  /** Simulation only: an incoming transfer to the public address. */
  async faucet(value = 1000000000000000000n): Promise<TxResult> {
    this.eth += value; this.tst += 100n * 10n ** 18n;
    return { hash: fakeHash(), gasUsed: 0n, detail: "Incoming transfer to the public address" };
  }

  async eoaSend(_to: Address, value: bigint) {
    this.need(value <= this.eth, "Not enough ETH in the public account");
    await this.stages(["sign-ecdsa", "submit", "confirm"]);
    this.eth -= value; this.nonce++;
    return this.ok(SIM_GAS.eoaSend, "Signed with the secp256k1 key");
  }
  async moveToVault(value: bigint) {
    const v = this.requireVault();
    this.need(value <= this.eth, "Not enough ETH in the public account");
    await this.stages(["sign-ecdsa", "submit", "confirm"]);
    this.eth -= value; v.eth += value; this.nonce++;
    return this.ok(SIM_GAS.eoaSend, "Plain transfer to the vault, secp256k1 key");
  }
  async link(reserve: bigint) {
    this.requireVault();
    await this.stages(["sign-auth", "submit", "confirm"]);
    this.linked = true; this.reserve = reserve; this.nonce++;
    return this.ok(SIM_GAS.delegate, "Type-4 transaction: delegate to the satellite, initialize(vault, reserve)");
  }
  async sweep() {
    const v = this.requireVault();
    this.need(this.linked, "Link the public account to the vault first");
    const amt = this.eth > this.reserve ? this.eth - this.reserve : 0n;
    this.need(amt > 0n || this.tst > 0n, "Nothing above the gas reserve to move");
    await this.stages(["submit", "confirm"]);
    this.eth -= amt; v.eth += amt; this.vaultTst += this.tst; this.tst = 0n;
    return this.ok(SIM_GAS.sweep, "sweep(), callable by anyone, no signature");
  }
  async createVault() {
    if (!this.vault) {
      await this.stages(["submit", "confirm"]);
      this.vault = { address: this.vaultAddress, eth: 0n, epNonce: 0n, pqNonce: 0n, preQKeyHash: keccak256(this.eoa), postQKeyHash: keccak256(addr(13)) };
    }
    return { ...(await this.ok(SIM_GAS.createVault, `Key blob written (${SIM_GAS.mldsa.pk} bytes), clone created and initialized`)), vault: this.vault.address };
  }
  async vaultSend(_to: Address, value: bigint, path: SubmitPath) {
    const v = this.requireVault();
    this.need(value <= v.eth, "Not enough ETH in the vault");
    if (path === "relay") this.need(this.linked, "Link the public account to the vault first");
    await this.stages(["sign-ecdsa", "sign-pq", "submit", "confirm"]);
    v.eth -= value;
    if (path === "relay") { v.pqNonce++; this.nonce++; } else v.epNonce++;
    return this.ok(path === "relay" ? SIM_GAS.mldsa.relayed : SIM_GAS.mldsa.userOp, path === "relay" ? "executeWithHybridSig, relayed by the public account, hybrid signature" : "UserOperation through the bundler, hybrid signature", "ML-DSA-44");
  }
  async sendAsPublic(_to: Address, value: bigint) {
    const v = this.requireVault();
    this.need(this.linked, "Link the public account to the vault first");
    this.need(value <= v.eth, "Not enough ETH in the vault");
    await this.stages(["sign-ecdsa", "sign-pq", "submit", "confirm"]);
    v.eth -= value; v.epNonce++;
    return this.ok(SIM_GAS.mldsa.asEoa, "Batch: push to the public account, then execute through it (the recipient sees the public address), hybrid signature", "ML-DSA-44");
  }
  async moveToPublic(value: bigint, path: SubmitPath) {
    const r = await this.vaultSend(this.eoa, value, path);
    this.eth += value;
    return r;
  }
  async signWrapped(hash: Hex) { this.requireVault(); return ("0x" + hex(64, Number(hash.slice(-6))) ) as Hex; }

  async shield(pool: string, from: "public" | "vault", value: bigint) {
    const p = SIM_POOLS[pool]; this.need(!!p, "Unknown pool");
    this.need(value > 0n, "Enter an amount");
    if (p.unit) this.need(value % p.unit === 0n, `${pool} takes multiples of 0.1 ETH`);
    if (from === "public") { this.need(value <= this.eth, "Not enough ETH in the public account"); this.eth -= value; this.nonce++; }
    else { const v = this.requireVault(); this.need(value <= v.eth, "Not enough ETH in the vault"); v.eth -= value; v.epNonce++; }
    await this.stages(from === "vault" ? ["sign-ecdsa", "sign-pq", "submit", "confirm"] : ["sign-ecdsa", "submit", "confirm"]);
    this.priv[pool] += value;
    return this.ok(p.shield + (from === "vault" ? SIM_GAS.mldsa.userOp : 0), from === "public" ? "Deposit from the public account, secp256k1 key" : "Deposit from the vault, hybrid signature", from === "vault" ? "ML-DSA-44" : undefined);
  }
  async unshield(pool: string, to: Address, value: bigint) {
    const p = SIM_POOLS[pool]; this.need(!!p, "Unknown pool");
    this.need(value > 0n, "Enter an amount");
    if (p.unit) this.need(value % p.unit === 0n, `${pool} notes are 0.1 ETH each`);
    this.need(value <= this.priv[pool], `Not enough in ${pool}`);
    await this.stages(["prove", "submit", "confirm"]);
    this.priv[pool] -= value;
    if (to.toLowerCase() === this.eoa.toLowerCase()) this.eth += value;
    else if (this.vault && to.toLowerCase() === this.vault.address.toLowerCase()) this.vault.eth += value;
    return this.ok(p.unshield, "Proof generated on this device, withdrawal relayed by a 4337 bundler, fee taken from the amount");
  }

  private requireVault() { if (!this.vault) throw new Error("No vault on this network: create it first"); return this.vault; }
  private need(c: boolean, msg: string) { if (!c) throw new Error(msg); }
  private async ok(gas: number, detail: string, sig?: string): Promise<TxResult & { sig?: string }> {
    this.progress?.("done");
    return { hash: fakeHash(), gasUsed: BigInt(gas), detail, sig };
  }
}
