import React from "react";
import type { Address, Hex } from "viem";
import type { WalletAdapter, WalletState, SubmitPath, TxResult, ActionRequest, Plan, Stage, TokenBalance } from "@zknox/pq-core";
import { SIM_GAS, SIM_POOLS } from "@zknox/pq-core";
import { ART } from "./art";

// ---------------------------------------------------------------------------------------------
// The wallet UI. Everything on-chain goes through a WalletAdapter (simulation or viem); the
// component only keeps view state (selection, dialogs, an activity log per network).
// ---------------------------------------------------------------------------------------------
export type NetworkEntry = { id: string; name: string; chainId: number; adapter: WalletAdapter; kind: "simulation" | "live" };

export type WalletProps = {
  networks: NetworkEntry[];
  initialNetwork?: string;
  title?: string;
  stripeWeight?: number;
  density?: "comfortable" | "compact";
  gasStyle?: "both" | "multiplier" | "absolute";
};

type Pot = "public" | "private" | "vault";
type ModalKind = "eoaSend" | "link" | "createVault" | "shield" | "unshield" | "vaultSend" | "moveToPublic" | "protect" | "receive";
type Modal = { kind: ModalKind; from?: string; asPublic?: boolean };
type Form = { to: string; amount: string; g1: string | null; g2: string | null; err: string | null; busy: boolean; step: number };
type Entry = { id: string; t: Date; pot: Pot; title: string; detail: string; gas?: bigint; sig?: string; hash?: Hex };

type State = {
  net: string;
  s: WalletState | null;
  loadErr: string | null;
  active: Pot;
  filter: "all" | Pot;
  modal: Modal | null;
  f: Form;
  disp: Record<Pot, number>;
  delta: Record<Pot, string | null>;
  banner: string | null;
  copied: string | null;
  activity: Record<string, Entry[]>;
  est: Plan | null; // gas for the open dialog, from the adapter
  estimating: boolean;
};

const TONE: Record<Pot, string> = { public: "#CE1126", private: "#ffffff", vault: "#0055A4" };
const LABEL: Record<Pot, string> = { public: "Public", private: "Private", vault: "Post-quantum" };
const TAB_LABEL: Record<Pot, string> = { public: "Public", private: "Private", vault: "PQ vault" };
const MAXSIG = 2420;
const short = (a?: string | null) => (a ? a.slice(0, 6) + "…" + a.slice(-4) : "");
const fmt = (wei: bigint) => (Number(wei) / 1e18).toLocaleString("en-US", { minimumFractionDigits: 4, maximumFractionDigits: 4 });
const fmtNum = (n: number) => n.toLocaleString("en-US", { minimumFractionDigits: 4, maximumFractionDigits: 4 });
const toWei = (s: string) => { const f = parseFloat(String(s).replace(",", ".")); return BigInt(Math.round((isFinite(f) ? f : 0) * 1e6)) * 1000000000000n; };
const isAddr = (a: string) => /^0x[0-9a-fA-F]{40}$/.test(a);
const privTotal = (s: WalletState | null) => (s ? Object.values(s.priv).reduce((a, b) => a + b, 0n) : 0n);
const noDelta = (): Record<Pot, string | null> => ({ public: null, private: null, vault: null });
const fmtTokens = (t: TokenBalance[]) => t.map((x) => ({ symbol: x.symbol, amount: (Number(x.balance) / 10 ** x.decimals).toLocaleString("en-US", { maximumFractionDigits: 2 }), fg: x.balance > 0n ? "#3d3d47" : "#9a9aa2" }));

const HELMET_CSS = `html, body { margin: 0; background: #0b0b0c; -webkit-font-smoothing: antialiased; }
  a { color: #c9aefc; text-decoration: none; }
  a:hover { color: #e2d2ff; }
  button:focus-visible, input:focus-visible, select:focus-visible { outline: 2px solid #8b5cf6; outline-offset: 2px; }
  @keyframes pqchip { 0% { opacity: 0; transform: translateY(5px); } 14% { opacity: 1; transform: none; } 78% { opacity: 1; } 100% { opacity: 0; } }
  @keyframes pqbanner { 0% { opacity: 0; } 8% { opacity: 1; } 88% { opacity: 1; } 100% { opacity: 0; } }
  ::selection { background: #4c1d95; color: #fff; }
  @keyframes pqsheen { 0% { transform: translateX(-130%) skewX(-18deg); } 55% { transform: translateX(230%) skewX(-18deg); } 100% { transform: translateX(230%) skewX(-18deg); } }
  @keyframes pqglow { 0%, 100% { box-shadow: 0 0 0 1px rgba(124,58,237,0.45), 0 0 22px rgba(124,58,237,0.35), 0 14px 40px rgba(76,29,149,0.28); } 50% { box-shadow: 0 0 0 1px rgba(167,139,250,0.9), 0 0 42px rgba(139,92,246,0.55), 0 14px 40px rgba(76,29,149,0.28); } }
  .pq-active { animation: pqglow 2.6s ease-in-out infinite; }
  .pq-sheen { position: absolute; top: -20%; bottom: -20%; left: 0; width: 38%; pointer-events: none; background: linear-gradient(100deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.55) 45%, rgba(196,181,253,0.55) 55%, rgba(255,255,255,0) 100%); animation: pqsheen 3.2s ease-in-out infinite; mix-blend-mode: screen; }
  @media (prefers-reduced-motion: reduce) { .pq-active { animation: none; } .pq-sheen { display: none; } }
`;

export class Wallet extends React.Component<WalletProps, State> {
  static defaultProps = { stripeWeight: 6, density: "comfortable", gasStyle: "both", title: "Ethereum wallet" };
  private _raf: number | null = null;
  private _timers: number[] = [];
  private _dialog: HTMLElement | null = null;
  private _wasOpen = false;
  private _key: (e: KeyboardEvent) => void = () => {};
  private _si: number | null = null;
  private _poll: number | null = null;
  private _estTimer: number | null = null;
  private _estSeq = 0;

  constructor(props: WalletProps) {
    super(props);
    const net = props.initialNetwork ?? props.networks[0].id;
    this.state = {
      net, s: null, loadErr: null, active: "public", filter: "all", modal: null,
      f: { to: "", amount: "", g1: null, g2: null, err: null, busy: false, step: 0 },
      disp: { public: 0, private: 0, vault: 0 }, delta: noDelta(), banner: null, copied: null,
      activity: Object.fromEntries(props.networks.map((n) => [n.id, []])),
      est: null, estimating: false,
    };
  }

  componentDidMount() {
    this._key = (e) => { if (e.key === "Escape" && this.state.modal) this.close(); };
    window.addEventListener("keydown", this._key);
    void this.refresh();
    this.startPolling();
  }
  startPolling() {
    if (this._poll) clearInterval(this._poll);
    this._poll = window.setInterval(() => { if (this.entry().kind === "live" && !this.state.f.busy) void this.refresh(); }, 12000);
  }
  componentWillUnmount() {
    window.removeEventListener("keydown", this._key);
    if (this._poll) clearInterval(this._poll);
    if (this._estTimer) clearTimeout(this._estTimer);
    if (this._raf) cancelAnimationFrame(this._raf);
    this._timers.forEach(clearTimeout);
    if (this._si) clearInterval(this._si);
  }
  componentDidUpdate() {
    const open = !!this.state.modal;
    if (open && !this._wasOpen && this._dialog) {
      const el = this._dialog.querySelector<HTMLElement>("input, button:not([disabled])");
      if (el) el.focus();
    }
    this._wasOpen = open;
  }

  // ---- adapter plumbing ----------------------------------------------------------------------
  entry() { return this.props.networks.find((n) => n.id === this.state.net)!; }
  adapter(): WalletAdapter { return this.entry().adapter; }
  linked() { const s = this.state.s; return !!(s && s.eoa.linked && s.vault); }
  vaultAddr() { return this.state.s?.vault?.address ?? null; }
  eoa() { return this.state.s?.eoa.address ?? ("0x" as Address); }

  async refresh(deltas?: Partial<Record<Pot, string>>) {
    try {
      const s = await this.adapter().read();
      this.setState({ s, loadErr: null }, () => {
        this.tween();
        if (deltas) {
          this.setState({ delta: { ...noDelta(), ...deltas } });
          this.later(() => this.setState({ delta: noDelta() }), 1800);
        }
      });
    } catch (e) {
      this.setState({ loadErr: (e as Error).message });
    }
  }
  later(fn: () => void, ms: number) { this._timers.push(window.setTimeout(fn, ms)); }
  log(pot: Pot, title: string, r: TxResult | null, extra?: Partial<Entry>) {
    this.setState((st) => ({
      activity: { ...st.activity, [st.net]: [{ id: String(Date.now() + Math.random()), t: new Date(), pot, title, detail: r?.detail ?? "", gas: r?.gasUsed, sig: r?.sig, hash: r?.hash, ...extra }, ...st.activity[st.net]] },
    }));
  }
  targets(): Record<Pot, number> {
    const s = this.state.s;
    return { public: s ? Number(s.eoa.eth) / 1e18 : 0, private: Number(privTotal(s)) / 1e18, vault: s?.vault ? Number(s.vault.eth) / 1e18 : 0 };
  }
  tween() {
    const t = this.targets();
    const from = { ...this.state.disp }, t0 = performance.now();
    if (this._raf) cancelAnimationFrame(this._raf);
    const step = (now: number) => {
      const k = Math.min(1, (now - t0) / 480), e = 1 - Math.pow(1 - k, 3);
      const d = { public: 0, private: 0, vault: 0 } as Record<Pot, number>;
      for (const key of ["public", "private", "vault"] as Pot[]) d[key] = from[key] + (t[key] - from[key]) * e;
      this.setState({ disp: d });
      this._raf = k < 1 ? requestAnimationFrame(step) : null;
    };
    this._raf = requestAnimationFrame(step);
  }
  gasText(gas: number | bigint) {
    const g = Number(gas);
    const x = g / SIM_GAS.eoaSend;
    const mult = "≈" + (x >= 10 ? Math.round(x) : x.toFixed(1)) + "× a plain ETH transfer";
    const abs = g.toLocaleString("en-US") + " gas";
    if (this.props.gasStyle === "absolute") return "about " + abs;
    if (this.props.gasStyle === "multiplier") return mult;
    return "about " + abs + " · " + mult;
  }
  copy(which: string, value: string) {
    if (navigator.clipboard) void navigator.clipboard.writeText(value);
    this.setState({ copied: which });
    this.later(() => this.setState({ copied: null }), 1200);
  }
  setNet(net: string) {
    const e = this.props.networks.find((n) => n.id === net)!;
    this.setState({ net, s: null, banner: `${e.name} · chain ${e.chainId} · ${e.kind === "simulation" ? "simulation, no network" : "live"}` }, () => {
      void this.refresh();
      this.later(() => this.setState({ banner: null }), 3500);
    });
  }
  open(modal: Modal) {
    const s = this.state.s; if (!s) return;
    const pools = Object.keys(SIM_POOLS);
    const funded = pools.filter((p) => (s.priv[p] ?? 0n) > 0n);
    const f: Form = { to: "", amount: "0.25", g1: null, g2: null, err: null, busy: false, step: 0 };
    if (modal.kind === "createVault") f.g1 = "ML-DSA-44";
    if (modal.kind === "link") f.amount = fmt(s.eoa.reserve || 50000000000000000n);
    if (modal.kind === "vaultSend" || modal.kind === "moveToPublic") f.g1 = "bundler";
    if (modal.kind === "shield") { f.g1 = modal.from || "public"; f.g2 = "Railgun"; f.amount = "0.1"; }
    if (modal.kind === "unshield") { f.g1 = funded[0] || pools[0]; f.g2 = "public"; f.amount = fmt(s.priv[funded[0] || pools[0]] ?? 0n); }
    if (modal.kind === "protect") {
      f.g1 = modal.from || "public";
      f.g2 = f.g1 === "private" ? funded[0] || pools[0] : this.linked() ? "all" : "amount";
      f.amount = f.g1 === "private" ? fmt(s.priv[funded[0] || pools[0]] ?? 0n) : fmt(s.eoa.eth);
    }
    this.setState({ modal, f, est: null }, () => this.scheduleEstimate());
  }
  close() { this.adapter().setProgress(null); this.setState({ modal: null, est: null }); }

  /** ActionRequest for the open dialog, or null when the form is not ready. */
  request(): ActionRequest | null {
    const { modal, f } = this.state; const s = this.state.s;
    if (!modal || !s) return null;
    const v = toWei(f.amount);
    const to = f.to as Address;
    switch (modal.kind) {
      case "eoaSend": return isAddr(f.to) && v > 0n ? { kind: "eoaSend", to, value: v } : null;
      case "link": return { kind: "link", reserve: v };
      case "createVault": return { kind: "createVault" };
      case "shield": return f.g2 && v > 0n ? { kind: "shield", pool: f.g2, from: f.g1 as "public" | "vault", value: v } : null;
      case "unshield": {
        const dest = f.g2 === "other" ? f.to : f.g2 === "vault" ? this.vaultAddr() : s.eoa.address;
        return f.g1 && dest && isAddr(dest) && v > 0n ? { kind: "unshield", pool: f.g1, to: dest as Address, value: v } : null;
      }
      case "vaultSend": return isAddr(f.to) && v > 0n ? (modal.asPublic ? { kind: "sendAsPublic", to, value: v } : { kind: "vaultSend", to, value: v, path: f.g1 as SubmitPath }) : null;
      case "moveToPublic": return v > 0n ? { kind: "moveToPublic", value: v, path: f.g1 as SubmitPath } : null;
      case "protect":
        if (f.g1 === "public") return this.linked() && f.g2 === "all" ? { kind: "sweep" } : v > 0n ? { kind: "moveToVault", value: v } : null;
        return f.g2 && this.vaultAddr() && v > 0n ? { kind: "unshield", pool: f.g2, to: this.vaultAddr()!, value: v } : null;
      case "receive": return null;
    }
  }
  scheduleEstimate() {
    if (this._estTimer) clearTimeout(this._estTimer);
    this._estTimer = window.setTimeout(() => void this.estimateNow(), 250);
  }
  async estimateNow() {
    const req = this.request();
    const seq = ++this._estSeq;
    if (!req) { this.setState({ est: null, estimating: false }); return; }
    this.setState({ estimating: true });
    try {
      const est = await this.adapter().estimate(req);
      if (seq === this._estSeq) this.setState({ est, estimating: false });
    } catch {
      if (seq === this._estSeq) this.setState({ est: null, estimating: false });
    }
  }
  setF(k: keyof Form, v: string) {
    this.setState((st) => {
      const f: Form = { ...st.f, [k]: v, err: null };
      const s = st.s!;
      if (st.modal?.kind === "unshield" && k === "g1") f.amount = fmt(s.priv[v] ?? 0n);
      if (st.modal?.kind === "protect" && (k === "g1" || k === "g2")) {
        const sweepable = s.eoa.eth > s.eoa.reserve ? s.eoa.eth - s.eoa.reserve : 0n;
        f.amount = f.g1 === "private" ? fmt(s.priv[f.g2!] ?? 0n) : fmt(s.eoa.linked ? sweepable : s.eoa.eth);
      }
      return { f };
    }, () => this.scheduleEstimate());
  }

  // ---- actions (each returns an error string, or null) ---------------------------------------
  run = async (): Promise<string | null> => {
    const { modal, f } = this.state; const a = this.adapter(); const s = this.state.s!;
    const v = toWei(f.amount);
    try {
      switch (modal!.kind) {
        case "eoaSend": {
          if (!isAddr(f.to)) return "Enter a valid address";
          const r = await a.eoaSend(f.to as Address, v);
          this.log("public", `Sent ${fmt(v)} ETH to ${short(f.to)}`, r); await this.refresh({ public: "−" + fmt(v) + " ETH" }); return null;
        }
        case "link": {
          const r = await a.link(v);
          this.log("public", "Linked the public account to the vault", r); await this.refresh(); return null;
        }
        case "createVault": {
          const r = await a.createVault();
          this.log("vault", "Created the ML-DSA-44 vault", r); await this.refresh(); return null;
        }
        case "shield": {
          if (!a.shield) return "Shielded pools are not wired on this network yet";
          const from = f.g1 as "public" | "vault";
          const r = await a.shield(f.g2!, from, v);
          this.log("private", `Shielded ${fmt(v)} ETH into ${f.g2}`, r); await this.refresh({ [from]: "−" + fmt(v) + " ETH", private: "+" + fmt(v) + " ETH" }); return null;
        }
        case "unshield": {
          if (!a.unshield) return "Shielded pools are not wired on this network yet";
          const dest = f.g2 === "other" ? f.to : f.g2 === "vault" ? this.vaultAddr() : s.eoa.address;
          if (!dest || !isAddr(dest)) return f.g2 === "vault" ? "No vault on this network" : "Enter a valid address";
          const r = await a.unshield(f.g1!, dest as Address, v);
          const where = f.g2 === "public" ? "the public account" : f.g2 === "vault" ? "the vault" : short(dest);
          const d: Partial<Record<Pot, string>> = { private: "−" + fmt(v) + " ETH" }; if (f.g2 !== "other") d[f.g2 as Pot] = "+" + fmt(v) + " ETH";
          this.log("private", `Unshielded ${fmt(v)} ETH from ${f.g1} to ${where}`, r); await this.refresh(d); return null;
        }
        case "vaultSend": {
          if (!isAddr(f.to)) return "Enter a valid address";
          const r = modal!.asPublic ? await a.sendAsPublic(f.to as Address, v) : await a.vaultSend(f.to as Address, v, f.g1 as SubmitPath);
          this.log("vault", (modal!.asPublic ? `Sent ${fmt(v)} ETH to ${short(f.to)} as the public account` : `Sent ${fmt(v)} ETH to ${short(f.to)}`), r);
          await this.refresh({ vault: "−" + fmt(v) + " ETH" }); return null;
        }
        case "moveToPublic": {
          const r = await a.moveToPublic(v, f.g1 as SubmitPath);
          this.log("vault", `Moved ${fmt(v)} ETH to the public account`, r); await this.refresh({ vault: "−" + fmt(v) + " ETH", public: "+" + fmt(v) + " ETH" }); return null;
        }
        case "protect": {
          if (f.g1 === "public") {
            const all = this.linked() && f.g2 === "all";
            const r = all ? await a.sweep() : await a.moveToVault(v);
            this.log("vault", all ? "Swept the public account into the vault" : `Moved ${fmt(v)} ETH into the vault`, r);
            await this.refresh({ public: all ? null as unknown as string : "−" + fmt(v) + " ETH", vault: all ? "+" : "+" + fmt(v) + " ETH" }); return null;
          }
          if (!a.unshield) return "Shielded pools are not wired on this network yet";
          const vault = this.vaultAddr(); if (!vault) return "No vault on this network";
          const r = await a.unshield(f.g2!, vault, v);
          this.log("private", `Unshielded ${fmt(v)} ETH from ${f.g2} to the vault`, r); await this.refresh({ private: "−" + fmt(v) + " ETH", vault: "+" + fmt(v) + " ETH" }); return null;
        }
        case "receive": return null;
      }
    } catch (e) {
      return (e as Error).message.split("\n")[0];
    }
    return null;
  };

  receive = async () => {
    const a = this.adapter();
    if (a.faucet) {
      try { const r = await a.faucet(); this.log("public", "Received 1.0000 ETH", r); await this.refresh({ public: "+1.0000 ETH" }); }
      catch (e) { this.log("public", "Faucet failed", null, { detail: (e as Error).message.split("\n")[0] }); }
    } else this.open({ kind: "receive" });
  };

  submit = () => {
    const spec = this.spec(); if (!spec) return;
    if (this.state.modal?.kind === "receive") { this.close(); return; }
    const n = spec.steps.length;
    const stages: (Stage | undefined)[] = spec.steps.map((x: any) => x.stage);
    this.setState((st) => ({ f: { ...st.f, busy: true, step: 0, err: null } }));
    // steps follow the adapter's progress; a step with no stage of its own is ticked with the next one
    this.adapter().setProgress((stage) => {
      let idx = stages.findIndex((x) => x === stage);
      if (stage === "done" || stage === "confirm") idx = n - 1;
      if (idx < 0) return;
      this.setState((st) => ({ f: { ...st.f, step: Math.max(st.f.step, idx + 1) } }));
    });
    void this.run().then((err) => {
      this.adapter().setProgress(null);
      if (err) this.setState((st) => ({ f: { ...st.f, busy: false, step: 0, err } }));
      else this.close();
    });
  };

  // ---- modal spec ---------------------------------------------------------------------------------
  spec(): any {
    const { modal, f } = this.state; const s = this.state.s;
    if (!modal || !s) return null;
    const v = s.vault;
    const pools = Object.keys(SIM_POOLS);
    const funded = pools.filter((p) => (s.priv[p] ?? 0n) > 0n);
    const opt = (v2: string, label: string, meta: string, disabled?: boolean, title?: string) => ({ v: v2, label, meta, disabled: !!disabled, title: title || "" });
    const ecdsa = { label: "Sign with the secp256k1 key", bytes: 65, stage: "sign-ecdsa" };
    const pq = () => ({ label: "Sign with ML-DSA-44", bytes: SIM_GAS.mldsa.sig, stage: "sign-pq" });
    const submit = (label: string) => ({ label, stage: "submit" });
    const prove = (label: string) => ({ label, stage: "prove" });
    const G = SIM_GAS.mldsa;
    const netName = this.entry().name;
    switch (modal.kind) {
      case "receive":
        return { title: "Receive", blurb: `Send ETH or tokens to your public address on ${netName}. Once the account is linked, anything above the gas reserve can be swept into the vault without a signature.`, submitLabel: "Done", fixedTo: s.eoa.address, steps: [], gas: 0 };
      case "eoaSend":
        return { title: "Send from the public account", submitLabel: "Send", showTo: true, amountLabel: "Amount — up to " + fmt(s.eoa.eth) + " ETH", steps: [ecdsa, submit("Broadcast")], gas: SIM_GAS.eoaSend };
      case "link":
        return {
          title: "Link the public account to the vault",
          blurb: "A type-4 transaction delegates your public account's code to the satellite implementation and calls initialize(vault, reserve). The address and the secp256k1 key stay exactly as they are.",
          submitLabel: "Link", amountLabel: "ETH kept on the public account for gas",
          gains: [
            { label: "sweep(), callable by anyone, no signature", detail: "Everything above the gas reserve can be pushed into the vault — so funds arriving at your usual address get protected without you signing." },
            { label: "The public account can relay a vault spend", detail: "executeWithHybridSig submitted and paid for by the public account, instead of a bundler." },
            { label: "The vault can send as the public account", detail: "Funds pass through the public account in the same transaction, so the recipient sees your usual address." },
          ],
          steps: [{ label: "Sign the delegation to the satellite", bytes: 65, stage: "sign-auth" }, submit("Send the transaction with initialize(vault, reserve)")],
          gas: SIM_GAS.delegate,
        };
      case "createVault":
        return {
          title: "Create the post-quantum vault on " + netName,
          blurb: "Every spend will need your usual key and a post-quantum signature. The scheme cannot be changed later.",
          submitLabel: "Create", slow: true,
          groups: [{ key: "g1", label: "Post-quantum scheme", options: [opt("ML-DSA-44", "ML-DSA-44", G.sig + " B signature · " + this.gasText(G.userOp))] }],
          steps: [{ label: "Derive the ML-DSA-44 key from your seed", stage: "sign-pq" }, submit("Write the public key (" + G.pk + " bytes, expanded on-chain form) once"), { label: "Create the vault clone, initialized with the two key references", stage: "confirm" }],
          gas: SIM_GAS.createVault,
        };
      case "shield": {
        const from = f.g1, pool = f.g2!;
        const max = from === "vault" ? (v ? v.eth : 0n) : s.eoa.eth;
        return {
          title: "Shield", blurb: "Moves funds into a shielded pool. The note stays on your seed.", submitLabel: "Shield", slow: from === "vault",
          groups: [
            { key: "g1", label: "From", options: [opt("public", "Public account", fmt(s.eoa.eth) + " ETH"), opt("vault", "Post-quantum vault", v ? fmt(v.eth) + " ETH" : "not created", !v, "No vault on this network")] },
            { key: "g2", label: "Pool", options: pools.map((p) => opt(p, p, SIM_POOLS[p].note)) },
          ],
          amountLabel: "Amount — up to " + fmt(max) + " ETH",
          steps: from === "vault" ? [ecdsa, pq(), submit("Deposit into " + pool + " through the bundler")] : [ecdsa, submit("Deposit into " + pool)],
          gas: SIM_POOLS[pool].shield + (from === "vault" ? G.userOp : 0),
        };
      }
      case "unshield":
        return {
          title: "Unshield", blurb: "The proof is generated on this device; a 4337 bundler relays the withdrawal and takes its fee from the amount.", submitLabel: "Unshield", slow: true,
          groups: [
            { key: "g1", label: "Pool", options: pools.map((p) => opt(p, p, fmt(s.priv[p] ?? 0n) + " ETH available", (s.priv[p] ?? 0n) === 0n, "Nothing shielded here")) },
            { key: "g2", label: "To", options: [opt("public", "Public account", short(s.eoa.address)), opt("vault", "Post-quantum vault", v ? "straight into the vault, without touching the public address" : "not created", !v, "No vault on this network"), opt("other", "Another address", "any recipient")] },
          ],
          showTo: f.g2 === "other", amountLabel: "Amount in ETH",
          steps: [prove("Generate the withdrawal proof"), submit("Send the UserOperation to the bundler — paymaster pays gas, fee taken from the amount")],
          gas: SIM_POOLS[f.g1!].unshield,
        };
      case "vaultSend": {
        const asPublic = !!modal.asPublic;
        return {
          title: asPublic ? "Send as the public account" : "Send from the vault",
          blurb: asPublic ? "The recipient sees your public address. One signature; the funds pass through the public account inside the same transaction." : null,
          submitLabel: "Send", slow: true, showTo: true,
          groups: asPublic ? [] : [{ key: "g1", label: "Submit through", options: [opt("bundler", "Bundler", "gas paid by the vault"), opt("relay", "Public account", this.linked() ? "relay, gas paid by it" : "requires the accounts to be linked", !this.linked(), "Link the public account to the vault first")] }],
          amountLabel: "Amount — up to " + fmt(v?.eth ?? 0n) + " ETH",
          steps: [ecdsa, pq(), submit(asPublic ? "Batch through the public account" : f.g1 === "bundler" ? "Send the UserOperation to the bundler" : "Relay executeWithHybridSig from the public account")],
          gas: asPublic ? G.asEoa : f.g1 === "bundler" ? G.userOp : G.relayed,
        };
      }
      case "moveToPublic":
        return {
          title: "Move to the public account", submitLabel: "Move", slow: true, fixedTo: short(s.eoa.address),
          groups: [{ key: "g1", label: "Submit through", options: [opt("bundler", "Bundler", "gas paid by the vault"), opt("relay", "Public account", this.linked() ? "relay, gas paid by it" : "requires the accounts to be linked", !this.linked(), "Link the accounts first")] }],
          amountLabel: "Amount — up to " + fmt(v?.eth ?? 0n) + " ETH",
          steps: [ecdsa, pq(), submit(f.g1 === "bundler" ? "Send the UserOperation to the bundler" : "Relay executeWithHybridSig from the public account")],
          gas: f.g1 === "bundler" ? G.userOp : G.relayed,
        };
      case "protect": {
        const fromPublic = f.g1 === "public";
        const sweepAll = fromPublic && s.eoa.linked && f.g2 === "all";
        const groups: any[] = [{ key: "g1", label: "From", options: [opt("public", "Public account", fmt(s.eoa.eth) + " ETH"), opt("private", "Shielded pools", funded.length ? fmt(privTotal(s)) + " ETH" : "nothing shielded", !funded.length, "Shield something first")] }];
        if (fromPublic && s.eoa.linked) groups.push({ key: "g2", label: "How much", options: [opt("all", "Everything above the gas reserve", "keeps " + fmt(s.eoa.reserve) + " ETH"), opt("amount", "A set amount", "signed transfer")] });
        if (!fromPublic) groups.push({ key: "g2", label: "Pool", options: pools.map((p) => opt(p, p, fmt(s.priv[p] ?? 0n) + " ETH", (s.priv[p] ?? 0n) === 0n, "Nothing shielded here")) });
        return {
          title: "Protect funds", blurb: "Moves funds into the post-quantum vault, where every spend needs your usual key and a post-quantum signature.",
          submitLabel: "Protect", slow: !fromPublic, groups,
          amountLabel: sweepAll ? null : "Amount in ETH",
          steps: fromPublic
            ? (sweepAll ? [submit("Call sweep() on the public account — no signature"), { label: "Funds land in the vault " + short(this.vaultAddr()), stage: "confirm" }] : [ecdsa, submit("Transfer to the vault " + short(this.vaultAddr()))])
            : [prove("Generate the " + f.g2 + " withdrawal proof"), submit("Send the UserOperation to the bundler, recipient = the vault")],
          gas: fromPublic ? (sweepAll ? SIM_GAS.sweep : SIM_GAS.eoaSend) : SIM_POOLS[f.g2!] ? SIM_POOLS[f.g2!].unshield : 0,
        };
      }
    }
    return null;
  }

  // ---- view model ---------------------------------------------------------------------------------
  btn(on: (e?: any) => void, opts?: { disabled?: boolean; primary?: boolean; title?: string }) {
    const o = opts || {};
    if (o.disabled) return { on: () => {}, disabled: true, title: o.title || "", bg: "#ededf0", fg: "#9a9aa2", bd: "#e0e0e6", cur: "not-allowed" };
    if (o.primary) return { on, disabled: false, title: o.title || "", bg: "linear-gradient(180deg, #7c3aed, #5b21b6)", fg: "#ffffff", bd: "#7c3aed", cur: "pointer" };
    return { on, disabled: false, title: o.title || "", bg: "#ffffff", fg: "#26262c", bd: "#cfcfd7", cur: "pointer" };
  }

  renderVals(): any {
    const st = this.state, s = st.s, v = s?.vault ?? null, e = this.entry();
    const dens = this.props.density ?? "comfortable";
    const stop = (ev: any) => ev.stopPropagation();
    const openFrom = (kind: ModalKind, extra?: Partial<Modal>) => (ev?: any) => { if (ev) ev.stopPropagation(); this.open({ kind, ...(extra || {}) }); };
    const pick = (id: Pot) => () => this.setState({ active: id });
    const spec = this.spec();
    const pools = Object.keys(SIM_POOLS);
    const pt = privTotal(s);
    const eoaEth = s?.eoa.eth ?? 0n;
    const tabs = (["public", "private", "vault"] as Pot[]).map((id) => ({
      id, label: TAB_LABEL[id], color: TONE[id], onSelect: pick(id),
      bg: st.active === id ? "#3f1d80" : "transparent", fg: st.active === id ? "#ffffff" : "#a0a0a8",
    }));
    const sel: any = {};
    for (const id of ["public", "private", "vault"] as Pot[]) sel[id] = st.active === id
      ? { bd: "#a78bfa", sh: "0 0 0 1px rgba(124,58,237,0.45), 0 0 22px rgba(124,58,237,0.35), 0 14px 40px rgba(76,29,149,0.28)", cls: "pq-active", shine: true, tf: "translateY(-2px)" }
      : { bd: "#e4e4e9", sh: "none", cls: "", shine: false, tf: "none" };
    const filters = [{ id: "all", label: "All", dot: "#7c7c86" }, { id: "public", label: "Public", dot: TONE.public }, { id: "private", label: "Private", dot: TONE.private }, { id: "vault", label: "Post-quantum", dot: TONE.vault }].map((x) => ({
      ...x, onSelect: () => this.setState({ filter: x.id as any }),
      bg: st.filter === x.id ? "#efe7ff" : "#ffffff", fg: st.filter === x.id ? "#4c1d95" : "#55555f", bd: st.filter === x.id ? "#a78bfa" : "#d9d9e0",
    }));
    const items = (st.activity[st.net] ?? []).filter((a) => st.filter === "all" || a.pot === st.filter).slice(0, 14).map((a) => ({
      id: a.id, title: a.title, detail: a.detail, color: TONE[a.pot], time: a.t.toLocaleTimeString("en-GB"),
      gasText: a.gas ? this.gasText(a.gas) + (a.sig ? " · " + a.sig + " + secp256k1" : "") : null,
    }));
    const form = spec ? {
      title: spec.title, blurb: spec.blurb || null, submitLabel: st.f.busy ? "Signing…" : spec.submitLabel,
      submitBg: st.f.busy ? "#3f2a6b" : "linear-gradient(180deg, #7c3aed, #5b21b6)", submitCur: st.f.busy ? "progress" : "pointer",
      busy: st.f.busy, err: st.f.err, to: st.f.to, amount: st.f.amount,
      showTo: !!spec.showTo, fixedTo: spec.fixedTo || null, amountLabel: spec.amountLabel || null,
      gasText: st.est ? this.gasText(st.est.gas) + (st.est.source === "estimated" ? " · node estimate" : " · typical") : st.estimating ? "estimating…" : spec.gas ? this.gasText(spec.gas) + " · typical" : "no transaction",
      gains: spec.gains || [], hasGains: !!(spec.gains && spec.gains.length),
      groups: (spec.groups || []).map((g: any) => ({
        label: g.label,
        options: g.options.map((o: any) => {
          const on = (st.f as any)[g.key] === o.v;
          return {
            label: o.label, meta: o.meta, disabled: o.disabled, title: o.title,
            onSelect: o.disabled ? () => {} : () => this.setF(g.key, o.v),
            bg: o.disabled ? "#141417" : on ? "#241a3d" : "#1a1a1f", fg: o.disabled ? "#5c5c65" : on ? "#f0e9ff" : "#d0d0d8",
            bd: o.disabled ? "#242429" : on ? "#7c3aed" : "#2f2f36", metaFg: o.disabled ? "#4f4f58" : "#9a9aa4", cur: o.disabled ? "not-allowed" : "pointer",
          };
        }),
      })),
      steps: spec.steps.map((x: any, i: number) => {
        const done = st.f.busy && st.f.step > i;
        return {
          label: x.label, bytes: x.bytes || null, pct: x.bytes ? Math.max(2, Math.round((x.bytes / MAXSIG) * 100)) : 0,
          barColor: x.bytes > 200 ? "#7c3aed" : "#4b5563", fg: done ? "#ffffff" : "#a8a8b2", tick: done ? "✓" : "",
          tickBg: done ? "#7c3aed" : "transparent", tickBd: done ? "#7c3aed" : "#3a3a42", tickFg: "#ffffff",
        };
      }),
    } : { title: "", blurb: null, submitLabel: "", submitBg: "transparent", submitCur: "pointer", busy: false, err: null, to: "", amount: "", showTo: false, fixedTo: null, amountLabel: null, gasText: "", gains: [], hasGains: false, groups: [], steps: [] };

    return {
      fs: dens === "compact" ? 14 : 15, pad: dens === "compact" ? 14 : 18, stripe: this.props.stripeWeight ?? 6,
      title: this.props.title,
      subtitle: LABEL[st.active] + " account on " + e.name + (e.kind === "simulation" ? " (simulation)" : ""),
      net: st.net, netName: e.name, chainId: e.chainId, satelliteShort: s?.eoa.delegate ? short(s.eoa.delegate) : "—",
      netOptions: this.props.networks.map((n) => ({ id: n.id, name: n.name + (n.kind === "simulation" ? " (simulation)" : "") })),
      banner: st.loadErr ? "Cannot read this network: " + st.loadErr : st.banner,
      totalEth: fmtNum(st.disp.public + st.disp.private + st.disp.vault),
      pubEth: fmtNum(st.disp.public), privEth: fmtNum(st.disp.private), vaultEth: fmtNum(st.disp.vault),
      pubNonce: s?.eoa.nonce ?? 0, epNonce: v ? v.epNonce.toString() : "0", pqNonce: v ? v.pqNonce.toString() : "0",
      pubTokens: fmtTokens(s?.eoa.tokens ?? []), vaultTokens: fmtTokens(v?.tokens ?? []),
      delta: st.delta,
      linkedPill: this.linked() ? "Linked · " + fmt(s!.eoa.reserve) + " ETH gas reserve" : s?.eoa.delegate ? "Delegated to " + short(s.eoa.delegate) : null,
      eoaShort: short(s?.eoa.address), vaultShort: short(v?.address),
      copiedEoa: st.copied === "eoa" ? "✓" : "⧉", copiedVault: st.copied === "vault" ? "✓" : "⧉",
      pubNote: s?.eoa.linked ? "Linked to the vault: keeps " + fmt(s.eoa.reserve) + " ETH for gas, anything above it can be swept without a signature." : "Standard Ethereum account, signing with its secp256k1 key.",
      vaultNote: v ? "ML-DSA-44 and secp256k1 together — quantum-safe custody with a familiar recovery story." : "",
      hasVault: !!v, noVault: !v, noVaultLine: "No vault on " + e.name, createGas: this.gasText(SIM_GAS.createVault),
      vaultKeys: v ? [
        { label: "secp256k1 · " + short(v.preQKeyHash), bytes: 65, pct: Math.max(2, Math.round((65 / MAXSIG) * 100)), color: "#6b7280" },
        { label: "ML-DSA-44 · " + short(v.postQKeyHash), bytes: SIM_GAS.mldsa.sig, pct: 100, color: "#7c3aed" },
      ] : [],
      pools: pools.map((p) => ({ name: p, note: SIM_POOLS[p].note, amount: fmt(s?.priv[p] ?? 0n) + " ETH", fg: (s?.priv[p] ?? 0n) > 0n ? "#16161a" : "#9a9aa2" })),
      tabs, sel, filters, log: items, hasActivity: items.length > 0, noActivity: items.length === 0,
      modalOpen: !!st.modal, form, dialogRef: (el: HTMLElement | null) => { this._dialog = el; },
      b: {
        receive: this.btn(() => void this.receive()),
        eoaSend: this.btn(openFrom("eoaSend"), { disabled: eoaEth === 0n, title: "The public account is empty" }),
        shieldPub: this.btn(openFrom("shield", { from: "public" }), { disabled: eoaEth === 0n || !this.adapter().shield, title: this.adapter().shield ? "The public account is empty" : "Shielded pools are not wired on this network yet" }),
        link: this.btn(openFrom("link"), { disabled: !v || !!s?.eoa.linked, title: !v ? "Create the vault first" : "Already linked" }),
        protectPub: this.btn(v ? openFrom("protect", { from: "public" }) : openFrom("createVault"), { primary: true, disabled: eoaEth === 0n, title: "The public account is empty" }),
        shield: this.btn(openFrom("shield", { from: "public" }), { primary: true, disabled: !this.adapter().shield, title: "Shielded pools are not wired on this network yet" }),
        unshield: this.btn(openFrom("unshield"), { disabled: pt === 0n, title: "Nothing shielded yet" }),
        protectPriv: this.btn(v ? openFrom("protect", { from: "private" }) : openFrom("createVault"), { disabled: pt === 0n, title: "Nothing shielded yet" }),
        vaultSend: this.btn(openFrom("vaultSend"), { disabled: !v || v.eth === 0n, title: "The vault is empty" }),
        shieldVault: this.btn(openFrom("shield", { from: "vault" }), { disabled: !v || v.eth === 0n || !this.adapter().shield, title: "The vault is empty" }),
        moveToPublic: this.btn(openFrom("moveToPublic"), { disabled: !v || v.eth === 0n, title: "The vault is empty" }),
        sendAsPublic: this.btn(openFrom("vaultSend", { asPublic: true }), { disabled: !v || !this.linked() || v.eth === 0n, title: !this.linked() ? "Link the public account to the vault first" : "The vault is empty" }),
        createVault: this.btn(openFrom("createVault"), { primary: true }),
      },
      on: {
        net: (ev: any) => this.setNet(ev.target.value),
        pickPublic: pick("public"), pickPrivate: pick("private"), pickVault: pick("vault"),
        copyEoa: (ev: any) => { ev.stopPropagation(); this.copy("eoa", s?.eoa.address ?? ""); },
        copyVault: (ev: any) => { ev.stopPropagation(); this.copy("vault", v?.address ?? ""); },
        close: () => this.close(), stop,
        toChange: (ev: any) => this.setF("to", ev.target.value),
        amountChange: (ev: any) => this.setF("amount", ev.target.value),
        submit: () => { if (!st.f.busy) this.submit(); },
        trap: (ev: any) => {
          if (ev.key !== "Tab" || !this._dialog) return;
          const nodes = Array.from(this._dialog.querySelectorAll<HTMLElement>("button:not([disabled]), input, select"));
          if (!nodes.length) return;
          const first = nodes[0], last = nodes[nodes.length - 1];
          if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
          else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
        },
      },
    };
  }

  render() {
    const v = this.renderVals();
    return (
      <>
        <style>{HELMET_CSS}</style>
        <div style={{ minHeight: "100vh", background: "#0b0b0c", color: "#ececee", fontFamily: "'Helvetica Neue', Helvetica, Arial, system-ui, sans-serif", fontSize: `${v.fs}px`, lineHeight: "1.45", padding: "18px 20px 40px" }}><div style={{ maxWidth: "1440px", margin: "0 auto" }}><header style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "14px 22px", paddingBottom: "16px", borderBottom: "1px solid #26262b" }}><img src={ART.zknox} alt="ZKNOX" style={{ height: "34px", width: "auto", display: "block" }} /><div style={{ display: "flex", alignItems: "center", gap: "10px", paddingLeft: "20px", borderLeft: "1px solid #2c2c33" }}><div><div style={{ fontSize: "17px", fontWeight: "600", letterSpacing: "-0.01em" }}>{v.title}</div><div style={{ fontSize: "13px", color: "#8f8f99" }}>{v.subtitle}</div></div></div><div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "10px", marginLeft: "auto" }}><div role="tablist" aria-label="Account" style={{ display: "flex", gap: "2px", padding: "3px", borderRadius: "999px", background: "#15151a", border: "1px solid #26262b" }}>{v.tabs.map((t: any, i_t: number) => (<React.Fragment key={i_t}><button role="tab" onClick={t.onSelect} style={{ display: "flex", alignItems: "center", gap: "7px", padding: "6px 13px", border: "0", borderRadius: "999px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: "pointer", whiteSpace: "nowrap", background: `${t.bg}`, color: `${t.fg}` }}><span style={{ width: "8px", height: "8px", borderRadius: "999px", background: `${t.color}`, boxShadow: "inset 0 0 0 1px rgba(0,0,0,0.28)" }}></span>{t.label}
            </button></React.Fragment>))}</div><select aria-label="Network" value={v.net} onChange={v.on.net} style={{ appearance: "none", padding: "7px 14px", borderRadius: "999px", background: "#15151a", border: "1px solid #26262b", color: "#d6d6db", fontFamily: "inherit", fontSize: "13px", cursor: "pointer" }}>{v.netOptions.map((n: any, i_n: number) => (<React.Fragment key={i_n}><option value={n.id}>{n.name}</option></React.Fragment>))}</select><div style={{ paddingLeft: "14px", borderLeft: "1px solid #2c2c33", fontSize: "13px", color: "#8f8f99" }}>
          Total <span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", color: "#ececee", fontSize: "14px" }}>{v.totalEth} ETH</span></div></div></header>{v.banner && (<><div style={{ marginTop: "12px", padding: "8px 13px", borderRadius: "8px", background: "#15151a", border: "1px solid #33333a", fontSize: "13px", color: "#b9b9c2", animation: "pqbanner 3.6s ease forwards", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>{v.banner}</div></>)}<div style={{ display: "grid", gap: "14px", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", marginTop: "16px", alignItems: "stretch" }}><section data-screen-label="Public" onClick={v.on.pickPublic} className={v.sel.public.cls} style={{ position: "relative", borderRadius: "12px", overflow: "hidden", background: "#f7f7f8", border: `1px solid ${v.sel.public.bd}`, boxShadow: `${v.sel.public.sh}`, transform: `${v.sel.public.tf}`, transition: "transform 240ms ease, box-shadow 240ms ease" }}>{v.sel.public.shine && <div className="pq-sheen" aria-hidden="true" />}<div style={{ height: `${v.stripe}px`, background: "#CE1126" }}></div><div style={{ padding: `${v.pad}px` }}><div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}><img src={ART.cards.public} alt="" style={{ height: "185px", width: "auto", borderRadius: "8px", display: "block", flexShrink: "0" }} /><div style={{ minWidth: "0", flex: "1" }}><div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}><h2 style={{ margin: "0", fontSize: "15px", fontWeight: "600", letterSpacing: "0.02em", textTransform: "uppercase", color: "#16161a" }}>Public account</h2>{v.linkedPill && (<><span style={{ padding: "2px 8px", borderRadius: "999px", background: "#efe7ff", border: "1px solid #cbb6ff", color: "#4c1d95", fontSize: "11.5px", whiteSpace: "nowrap" }}>{v.linkedPill}</span></>)}</div><button onClick={v.on.copyEoa} title="Copy the address" style={{ marginTop: "4px", padding: "3px 7px", borderRadius: "5px", background: "#ffffff", border: "1px solid #d6d6dd", color: "#3d3d47", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", cursor: "pointer" }}>{v.eoaShort} {v.copiedEoa}</button><div style={{ marginTop: "14px", display: "flex", alignItems: "baseline", gap: "9px", flexWrap: "wrap" }}><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "32px", fontWeight: "300", letterSpacing: "-0.02em", color: "#0f0f12" }}>{v.pubEth}</div><div style={{ fontSize: "14px", color: "#6b6b76" }}>ETH</div>{v.delta.public && (<><div style={{ padding: "2px 8px", borderRadius: "999px", background: "#efe7ff", color: "#5b21b6", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", animation: "pqchip 1.8s ease forwards" }}>{v.delta.public}</div></>)}</div><div style={{ marginTop: "3px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13px", color: "#6b6b76" }}>nonce {v.pubNonce}</div>{v.pubTokens.map((t: any, i_t2: number) => (<div key={i_t2} style={{ marginTop: "2px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13px", color: t.fg }}>{t.amount} {t.symbol}</div>))}</div></div><p style={{ margin: "12px 0 0", fontSize: "13.5px", color: "#4b4b55", textWrap: "pretty" }}>{v.pubNote}</p><div style={{ display: "flex", flexWrap: "wrap", gap: "7px", marginTop: "16px" }}><button disabled={v.b.receive.disabled} title={v.b.receive.title} onClick={v.b.receive.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.receive.cur}`, background: `${v.b.receive.bg}`, color: `${v.b.receive.fg}`, border: `1px solid ${v.b.receive.bd}` }}>Receive</button><button disabled={v.b.eoaSend.disabled} title={v.b.eoaSend.title} onClick={v.b.eoaSend.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.eoaSend.cur}`, background: `${v.b.eoaSend.bg}`, color: `${v.b.eoaSend.fg}`, border: `1px solid ${v.b.eoaSend.bd}` }}>Send</button><button disabled={v.b.shieldPub.disabled} title={v.b.shieldPub.title} onClick={v.b.shieldPub.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.shieldPub.cur}`, background: `${v.b.shieldPub.bg}`, color: `${v.b.shieldPub.fg}`, border: `1px solid ${v.b.shieldPub.bd}` }}>Shield</button><button disabled={v.b.link.disabled} title={v.b.link.title} onClick={v.b.link.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.link.cur}`, background: `${v.b.link.bg}`, color: `${v.b.link.fg}`, border: `1px solid ${v.b.link.bd}` }}>Link to vault</button><button disabled={v.b.protectPub.disabled} title={v.b.protectPub.title} onClick={v.b.protectPub.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.protectPub.cur}`, background: `${v.b.protectPub.bg}`, color: `${v.b.protectPub.fg}`, border: `1px solid ${v.b.protectPub.bd}` }}>Protect funds</button></div></div></section><section data-screen-label="Private" onClick={v.on.pickPrivate} className={v.sel.private.cls} style={{ position: "relative", borderRadius: "12px", overflow: "hidden", background: "#f7f7f8", border: `1px solid ${v.sel.private.bd}`, boxShadow: `${v.sel.private.sh}`, transform: `${v.sel.private.tf}`, transition: "transform 240ms ease, box-shadow 240ms ease" }}>{v.sel.private.shine && <div className="pq-sheen" aria-hidden="true" />}<div style={{ height: `${v.stripe}px`, background: "#ffffff", boxShadow: "inset 0 -1px 0 #d8d8de" }}></div><div style={{ padding: `${v.pad}px` }}><div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}><img src={ART.cards.private} alt="" style={{ height: "185px", width: "auto", borderRadius: "8px", display: "block", flexShrink: "0" }} /><div style={{ minWidth: "0", flex: "1" }}><h2 style={{ margin: "0", fontSize: "15px", fontWeight: "600", letterSpacing: "0.02em", textTransform: "uppercase", color: "#16161a" }}>Private</h2><div style={{ marginTop: "5px", fontSize: "12px", color: "#6b6b76" }}>Shielded pools · Kohaku SDK</div><div style={{ marginTop: "14px", display: "flex", alignItems: "baseline", gap: "9px", flexWrap: "wrap" }}><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "32px", fontWeight: "300", letterSpacing: "-0.02em", color: "#0f0f12" }}>{v.privEth}</div><div style={{ fontSize: "14px", color: "#6b6b76" }}>ETH</div>{v.delta.private && (<><div style={{ padding: "2px 8px", borderRadius: "999px", background: "#efe7ff", color: "#5b21b6", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", animation: "pqchip 1.8s ease forwards" }}>{v.delta.private}</div></>)}</div></div></div><p style={{ margin: "12px 0 0", fontSize: "13.5px", color: "#4b4b55", textWrap: "pretty" }}>Withdrawals are proved on this device and relayed through the 4337 mempool — no relayer of your own.</p><div style={{ marginTop: "14px", display: "grid", gap: "1px", background: "#e4e4e9", border: "1px solid #e4e4e9", borderRadius: "8px", overflow: "hidden" }}>{v.pools.map((p: any, i_p: number) => (<React.Fragment key={i_p}><div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px", padding: "9px 11px", background: "#ffffff" }}><div style={{ minWidth: "0" }}><div style={{ fontSize: "13.5px", color: "#16161a" }}>{p.name}</div><div style={{ fontSize: "12px", color: "#6b6b76" }}>{p.note}</div></div><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13.5px", color: `${p.fg}`, whiteSpace: "nowrap" }}>{p.amount}</div></div></React.Fragment>))}</div><div style={{ display: "flex", flexWrap: "wrap", gap: "7px", marginTop: "16px" }}><button disabled={v.b.shield.disabled} title={v.b.shield.title} onClick={v.b.shield.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.shield.cur}`, background: `${v.b.shield.bg}`, color: `${v.b.shield.fg}`, border: `1px solid ${v.b.shield.bd}` }}>Shield</button><button disabled={v.b.unshield.disabled} title={v.b.unshield.title} onClick={v.b.unshield.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.unshield.cur}`, background: `${v.b.unshield.bg}`, color: `${v.b.unshield.fg}`, border: `1px solid ${v.b.unshield.bd}` }}>Unshield</button><button disabled={v.b.protectPriv.disabled} title={v.b.protectPriv.title} onClick={v.b.protectPriv.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.protectPriv.cur}`, background: `${v.b.protectPriv.bg}`, color: `${v.b.protectPriv.fg}`, border: `1px solid ${v.b.protectPriv.bd}` }}>Protect funds</button></div></div></section><section data-screen-label="Post-quantum vault" onClick={v.on.pickVault} className={v.sel.vault.cls} style={{ position: "relative", borderRadius: "12px", overflow: "hidden", background: "#f7f7f8", border: `1px solid ${v.sel.vault.bd}`, boxShadow: `${v.sel.vault.sh}`, transform: `${v.sel.vault.tf}`, transition: "transform 240ms ease, box-shadow 240ms ease" }}>{v.sel.vault.shine && <div className="pq-sheen" aria-hidden="true" />}<div style={{ height: `${v.stripe}px`, background: "#0055A4" }}></div><div style={{ padding: `${v.pad}px` }}><div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}><img src={ART.cards.vault} alt="" style={{ height: "185px", width: "auto", borderRadius: "8px", display: "block", flexShrink: "0" }} /><div style={{ minWidth: "0", flex: "1" }}><h2 style={{ margin: "0", fontSize: "15px", fontWeight: "600", letterSpacing: "0.02em", textTransform: "uppercase", color: "#16161a" }}>Post-quantum vault</h2>{v.hasVault && (<><button onClick={v.on.copyVault} title="Copy the address" style={{ marginTop: "4px", padding: "3px 7px", borderRadius: "5px", background: "#ffffff", border: "1px solid #d6d6dd", color: "#3d3d47", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", cursor: "pointer" }}>{v.vaultShort} {v.copiedVault}</button><div style={{ marginTop: "14px", display: "flex", alignItems: "baseline", gap: "9px", flexWrap: "wrap" }}><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "32px", fontWeight: "300", letterSpacing: "-0.02em", color: "#0f0f12" }}>{v.vaultEth}</div><div style={{ fontSize: "14px", color: "#6b6b76" }}>ETH</div>{v.delta.vault && (<><div style={{ padding: "2px 8px", borderRadius: "999px", background: "#efe7ff", color: "#5b21b6", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", animation: "pqchip 1.8s ease forwards" }}>{v.delta.vault}</div></>)}</div><div style={{ marginTop: "3px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12.5px", color: "#6b6b76" }}>EntryPoint nonce {v.epNonce} · relay nonce {v.pqNonce}</div>{v.vaultTokens.map((t: any, i_t3: number) => (<div key={i_t3} style={{ marginTop: "2px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12.5px", color: t.fg }}>{t.amount} {t.symbol}</div>))}</>)}{v.noVault && (<><div style={{ marginTop: "14px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "19px", fontWeight: "300", color: "#6b6b76" }}>{v.noVaultLine}</div></>)}</div></div>{v.hasVault && (<><div><p style={{ margin: "12px 0 0", fontSize: "13.5px", color: "#4b4b55", textWrap: "pretty" }}>{v.vaultNote}</p><div style={{ marginTop: "14px", display: "grid", gap: "8px", padding: "11px", borderRadius: "8px", background: "#ffffff", border: "1px solid #e4e4e9" }}>{v.vaultKeys.map((k: any, i_k: number) => (<React.Fragment key={i_k}><div><div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "12.5px", color: "#3d3d47" }}><span>{k.label}</span><span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>{k.bytes} B signature</span></div><div style={{ marginTop: "5px", height: "6px", borderRadius: "999px", background: "#e4e4e9", overflow: "hidden" }}><div style={{ height: "6px", borderRadius: "999px", width: `${k.pct}%`, background: `${k.color}` }}></div></div></div></React.Fragment>))}<div style={{ fontSize: "12px", color: "#6b6b76" }}>Both are required on every spend — no single key can move these funds.</div></div><div style={{ display: "flex", flexWrap: "wrap", gap: "7px", marginTop: "16px" }}><button disabled={v.b.vaultSend.disabled} title={v.b.vaultSend.title} onClick={v.b.vaultSend.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.vaultSend.cur}`, background: `${v.b.vaultSend.bg}`, color: `${v.b.vaultSend.fg}`, border: `1px solid ${v.b.vaultSend.bd}` }}>Send</button><button disabled={v.b.shieldVault.disabled} title={v.b.shieldVault.title} onClick={v.b.shieldVault.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.shieldVault.cur}`, background: `${v.b.shieldVault.bg}`, color: `${v.b.shieldVault.fg}`, border: `1px solid ${v.b.shieldVault.bd}` }}>Shield</button><button disabled={v.b.moveToPublic.disabled} title={v.b.moveToPublic.title} onClick={v.b.moveToPublic.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.moveToPublic.cur}`, background: `${v.b.moveToPublic.bg}`, color: `${v.b.moveToPublic.fg}`, border: `1px solid ${v.b.moveToPublic.bd}` }}>Move to public</button><button disabled={v.b.sendAsPublic.disabled} title={v.b.sendAsPublic.title} onClick={v.b.sendAsPublic.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.b.sendAsPublic.cur}`, background: `${v.b.sendAsPublic.bg}`, color: `${v.b.sendAsPublic.fg}`, border: `1px solid ${v.b.sendAsPublic.bd}` }}>Send as public</button></div></div></>)}{v.noVault && (<><div><p style={{ margin: "12px 0 0", fontSize: "13.5px", color: "#4b4b55", textWrap: "pretty" }}>A separate account whose funds need a post-quantum signature in addition to your usual key.</p><div style={{ marginTop: "14px", padding: "11px", borderRadius: "8px", background: "#ffffff", border: "1px solid #e4e4e9", fontSize: "12.5px", color: "#3d3d47", display: "grid", gap: "5px" }}><div>Creation costs <span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", color: "#16161a" }}>{v.createGas}</span>.</div><div>The scheme is written into the account at creation and cannot be changed afterwards.</div></div><div style={{ display: "flex", flexWrap: "wrap", gap: "7px", marginTop: "16px" }}><button onClick={v.b.createVault.on} style={{ padding: "8px 12px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: "pointer", background: `${v.b.createVault.bg}`, color: `${v.b.createVault.fg}`, border: `1px solid ${v.b.createVault.bd}` }}>Create vault</button></div></div></>)}</div></section></div><section style={{ marginTop: "18px", border: "1px solid #e4e4e9", borderRadius: "12px", background: "#f7f7f8", overflow: "hidden" }}><div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "10px", padding: "12px 16px", borderBottom: "1px solid #e4e4e9" }}><h2 style={{ margin: "0", fontSize: "13px", fontWeight: "600", letterSpacing: "0.06em", textTransform: "uppercase", color: "#3d3d47" }}>Activity</h2><div style={{ display: "flex", flexWrap: "wrap", gap: "5px", marginLeft: "auto" }}>{v.filters.map((f: any, i_f: number) => (<React.Fragment key={i_f}><button onClick={f.onSelect} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "5px 11px", borderRadius: "999px", fontFamily: "inherit", fontSize: "12.5px", cursor: "pointer", background: `${f.bg}`, color: `${f.fg}`, border: `1px solid ${f.bd}` }}><span style={{ width: "7px", height: "7px", borderRadius: "999px", background: `${f.dot}`, boxShadow: "inset 0 0 0 1px rgba(0,0,0,0.28)" }}></span>{f.label}
            </button></React.Fragment>))}</div></div>{v.hasActivity && (<><div style={{ display: "grid" }}>{v.log.map((a: any, i_a: number) => (<React.Fragment key={i_a}><div style={{ display: "grid", gridTemplateColumns: "78px 10px minmax(0, 1fr)", gap: "12px", alignItems: "stretch", padding: "11px 16px", borderTop: "1px solid #eaeaef" }}><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12.5px", color: "#6b6b76" }}>{a.time}</div><div style={{ width: "8px", height: "8px", marginTop: "5px", borderRadius: "999px", background: `${a.color}`, boxShadow: "inset 0 0 0 1px rgba(0,0,0,0.28)" }}></div><div style={{ minWidth: "0" }}><div style={{ fontSize: "13.5px", color: "#16161a" }}>{a.title}</div><div style={{ fontSize: "12.5px", color: "#4b4b55", marginTop: "1px" }}>{a.detail}</div>{a.gasText && (<><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "12px", color: "#6b6b76", marginTop: "3px" }}>{a.gasText}</div></>)}</div></div></React.Fragment>))}</div></>)}{v.noActivity && (<><div style={{ padding: "16px", fontSize: "13px", color: "#6b6b76" }}>Nothing on {v.netName} yet.</div></>)}</section><footer style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px 18px", marginTop: "18px", fontSize: "12px", color: "#7c7c86" }}><span style={{ color: "#c9aefc" }}>ZKNOX</span><span>Simulation, no network. Vault gas is measured by the contract tests (EntryPoint v0.8); pool figures are typical.</span><span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>{v.netName} · chain {v.chainId} · satellite {v.satelliteShort}</span><span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "10px" }}><a href="https://zknox.com">zknox.com</a><img src={ART.kohaku} alt="Kohaku" style={{ height: "26px", width: "auto", display: "block" }} /></span></footer></div>{v.modalOpen && (<><div onClick={v.on.close} style={{ position: "fixed", inset: "0", zIndex: "40", display: "flex", alignItems: "flex-start", justifyContent: "center", padding: "20px", background: "rgba(4, 4, 6, 0.72)", overflow: "auto" }}><div role="dialog" aria-modal="true" ref={v.dialogRef} onClick={v.on.stop} onKeyDown={v.on.trap} style={{ position: "relative", width: "100%", maxWidth: "520px", margin: "auto", padding: "22px", borderRadius: "14px", background: "#101014", border: "1px solid #33333a", boxShadow: "0 24px 80px rgba(0, 0, 0, 0.7)" }}><button onClick={v.on.close} aria-label="Close" style={{ position: "absolute", top: "12px", right: "12px", width: "28px", height: "28px", borderRadius: "7px", background: "#1c1c21", border: "1px solid #33333a", color: "#b9b9c2", fontFamily: "inherit", fontSize: "14px", cursor: "pointer" }}>×</button><h3 style={{ margin: "0 34px 0 0", fontSize: "17px", fontWeight: "600", color: "#ffffff" }}>{v.form.title}</h3>{v.form.blurb && (<><p style={{ margin: "7px 0 0", fontSize: "13px", color: "#a8a8b2", textWrap: "pretty" }}>{v.form.blurb}</p></>)}{v.form.hasGains && (<><div style={{ marginTop: "14px", display: "grid", gap: "8px", padding: "12px", borderRadius: "10px", background: "#17171b", border: "1px solid #26262b" }}><div style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>What the link unlocks</div>{v.form.gains.map((x: any, i_x: number) => (<React.Fragment key={i_x}><div style={{ display: "grid", gridTemplateColumns: "8px minmax(0, 1fr)", gap: "9px", alignItems: "start" }}><div style={{ width: "6px", height: "6px", marginTop: "6px", borderRadius: "999px", background: "#7c3aed" }}></div><div style={{ minWidth: "0" }}><div style={{ fontSize: "13px", color: "#ececee" }}>{x.label}</div><div style={{ fontSize: "12.5px", color: "#a8a8b2" }}>{x.detail}</div></div></div></React.Fragment>))}<div style={{ fontSize: "12px", color: "#8f8f99", marginTop: "2px" }}>Nothing moves now — this is a wiring step, not a transfer.</div></div></>)}{v.form.groups.map((g: any, i_g: number) => (<React.Fragment key={i_g}><div style={{ marginTop: "16px" }}><div style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>{g.label}</div><div style={{ display: "grid", gap: "6px", marginTop: "7px" }}>{g.options.map((o: any, i_o: number) => (<React.Fragment key={i_o}><button disabled={o.disabled} title={o.title} onClick={o.onSelect} style={{ textAlign: "left", padding: "9px 11px", borderRadius: "8px", fontFamily: "inherit", fontSize: "13px", cursor: `${o.cur}`, background: `${o.bg}`, color: `${o.fg}`, border: `1px solid ${o.bd}` }}><span style={{ fontWeight: "500" }}>{o.label}</span><span style={{ color: `${o.metaFg}`, marginLeft: "8px" }}>{o.meta}</span></button></React.Fragment>))}</div></div></React.Fragment>))}{v.form.showTo && (<><label style={{ display: "block", marginTop: "16px" }}><span style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>Recipient</span><input value={v.form.to} onChange={v.on.toChange} placeholder="0x…" style={{ display: "block", width: "100%", boxSizing: "border-box", marginTop: "7px", padding: "9px 11px", borderRadius: "8px", background: "#17171b", border: "1px solid #33333a", color: "#ececee", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13px" }} /></label></>)}{v.form.fixedTo && (<><div style={{ marginTop: "16px" }}><div style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>Recipient</div><div style={{ marginTop: "5px", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13px", color: "#ececee" }}>{v.form.fixedTo}</div></div></>)}{v.form.amountLabel && (<><label style={{ display: "block", marginTop: "16px" }}><span style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>{v.form.amountLabel}</span><input value={v.form.amount} onChange={v.on.amountChange} inputMode="decimal" style={{ display: "block", width: "100%", boxSizing: "border-box", marginTop: "7px", padding: "9px 11px", borderRadius: "8px", background: "#17171b", border: "1px solid #33333a", color: "#ececee", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "13px" }} /></label></>)}<div style={{ marginTop: "18px", padding: "13px", borderRadius: "10px", background: "#17171b", border: "1px solid #26262b" }}><div style={{ fontSize: "12px", letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" }}>What gets signed</div><div style={{ display: "grid", gap: "9px", marginTop: "10px" }}>{v.form.steps.map((s: any, i_s: number) => (<React.Fragment key={i_s}><div style={{ display: "grid", gridTemplateColumns: "16px minmax(0, 1fr)", gap: "9px", alignItems: "start" }}><div style={{ width: "15px", height: "15px", marginTop: "2px", borderRadius: "999px", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "10px", color: `${s.tickFg}`, background: `${s.tickBg}`, border: `1px solid ${s.tickBd}` }}>{s.tick}</div><div style={{ minWidth: "0" }}><div style={{ fontSize: "13px", color: `${s.fg}` }}>{s.label}</div>{s.bytes && (<><div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}><div style={{ flex: "1", height: "7px", borderRadius: "999px", background: "#26262b", overflow: "hidden" }}><div style={{ height: "7px", borderRadius: "999px", width: `${s.pct}%`, background: `${s.barColor}` }}></div></div><div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "11.5px", color: "#b9b9c2", whiteSpace: "nowrap" }}>{s.bytes} B</div></div></>)}</div></div></React.Fragment>))}</div><div style={{ marginTop: "12px", paddingTop: "10px", borderTop: "1px solid #26262b", fontSize: "12.5px", color: "#b9b9c2", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>{v.form.gasText}</div></div>{v.form.err && (<><div style={{ marginTop: "12px", padding: "9px 11px", borderRadius: "8px", background: "#2a1113", border: "1px solid #5c1d22", color: "#ff9ea6", fontSize: "13px" }}>{v.form.err}</div></>)}<div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "18px" }}><button onClick={v.on.close} style={{ padding: "9px 14px", borderRadius: "8px", background: "#1c1c21", border: "1px solid #33333a", color: "#d6d6db", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: "pointer" }}>Cancel</button><button disabled={v.form.busy} onClick={v.on.submit} style={{ padding: "9px 16px", borderRadius: "8px", background: `${v.form.submitBg}`, border: "1px solid #7c3aed", color: "#ffffff", fontFamily: "inherit", fontSize: "13px", fontWeight: "500", cursor: `${v.form.submitCur}` }}>{v.form.submitLabel}</button></div></div></div></>)}</div>
      </>
    );
  }
}

export default Wallet;
