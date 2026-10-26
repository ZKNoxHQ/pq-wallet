// Configuration and chain state for one signing session.
//
// Everything is addressable: the root, the children and the chain come from the URL or the environment, so
// a link is enough to put several holders in front of the same transaction. Nothing secret travels that way
// — a holder's seed is only ever read from the environment of a development build, and a hardware holder
// gives nothing to the page at all.
import {
  createPublicClient, defineChain, getAddress, http, isAddress, isHex,
  type Address, type Chain, type Hex, type PublicClient, type Transport,
} from "viem";
import { arbitrum, foundry, mainnet, sepolia } from "viem/chains";
import {
  checkNestedPolicy, readApprovals, readPqOwners, readSafe, serviceFor, seedSigner,
  type PqOwnerInfo, type SafeInfo, type Signer,
} from "@zknox/pq-safe";

export const CHAINS = { 1: mainnet, 11155111: sepolia, 31337: foundry, 42161: arbitrum } as const;

export type Config = {
  chainId: number;
  /** empty inside Safe{Wallet}: the host proxies the RPC and nobody types a URL */
  rpcUrl: string;
  root: Address;
  sEcdsa: Address;
  sPq: Address;
  k: number;
  lens?: Address;
  pqImplementation?: Address;
  serviceApiKey?: string;
};

const env = import.meta.env as Record<string, string | undefined>;

const addr = (v?: string | null): Address | undefined =>
  v && isAddress(v, { strict: false }) ? getAddress(v) : undefined;

/** An RPC URL for this chain, if the build was given one. Inside Safe{Wallet} the reads go through the
 *  host and this stays empty; it matters only for the last step, where a relayer has to broadcast and the
 *  host offers no way to. */
export const rpcUrlFor = (chainId: number): string => env[`VITE_RPC_URL_${chainId}`] ?? "";

/** URL first, then the build's environment. A pasted link wins so one holder can be sent exactly the
 *  arrangement another is looking at. */
export function initialConfig(): Partial<Config> {
  const q = new URLSearchParams(location.search);
  const pick = (name: string) => q.get(name) ?? env[`VITE_${name.toUpperCase()}`];
  const chainId = Number(pick("chainId") ?? pick("chain_id") ?? 11155111);
  return {
    chainId,
    rpcUrl: q.get("rpc") ?? env[`VITE_RPC_URL_${chainId}`] ?? "",
    root: addr(pick("root")),
    sEcdsa: addr(pick("sEcdsa") ?? pick("s_ecdsa")),
    sPq: addr(pick("sPq") ?? pick("s_pq")),
    k: Number(pick("k") ?? 2),
    lens: addr(pick("lens")),
    pqImplementation: addr(pick("pqImplementation") ?? pick("pq_implementation")),
    serviceApiKey: env.VITE_SAFE_API_KEY,
  };
}

/** The config, as a link to pass to the other holders. */
export function shareLink(c: Config, rootSafeTxHash?: Hex): string {
  const q = new URLSearchParams({
    chainId: String(c.chainId), root: c.root, sEcdsa: c.sEcdsa, sPq: c.sPq, k: String(c.k),
  });
  if (c.lens) q.set("lens", c.lens);
  if (c.pqImplementation) q.set("pqImplementation", c.pqImplementation);
  if (rootSafeTxHash) q.set("hash", rootSafeTxHash);
  return `${location.origin}${location.pathname}?${q}`;
}

/** `hosted` means a Safe App host supplies the transport, so no RPC URL is needed or wanted. */
export const isComplete = (c: Partial<Config>, hosted = false): c is Config =>
  !!c.root && !!c.sEcdsa && !!c.sPq && !!c.chainId && !!c.k && (hosted || !!c.rpcUrl);

/** A chain this app has never heard of is still usable: only the id and the EIP-1559 defaults matter here,
 *  and inside Safe{Wallet} the host decides which chain we are on. */
export const chainFor = (chainId: number): Chain =>
  CHAINS[chainId as keyof typeof CHAINS] ??
  defineChain({
    id: chainId,
    name: `chain ${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [] } },
  });

export const clientFor = (c: Config, transport?: Transport): PublicClient =>
  createPublicClient({
    chain: chainFor(c.chainId),
    transport: transport ?? http(c.rpcUrl),
  }) as PublicClient;

export type Loaded = {
  root: SafeInfo;
  sEcdsa: SafeInfo;
  sPq: SafeInfo;
  owners: PqOwnerInfo[];
  /** null when no lens address was given: the policy was not checked, which is worth saying */
  violations: string[] | null;
};

export async function load(client: PublicClient, c: Config): Promise<Loaded> {
  const [root, sEcdsa, sPq] = await Promise.all([
    readSafe(client, c.root), readSafe(client, c.sEcdsa), readSafe(client, c.sPq),
  ]);
  const [owners, violations] = await Promise.all([
    readPqOwners(client, sPq.owners, c.lens, c.pqImplementation),
    c.lens && c.pqImplementation
      ? checkNestedPolicy(client, c.lens, { ...c, pqImplementation: c.pqImplementation })
      : Promise.resolve(null),
  ]);
  return { root, sEcdsa, sPq, owners, violations };
}

/** Which of the root's two owners have already approved the hash. */
export const approvals = (client: PublicClient, c: Config, hash: Hex) =>
  readApprovals(client, c.root, [c.sEcdsa, c.sPq], hash);

export const service = (c: Config) => serviceFor(c.chainId, c.serviceApiKey);

/** Software holders, for a demo without hardware: `VITE_HOLDER_SEEDS=<64 hex>,<64 hex>`. A seed in a
 *  browser bundle is not a key, it is a fixture — the variable exists so the flow can be shown end to end,
 *  and the screen says as much when it is set. */
export function devSigners(): Signer[] {
  const raw = env.VITE_HOLDER_SEEDS;
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^(0x)?[0-9a-fA-F]{64}$/.test(s))
    .map((s, i) => {
      const hex = (s.startsWith("0x") ? s : `0x${s}`) as Hex;
      if (!isHex(hex)) throw new Error("a holder seed is 32 bytes of hex");
      const bytes = new Uint8Array(32);
      for (let b = 0; b < 32; b++) bytes[b] = parseInt(hex.slice(2 + b * 2, 4 + b * 2), 16);
      return seedSigner(bytes, `holder ${i + 1}`);
    });
}
