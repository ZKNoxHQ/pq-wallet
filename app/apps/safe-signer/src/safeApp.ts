// Running inside Safe{Wallet}, as a custom Safe App.
//
// Safe{Wallet} loads any URL that serves a manifest.json (Apps → My custom apps), with no review and no
// listing, and talks to it over postMessage. What that gives us:
//
//   sdk.safe.getInfo()      the Safe the user is looking at: address, chainId, owners, threshold, nonce,
//                           version, modules, fallback handler — the whole first block, for free
//   sdk.eth.call and co.    an RPC proxy through the host, so nobody types an RPC URL
//
// What it does not give us is a way to broadcast: `Eth` exposes call, getCode, getStorageAt,
// getTransactionCount, getEstimateGas and friends, and no `eth_sendRawTransaction`. The host's own
// `sendTransactions` would propose a transaction *from the Safe we are opened in*, which for S_pq is the
// very transaction we are trying to produce. So the signatures are collected here and the sending falls
// back to a wallet, a relayer key, or the file the user carries out (the iframe sandbox allows downloads).
// See the Send block.
import SafeAppsSDK, { type SafeInfoExtended } from "@safe-global/safe-apps-sdk";
import { custom, getAddress, hexToBigInt, numberToHex, type Address, type Hex, type PublicClient } from "viem";
import { pqAccountAbi, readSafe, safeAbi, type SafeInfo } from "@zknox/pq-safe";

export type SafeAppContext = { sdk: SafeAppsSDK; info: SafeInfoExtended };

/** True when this page is framed. Not proof that the parent is Safe{Wallet}: the handshake below is. */
export const isFramed = () => {
  try {
    return window.self !== window.top;
  } catch {
    return true; // cross-origin parent: framed
  }
};

/** Connects to the host, or resolves null when nobody answers. The SDK's own calls hang forever when the
 *  parent is not a Safe App host, so the timeout is what makes the standalone page still work in a frame. */
export async function connectSafeApp(timeoutMs = 2500): Promise<SafeAppContext | null> {
  if (!isFramed()) return null;
  const sdk = new SafeAppsSDK({ allowedDomains: [/.*/], debug: false });
  try {
    const info = (await Promise.race([
      sdk.safe.getInfo(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("no Safe host")), timeoutMs)),
    ])) as SafeInfoExtended;
    return { sdk, info };
  } catch {
    return null;
  }
}

/** A viem transport over the host's RPC proxy. Only the methods this app actually calls are mapped; an
 *  unmapped one throws by name rather than returning something plausible. */
export function safeAppTransport(ctx: SafeAppContext) {
  const { sdk, info } = ctx;
  return custom({
    async request({ method, params }: { method: string; params?: unknown }) {
      const p = (params ?? []) as unknown[];
      switch (method) {
        case "eth_chainId":
          return numberToHex(info.chainId);
        case "eth_call":
          return sdk.eth.call([p[0] as never, p[1] as string | undefined]);
        case "eth_getCode":
          return sdk.eth.getCode([p[0] as string, p[1] as string | undefined]);
        case "eth_getBalance":
          return sdk.eth.getBalance([p[0] as string, p[1] as string | undefined]);
        // eth_getStorageAt is deliberately absent: the SDK types its slot as a number, which cannot hold a
        // 32-byte slot. Nothing here reads storage directly — the lens does it on chain, inside a call.
        case "eth_getTransactionCount":
          return sdk.eth.getTransactionCount([p[0] as string, p[1] as string | undefined]);
        case "eth_estimateGas":
          return sdk.eth.getEstimateGas(p[0] as never);
        case "eth_gasPrice":
          return sdk.eth.getGasPrice();
        case "eth_getTransactionReceipt":
          return sdk.eth.getTransactionReceipt([p[0] as string]);
        case "eth_getTransactionByHash":
          return sdk.eth.getTransactionByHash([p[0] as string]);
        case "eth_blockNumber": {
          const block = await sdk.eth.getBlockByNumber(["latest"]);
          return numberToHex(BigInt((block as { number: number | string }).number));
        }
        default:
          throw new Error(`Safe App host does not proxy ${method}`);
      }
    },
  });
}

// ---- working out the arrangement from the Safe we were opened in ---------------------------------

export type Discovery =
  | { kind: "root"; root: Address; sEcdsa: Address; sPq: Address; k: number }
  | { kind: "sPq"; sPq: Address; k: number }
  | { kind: "unrelated"; reason: string };

const isSafe = async (client: PublicClient, address: Address): Promise<SafeInfo | null> => {
  try {
    return await readSafe(client, address);
  } catch {
    return null;
  }
};

/** A post-quantum clone answers `keyHashes()` with a non-zero post-quantum hash. Cheaper than the lens and
 *  it needs no deployment: the lens still runs later for the policy, this only sorts the two children. */
async function isPqOwned(client: PublicClient, owners: readonly Address[]): Promise<boolean> {
  if (owners.length === 0) return false;
  const results = await Promise.all(
    owners.map((address) =>
      client
        .readContract({ address, abi: pqAccountAbi, functionName: "keyHashes" })
        .then(([, postQ]) => postQ !== `0x${"00".repeat(32)}`)
        .catch(() => false),
    ),
  );
  return results.every(Boolean);
}

/** Which Safe is this, in a NESTED arrangement?
 *
 *  Opened on the root, everything follows: two owners, both Safes, and the one whose owners answer
 *  `keyHashes()` is S_pq. Opened on S_pq we know the child but not its parent — a Safe cannot be asked who
 *  owns it — so the root still has to come from the URL or be typed once. */
export async function discover(client: PublicClient, safeAddress: Address): Promise<Discovery> {
  const me = await isSafe(client, safeAddress);
  if (!me) return { kind: "unrelated", reason: "this address does not answer as a Safe" };

  if (me.owners.length === 2) {
    const [a, b] = await Promise.all(me.owners.map((o) => isSafe(client, o)));
    if (a && b) {
      const [aIsPq, bIsPq] = await Promise.all([isPqOwned(client, a.owners), isPqOwned(client, b.owners)]);
      if (aIsPq !== bIsPq) {
        const pq = aIsPq ? a : b;
        const ecdsa = aIsPq ? b : a;
        return { kind: "root", root: safeAddress, sEcdsa: ecdsa.address, sPq: pq.address, k: pq.threshold };
      }
      return {
        kind: "unrelated",
        reason: aIsPq
          ? "both children are owned by post-quantum clones"
          : "neither child is owned by post-quantum clones",
      };
    }
  }

  if (await isPqOwned(client, me.owners)) {
    return { kind: "sPq", sPq: safeAddress, k: me.threshold };
  }

  return {
    kind: "unrelated",
    reason:
      me.owners.length === 2
        ? "the two owners of this Safe are not both Safes"
        : `this Safe has ${me.owners.length} owners and none is a post-quantum clone`,
  };
}

/** The root's queue is not reachable from the SDK, so a transaction opened in Safe{Wallet} reaches this
 *  page by its hash. Safe{Wallet} passes the app URL through unchanged, so `?hash=` survives. */
export const hashFromUrl = (): Hex | null => {
  const h = new URLSearchParams(location.search).get("hash");
  return h && /^0x[0-9a-fA-F]{64}$/.test(h) ? (h as Hex) : null;
};

export const toAddress = (v: string): Address => getAddress(v);

/** `safeAbi` and `hexToBigInt` are re-exported for the few call sites that need them alongside this
 *  module, so the Safe App path imports one file. */
export { safeAbi, hexToBigInt };
