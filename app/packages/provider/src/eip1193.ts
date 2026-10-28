// The EIP-1193 plumbing the provider needs and nothing more: a request type, a typed error, a JSON-RPC
// transport over fetch, a payer around any EIP-1193 wallet, and EIP-6963 discovery of the wallets a browser
// has installed.
import { getAddress, toHex, type Address, type Hex } from "viem";
import type { Payer } from "./provider";

export type RequestArgs = { method: string; params?: unknown[] | object };
export type Eip1193 = { request(args: RequestArgs): Promise<unknown> };

/** EIP-1193 error codes: 4001 rejected, 4100 unauthorized, 4200 unsupported, 4902 unknown chain. */
export class Eip1193Error extends Error {
  constructor(readonly code: number, message: string, readonly data?: unknown) {
    super(message);
    this.name = "Eip1193Error";
  }
}

/** A JSON-RPC endpoint as an EIP-1193 provider. Errors keep the node's `data`, which holds revert bytes. */
export function httpRpc(url: string, fetchImpl: typeof fetch = fetch): Eip1193 {
  let id = 0;
  return {
    async request({ method, params }) {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params: params ?? [] }),
      });
      if (!res.ok) throw new Eip1193Error(-32603, `${method}: HTTP ${res.status} from ${url}`);
      const body = (await res.json()) as { result?: unknown; error?: { code: number; message: string; data?: unknown } };
      if (body.error) throw new Eip1193Error(body.error.code, body.error.message, body.error.data);
      return body.result;
    },
  };
}

/** Any EIP-1193 wallet as the payer: asks for its account, moves it to the right chain, sends. */
export function eip1193Payer(wallet: Eip1193, chainId: number): Payer {
  let cached: Address | undefined;
  const ensureChain = async () => {
    const current = Number(await wallet.request({ method: "eth_chainId" }));
    if (current !== chainId) {
      await wallet.request({ method: "wallet_switchEthereumChain", params: [{ chainId: toHex(chainId) }] });
    }
  };
  return {
    async address() {
      if (cached) return cached;
      const accounts = (await wallet.request({ method: "eth_requestAccounts" })) as string[];
      if (!accounts?.length) throw new Eip1193Error(4100, "the paying wallet exposes no account");
      cached = getAddress(accounts[0]!);
      return cached;
    },
    async send({ to, data, gas }) {
      await ensureChain();
      const from = await this.address();
      return (await wallet.request({
        method: "eth_sendTransaction",
        params: [{ from, to, data, gas: toHex(gas) }],
      })) as Hex;
    },
  };
}

export type InjectedWallet = { info: { uuid: string; name: string; icon: string; rdns: string }; provider: Eip1193 };

/** EIP-6963: every wallet extension announces itself on request. Browser only; resolves to [] elsewhere. */
export function discoverInjected(waitMs = 300): Promise<InjectedWallet[]> {
  const w = (globalThis as { window?: Window }).window;
  if (!w) return Promise.resolve([]);
  const found = new Map<string, InjectedWallet>();
  const onAnnounce = (e: Event) => {
    const d = (e as CustomEvent<InjectedWallet>).detail;
    if (d?.info?.uuid) found.set(d.info.uuid, d);
  };
  w.addEventListener("eip6963:announceProvider", onAnnounce);
  w.dispatchEvent(new Event("eip6963:requestProvider"));
  return new Promise((resolve) =>
    setTimeout(() => {
      w.removeEventListener("eip6963:announceProvider", onAnnounce);
      resolve([...found.values()]);
    }, waitMs),
  );
}
