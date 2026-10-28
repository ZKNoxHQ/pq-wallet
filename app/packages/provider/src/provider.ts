// An EIP-1193 provider whose account is a ZKNOX_PQAccount7702 clone.
//
// Any dapp that knows how to drive a contract wallet through `eth_sendTransaction` can then drive a
// post-quantum account without knowing it is one. That is exactly what Safe{Wallet} does for a contract
// owner: it asks the connected wallet to send `safe.approveHash(h)` (`dispatchOnChainSigning`), and for a
// nested Safe it proposes the parent transaction and asks for the same call
// (`nested-safe-wallet.ts`). Here that request becomes
//
//   clone.executeWithHybridSig([{ to, value, data }], deadline, hybridSignature)
//
// signed by the holder (the ECML-Signer device, or a software holder in tests) and paid by a separate
// wallet. The clone is `msg.sender` of the inner call, so the Safe records the clone's approval and the
// Transaction Service indexes it as an ordinary 65-byte confirmation of that owner.
//
// What it refuses: every off-chain signature method. A clone's ERC-1271 signature is 41.8 kB and the
// Transaction Service caps a confirmation at 5,000 bytes, so there is no off-chain path to offer.
import {
  decodeErrorResult, decodeFunctionResult, encodeFunctionData, getAddress, isAddressEqual, keccak256,
  recoverAddress, toHex, type Address, type Hex,
} from "viem";
import { hybridPayload, type PqAnswer, type Signer } from "@zknox/pq-safe";
import { pqRelayAbi } from "./abi";
import { executeData, hashExecute, type Call } from "./execute";
import { Eip1193Error, type Eip1193, type RequestArgs } from "./eip1193";

/** Whoever pays for the relayed transaction. The holder authorizes; this account only carries it. */
export type Payer = {
  address(): Promise<Address>;
  send(tx: { to: Address; data: Hex; gas: bigint }): Promise<Hex>;
};

/** What the page shows while a request is in flight. `sign` comes before the device asks anything: it is
 *  the moment to display the digest the holder will compare. */
export type PqStep =
  | { kind: "sign"; account: Address; digest: Hex; calls: readonly Call[]; nonce: bigint; deadline: bigint }
  | { kind: "signed"; account: Address; digest: Hex }
  | { kind: "estimate"; account: Address; payer: Address; gas: bigint; calldataBytes: number }
  | { kind: "sent"; account: Address; hash: Hex };

export type PqProviderOptions = {
  /** the clone */
  account: Address;
  chainId: number;
  /** reads, estimates and receipts; never asked to sign */
  rpc: Eip1193;
  holder: Signer;
  payer: Payer;
  /** seconds between the latest block and the signature's deadline */
  ttlSeconds?: number;
  /** percent added to the payer's estimate */
  gasMarginPercent?: number;
  onStep?: (step: PqStep) => void;
};

export type PqProvider = Eip1193 & {
  readonly account: Address;
  readonly chainId: number;
  on(event: string, listener: (...args: unknown[]) => void): PqProvider;
  removeListener(event: string, listener: (...args: unknown[]) => void): PqProvider;
};

const OFF_CHAIN = new Set([
  "personal_sign",
  "eth_sign",
  "eth_signTypedData",
  "eth_signTypedData_v3",
  "eth_signTypedData_v4",
  "eth_signTransaction",
]);

/** Errors a relayed call can revert with, decoded so the page can say which. */
const REVERTS = [
  ...pqRelayAbi.filter((x) => x.type === "error"),
  { type: "error", name: "Error", inputs: [{ type: "string" }] },
] as const;

export function createPqProvider(opts: PqProviderOptions): PqProvider {
  const account = getAddress(opts.account);
  const { chainId, rpc, holder, payer } = opts;
  const ttl = BigInt(opts.ttlSeconds ?? 1800);
  const margin = BigInt(opts.gasMarginPercent ?? 25);
  const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  const step = (s: PqStep) => opts.onStep?.(s);

  const ethCall = async (data: Hex): Promise<Hex> =>
    (await rpc.request({ method: "eth_call", params: [{ to: account, data }, "latest"] })) as Hex;

  async function relay(tx: { from?: string; to?: string; value?: string; data?: string }): Promise<Hex> {
    if (!tx.from || !isAddressEqual(getAddress(tx.from), account)) {
      throw new Eip1193Error(4100, `this provider sends as ${account} only, not ${tx.from ?? "an unnamed sender"}`);
    }
    if (!tx.to) throw new Eip1193Error(-32602, "a post-quantum account cannot deploy a contract by itself");
    const calls: Call[] = [{ target: getAddress(tx.to), value: BigInt(tx.value ?? 0), data: (tx.data ?? "0x") as Hex }];

    const readNonce = async () =>
      decodeFunctionResult({
        abi: pqRelayAbi,
        functionName: "pqNonce",
        data: await ethCall(encodeFunctionData({ abi: pqRelayAbi, functionName: "pqNonce" })),
      });
    const readKeyHashes = async () =>
      decodeFunctionResult({
        abi: pqRelayAbi,
        functionName: "keyHashes",
        data: await ethCall(encodeFunctionData({ abi: pqRelayAbi, functionName: "keyHashes" })),
      });

    const [nonce, stored, block, mine] = await Promise.all([
      readNonce(),
      readKeyHashes(),
      rpc.request({ method: "eth_getBlockByNumber", params: ["latest", false] }) as Promise<{ timestamp: Hex }>,
      holder.keyHashes(),
    ]);
    // the cheapest place to find out the device account is not this clone's
    if (stored[0].toLowerCase() !== mine.preQKeyHash.toLowerCase() || stored[1].toLowerCase() !== mine.postQKeyHash.toLowerCase()) {
      throw new Eip1193Error(4100, `${holder.id} does not hold the keys of ${account}`);
    }

    const deadline = BigInt(block.timestamp) + ttl;
    const digest = hashExecute(account, chainId, calls, nonce, deadline);
    const onChain = (await ethCall(
      encodeFunctionData({ abi: pqRelayAbi, functionName: "hashExecute", args: [calls, nonce, deadline] }),
    )).toLowerCase();
    if (onChain !== digest.toLowerCase()) {
      // Either the clone is not what it claims, or the RPC lies about it. Signing in both cases would be
      // signing a value the holder cannot check.
      throw new Eip1193Error(-32603, `digest mismatch: computed ${digest}, the clone answers ${onChain}`);
    }

    step({ kind: "sign", account, digest, calls, nonce, deadline });
    const answer = await holder.sign(account, digest);
    await checkAnswer(answer, digest, mine);
    step({ kind: "signed", account, digest });

    const data = executeData(
      calls,
      deadline,
      hybridPayload(answer.k1Address, answer.k1Signature, answer.expandedKey, answer.pqSignature),
    );
    const from = getAddress(await payer.address());
    let estimate: bigint;
    try {
      estimate = BigInt((await rpc.request({ method: "eth_estimateGas", params: [{ from, to: account, data }] })) as Hex);
    } catch (err) {
      throw new Eip1193Error(-32603, `the relayed call would revert: ${revertReason(err)}`);
    }
    const gas = (estimate * (100n + margin)) / 100n;
    step({ kind: "estimate", account, payer: from, gas, calldataBytes: (data.length - 2) / 2 });

    const hash = await payer.send({ to: account, data, gas });
    step({ kind: "sent", account, hash });
    return hash;
  }

  const provider: PqProvider = {
    account,
    chainId,
    async request({ method, params }: RequestArgs): Promise<unknown> {
      const p = (Array.isArray(params) ? params : []) as unknown[];
      switch (method) {
        case "eth_accounts":
        case "eth_requestAccounts":
          return [account];
        case "eth_chainId":
          return toHex(chainId);
        case "net_version":
          return String(chainId);
        case "wallet_switchEthereumChain": {
          const wanted = Number((p[0] as { chainId?: string } | undefined)?.chainId);
          if (wanted === chainId) return null;
          throw new Eip1193Error(4902, `this post-quantum account is bound to chain ${chainId}; reconnect it on ${wanted}`);
        }
        case "eth_sendTransaction":
          return relay((p[0] ?? {}) as Parameters<typeof relay>[0]);
        default:
          if (OFF_CHAIN.has(method)) {
            throw new Eip1193Error(
              4200,
              `${method}: a post-quantum account signs on-chain only; its 41.8 kB signature does not fit any off-chain channel`,
            );
          }
          if (method.startsWith("wallet_")) throw new Eip1193Error(4200, `${method} is not supported`);
          return rpc.request({ method, params });
      }
    },
    on(event, listener) {
      (listeners.get(event) ?? listeners.set(event, new Set()).get(event)!).add(listener);
      return provider;
    },
    removeListener(event, listener) {
      listeners.get(event)?.delete(listener);
      return provider;
    },
  };
  return provider;
}

/** The answer is checked before anyone pays for it: the keys must be the clone's, and the k1 half must
 *  recover over the digest. The ML-DSA half is left to the estimate, which runs the verifier itself. */
async function checkAnswer(answer: PqAnswer, digest: Hex, mine: { preQKeyHash: Hex; postQKeyHash: Hex }) {
  if (keccak256(answer.k1Address).toLowerCase() !== mine.preQKeyHash.toLowerCase()) {
    throw new Eip1193Error(-32603, "the holder answered with another k1 key");
  }
  if (keccak256(answer.expandedKey).toLowerCase() !== mine.postQKeyHash.toLowerCase()) {
    throw new Eip1193Error(-32603, "the holder answered with another ML-DSA-65 key");
  }
  const signer = await recoverAddress({ hash: digest, signature: answer.k1Signature });
  if (!isAddressEqual(signer, answer.k1Address)) {
    throw new Eip1193Error(-32603, `the k1 half recovers to ${signer}, not ${answer.k1Address}`);
  }
}

function revertReason(err: unknown): string {
  const e = err as { data?: unknown; message?: string; cause?: { data?: unknown } };
  const data = (typeof e?.data === "string" ? e.data : typeof e?.cause?.data === "string" ? e.cause.data : undefined) as
    | Hex
    | undefined;
  if (data && data.length >= 10) {
    try {
      const d = decodeErrorResult({ abi: REVERTS, data });
      return d.args?.length ? `${d.errorName}(${d.args.join(", ")})` : d.errorName;
    } catch {
      return data;
    }
  }
  return e?.message ?? String(err);
}
