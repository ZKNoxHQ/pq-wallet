// Safe Transaction Service, read only.
//
// The front can work without it: paste the root's transaction fields, or its `safeTxHash` alone, and
// everything else is derived. The service is there so that a transaction already proposed in
// Safe{Wallet} can be picked up by its nonce instead of retyped — and so the front can say whether the
// ECDSA child has confirmed yet.
//
// Nothing is ever written here. The service refuses what we would want to write anyway: its confirmation
// endpoint caps a signature at 5,000 bytes (`SIGNATURE_LENGTH`, read from history/serializers.py on
// 2026-10-22), and one post-quantum owner's signature is 41,824. That cap is the reason the front assembles
// the transaction itself and sends it to an RPC. See safe/DECISIONS.md, ADR-010.
import { getAddress, type Address, type Hex } from "viem";
import type { SafeTx } from "./digests";

/** `https://api.safe.global/tx-service/{shortName}/api/v2`, with the key in `Authorization: Bearer`.
 *  A key in a browser bundle is a public key — fine for a demo, wrong for anything else, which is why the
 *  front also runs with the service switched off. */
export type ServiceConfig = { baseUrl?: string; shortName: string; apiKey?: string };

/** EIP-3770 short names, for the chains this repository deploys to. */
export const SHORT_NAME: Record<number, string> = {
  1: "eth",
  11155111: "sep",
  100: "gno",
  8453: "base",
  42161: "arb1",
  10: "oeth",
};

export const serviceFor = (chainId: number, apiKey?: string): ServiceConfig | null => {
  const shortName = SHORT_NAME[chainId];
  return shortName ? { shortName, apiKey } : null;
};

export type ProposedTx = {
  safeTxHash: Hex;
  tx: SafeTx;
  confirmations: Address[];
  confirmationsRequired: number;
  isExecuted: boolean;
  proposer?: Address;
  submissionDate?: string;
};

const base = (c: ServiceConfig) => `${c.baseUrl ?? "https://api.safe.global/tx-service"}/${c.shortName}/api/v2`;

async function get(c: ServiceConfig, path: string): Promise<unknown> {
  const res = await fetch(`${base(c)}${path}`, {
    headers: c.apiKey ? { Authorization: `Bearer ${c.apiKey}` } : {},
  });
  if (!res.ok) {
    const hint = res.status === 401 || res.status === 403 ? " (the Transaction Service needs an API key)" : "";
    throw new Error(`Safe Transaction Service: ${res.status} ${res.statusText}${hint}`);
  }
  return res.json();
}

// The service returns numbers as decimal strings and `data: null` for a plain transfer.
type RawTx = {
  safeTxHash: string; to: string; value: string; data: string | null; operation: number;
  safeTxGas: string; baseGas: string; gasPrice: string; gasToken: string | null;
  refundReceiver: string | null; nonce: string; isExecuted: boolean;
  confirmationsRequired: number | null; confirmations?: { owner: string }[];
  proposer?: string | null; submissionDate?: string;
};

const parse = (r: RawTx): ProposedTx => ({
  safeTxHash: r.safeTxHash as Hex,
  tx: {
    to: getAddress(r.to),
    value: BigInt(r.value),
    data: (r.data ?? "0x") as Hex,
    operation: r.operation === 1 ? 1 : 0,
    safeTxGas: BigInt(r.safeTxGas),
    baseGas: BigInt(r.baseGas),
    gasPrice: BigInt(r.gasPrice),
    gasToken: getAddress(r.gasToken ?? "0x0000000000000000000000000000000000000000"),
    refundReceiver: getAddress(r.refundReceiver ?? "0x0000000000000000000000000000000000000000"),
    nonce: BigInt(r.nonce),
  },
  confirmations: (r.confirmations ?? []).map((c) => getAddress(c.owner)),
  confirmationsRequired: r.confirmationsRequired ?? 0,
  isExecuted: r.isExecuted,
  proposer: r.proposer ? getAddress(r.proposer) : undefined,
  submissionDate: r.submissionDate,
});

/** The Safe's transactions that have not executed yet, newest nonce last. */
export async function pendingTransactions(c: ServiceConfig, safe: Address): Promise<ProposedTx[]> {
  const body = (await get(c, `/safes/${safe}/multisig-transactions/?executed=false&limit=20`)) as {
    results?: RawTx[];
  };
  return (body.results ?? []).map(parse).sort((a, b) => Number(a.tx.nonce - b.tx.nonce));
}

export async function transactionByHash(c: ServiceConfig, safeTxHash: Hex): Promise<ProposedTx> {
  return parse((await get(c, `/multisig-transactions/${safeTxHash}/`)) as RawTx);
}
