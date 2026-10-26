// Chain reads. Everything the front needs to show before anyone signs, in two multicalls.
//
// The digests themselves are computed locally (see digests.ts) and never read from here: a digest the front
// did not derive is a digest the signer cannot check. What the chain is asked for is state it alone knows —
// nonces, owners, thresholds, who has already approved — plus one confirmation that the locally computed
// `safeTxHash` matches what the Safe itself would return.
import { getAddress, type Address, type Hex, type PublicClient } from "viem";
import { ACCOUNT_KIND, decodeViolations, lensAbi, pqAccountAbi, safeAbi, type AccountKind } from "./abi";
import { fullTx, safeTxHash, type SafeTx } from "./digests";

export type SafeInfo = {
  address: Address;
  version: string;
  owners: Address[];
  threshold: number;
  nonce: bigint;
  domainSeparator: Hex;
};

export async function readSafe(client: PublicClient, address: Address): Promise<SafeInfo> {
  const safe = { address, abi: safeAbi } as const;
  const [version, owners, threshold, nonce, domainSeparator] = await Promise.all([
    client.readContract({ ...safe, functionName: "VERSION" }),
    client.readContract({ ...safe, functionName: "getOwners" }),
    client.readContract({ ...safe, functionName: "getThreshold" }),
    client.readContract({ ...safe, functionName: "nonce" }),
    client.readContract({ ...safe, functionName: "domainSeparator" }),
  ]);
  return {
    address,
    version,
    owners: owners.map((o) => getAddress(o)),
    threshold: Number(threshold),
    nonce,
    domainSeparator,
  };
}

/** True when the locally computed hash is the one the Safe would produce. The front refuses to show a
 *  digest until this holds: a mismatch means the Safe's version or domain is not what we assumed, and every
 *  digest below it would be wrong in a way no one could see. */
export async function confirmSafeTxHash(
  client: PublicClient, safe: Address, chainId: number, tx: SafeTx,
): Promise<{ local: Hex; onChain: Hex; agrees: boolean }> {
  const t = fullTx(tx);
  const onChain = await client.readContract({
    address: safe,
    abi: safeAbi,
    functionName: "getTransactionHash",
    args: [t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver, t.nonce],
  });
  const local = safeTxHash(safe, chainId, tx);
  return { local, onChain, agrees: local.toLowerCase() === onChain.toLowerCase() };
}

/** Which owners of the root have already called `approveHash`, so the front knows what is left. */
export async function readApprovals(
  client: PublicClient, root: Address, owners: readonly Address[], hash: Hex,
): Promise<Record<Address, boolean>> {
  const results = await Promise.all(
    owners.map((owner) =>
      client.readContract({ address: root, abi: safeAbi, functionName: "approvedHashes", args: [owner, hash] }),
    ),
  );
  return Object.fromEntries(owners.map((o, i) => [o, results[i] > 0n])) as Record<Address, boolean>;
}

export type PqOwnerInfo = {
  address: Address;
  kind: AccountKind | "unknown";
  initialized: boolean;
  preQKeyHash: Hex;
  postQKeyHash: Hex;
};

/** The post-quantum owners of S_pq, as the front lists them. `keyHashes` is what matters: the account
 *  stores only `keccak256` of each key, and a signer whose expanded key does not hash to `postQKeyHash`
 *  will be rejected on chain — the front can say so before the device is even touched. */
export async function readPqOwners(
  client: PublicClient, owners: readonly Address[], lens?: Address, pqImplementation?: Address,
): Promise<PqOwnerInfo[]> {
  return Promise.all(
    owners.map(async (address) => {
      const [keys, initialized, kind] = await Promise.all([
        client
          .readContract({ address, abi: pqAccountAbi, functionName: "keyHashes" })
          .catch(() => ["0x", "0x"] as const),
        client.readContract({ address, abi: pqAccountAbi, functionName: "isInitialized" }).catch(() => false),
        lens && pqImplementation
          ? client
              .readContract({ address: lens, abi: lensAbi, functionName: "classify", args: [address, pqImplementation] })
              .then((k) => ACCOUNT_KIND[Number(k)] ?? ("unknown" as const))
              .catch(() => "unknown" as const)
          : Promise.resolve("unknown" as const),
      ]);
      return {
        address,
        kind,
        initialized,
        preQKeyHash: keys[0] as Hex,
        postQKeyHash: keys[1] as Hex,
      };
    }),
  );
}

/** The policy check, as a list of sentences. Empty means the arrangement satisfies NESTED. */
export async function checkNestedPolicy(
  client: PublicClient,
  lens: Address,
  cfg: { root: Address; sEcdsa: Address; sPq: Address; k: number; pqImplementation: Address },
): Promise<string[]> {
  const v = await client.readContract({
    address: lens,
    abi: lensAbi,
    functionName: "nestedViolations",
    args: [cfg.root, cfg.sEcdsa, cfg.sPq, BigInt(cfg.k), cfg.pqImplementation],
  });
  return decodeViolations(v);
}
