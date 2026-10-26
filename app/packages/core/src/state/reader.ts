import { type Address, type Hex, type PublicClient, keccak256, parseAbiItem, encodeAbiParameters } from "viem";
import { erc20Abi } from "viem";
import { ZKNOX_PQAccount7702Abi, ZKNOX_PQSatellite7702Abi, EntryPointAbi } from "../abi";
import type { Deployments } from "../deployments";
import type { TokenBalance, WalletState } from "../adapter/types";

export type TokenInfo = { address: Address; symbol: string; decimals: number };

export async function readTokens(client: PublicClient, tokens: TokenInfo[], holder: Address): Promise<TokenBalance[]> {
  return Promise.all(tokens.map(async (t) => ({ ...t, balance: await client.readContract({ address: t.address, abi: erc20Abi, functionName: "balanceOf", args: [holder] }) })));
}

const CREATED = parseAbiItem("event AccountCreated(address indexed account, bytes32 indexed preQKeyHash, bytes32 indexed postQKeyHash)");

export const delegateOf = (code: Hex | undefined): Address | null =>
  code && code.length === 2 + 46 && code.startsWith("0xef0100") ? (("0x" + code.slice(8)) as Address) : null;

/** Finds the vault created for this EOA key on this chain (factory event, indexed by the pre-quantum key hash). */
export async function findVault(client: PublicClient, d: Deployments, eoa: Address): Promise<Address | null> {
  const logs = await client.getLogs({
    address: d.factoryMLDSA,
    event: CREATED,
    args: { preQKeyHash: keccak256(eoa) },
    fromBlock: BigInt(d.startBlock),
    toBlock: "latest",
  });
  return logs.length ? (logs[logs.length - 1].args.account as Address) : null;
}

export async function readState(client: PublicClient, d: Deployments, eoa: Address, vaultAddress: Address | null, tokens: TokenInfo[] = []): Promise<WalletState> {
  const [eth, nonce, code, eoaTokens] = await Promise.all([
    client.getBalance({ address: eoa }),
    client.getTransactionCount({ address: eoa }),
    client.getCode({ address: eoa }),
    readTokens(client, tokens, eoa),
  ]);
  const delegate = delegateOf(code);
  let linked = false, reserve = 0n;
  if (delegate && delegate.toLowerCase() === d.satellite.toLowerCase()) {
    const [v, r] = await Promise.all([
      client.readContract({ address: eoa, abi: ZKNOX_PQSatellite7702Abi, functionName: "vault" }),
      client.readContract({ address: eoa, abi: ZKNOX_PQSatellite7702Abi, functionName: "gasReserve" }),
    ]);
    linked = !!vaultAddress && v.toLowerCase() === vaultAddress.toLowerCase();
    reserve = r;
  }
  let vault: WalletState["vault"] = null;
  if (vaultAddress) {
    const [veth, hashes, pqNonce, epNonce, vaultTokens] = await Promise.all([
      client.getBalance({ address: vaultAddress }),
      client.readContract({ address: vaultAddress, abi: ZKNOX_PQAccount7702Abi, functionName: "keyHashes" }),
      client.readContract({ address: vaultAddress, abi: ZKNOX_PQAccount7702Abi, functionName: "pqNonce" }),
      client.readContract({ address: d.entryPoint, abi: EntryPointAbi, functionName: "getNonce", args: [vaultAddress, 0n] }),
      readTokens(client, tokens, vaultAddress),
    ]);
    vault = { address: vaultAddress, scheme: "ML-DSA-44", eth: veth, tokens: vaultTokens, preQKeyHash: hashes[0], postQKeyHash: hashes[1], epNonce, pqNonce };
  }
  return { chainId: d.chainId, eoa: { address: eoa, eth, tokens: eoaTokens, nonce, delegate, linked, reserve }, vault, priv: {} };
}
