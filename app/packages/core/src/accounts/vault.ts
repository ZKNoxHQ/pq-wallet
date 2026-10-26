// The post-quantum vault as a viem SmartAccount (EntryPoint v0.8). Hybrid signature on every userOp.
import { encodeFunctionData, decodeFunctionData, hashTypedData, type Address, type Hex, type PublicClient } from "viem";
import { toSmartAccount, getUserOperationTypedData, entryPoint08Abi, type SmartAccount } from "viem/account-abstraction";
import { ZKNOX_PQAccount7702Abi } from "../abi";
import { signHybrid, stubSignature, type HybridKeys } from "../signers";
import type { ProgressFn } from "../adapter/types";

export type VaultAccountParams = {
  client: PublicClient;
  address: Address; // the clone
  entryPoint: Address;
  keys: HybridKeys;
  progress?: ProgressFn;
};

export async function toVaultAccount(p: VaultAccountParams) {
  const { client, address, keys } = p;
  const abi = ZKNOX_PQAccount7702Abi;
  const entryPoint = { abi: entryPoint08Abi, address: p.entryPoint, version: "0.8" as const };

  const account = await toSmartAccount({
    client,
    entryPoint,
    abi,
    extend: { abi, keys },
    async getAddress() { return address; },
    async encodeCalls(calls) {
      if (calls.length === 1) {
        return encodeFunctionData({ abi, functionName: "execute", args: [calls[0].to, calls[0].value ?? 0n, calls[0].data ?? "0x"] });
      }
      return encodeFunctionData({ abi, functionName: "executeBatch", args: [calls.map((c) => ({ target: c.to, value: c.value ?? 0n, data: c.data ?? "0x" }))] });
    },
    async decodeCalls(data) {
      const r = decodeFunctionData({ abi, data });
      if (r.functionName === "execute") return [{ to: r.args[0], value: r.args[1], data: r.args[2] }];
      if (r.functionName === "executeBatch") return r.args[0].map((a) => ({ to: a.target, value: a.value, data: a.data }));
      throw new Error(`cannot decode ${r.functionName}`);
    },
    async getFactoryArgs() { return { factory: undefined, factoryData: undefined }; },
    async getStubSignature() { return stubSignature(keys); },
    async signMessage() { throw new Error("use signWrapped(): ERC-1271 signatures must be over hashWrapped(hash)"); },
    async signTypedData() { throw new Error("use signWrapped(): ERC-1271 signatures must be over hashWrapped(hash)"); },
    async signUserOperation(parameters) {
      const { chainId = client.chain!.id, ...userOperation } = parameters;
      const typedData = getUserOperationTypedData({ chainId, entryPointAddress: p.entryPoint, userOperation: { ...userOperation, sender: address } });
      return signHybrid(keys, hashTypedData(typedData), p.progress);
    },
  });
  return account as SmartAccount<typeof account extends SmartAccount<infer I> ? I : never> & { keys: HybridKeys };
}

/** Digest the vault verifies for ERC-1271 over an application hash. */
export const wrappedTypedDataHash = (chainId: number, vault: Address, hash: Hex) =>
  hashTypedData({
    domain: { name: "ZKNOX_PQAccount7702", version: "1", chainId, verifyingContract: vault },
    types: { ZKNOXWrapped: [{ name: "hash", type: "bytes32" }] },
    primaryType: "ZKNOXWrapped",
    message: { hash },
  });
