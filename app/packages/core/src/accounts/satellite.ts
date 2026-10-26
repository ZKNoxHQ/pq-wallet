// The linked EOA as a viem SmartAccount: delegated to ZKNOX_PQSatellite7702, ECDSA-only userOps.
import { encodeFunctionData, decodeFunctionData, hashTypedData, type Address, type PublicClient } from "viem";
import type { PrivateKeyAccount } from "viem/accounts";
import { toSmartAccount, getUserOperationTypedData, entryPoint08Abi, type SmartAccount } from "viem/account-abstraction";
import { ZKNOX_PQSatellite7702Abi } from "../abi";

export async function toSatelliteAccount(p: { client: PublicClient; owner: PrivateKeyAccount; entryPoint: Address; delegate: Address }): Promise<SmartAccount> {
  const { client, owner } = p;
  const abi = ZKNOX_PQSatellite7702Abi;
  return (await toSmartAccount({
    client,
    entryPoint: { abi: entryPoint08Abi, address: p.entryPoint, version: "0.8" },
    abi,
    authorization: { account: owner, address: p.delegate },
    extend: { abi, owner },
    async getAddress() { return owner.address; },
    async encodeCalls(calls) {
      if (calls.length === 1) return encodeFunctionData({ abi, functionName: "execute", args: [calls[0].to, calls[0].value ?? 0n, calls[0].data ?? "0x"] });
      return encodeFunctionData({ abi, functionName: "executeBatch", args: [calls.map((c) => ({ target: c.to, value: c.value ?? 0n, data: c.data ?? "0x" }))] });
    },
    async decodeCalls(data) {
      const r = decodeFunctionData({ abi, data });
      if (r.functionName === "execute") return [{ to: r.args[0], value: r.args[1], data: r.args[2] }];
      if (r.functionName === "executeBatch") return r.args[0].map((a) => ({ to: a.target, value: a.value, data: a.data }));
      throw new Error(`cannot decode ${r.functionName}`);
    },
    async getFactoryArgs() { return { factory: "0x7702", factoryData: "0x" }; },
    async getStubSignature() {
      return "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";
    },
    async signMessage({ message }) { return owner.signMessage({ message }); },
    async signTypedData(t) { return owner.signTypedData(t as any); },
    async signUserOperation(parameters) {
      const { chainId = client.chain!.id, ...userOperation } = parameters;
      const typedData = getUserOperationTypedData({ chainId, entryPointAddress: p.entryPoint, userOperation: { ...userOperation, sender: owner.address } });
      return owner.sign({ hash: hashTypedData(typedData) });
    },
  })) as unknown as SmartAccount;
}
