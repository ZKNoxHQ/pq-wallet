// The arrangement planner: one value pinned by `cast` (the salt encoding the script uses), then the real
// thing on anvil — the three Safes created from the plan, at the planned addresses, and the lens saying
// the result satisfies NESTED.
//
//   make anvil && make safe-deploy-local      # the Safe singletons, the PQ stack, three clones
//   pnpm --filter @zknox/pq-safe test
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPublicClient, createWalletClient, http, type Address, type Hex, type PublicClient } from "viem";
import { foundry } from "viem/chains";
import { lensAbi, nestedSaltNonce, planArrangement, proxyFactoryAbi, safeAbi } from "../src";

const FILE = resolve(__dirname, "../../../../safe/deployments/31337-nested.json");
const RPC = process.env.ANVIL_RPC ?? "http://127.0.0.1:8545";
const SENDER: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"; // anvil account 2

type Deployment = {
  lens: Address; pqImplementation: Address; pqOwners: Address[];
  safeSingleton?: Address; safeProxyFactory?: Address; fallbackHandler?: Address;
};
const d: Deployment | null = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
const client = createPublicClient({ chain: foundry, transport: http(RPC) }) as PublicClient;
const wallet = createWalletClient({ chain: foundry, transport: http(RPC), account: SENDER });
let up = false;

beforeAll(async () => {
  up = await client.getChainId().then((id) => id === 31337).catch(() => false);
});

describe("nestedSaltNonce", () => {
  it("encodes as CreateArrangement.s.sol does", () => {
    // cast keccak $(cast abi-encode "f(address[],uint256,uint256,string)" "[0x11…11,0x22…22]" 2 7 zknox.nested)
    expect(
      nestedSaltNonce(["0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222"], 2n, 7n),
    ).toBe(0x7bf0032b83e609bc9d00143c2abe4b93df1383ac76c8c7e8f972dde0c8780e05n);
  });

  it("refuses an arrangement that cannot satisfy its own threshold", () => {
    const stack = { singleton: d?.pqImplementation ?? "0x0000000000000000000000000000000000000001", proxyFactory: "0x0000000000000000000000000000000000000002", fallbackHandler: "0x0000000000000000000000000000000000000003" } as const;
    const a = "0x00000000000000000000000000000000000000a1" as Address;
    const b = "0x00000000000000000000000000000000000000b1" as Address;
    expect(() => planArrangement(stack, "0x00", { ecdsaOwners: [a], pqOwners: [b], k: 2 })).toThrow(/only 1 ECDSA/);
    expect(() => planArrangement(stack, "0x00", { ecdsaOwners: [a, b], pqOwners: [b], k: 1 })).toThrow(/twice/);
  });
});

describe.skipIf(!d?.safeProxyFactory)("planArrangement, on anvil", () => {
  it("creates the three Safes where it said, and the lens accepts them", async (ctx) => {
    if (!up) ctx.skip();
    const stack = { singleton: d!.safeSingleton!, proxyFactory: d!.safeProxyFactory!, fallbackHandler: d!.fallbackHandler! };
    const code = (await client.readContract({ address: stack.proxyFactory, abi: proxyFactoryAbi, functionName: "proxyCreationCode" })) as Hex;
    const ecdsaOwners: Address[] = [
      "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
      "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
      "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    ];
    const saltNonce = BigInt(Date.now());
    const plan = planArrangement(stack, code, { ecdsaOwners, pqOwners: d!.pqOwners, k: 2, saltNonce });

    // the root first, to show the order does not matter
    for (const s of [plan[2]!, plan[0]!, plan[1]!]) {
      expect(await client.getCode({ address: s.address })).toBeUndefined();
      const hash = await wallet.sendTransaction({ to: s.to, data: s.data });
      expect((await client.waitForTransactionReceipt({ hash })).status).toBe("success");
      expect(await client.getCode({ address: s.address })).toBeDefined();
    }

    const [sEcdsa, sPq, root] = plan.map((s) => s.address) as [Address, Address, Address];
    expect(await client.readContract({ address: root, abi: safeAbi, functionName: "getOwners" })).toEqual(
      expect.arrayContaining([sEcdsa, sPq]),
    );
    const v = await client.readContract({
      address: d!.lens, abi: lensAbi, functionName: "nestedViolations", args: [root, sEcdsa, sPq, 2n, d!.pqImplementation],
    });
    expect(v).toBe(0n);

    // planned again with the same input, the same three addresses: what makes a creation resumable
    const again = planArrangement(stack, code, { ecdsaOwners, pqOwners: d!.pqOwners, k: 2, saltNonce });
    expect(again.map((s) => s.address)).toEqual(plan.map((s) => s.address));
  });
});
