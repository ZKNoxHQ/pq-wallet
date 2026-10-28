// The provider against the real arrangement on anvil. A provider is a sequence of chain reads and one
// broadcast, so a stubbed RPC would only test the stub.
//
//   make anvil && make safe-deploy-local      # writes safe/deployments/31337-nested.json
//   pnpm --filter @zknox/pq-provider test
//
// Skips when the chain or the deployment is absent. The holders are the software holders of the three
// default seeds of DeployLocalNested, so the clones they talk to are the owners of S_pq.
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createPublicClient, encodeFunctionData, getAddress, hexToBytes, http, keccak256, toHex,
  type Address, type Hex, type PublicClient,
} from "viem";
import { foundry } from "viem/chains";
import { approvedSig, pack, safeAbi, seedSigner, safeTxHash, type Signer } from "@zknox/pq-safe";
import {
  createPqProvider, eip1193Payer, hashExecute, httpRpc, pqRelayAbi, pqFactoryAbi, predictClone,
  type Call, type Eip1193, type Payer, type PqStep,
} from "../src";

const FILE = resolve(__dirname, "../../../../safe/deployments/31337-nested.json");
const RPC = process.env.ANVIL_RPC ?? "http://127.0.0.1:8545";
const SEEDS = [
  "18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a",
  "29e7c5a381df6b4929e7c5a381df6b4929e7c5a381df6b4929e7c5a381df6b49",
  "3ad8b69472ea5c583ad8b69472ea5c583ad8b69472ea5c583ad8b69472ea5c58",
];
/** anvil account 1: pays, owns nothing */
const PAYER: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

type Deployment = {
  chainId: number; k: number; root: Address; sEcdsa: Address; sPq: Address;
  pqImplementation: Address; pqFactory?: Address; pqOwners: Address[];
};

const d: Deployment | null = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
const client = createPublicClient({ chain: foundry, transport: http(RPC) }) as PublicClient;
const rpc = httpRpc(RPC);
const holders: Signer[] = SEEDS.map((s, i) => seedSigner(hexToBytes(`0x${s}`), `holder-${i}`));
let up = false;

/** anvil signs for its unlocked accounts, so the node itself is the paying wallet; only the account
 *  request is answered here, as a browser wallet would after the user picks an account */
const anvilWallet: Eip1193 = {
  request: ({ method, params }) =>
    method === "eth_requestAccounts" ? Promise.resolve([PAYER]) : rpc.request({ method, params }),
};
const anvilPayer = (): Payer => eip1193Payer(anvilWallet, 31337);

const providerFor = (i: number, steps: PqStep[] = [], holder: Signer = holders[i]!) =>
  createPqProvider({
    account: d!.pqOwners[i]!,
    chainId: d!.chainId,
    rpc,
    holder,
    payer: anvilPayer(),
    onStep: (s) => steps.push(s),
  });

const receipt = (hash: Hex) => client.waitForTransactionReceipt({ hash });

beforeAll(async () => {
  up = await client.getChainId().then((id) => id === 31337).catch(() => false);
});

describe.skipIf(!d)("@zknox/pq-provider against the deployed arrangement", () => {
  it("predicts each clone where the factory put it", async (ctx) => {
    if (!up || !d!.pqFactory) ctx.skip();
    for (let i = 0; i < holders.length; i++) {
      const { preQKeyHash, postQKeyHash } = await holders[i]!.keyHashes();
      const answer = await holders[i]!.sign(d!.pqOwners[i]!, keccak256("0x01"));
      expect(keccak256(answer.k1Address)).toBe(preQKeyHash);
      expect(keccak256(answer.expandedKey)).toBe(postQKeyHash);
      const local = predictClone(
        { factory: d!.pqFactory!, implementation: d!.pqImplementation },
        answer.k1Address,
        answer.expandedKey,
      );
      const factory = await client.readContract({
        address: d!.pqFactory!, abi: pqFactoryAbi, functionName: "getAddress",
        args: [answer.k1Address.toLowerCase() as Hex, answer.expandedKey, 0n],
      });
      expect(local).toBe(getAddress(factory));
      expect(local).toBe(getAddress(d!.pqOwners[i]!));
    }
  });

  it("computes the digest the clone computes", async (ctx) => {
    if (!up) ctx.skip();
    const calls: Call[] = [
      { target: d!.sPq, value: 0n, data: "0x" },
      { target: d!.root, value: 7n, data: "0xd4d9bdcd" },
    ];
    for (const [nonce, deadline] of [[0n, 1n], [3n, 2_000_000_000n]] as const) {
      const onChain = await client.readContract({
        address: d!.pqOwners[0]!, abi: pqRelayAbi, functionName: "hashExecute", args: [calls, nonce, deadline],
      });
      expect(hashExecute(d!.pqOwners[0]!, d!.chainId, calls, nonce, deadline)).toBe(onChain);
    }
  });

  it("turns Safe{Wallet}'s on-chain signature into the clone's own approveHash", async (ctx) => {
    if (!up) ctx.skip();
    const h = keccak256(toHex(`approve-${Date.now()}`));
    const steps: PqStep[] = [];
    const p = providerFor(0, steps);

    // the request dispatchOnChainSigning makes, verbatim
    const hash = (await p.request({
      method: "eth_sendTransaction",
      params: [{ from: d!.pqOwners[0], to: d!.sPq, data: encodeFunctionData({ abi: safeAbi, functionName: "approveHash", args: [h] }) }],
    })) as Hex;
    const r = await receipt(hash);
    expect(r.status).toBe("success");
    expect(getAddress(r.from)).toBe(PAYER);
    expect(getAddress(r.to!)).toBe(getAddress(d!.pqOwners[0]!));

    const approved = await client.readContract({
      address: d!.sPq, abi: safeAbi, functionName: "approvedHashes", args: [d!.pqOwners[0]!, h],
    });
    expect(approved).toBe(1n);
    expect(steps.map((s) => s.kind)).toEqual(["sign", "signed", "estimate", "sent"]);
    const est = steps.find((s) => s.kind === "estimate") as Extract<PqStep, { kind: "estimate" }>;
    console.log(`one post-quantum confirmation: ${r.gasUsed} gas, ${est.calldataBytes} bytes of calldata`);
  });

  it("walks S_pq's half of a root transaction: one approval, then the second holder executes", async (ctx) => {
    if (!up) ctx.skip();
    const rootNonce = await client.readContract({ address: d!.root, abi: safeAbi, functionName: "nonce" });
    const rootTx = { to: "0x000000000000000000000000000000000000dEaD" as Address, value: 1n, nonce: rootNonce };
    const rootH = safeTxHash(d!.root, d!.chainId, rootTx);

    const pqNonce = await client.readContract({ address: d!.sPq, abi: safeAbi, functionName: "nonce" });
    const approveRoot = encodeFunctionData({ abi: safeAbi, functionName: "approveHash", args: [rootH] });
    const pqH = safeTxHash(d!.sPq, d!.chainId, { to: d!.root, data: approveRoot, nonce: pqNonce });

    // holder 0 confirms S_pq's transaction, as Safe{Wallet} would ask it to
    const a = (await providerFor(0).request({
      method: "eth_sendTransaction",
      params: [{ from: d!.pqOwners[0], to: d!.sPq, data: encodeFunctionData({ abi: safeAbi, functionName: "approveHash", args: [pqH] }) }],
    })) as Hex;
    expect((await receipt(a)).status).toBe("success");

    // holder 1 executes it: Safe counts the executor as its own approval, so no third transaction
    const signatures = pack([approvedSig(d!.pqOwners[0]!), approvedSig(d!.pqOwners[1]!)]);
    const exec = encodeFunctionData({
      abi: safeAbi, functionName: "execTransaction",
      args: [d!.root, 0n, approveRoot, 0, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", signatures],
    });
    const b = (await providerFor(1).request({
      method: "eth_sendTransaction", params: [{ from: d!.pqOwners[1], to: d!.sPq, data: exec }],
    })) as Hex;
    const rb = await receipt(b);
    expect(rb.status).toBe("success");
    console.log(`second holder confirms and executes: ${rb.gasUsed} gas`);

    expect(await client.readContract({ address: d!.sPq, abi: safeAbi, functionName: "nonce" })).toBe(pqNonce + 1n);
    expect(await client.readContract({ address: d!.root, abi: safeAbi, functionName: "approvedHashes", args: [d!.sPq, rootH] })).toBe(1n);
  });

  it("refuses what a post-quantum account cannot do", async (ctx) => {
    if (!up) ctx.skip();
    const p = providerFor(0);
    await expect(p.request({ method: "personal_sign", params: ["0x00", d!.pqOwners[0]] })).rejects.toMatchObject({ code: 4200 });
    await expect(p.request({ method: "eth_signTypedData_v4", params: [d!.pqOwners[0], "{}"] })).rejects.toMatchObject({ code: 4200 });
    await expect(
      p.request({ method: "eth_sendTransaction", params: [{ from: d!.pqOwners[1], to: d!.sPq, data: "0x" }] }),
    ).rejects.toMatchObject({ code: 4100 });
    await expect(p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] })).rejects.toMatchObject({ code: 4902 });
    expect(await p.request({ method: "eth_accounts" })).toEqual([getAddress(d!.pqOwners[0]!)]);
    expect(await p.request({ method: "eth_chainId" })).toBe("0x7a69");
    // reads go through
    expect(BigInt((await p.request({ method: "eth_blockNumber" })) as Hex)).toBeGreaterThan(0n);
  });

  it("refuses a holder that is not the clone's, before the device is asked anything", async (ctx) => {
    if (!up) ctx.skip();
    const steps: PqStep[] = [];
    const p = providerFor(0, steps, holders[2]);
    await expect(
      p.request({ method: "eth_sendTransaction", params: [{ from: d!.pqOwners[0], to: d!.sPq, data: "0x" }] }),
    ).rejects.toThrow(/does not hold the keys/);
    expect(steps).toEqual([]);
  });

  it("pays nothing for a signature the clone would reject", async (ctx) => {
    if (!up) ctx.skip();
    // a holder whose ML-DSA half is made over another digest: the k1 half is right, so only the
    // verifier itself can tell, and it does so in the estimate
    const honest = holders[0]!;
    const forger: Signer = {
      id: "forger",
      keyHashes: () => honest.keyHashes(),
      async sign(owner, digest) {
        const good = await honest.sign(owner, digest);
        const other = await honest.sign(owner, keccak256(digest));
        return { ...good, pqSignature: other.pqSignature };
      },
    };
    const before = await client.getTransactionCount({ address: PAYER });
    await expect(
      providerFor(0, [], forger).request({
        method: "eth_sendTransaction",
        params: [{ from: d!.pqOwners[0], to: d!.sPq, data: encodeFunctionData({ abi: safeAbi, functionName: "approveHash", args: [keccak256("0x02")] }) }],
      }),
    ).rejects.toThrow(/would revert: InvalidSignature/);
    expect(await client.getTransactionCount({ address: PAYER })).toBe(before);
  });
});
