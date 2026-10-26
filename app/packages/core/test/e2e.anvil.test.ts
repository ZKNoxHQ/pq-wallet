// End to end against the contracts deployed on a local anvil (contracts/deployments/31337.json):
//   create vault → link → sweep → vault sends (relay + local handleOps) → send as public → ERC-1271.
// Run `anvil` and `forge script script/DeployPQAccount7702.s.sol --broadcast` first (see makefile: e2e).
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPublicClient, http, parseEther, keccak256, stringToBytes, type Address, type Hex } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { foundry } from "viem/chains";
import { ViemWalletAdapter, parseDeployments, deriveSeed, mnemonicToSeed, ZKNOX_PQAccount7702Abi, ZKNOX_PQSatellite7702Abi } from "../src";

const RPC = process.env.RPC_URL ?? "http://127.0.0.1:8545";
const DEP = resolve(__dirname, "../../../../contracts/deployments/31337.json");
const FUNDER = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"); // anvil #0
const RELAYER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"); // anvil #1

const up = async () => { try { await createPublicClient({ chain: foundry, transport: http(RPC) }).getChainId(); return existsSync(DEP); } catch { return false; } };

describe("viem adapter on anvil", async () => {
  const available = await up();
  let a: ViemWalletAdapter;
  const client = createPublicClient({ chain: foundry, transport: http(RPC) });
  const eoa = privateKeyToAccount(generatePrivateKey()); // a fresh public account
  const recipient = privateKeyToAccount(generatePrivateKey()).address;

  beforeAll(async () => {
    if (!available) return;
    const d = parseDeployments(JSON.parse(readFileSync(DEP, "utf8")));
    const seed = mnemonicToSeed("test test test test test test test test test test test junk");
    const { seed: pqSeed } = deriveSeed("ML-DSA-44", seed);
    a = new ViemWalletAdapter({ chain: foundry, transport: http(RPC), deployments: d, ecdsa: eoa, pqSeed, relayer: RELAYER, localFaucet: true });
    // fund the public account and the relayer
    const { createWalletClient } = await import("viem");
    const w = createWalletClient({ chain: foundry, transport: http(RPC), account: FUNDER });
    for (const to of [eoa.address, RELAYER.address]) {
      const h = await w.sendTransaction({ to, value: parseEther("10") });
      await client.waitForTransactionReceipt({ hash: h });
    }
  });

  it.skipIf(!available)("reads a plain public account", async () => {
    const s = await a.read();
    expect(s.eoa.address).toBe(eoa.address);
    expect(s.eoa.delegate).toBeNull();
    expect(s.vault).toBeNull();
    expect(s.eoa.eth).toBe(parseEther("10"));
  });

  it.skipIf(!available)("estimates before signing, within 10% of the actual gas", async () => {
    const est = await a.estimate({ kind: "eoaSend", to: recipient, value: parseEther("0.01") });
    expect(est.source).toBe("estimated");
    const r = await a.eoaSend(recipient, parseEther("0.01"));
    expect(Number(r.gasUsed)).toBeGreaterThan(Number(est.gas) * 0.9);
    expect(Number(r.gasUsed)).toBeLessThanOrEqual(Number(est.gas));
    const estCreate = await a.estimate({ kind: "createVault" });
    expect(estCreate.gas).toBeGreaterThan(4_000_000n);
  });

  it.skipIf(!available)("local faucet credits ETH and test tokens", async () => {
    const before = await a.read();
    await a.faucet(parseEther("1"));
    const after = await a.read();
    expect(after.eoa.eth - before.eoa.eth).toBe(parseEther("1"));
    expect(after.eoa.tokens[0].symbol).toBe("TST");
    expect(after.eoa.tokens[0].balance - before.eoa.tokens[0].balance).toBe(100n * 10n ** 18n);
  });

  it.skipIf(!available)("creates the vault (key blob + clone) and finds it back from the factory event", async () => {
    const r = await a.createVault();
    console.log("createVault gas", r.gasUsed);
    const s = await a.read();
    expect(s.vault?.address).toBe(r.vault);
    expect(s.vault?.preQKeyHash).toBe(keccak256(eoa.address));
    expect(s.vault?.postQKeyHash).not.toBe("0x" + "0".repeat(64));
    // a fresh adapter with no vault address discovers it
    const b = new ViemWalletAdapter({ ...a.cfg });
    expect((await b.read()).vault?.address).toBe(r.vault);
  });

  it.skipIf(!available)("links the public account (type-4) and sweeps above the reserve", async () => {
    const estLink = await a.estimate({ kind: "link", reserve: parseEther("0.05") });
    const r = await a.link(parseEther("0.05"));
    console.log("link gas", r.gasUsed, "estimated", estLink.gas);
    expect(Number(r.gasUsed)).toBeLessThanOrEqual(Number(estLink.gas));
    let s = await a.read();
    expect(s.eoa.delegate?.toLowerCase()).toBe(a.d.satellite.toLowerCase());
    expect(s.eoa.linked).toBe(true);
    expect(s.eoa.reserve).toBe(parseEther("0.05"));
    const before = s.eoa.eth, tstBefore = s.eoa.tokens[0].balance;
    const r2 = await a.sweep();
    console.log("sweep gas", r2.gasUsed);
    s = await a.read();
    expect(s.eoa.eth).toBe(parseEther("0.05"));
    expect(s.vault!.eth).toBe(before - parseEther("0.05"));
    expect(s.eoa.tokens[0].balance).toBe(0n);
    expect(s.vault!.tokens[0].balance).toBe(tstBefore);
  });

  it.skipIf(!available)("the public account relays a hybrid-signed vault spend", async () => {
    // give the public account some gas back
    await a.moveToPublic(parseEther("1"), "relay").catch(() => {});
    const r = await a.vaultSend(recipient, parseEther("0.5"), "relay");
    console.log("relay gas", r.gasUsed);
    expect(await client.getBalance({ address: recipient })).toBe(parseEther("0.51"));
    expect((await a.read()).vault!.pqNonce).toBeGreaterThanOrEqual(1n);
  });

  it.skipIf(!available)("vault userOp through handleOps (local relayer), estimated first, progress reported", async () => {
    const est = await a.estimate({ kind: "vaultSend", to: recipient, value: parseEther("0.25"), path: "bundler" });
    const stages: string[] = [];
    a.setProgress((s) => stages.push(s));
    const r = await a.vaultSend(recipient, parseEther("0.25"), "bundler");
    a.setProgress(null);
    console.log("handleOps gas", r.gasUsed, "estimated", est.gas);
    expect(stages).toEqual(["sign-ecdsa", "sign-pq", "submit", "confirm", "done"]);
    // handleOps estimation is bounded below by the userOp gas limits the EntryPoint checks: an upper bound
    expect(Number(r.gasUsed)).toBeLessThanOrEqual(Number(est.gas));
    expect(Number(est.gas)).toBeLessThan(Number(r.gasUsed) * 1.5);
    expect(await client.getBalance({ address: recipient })).toBe(parseEther("0.76"));
    expect((await a.read()).vault!.epNonce).toBe(1n);
  });

  it.skipIf(!available)("vault sends as the public account: recipient sees the EOA", async () => {
    // a probe contract is not deployed here; check balances and that the EOA balance is unchanged
    const eoaBefore = (await a.read()).eoa.eth;
    const r = await a.sendAsPublic(recipient, parseEther("0.1"));
    console.log("sendAsPublic gas", r.gasUsed);
    expect(await client.getBalance({ address: recipient })).toBe(parseEther("0.86"));
    expect((await a.read()).eoa.eth).toBe(eoaBefore);
  });

  it.skipIf(!available)("ERC-1271: vault and linked EOA accept the hybrid signature over the wrapped hash", async () => {
    const s = await a.read();
    const hash = keccak256(stringToBytes("dApp message"));
    const sigVault = await a.signWrapped(hash);
    const magic = await client.readContract({ address: s.vault!.address, abi: ZKNOX_PQAccount7702Abi, functionName: "isValidSignature", args: [hash, sigVault] });
    expect(magic).toBe("0x1626ba7e");
    const sigEoa = await a.signWrapped(hash, true);
    const magic2 = await client.readContract({ address: eoa.address, abi: ZKNOX_PQSatellite7702Abi, functionName: "isValidSignature", args: [hash, sigEoa] });
    expect(magic2).toBe("0x1626ba7e");
    // not interchangeable
    const cross = await client.readContract({ address: s.vault!.address, abi: ZKNOX_PQAccount7702Abi, functionName: "isValidSignature", args: [hash, sigEoa] });
    expect(cross).toBe("0xffffffff");
  });

  it.skipIf(!available)("the EOA key alone cannot spend the vault", async () => {
    const s = await a.read();
    await expect(
      a.wallet.writeContract({ account: eoa, chain: foundry, address: s.vault!.address, abi: ZKNOX_PQAccount7702Abi, functionName: "execute", args: [recipient, 1n, "0x"] }),
    ).rejects.toThrow();
  });
});
