// Discovery against the real arrangement on anvil, which is the only way to check it: the whole point of
// `discover` is reading contracts, so a stubbed client would only test the stub.
//
//   make anvil && make safe-deploy-local      # writes safe/deployments/31337-nested.json
//   pnpm --filter safe-signer test
//
// Skips when the chain or the deployment is absent.
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPublicClient, getAddress, http, type Address, type PublicClient } from "viem";
import { foundry } from "viem/chains";
import { discover } from "../src/safeApp";

const FILE = resolve(__dirname, "../../../../safe/deployments/31337-nested.json");
const RPC = process.env.ANVIL_RPC ?? "http://127.0.0.1:8545";

type Deployment = {
  chainId: number; k: number; root: Address; sEcdsa: Address; sPq: Address;
  lens: Address; pqImplementation: Address; pqOwners: Address[];
};

const d: Deployment | null = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
let up = false;
const client = createPublicClient({ chain: foundry, transport: http(RPC) }) as PublicClient;

beforeAll(async () => {
  up = await client
    .getChainId()
    .then((id) => id === 31337)
    .catch(() => false);
});

describe.skipIf(!d)("discover, against the deployed arrangement", () => {
  it("opened on the root: finds both children and tells them apart", async (ctx) => {
    if (!up) ctx.skip();
    const got = await discover(client, getAddress(d!.root));
    expect(got.kind).toBe("root");
    if (got.kind !== "root") return;
    expect(got.sPq).toBe(getAddress(d!.sPq));
    expect(got.sEcdsa).toBe(getAddress(d!.sEcdsa));
    expect(got.k).toBe(d!.k);
  });

  it("opened on S_pq: recognises the child, and cannot name its parent", async (ctx) => {
    if (!up) ctx.skip();
    const got = await discover(client, getAddress(d!.sPq));
    expect(got.kind).toBe("sPq");
    if (got.kind !== "sPq") return;
    expect(got.sPq).toBe(getAddress(d!.sPq));
    expect(got.k).toBe(d!.k);
  });

  it("opened on S_ecdsa: says so rather than guessing", async (ctx) => {
    if (!up) ctx.skip();
    const got = await discover(client, getAddress(d!.sEcdsa));
    expect(got.kind).toBe("unrelated");
    if (got.kind !== "unrelated") return;
    expect(got.reason).toMatch(/post-quantum clone/);
  });

  it("an address that is not a Safe is refused, not guessed at", async (ctx) => {
    if (!up) ctx.skip();
    const got = await discover(client, getAddress(d!.pqOwners[0]));
    expect(got.kind).toBe("unrelated");
  });
});
