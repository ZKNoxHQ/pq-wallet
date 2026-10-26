import type { Address } from "viem";

/** Written by contracts/script/DeployPQAccount7702.s.sol into contracts/deployments/<chainId>.json */
export type Deployments = {
  chainId: number;
  startBlock: number;
  entryPoint: Address;
  f1600Helper: Address; // Fireblocks Keccak-f[1600], bound by the ML-DSA verifier
  f1600ZknoxHelper?: Address; // ETHFALCON's own helper, bound by the Falcon verifier
  ecdsaK1Verifier: Address;
  mldsaVerifier: Address;
  factoryMLDSA: Address;
  delegateMLDSA: Address;
  satellite: Address;
  falconVerifier?: Address;
  testToken?: Address; // mintable ERC-20 on local chains and testnets (public mint)
};

const FIELDS: (keyof Deployments)[] = ["chainId", "startBlock", "entryPoint", "f1600Helper", "ecdsaK1Verifier", "mldsaVerifier", "factoryMLDSA", "delegateMLDSA", "satellite"];

export function parseDeployments(json: unknown): Deployments {
  const o = json as Record<string, unknown>;
  for (const f of FIELDS) if (o[f] === undefined) throw new Error(`deployments: missing ${f}`);
  const d = { ...(o as Deployments), chainId: Number(o.chainId), startBlock: Number(o.startBlock) };
  if (d.testToken && /^0x0{40}$/.test(d.testToken)) delete d.testToken;
  return d;
}
