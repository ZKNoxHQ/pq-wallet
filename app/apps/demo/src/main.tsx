import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { http, type Chain } from "viem";
import { mnemonicToAccount, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { foundry, sepolia, mainnet, arbitrum } from "viem/chains";
import { SimulationAdapter, ViemWalletAdapter, parseDeployments, deriveSeed, mnemonicToSeed, defaultPath } from "@zknox/pq-core";
import { Wallet, type NetworkEntry } from "@zknox/pq-wallet-ui";
import { Unlock } from "./Unlock";

// Every contracts/deployments/<chainId>.json becomes a live network when an RPC URL is configured for it.
const deploymentFiles = import.meta.glob("../../../../contracts/deployments/*.json", { eager: true, import: "default" }) as Record<string, unknown>;
const chains: Record<number, Chain> = { 31337: foundry, 11155111: sepolia, 1: mainnet, 42161: arbitrum };
const env = import.meta.env as Record<string, string | undefined>;

function networksFor(mnemonic: string): NetworkEntry[] {
  const ecdsa = mnemonicToAccount(mnemonic) as unknown as PrivateKeyAccount; // m/44'/60'/0'/0/0 (HD account has the same signing surface)
  const pqSeed = deriveSeed("ML-DSA-44", mnemonicToSeed(mnemonic), defaultPath()).seed;
  const live: NetworkEntry[] = [];
  for (const json of Object.values(deploymentFiles)) {
    const d = parseDeployments(json);
    const rpc = env[`VITE_RPC_URL_${d.chainId}`];
    const chain = chains[d.chainId];
    if (!rpc || !chain) continue;
    const relayerKey = env[`VITE_RELAYER_KEY_${d.chainId}`] as `0x${string}` | undefined;
    const relayer = relayerKey ? privateKeyToAccount(relayerKey) : undefined;
    live.push({
      id: `live-${d.chainId}`, name: chain.name, chainId: d.chainId, kind: "live",
      adapter: new ViemWalletAdapter({ chain, transport: http(rpc), deployments: d, ecdsa, pqSeed, relayer, bundlerUrl: env[`VITE_BUNDLER_URL_${d.chainId}`], localFaucet: d.chainId === 31337 && !!relayer }),
    });
  }
  const simulated: NetworkEntry[] = [
    { id: "sim-sepolia", name: "Sepolia", chainId: 11155111, kind: "simulation", adapter: new SimulationAdapter({ chainId: 11155111, eth: 2500000000000000000n }) },
    { id: "sim-mainnet", name: "Ethereum", chainId: 1, kind: "simulation", adapter: new SimulationAdapter({ chainId: 1, eth: 400000000000000000n }) },
    { id: "sim-arbitrum", name: "Arbitrum One", chainId: 42161, kind: "simulation", adapter: new SimulationAdapter({ chainId: 42161, eth: 1200000000000000000n }) },
  ];
  return [...live, ...simulated];
}

function App() {
  // VITE_MNEMONIC skips the keystore: development only
  const [mnemonic, setMnemonic] = useState<string | null>(env.VITE_MNEMONIC ?? null);
  if (!mnemonic) return <Unlock onUnlocked={setMnemonic} />;
  return <Wallet networks={networksFor(mnemonic)} title="Ethereum wallet" />;
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
