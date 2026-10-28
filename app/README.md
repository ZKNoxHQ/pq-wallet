# app — the wallet front

pnpm workspace, TypeScript.

| Package | Role |
|-|-|
| `packages/core` (`@zknox/pq-core`) | No React. Key derivation (BIP39, SLIP-0010 extended), ML-DSA-44 (keygen, sign, on-chain key blob), hybrid signature encoding, viem smart accounts for the vault and the satellite, on-chain state reader, and the `WalletAdapter` interface with two implementations: `ViemWalletAdapter` (real) and `SimulationAdapter`. ABIs are generated from `contracts/out`. |
| `packages/ui` (`@zknox/pq-wallet-ui`) | No viem. The `Wallet` React component over a list of `NetworkEntry` (name, chainId, adapter). |
| `packages/safe` (`@zknox/pq-safe`) | No React. The TypeScript side of [`safe/`](../safe): ML-DSA-65 and its expanded key, the digest chain, Safe signature packing, the `approveHash` plan, chain reads. Checked byte for byte against the Solidity through a Forge fixture. |
| `packages/provider` (`@zknox/pq-provider`) | No React. An EIP-1193 provider whose account is a `ZKNOX_PQAccount7702` clone: `eth_sendTransaction` becomes `executeWithHybridSig`, signed by the holder (ECML-Signer or a software holder) and paid by a separate wallet. What the Safe{Wallet} fork connects as a wallet. Tested against the deployed arrangement on anvil. |
| `apps/demo` | Vite app. Builds one live network per `contracts/deployments/<chainId>.json` that has a `VITE_RPC_URL_<chainId>`, plus three simulated networks. |
| `apps/safe-signer` | Vite app, also servable as a Safe App. Collects post-quantum owner signatures for a Safe and turns them into `S_pq`'s approval of the root's hash — the one step Safe{Wallet} cannot carry. |

```
make anvil                # terminal 1
make deploy-local         # terminal 2: deploys the stack on anvil, writes contracts/deployments/31337.json, regenerates ABIs
cp app/apps/demo/.env.example app/apps/demo/.env
make dev                  # http://localhost:5173, network "Foundry" is the live anvil
```

The Safe signer has a local chain of its own, since it needs Safe singletons that anvil does not have:

```
make safe-deploy-local    # deploys the whole NESTED arrangement, prints the .env to paste
make safe-signer          # http://localhost:5174
```

Tests: `pnpm -r test` in `app/`. `core` checks the ML-DSA key blob and signatures byte for byte against the Python
reference used by the Forge tests, and runs the whole flow (create vault, link, sweep, relay, handleOps, send as
public, ERC-1271) against anvil when it is up. `ui` drives the component in jsdom over the simulation adapter.

## Keys

The public account is `m/44'/60'/0'/0/0` of the mnemonic (viem `mnemonicToAccount`). The ML-DSA-44 seed is
`deriveSeed("ML-DSA-44", bip39Seed, "m/44'/60'/0'/0'/0'")` from `keys/slip10ext.ts`: HMAC-SHA512 with the key
`"ML-DSA-44-v1 seed"`, then hardened-only SLIP-0010 child derivation. The snapshot in `test/mldsa44.test.ts` is
the vector to align the Ledger side on.

## Submitting userOps

`ViemWalletAdapter` sends userOps to `bundlerUrl` when set (EntryPoint v0.8, viem bundler client). Without it, a
`relayer` key submits `handleOps` directly to the EntryPoint (anvil, tests). The stub signature for estimation is a
real hybrid signature over a fixed digest, so both verifiers run to their last comparison.

## Real vs simulated

Real on live networks: keys and signatures, key blob, vault creation, link (type-4), sweep with the listed ERC-20s,
vault spends through the relay path or `handleOps`, send as public, ERC-1271, gas estimated by the node before
signing (`adapter.estimate`, shown in the dialog as "node estimate"; the handleOps figure is the transaction's gas
limit, the EntryPoint refunds what is not used), signing progress driven by the adapter (`setProgress`), balances
polled every 12 s, encrypted keystore (PBKDF2 600k / AES-256-GCM in `localStorage`) behind an unlock screen,
a faucet on anvil (relayer ETH + test token mint).

Still simulated or absent:
- Shielded pools on live networks (`shield`/`unshield` are optional on the adapter; only `SimulationAdapter` has them).
- The bundler path (`bundlerUrl`): written on viem's bundler client, never exercised here; `handleOps` by a relayer is.
- Sepolia and other public deployments (`contracts/deployments/<chainId>.json` from the deploy script).
- Ledger signers, Falcon.
- The "Total" in the header is the current network only.
