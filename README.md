# pq-wallet

Post-quantum Ethereum accounts, and the ways to hold funds behind one: a hybrid account that authorizes
nothing without both an ECDSA and an ML-DSA signature, a satellite that keeps an ordinary EOA usable beside
it, and post-quantum signers inside a Safe multisig. One signature scheme, three arrangements.

```
contracts/   the hybrid account, its EIP-7702 satellite, the factory, the Falcon adapter
safe/        post-quantum owners of a Safe 1.5.0: policy lens, migration plan, digests, scripts
app/         the fronts: TypeScript cores without React, React UI without viem, the wallet demo
             and safe-signer, which collects post-quantum owner signatures for a Safe
lib/         pinned dependencies, as git submodules
```

Every piece is experimental and none is audited.

## Getting started

Prerequisites: git, [Foundry](https://getfoundry.sh) (forge, anvil, cast), solc 0.8.30 (Foundry downloads
it, or set `FOUNDRY_SOLC`), Node.js 22 with `corepack enable` (pnpm 12 is pinned in `app/package.json`),
Python 3.10+ with `venv` for the reference signers.

```
make install              # submodules at their pinned commits, reference signers, pnpm install
make test                 # contracts 48/48, safe 25/25, app
make test-contracts-fast  # ML-DSA scenarios only (Falcon takes ~20 s per python signature)
```

## The three arrangements

| | what it is | a withdrawal needs |
|-|-|-|
| **vault** `ZKNOX_PQAccount7702` | an ERC-4337 clone with no EOA key, holding the funds to protect | ECDSA k1 **and** ML-DSA, both |
| **satellite** `ZKNOX_PQSatellite7702` | the owner's ordinary EOA, delegated with EIP-7702 and linked to the vault | the EOA's ECDSA alone |
| **Safe** `safe/` | clones of the vault as owners of a Safe, beside classical EOA owners | k ECDSA **and** k hybrid |

The vault and the satellite go together for one person: what you want to keep from a quantum adversary
sits in the vault, the rest stays on the EOA and costs nothing extra. The Safe arrangement is for a
treasury several people share; `safe/README.md` has its policies, its gas and its limits.

The account never stores a public key, only `keccak256` of what the verifier's `setKey` returned. That one
line is why a verifier can change shape — an SSTORE2 pointer, or the expanded key itself travelling in the
calldata — without the account changing at all.

## Pinned dependencies

`lib/` holds git submodules pinned **by commit**, never by branch name, so a clone a year from now builds
the same bytecode. The ZKNOX ones sit on experimental branches:

| | branch | commit |
|-|-|-|
| ETHDILITHIUM | `mldsa65-calldata` | `ccdc874` |
| ETHFALCON | `exp/pq-verifier-gas` | `012e080` |
| InterfaceVerifier | `main` | `e655a5f` |
| safe-smart-account | `v1.5.0` / `v1.4.1` | `dc437e8` / `bf943f8` |

Moving a pin means checking the submodule out and committing it, and running both suites: `contracts/` and
`safe/` consume the same verifiers and break together. That is the reason they share a repository.

## Local chain

```
make anvil              # terminal 1
make deploy-local       # terminal 2: EntryPoint v0.8, helpers, verifiers, factory, satellite, test token
make e2e                # the app's viem adapter against anvil
cp app/apps/demo/.env.example app/apps/demo/.env
make dev                # http://localhost:5173
```

On first launch the demo asks for a password and creates or imports a recovery phrase, kept encrypted in
the browser. On anvil, "Receive" is a faucet; the flow is then Create vault, Link to vault, Protect funds,
Send.

## Public networks

`SEPOLIA_RPC=… DEPLOYER_KEY=… make deploy-sepolia` writes `contracts/deployments/11155111.json`. Add
`VITE_RPC_URL_11155111` to `app/apps/demo/.env` and the network shows up in the demo.

The Safe scripts take an `RPC` and the variables each one's header documents: `make safe-inspect`,
`safe-plan`, `safe-digest`, `safe-deploy-children`, `safe-exec-nested`.

## Signing for a Safe

Collecting a post-quantum owner's signature is the one step Safe{Wallet} cannot carry — 41.8 kB where its
API caps a confirmation at 5,000 bytes. `app/apps/safe-signer` is the screen that does it, and the whole
arrangement runs locally:

```
make anvil              # terminal 1
make safe-deploy-local  # terminal 2: Safe singletons, the PQ stack, the three Safes; prints the .env
make safe-signer        # http://localhost:5174
```
