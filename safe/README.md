# safe: post-quantum owners of a Safe

Safe owners that are `ZKNOX_PQAccount7702` clones (hybrid ECDSA k1 + ML-DSA-65, from
[`../contracts`](../contracts)), mixed with classical EOA owners, using the Safe framework as is:
no Safe fork, no guard, no module, no new signature scheme on the Safe side. The PQ account already
implements ERC-1271; Safe 1.5.0 calls it as it calls any contract owner.

The ML-DSA-65 key is not deployed: its 38,112-byte expansion travels in the signature of every
transaction, so adding a post-quantum signer costs a clone and nothing else.

This part of the repository adds what the Safe side needs around it: a stateless policy checker
(`ZKNOX_SafePQLens`), signature packing and digest helpers, the plan for moving an existing Safe in place,
scripts and tests.

## Policies

Both guarantee that every accepted signature set contains at least `k` ECDSA owners and `k` PQ owners.

| | Layout | Signatures per transaction |
|-|-|-|
| **NESTED** (recommended) | root Safe, owners `{S_ecdsa, S_pq}`, threshold 2; `S_ecdsa`: n EOAs, threshold k; `S_pq`: n PQ clones, threshold k | k ECDSA + k hybrid |
| **SINGLE** | one Safe, nE EOAs + nP PQ clones, threshold T with T >= nE + k and T >= nP + k | T in total |

With a broken post-quantum verifier (or all PQ keys stolen), NESTED still requires k of the n ECDSA owners:
the security is then the classical k-of-n one (`test_brokenPQVerifier_securityFallsBackToEcdsaSide`).

**Transaction size caps k.** Each post-quantum owner adds 41,824 bytes of payload, its expanded key
included. A k = 2 execution is an 84,580-byte transaction costing 4,949,950 gas in all (1,084,444 of it
calldata). geth refuses to relay past 128 kB, which puts the ceiling at k = 3 and rules out k = 4 on the
mempool path.

Requirements checked by the lens, and why:

- every Safe involved is a **1.5.0** proxy: Safe 1.4.1 calls the legacy `isValidSignature(bytes,bytes)`, which
  the PQ account does not implement (`test_safe141_rejectsPQOwner`);
- PQ owners are initialized **ERC-1167 clones** of a given implementation (hence of an audited verifier pair).
  An EOA delegated with EIP-7702 is refused: Safe accepts its plain ECDSA signature through `ecrecover`
  (`test_7702DelegatedOwner_bypassesPQ`);
- **no module** anywhere: a module executes without signatures, and a module of a child Safe can make it call
  `approveHash` on the root;
- the **fallback handler** of the children is the canonical `CompatibilityFallbackHandler` 1.5.0 (it answers
  ERC-1271 for the child); root and single Safe: that handler or none.

The lens is a point-in-time view. Messages already stored in `signedMessages` and token allowances granted
before the reconfiguration stay valid; review them separately.

## Digests

| Owner of Safe `S` validating hash `h` | Signs |
|-|-|
| EOA | `h` (or EIP-191 of `h`, packed with v + 4) |
| PQ clone `P` | `P.hashWrapped(h)` with both keys, payload `abi.encode(preQKey, preQSig, postQKey, postQSig)`, where `postQKey` is the 38,112-byte expanded ML-DSA-65 key |
| nested Safe `C` | the owners of `C` sign `safeMessageHash(C, h)`, recursively |

For NESTED, `h` is the root `safeTxHash`. `ZKNOX_SafePQSignatures` computes the digests and packs the
signatures in Safe order (ascending owner, contract payloads appended).

## Layout

```
src/ZKNOX_SafePQLens.sol                  policy checker (NESTED / SINGLE), owner classification
src/libraries/ZKNOX_SafePQSignatures.sol  digests, signature packing
src/libraries/ZKNOX_SafePQPlan.sol        migration tx, reconfiguration batch (MultiSendCallOnly)
src/libraries/ZKNOX_SafeDeployments.sol   canonical Safe 1.5.0 / 1.4.1 / 1.3.0 addresses
script/InspectSafe.s.sol                  report on an existing Safe
script/DeployLens.s.sol                   lens bound to the canonical 1.5.0 singletons and handler
script/DeployNestedSafes.s.sol            S_ecdsa and S_pq (owner kinds checked before broadcast)
script/PlanNestedMigration.s.sol          plan + SafeTx hashes to plans/<chainId>-<root>.json, dry run on the fork
script/ExecPlannedTx.s.sol                executes one plan step with EOA owner signatures
script/PqOwnerDigest.s.sol                the digest each signer is handed for one root transaction
script/ExecNestedTx.s.sol                 executes a root transaction from those signers' answers
script/DeployLocalNested.s.sol            the whole arrangement on anvil, Safe singletons included
script/DeployPqStack65.s.sol              the ML-DSA-65 stack on a chain that already has Safe 1.5.0
script/CreatePqOwner.s.sol                one post-quantum owner, from the keys a device reported
script/CreateRootSafe.s.sol               the 2-of-2 root owning the two children
scripts/ecml.mjs                          the ECML-Signer Ledger client: read the keys, sign a digest
test/                                     25 tests, real ML-DSA-65 signatures
test/SafePQFrontFixture.t.sol             the fixture generator: writes test/fixtures/front.json (run by
                                          `make safe-front-fixture`, excluded from `make test-safe`)
```

## Setup

From the root of the repository, `make install` fetches every pinned submodule and the reference signers
(the tests drive the ML-DSA-65 js signer through `vm.ffi`, so node and npm are needed), then:

```
make test-safe       # from the root
forge test           # or from this directory
```

## Moving an existing Safe (mainnet example)

```
export RPC=https://ethereum-rpc.publicnode.com
export SAFE=0x5566FE8b9802f9Fc6f94A16BF349b354D3e58BFe
make inspect

# once the PQ clones exist on the chain (the ../contracts factory deployed there)
export PQ_IMPLEMENTATION=0x...            # factory.IMPLEMENTATION()
export SENDER=0x...                       # Ledger account paying the gas
make deploy-lens                          # -> LENS
ECDSA_OWNERS=0x..,0x..,0x.. PQ_OWNERS=0x..,0x..,0x.. K=2 make deploy-children   # -> S_ecdsa, S_pq

ROOT=$SAFE S_ECDSA=0x... S_PQ=0x... K=2 LENS=0x... make plan   # writes the plan, dry-runs both steps
```

Each owner signs the `safeTxHash` of each step printed by `plan` (both can be signed in advance, the hash
does not change across the migration), e.g. `cast wallet sign --ledger <safeTxHash>`. Then:

```
PLAN=plans/1-$SAFE.json STEP=migration SIGNATURES=0x..,0x..,0x.. make exec
PLAN=plans/1-$SAFE.json STEP=reconfig  SIGNATURES=0x..,0x..,0x.. make exec
```

The reconfiguration batch ends with `lens.requireNested`: if the result does not satisfy the policy, the Safe
transaction reverts and nothing changes (`test_reconfig_revertsAtomically_onPolicyViolation`).

## Hardware signers

A post-quantum owner signs `Sigs.nestedOwnerDigest(S_pq, clone, safeTxHash)`: the root safeTxHash wrapped
through the child Safe's SafeMessage and the clone's EIP-712 domain. The ECML-Signer Ledger app
([ZKNoxHQ/ecml-signer](https://github.com/ZKNoxHQ/ecml-signer)) signs an arbitrary 32-byte digest through
`HYBRID_SIGN_HASH`, so that one value is all it needs, and the k1 half is signed over the same bytes.
`script/PqOwnerDigest.s.sol` prints it for a live Safe, owner by owner.

`test/SafePQDeviceKey.t.sol` puts a real device key in a Safe and checks the device's recorded signatures
on the ML-DSA-65 verifier. A recorded signature cannot stand in for an owner signature, since the device
signed a digest of its own; DECISIONS.md ADR-009 spells out why, and what the test proves instead.

## Two ways to execute

| | root signature | where it goes |
|-|-:|-|
| one transaction, `ExecNestedTx` | 84,166 bytes | straight to an RPC, 4,246,915 gas |
| each child calls `approveHash` first | 130 bytes | an ordinary Safe transaction, 67,786 gas |

The second moves the weight into the children: `S_pq`'s own `approveHash`
transaction carries both expanded keys (84,324 bytes of calldata, 3,936,958
gas), and the root then executes on two 65-byte approved-hash slots. That makes
the root transaction ordinary enough for Safe{Wallet}, which produces the ECDSA
child's `approveHash` by itself under the name "on-chain signature". See
DECISIONS.md ADR-010.

Note what the Safe infrastructure will not carry, as of 2026-10-22: the
Transaction Service caps a confirmation signature at 5,000 bytes, and the
Client Gateway behind app.safe.global mis-parses a signature blob holding more
than one contract signature. Both are read from the code, not from an incident.

## Checking a deployment

`make safe-verify-deployed RPC=… ORIGIN_ROOT=…` (from the root of the repository) compares what is live with
what this repository compiles: every contract ZKNOX deployed, byte for byte, the addresses each one holds, the
canonical Safe contracts by code hash, and the arrangement from the root Safe down to the post-quantum clones.
`ORIGIN_ROOT` is the repository's path on the machine that compiled the deployment; DECISIONS.md ADR-016 says
why it is needed and what the check does not cover.

## A demonstration on Sepolia

[`SEPOLIA.md`](SEPOLIA.md) walks the whole path: installing the Ledger app, reading its keys, deploying the
ML-DSA-65 stack, creating the owners and the three Safes, publishing the page, signing on the device, and
executing from Safe{Wallet}. It is also the experiment that settles the four things this repository only
knows from reading code.

## The front

[`app/apps/safe-signer`](../app/apps/safe-signer) is the screen on top of all this: it derives the digest each
holder signs, takes the answers back, assembles `S_pq`'s `approveHash` transaction and sends it to an RPC.
Everything it shows is recomputed in TypeScript rather than read from a service, so a holder can check it;
`app/packages/safe` holds that code and `test/SafePQFrontFixture.t.sol` pins it to this Solidity, digest by
digest and byte by byte.

```
make anvil && make safe-deploy-local   # the whole arrangement on a local chain
make safe-signer                       # http://localhost:5174
```

## Not covered

- Distributing the digests: the front reaches holders by a link that carries the arrangement, and nothing
  stores or relays anything.
- Safe{Wallet} and the Safe Transaction Service with contract owners whose validation runs to 2 M gas and
  whose signature is 41.8 kB: not tested, and the size is the likelier problem. The `approveHash` path is
  how that is avoided rather than solved.
- ERC-4337 through Safe4337Module: the child Safe's owner reads are storage not associated with the sender,
  which ERC-7562 forbids, and the signature size would fail bundler policy anyway; execute with
  `execTransaction` from a relayer.

Experimental, not audited.
