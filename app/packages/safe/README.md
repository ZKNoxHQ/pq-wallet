# @zknox/pq-safe

What a front needs to collect post-quantum owner signatures for a Safe. No React, no transport, nothing that
writes to a chain: the caller brings its own viem client and its own relayer.

It is the TypeScript side of [`safe/`](../../../safe), and therefore a **second implementation** of
`ZKNOX_SafePQSignatures`. That is deliberate — a signer can only check a digest the screen derived itself,
and a digest read from an RPC or an API is one nobody can check. `test/fixture.test.ts` keeps the two
honest: it rebuilds, from the same seeds, every value Forge produced in `safe/test/fixtures/front.json` —
digests, the 38,112-byte key expansion, the hybrid payload, the 83,842-byte signature blob by hash, and the
gas figures the screen shows.

```
src/mldsa65.ts     keygen, deterministic sign, and the flat expanded key the verifier reads in calldata
src/digests.ts     safeTxHash, safeMessageHash, hashWrapped, and the two digests a PQ owner may be handed
src/signatures.ts  Safe signature packing, the ERC-1271 hybrid payload
src/plan.ts        the approveHash plan, the transaction it becomes, its size and its EIP-7623 floor
src/client.ts      the chain reads: owners, thresholds, nonces, approvals, key hashes, the policy check
src/service.ts     Safe Transaction Service, read only
src/signer.ts      a holder: a software one from a seed, or a device's answer checked for shape
```

## The two digests

A post-quantum owner of `S_pq` signs one of two things, and they are not interchangeable:

| path | the owner signs | when |
|-|-|-|
| `approveHashOwnerDigest(owner, chainId, pqSafeTxHash)` | **one** EIP-712 wrap of S_pq's own transaction | S_pq executes `root.approveHash(h)` — the default |
| `nestedOwnerDigest(sPq, owner, chainId, rootSafeTxHash)` | the three-layer chain, root → SafeMessage of S_pq → wrap | the root executes in one transaction (`ExecNestedTx`) |

Handing a device the wrong one produces a signature the Safe rejects without saying why, so both are in the
fixture and the test asserts they differ.

## Using it

```ts
import { approveHashPlan, pqChildTransaction, readSafe } from "@zknox/pq-safe";

const sPq = await readSafe(client, S_PQ);
const plan = approveHashPlan({ chainId, root, sEcdsa, sPq: S_PQ, pqOwners: sPq.owners, k }, rootTx, sPq.nonce);

// plan.digests: one 32-byte value per owner — this is what a holder compares to its screen
// collect a PqAnswer per owner (k1 address, k1 signature, expanded key, ML-DSA-65 signature)

const tx = pqChildTransaction(cfg, plan, answers); // ~84 kB of calldata, straight to an RPC
```

`calldataGas(tx.data)` gives the byte count, the intrinsic cost and the EIP-7623 floor; `fitsInMempool`
says whether a node will relay it at all. Both belong on screen before anyone presses send.

## Tests

```
pnpm test                    # 23, no chain and no Forge needed
make safe-front-fixture      # regenerate safe/test/fixtures/front.json after a digest changes
```

The generator is excluded from `make test-safe`: it rewrites a committed file, and the guard against drift
is this side, where the fixture is read rather than written.
