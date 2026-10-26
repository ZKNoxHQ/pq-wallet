# Post-Quantum Account, EIP-7702 / ERC-4337

Hybrid account: a transaction is authorized when both a pre-quantum signature (ECDSA secp256k1, or
P-256 through any `ISigVerifier`) and a post-quantum signature (ML-DSA-44 or Falcon-512, NIST variants)
verify on the same digest.

The same code serves two deployment models:

- **EIP-7702**: an EOA delegates to the implementation and calls `initialize` on itself.
- **ERC-4337**: `ZKNOX_PQFactory7702` deploys an ERC-1167 clone of the implementation and initializes it
  in the same transaction.

## Two pots: vault + satellite

Under EIP-7702 the EOA's secp256k1 key keeps its protocol-level authority over everything held at the
EOA address, so funds there cannot be made quantum-resistant. The recommended layout splits the funds:

- **Vault**: an ERC-4337 clone of `ZKNOX_PQAccount7702`. No EOA key. The post-quantum pot. Spent only
  through userOps or `executeWithHybridSig`, both requiring the hybrid signature.
- **Satellite**: the EOA delegates to `ZKNOX_PQSatellite7702`, linked to the vault. The non-post-quantum
  pot, authorized by the EOA key alone (like `Simple7702Account`). The link adds:
  - `sweep(tokens)`, callable by anyone: ETH above a gas reserve and the listed tokens go to the vault.
    Incoming funds on the public address reach the post-quantum pot without a signature.
  - `execute`/`executeBatch` accepted from `msg.sender == vault`: one hybrid signature can act with
    `msg.sender == EOA` (vault batch: push funds to the EOA, then execute through it).
  - ERC-1271 relayed to the vault: a signature in the name of the EOA requires the hybrid keys.

```
                 anyone: sweep()                 hybrid sig
  incoming  --->  EOA (satellite)  ----------->  vault (clone)  ---> spend
                  non-PQ pot        <-----------  PQ pot
                  EOA key only      vault.execute
```

Setup per user: `factory.createAccount(preQ, postQ, salt)` for the vault, then a type-4 transaction from
the EOA with `to = EOA`, `data = satellite.initialize(vault, gasReserve)`. See `test/PQPairScenarios.sol`.

Post-quantum verifiers come from the experimental branches of the ZKNOX repositories:

| Scheme | Contract | Branch | verify (gas) |
|-|-|-|-:|
| ML-DSA-44 NIST | `ZKNOX_dilithium` (packed 4x64 lanes, external SHAKE) | ETHDILITHIUM `exp/packed-verifier` | ~1.20M |
| Falcon-512 NIST | `ZKNOX_falcon_fused` via `ZKNOX_falcon_fused_verifier` (this package) | ETHFALCON `exp/pq-verifier-gas` | ~0.73M |

Both verifiers take the address of the Keccak-f[1600] helper (`f1600_170.hex`, fireblocks-labs) in their
constructor and re-check its code hash on every call.

## Contracts

- `src/ZKNOX_PQAccount7702.sol`: the account. Verifiers and EntryPoint are immutables (shared code);
  per-account data lives in an ERC-7201 slot (`zknox.pqaccount.v1`), never in slots 0..n.
  The account stores `keccak256` of each normalized key, not the keys: every signature carries the keys.
- `src/ZKNOX_PQFactory7702.sol`: deploys the implementation (so `FACTORY` is known to it) and the clones.
- `src/ZKNOX_PQSatellite7702.sol`: EIP-7702 delegate for the EOA side of the pair (ECDSA userOps,
  `sweep`, vault as executor, ERC-1271 relay). One deployment per chain, scheme-independent, state in
  the ERC-7201 slot `zknox.pqsatellite.v1`.
- `src/ZKNOX_falcon_fused_verifier.sol`: `ISigVerifier` adapter over `falcon_core_fused` and
  `hashToPointNISTPacked`. Same key blob (32 words, h in NTT domain, SSTORE2) and signature encoding
  (salt 40 bytes || s2 compact 1024 bytes) as `ZKNOX_falcon`.

### Signature encoding

```
abi.encode(bytes preQKey, bytes preQSig, bytes postQKey, bytes postQSig)
```

`preQKey` / `postQKey` are the normalized keys, i.e. what `verifier.setKey(rawKey)` returned: the 20-byte
address for k1, the 20-byte SSTORE2 pointer for ML-DSA and Falcon. `preQSig` is `r || s || v`.
`postQSig` is `cTilde || z || h` (2420 bytes) for ML-DSA, `salt || s2` (1064 bytes) for Falcon.

### Entry points

| Function | Caller | Purpose |
|-|-|-|
| `initialize(rawPreQ, rawPostQ)` | self (7702) or factory | normalizes keys through `setKey`, stores hashes |
| `initializeWithKeyRefs(preQRef, postQRef)` | self or factory | same, with a key blob written beforehand by anyone |
| `validateUserOp` / `execute` / `executeBatch` | EntryPoint v0.8, self | ERC-4337 path (BaseAccount) |
| `executeWithHybridSig(calls, deadline, sig)` | anyone | relayed execution without a bundler, own nonce, EIP-712 |
| `isValidSignature(hash, sig)` | dApps | ERC-1271 over `hashWrapped(hash)` (bound to chainId and account) |
| `setPreQuantumKey` / `setPostQuantumKey` | EntryPoint or self | rotation, emits events |

### Stub signature for gas estimation

Bundlers estimate `verificationGasLimit` with a stub signature and ignore the signature failure. Use a
real hybrid signature over any fixed digest as the stub: both verifiers run to their last comparison
and the estimate matches a valid signature within 2% (see `test_7702_stubSignature_costsLikeValidOne`).
A random byte string is not a good stub: it fails structural checks early and under-estimates.

## EIP-7702 flow

1. (optional, any payer) `pointer = verifier.setKey(rawPostQuantumKey)`; for ML-DSA this writes the
   expanded public key (~21 kB) once, reusable by every account of that key.
2. Type-4 transaction from the EOA: authorization `(chainId or 0, delegate, nonce)`, `to = EOA`,
   `data = initializeWithKeyRefs(abi.encodePacked(eoa), abi.encodePacked(pointer))`.
   `msg.sender == address(this)`, so nobody can initialize the account first.
3. UserOps with `sender = EOA` through the EntryPoint, or `executeWithHybridSig` through any relayer.

**Caveat.** Under EIP-7702 the EOA's secp256k1 key keeps its protocol-level authority: it can send
transactions that bypass this code (`test_7702_eoaDirectExecute_bypassesPQ`) and it can re-delegate.
The post-quantum signature is a second factor for a 7702 account. Quantum resistance of the EOA itself
requires a protocol change (deactivation of the EOA key) or the ERC-4337 clone path, where no such key exists.

## Build and test

```
make install        # submodules on the experimental branches + python signers
make test_mldsa     # fast
make test_falcon    # python Falcon keygen ~20 s per signature
```

Requires solc 0.8.30 with via-IR (`foundry.toml`), like both verifier branches.

Measured with `forge test -vv` (EntryPoint v0.8, `handleOps` with one `execute` userOp):

| | ML-DSA-44 NIST | Falcon-512 NIST |
|-|-:|-:|
| `handleOps`, 7702 account | 1 431 642 | 883 090 |
| `handleOps`, 4337 clone | 1 434 121 | 925 874 |
| `executeWithHybridSig`, 2 calls | 1 377 543 | 871 431 |
| `handleOps`, vault acting as the EOA (2-call batch) | 1 501 489 | 951 380 |
| `handleOps`, satellite (ECDSA only) | 203 113 | 203 195 |

## Deployment

```
forge script script/DeployPQAccount7702.s.sol --rpc-url $RPC --broadcast
```

Deploys the helper (or reuses `F1600_HELPER`), the three verifiers and one factory per scheme; each
factory's `IMPLEMENTATION()` is the EIP-7702 delegate. Deploy the factories with CREATE2 from the same
deployer on every chain to obtain identical delegate addresses (a chainId 0 authorization covers all chains).

## Known limits

- Not audited.
- The ML-DSA key blob is written by the verifier with plain `CREATE`: its address depends on the writer.
  A content-addressed blob (`CREATE2`, salt = hash of the FIPS-204 compressed key) would make the
  reference derivable from the compressed key alone; see DECISIONS.md, ADR-003.
- Bundlers cap `verificationGasLimit` well below 1.2M on public mempools; `executeWithHybridSig` is the
  fallback path.
