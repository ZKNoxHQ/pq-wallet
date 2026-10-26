# VERSION.md — changelog

## [0.4.1] — 2026-09-09 — alignement sur les têtes du 2026-09-09 des deux branches expérimentales

### Changed
- ETHDILITHIUM `exp/packed-verifier` @ f85ca80 (tables de twiddles copiées une fois, 1 196 707 → 1 189 532) :
  interface et format de clé inchangés, rien à modifier côté compte ni côté front ; blob de clé et signature
  toujours identiques octet pour octet au signer Python (test core).
- ETHFALCON `exp/pq-verifier-gas` @ 012e080 : `ZKNOX_falcon8` (huit lanes de 32 bits, Montgomery R = 2¹⁶,
  norme repliée dans le sampler, helper Keccak propre `test/f1600_zknox.hex`, code hash 0x661c9f13…).
  `ZKNOX_falcon_fused_verifier` remplacé par `ZKNOX_falcon8_verifier` (adaptateur `ISigVerifier` sur
  `falcon_core8`, mêmes encodages de clé et de signature). Le helper Falcon n'est plus celui de ML-DSA :
  le script en déploie deux (`f1600Helper`, `f1600ZknoxHelper` dans le JSON, `F1600_ZKNOX_HELPER` en env),
  la fixture de test aussi.
- Pins de `scripts/bootstrap.sh` mis à jour ; `deployments.ts` et `gen-abi.mjs` suivent.

### Measured
| | ML-DSA-44 | Falcon-512 |
|-|-:|-:|
| `validateUserOp` valide / factice | 1 282 498 / 1 276 887 | 702 644 / 697 236 (était 781 491) |
| `handleOps` 7702 | 1 445 569 | 867 431 (était 883 090) |
| vault agissant comme l'EOA | 1 491 809 | 914 507 (était 951 380) |

Tests : contrats 24 ML-DSA + 24 Falcon8, core 15/15 (dont e2e anvil), ui 2/2.

## [0.4.0] — 2026-09-07 — vers la production : estimation réelle, progression réelle, tokens, keystore

### Added
- `WalletAdapter.estimate(action)` : sur réseau réel, `eth_estimateGas` / `estimateContractGas` pour chaque
  action (link avec `authorizationList`, relay et handleOps avec une vraie signature hybride non diffusée,
  createVault = setKey + createAccountWithKeyRefs). La modale affiche « node estimate » ou « typical ».
  Vérifié sur anvil : eoaSend estimé à 10 % près, link 92 789 estimé / 80 289 réel, handleOps 1 775 110
  (limite de gas) / 1 374 123 réel.
- `WalletAdapter.setProgress(cb)` : étapes `sign-ecdsa`, `sign-pq`, `sign-auth`, `prove`, `submit`, `confirm`,
  `done` émises par les adaptateurs ; les coches de la modale suivent ces étapes, plus de minuteur.
- Tokens ERC-20 : lus par le lecteur d'état (liste depuis la config ou `testToken` du déploiement), affichés
  sur le compte public et le vault, passés à `sweep`. `contracts/src/TestToken.sol` déployé sur chaînes
  locales et testnets par le script.
- `faucet()` sur réseau local (relayer + mint), `keys/keystore.ts` (PBKDF2-SHA256 / AES-256-GCM, WebCrypto)
  et écran `Unlock` (créer, importer, déverrouiller, oublier) dans la démo ; `VITE_MNEMONIC` devient un
  raccourci de développement optionnel.
- Rafraîchissement des soldes toutes les 12 s sur réseau réel. Test keystore, tests e2e étendus
  (estimation, faucet, tokens, progression) : core 15/15, ui 2/2.

### Changed
- Limites de gas des userOps locales : verification 1,6 M, call 400 k, preVerification 60 k.

## [0.3.0] — 2026-09-07 — monorepo, le vrai front (app/)

### Added
- `app/` : workspace pnpm. `packages/core` (dérivation BIP39 + SLIP-0010 étendu, ML-DSA-44 avec blob de clé
  on-chain, signature hybride, comptes viem vault et satellite, lecteur d'état, `WalletAdapter` avec
  `ViemWalletAdapter` et `SimulationAdapter`, ABIs générés), `packages/ui` (composant `Wallet` sur
  l'adaptateur), `apps/demo` (Vite, réseaux réels depuis `contracts/deployments/*.json` + simulations).
- Tests : blob de clé et signature ML-DSA identiques octet pour octet au signer Python des tests Forge ;
  flux complet sur anvil via l'adaptateur viem (createVault 4 959 790 gas, link 80 289, sweep 40 286, relay
  1 322 770, handleOps 1 372 053, sendAsPublic 1 376 982, ERC-1271 sur le vault et sur l'EOA lié) ; composant
  en jsdom sur la simulation.
- `ZKNOX_PQFactory7702.createAccountWithKeyRefs(preQRef, postQRef, salt)` : clone initialisé avec des
  références de clés déjà écrites (le front écrit le blob via `verifier.setKey` puis crée le clone, sans
  second déploiement du blob). Test `test_4337_factoryClone_withKeyRefs`.
- Script de déploiement : déploie un EntryPoint v0.8 si l'adresse canonique n'a pas de code (anvil),
  écrit `deployments/<chainId>.json` (adresses, `startBlock`).

### Changed
- Dépôt réorganisé : le Foundry passe dans `contracts/`, `.gitmodules` à la racine, makefile racine.

## [0.2.0] — 2026-09-07 — paire vault + satellite

### Added
- `src/ZKNOX_PQSatellite7702.sol` : délégué 7702 de l'EOA lié à un vault (clone `ZKNOX_PQAccount7702`).
  UserOps par la seule clé EOA (comme `Simple7702Account`), `sweep(tokens)` public vers le vault avec
  réserve de gas, `execute`/`executeBatch` acceptés depuis le vault, ERC-1271 relayé au vault avec
  enveloppe liée à l'EOA, `setVault`/`setGasReserve` par l'EOA, l'EntryPoint ou le vault, storage
  ERC-7201 `zknox.pqsatellite.v1`.
- `test/PQPairScenarios.sol` : 10 scénarios sur les deux schémas (storage, init non front-runnable,
  sweep ETH + ERC-20 par un tiers, vault non dépensable par la clé EOA, EOA relayant une signature hybride,
  vault agissant comme l'EOA en un batch atomique, autorisations du satellite, userOp ECDSA, 1271 relayé,
  réglages). Mesuré : vault agissant comme l'EOA 1 501 489 (ML-DSA) / 951 380 (Falcon) ; satellite
  ECDSA 203 k.
- Script : déploiement du satellite. README : section « Two pots ». Tests : 33 ML-DSA, 33 Falcon.

### Notes
- `isValidSignature` du vault revert sur une signature non décodable (ERC-1271 l'autorise, OZ
  `SignatureChecker` la traite comme invalide) ; le satellite relaie tel quel.

## [0.1.1] — 2026-09-06 — vérification hybride sans court-circuit (estimation par signature factice)

### Changed
- `ZKNOX_PQAccount7702._verifyHybrid` : les deux vérifieurs sont toujours appelés, quel que soit le
  résultat du premier. Les bundlers dimensionnent `verificationGasLimit` avec une signature factice
  (`eth_estimateUserOperationGas` ignore l'échec de signature) ; avec le court-circuit, une factice
  échouant sur l'ECDSA n'exécutait jamais le vérifieur post-quantique et l'estimation manquait de
  0,7 à 1,2 M gas. La factice recommandée est une vraie signature hybride sur un autre digest.

### Added
- `test_7702_stubSignature_costsLikeValidOne` : `validateUserOp` valide / factice à moins de 2 % ;
  mesuré ML-DSA 1 288 004 / 1 284 179, Falcon 781 491 / 775 903.

## [0.1.0] — 2026-09-05 — compte hybride 7702/4337 sur les vérifieurs des branches expérimentales

Refonte de `packages/pq-account` (kohaku) pour EIP-7702, en conservant le chemin ERC-4337.

### Measured (`forge test -vv`, EntryPoint v0.8, `handleOps` avec un userOp `execute`)
| | ML-DSA-44 NIST (`ZKNOX_dilithium`, exp/packed-verifier) | Falcon-512 NIST (`ZKNOX_falcon_fused`, exp/pq-verifier-gas) |
|-|-:|-:|
| `handleOps`, compte 7702 | 1 431 642 | 883 090 |
| `handleOps`, clone 4337 | 1 434 121 | 925 874 |
| `executeWithHybridSig`, 2 appels | 1 377 543 | 871 431 |

Référence kohaku (`ZKNOX_ERC4337_account`, README) : MLDSA 8,39 M, FALCON 4,06 M. Tests : 24/24
(12 scénarios × 2 schémas).

### Added
- `src/ZKNOX_PQAccount7702.sol` : remplace `ZKNOX_ERC4337_account`. Vérifieurs et EntryPoint en
  `immutable`, état par compte dans un slot ERC-7201 (`zknox.pqaccount.v1`), `initialize` réservé au
  compte lui-même (auto-appel 7702) ou à la factory (clone 4337), `initializeWithKeyRefs` pour un blob de
  clé déjà écrit, hachés de clés en storage et clés dans la signature, `executeWithHybridSig` (relais sans
  bundler, nonce propre, EIP-712), ERC-1271 avec enveloppe de domaine, rotation des deux clés avec events,
  receivers ERC-721/1155, ERC-165. Plus de `fallback` payable attrape-tout.
- `src/ZKNOX_PQFactory7702.sol` : remplace `ZKNOX_PQFactory`. Déploie l'implémentation (le délégué 7702)
  et des clones ERC-1167 déterministes pour le chemin 4337, création et initialisation atomiques.
- `src/ZKNOX_falcon_fused_verifier.sol` : adaptateur `ISigVerifier` sur `falcon_core_fused` +
  `hashToPointNISTPacked`, mêmes encodages de clé (blob SSTORE2 de 1024 octets) et de signature
  (salt || s2, 1064 octets) que `ZKNOX_falcon`, liaison du helper Keccak-f[1600] par code hash.
- `test/PQAccountTestBase.sol`, `test/PQAccountScenarios.sol` : fixture et scénarios communs
  (délégation via `vm.signDelegation` / `vm.attachDelegation`, userOp, signatures fausses, clé ne
  correspondant pas au haché, exécution directe par l'EOA, relais et anti-rejeu, ERC-1271, initialisation
  non front-runnable et unique, storage namespacé, rotation de clé, clone 4337).
- `test/PQAccount7702_K1_FALCON_fused.t.sol`, `test/PQAccount7702_K1_MLDSA_packed.t.sol` : liaisons des
  deux schémas, signatures par les signers Python des deux dépôts.
- `script/DeployPQAccount7702.s.sol` : helper, trois vérifieurs, une factory par schéma.

### Changed
- `foundry.toml` : solc 0.8.30, via-IR, `optimizer_runs = 1000000` (imposé par les noyaux packés des deux
  branches). `.gitmodules` : account-abstraction v0.8.0, openzeppelin v5.4.0, sstore2, ETHFALCON
  `exp/pq-verifier-gas`, ETHDILITHIUM `exp/packed-verifier`.

### Removed
- Constructeur porteur d'état, factory CREATE2 sur le bytecode du compte, `isValid` public avec adresses
  de logique fournies par l'appelant, contrôle `digest.length > 32` (code mort sur un `bytes32`).

### Notes
- Le chemin `ISigVerifier` de `ZKNOX_falcon` (scalaire, branche exp) revert sur un blob brut de 1024
  octets : `verify` fait `abi.decode(SSTORE2.read(ptr), (uint256[]))` alors que `setKey` stocke la sortie
  brute de `_packUint256Array`. Constaté en test, non corrigé ici (le nouvel adaptateur lit le blob en
  place).
