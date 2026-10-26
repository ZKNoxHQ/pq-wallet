# VERSION.md : changelog

## [0.5.0] 2026-10-22 : la fixture du front, et l'arrangement sur une chaîne locale

### Added
- `test/SafePQFrontFixture.t.sol` : écrit `test/fixtures/front.json`, le vecteur
  contre lequel `app/packages/safe` est vérifié — condensats des deux chemins,
  `safeTxHash` du root et de `S_pq`, graines et clés k1 des détenteurs, le blob
  de 83 842 octets par son keccak, la signature du root, et les chiffres de gas
  de la transaction de `S_pq`. Le test parcourt le chemin `approveHash` en
  entier avant d'écrire : la fixture est un chemin qui marche, pas une liste de
  nombres. `make safe-front-fixture` la régénère.
- `script/DeployLocalNested.s.sol` : tout l'arrangement sur anvil, singletons
  Safe compris, pour jouer le front de bout en bout sans chaîne publique.
  `make safe-deploy-local`.

### Measured
`S_pq.approveHash` avec deux signataires : 84 324 octets de calldata, dont
22 268 à zéro, soit 1 102 968 de coût intrinsèque et un plancher EIP-7623 de
2 725 920. Ces quatre valeurs sont celles que le front affiche, et le test
TypeScript les compare à celles-ci.

### Tests
25/25, plus le générateur de fixture, exclu du run par défaut :
il réécrit un fichier versionné, et c'est le test TypeScript qui garde le
vecteur.

## [0.4.0] 2026-10-22 : exécution en une transaction, et le chemin approveHash mesuré

### Added
- `script/ExecNestedTx.s.sol` : exécute une transaction du root à partir des
  réponses des signataires, en assemblant les trois couches (EOA de S_ecdsa,
  clones de S_pq, les deux enfants comme signatures contrat du root). C'est le
  pendant de `PqOwnerDigest`, qui imprime ce que chacun signe. Envoi direct au
  RPC, sans Transaction Service, ce qu'une signature de 84 Ko impose.
  `DRY_RUN=true` s'arrête avant l'envoi.
- `test_nested_approveHash_path` mesure désormais les deux tailles et encadre la
  transaction de S_pq par le plancher EIP-7623 et le plafond EIP-7825.
- `test_scripts_endToEnd` exerce `ExecNestedTx` sur un transfert réel du root.

### Measured
| | signature | exécution | total tx |
|---|---:|---:|---:|
| root en une transaction (`ExecNestedTx`) | 84 166 o | 3 141 471 | 4 246 915 |
| `S_pq.approveHash` | 83 842 o | 2 833 882 | 3 936 958 |
| root après approbations | **130 o** | **67 786** | ~70 000 |

Le chemin `approveHash` déplace le poids vers la transaction de l'enfant et
rend celle du root ordinaire, donc exécutable depuis Safe{Wallet}. Plancher
EIP-7623 de la transaction de S_pq : 2 726 190, franchi. DECISIONS.md ADR-010.

### Dependency
- ETHDILITHIUM `mldsa65-calldata` @ ccdc874 : API du vérifieur inchangée,
  exécution du 65 de 1 549 610 à 1 198 467. L'exécution NESTED à k = 2 passe de
  3 844 506 à 3 141 471.

### Tests
25/25.

## [0.3.0] 2026-10-21 : clé d'un signeur matériel comme owner, digest à signer

### Added
- `Sigs.nestedOwnerDigest(sPq, pqAccount, safeTxHash)` : la chaîne complète en
  un appel, safeTxHash du root puis SafeMessage de l'enfant puis wrap EIP-712 du
  clone. C'est la valeur qu'un signeur reçoit, matériel ou logiciel.
- `script/PqOwnerDigest.s.sol` : pour une transaction du root, imprime le
  safeTxHash, le digest des owners EOA et celui de chaque owner
  post-quantique. `PQ_OWNERS` restreint la liste, sinon tous les owners de S_pq.
- `test/SafePQDeviceKey.t.sol` (2 tests) : la clé publique de l'app Ledger
  ecml-signer comme owner post-quantique, enregistrée par le clone, classée par
  le lens, politique NESTED vérifiée ; les trois signatures du device acceptées
  par le vérifieur ML-DSA-65 du chemin Safe, avec digest modifié et bits
  retournés refusés ; et une signature portant sur un autre digest refusée par
  l'ERC-1271 du compte. DECISIONS.md ADR-009 dit pourquoi un vecteur figé n'est
  pas rejouable comme signature d'owner.

### Changed
- `test/SafePQScripts.t.sol` exerce aussi `PqOwnerDigest`.
- Dépendance : ETHDILITHIUM `mldsa65-calldata` @ fcfc3fe, qui apporte les
  vecteurs device. API du vérifieur inchangée.

### Tests
25/25.

## [0.2.0] 2026-10-20 : signataires ML-DSA-65 à clé en calldata

### Changed
- Les owners post-quantiques sont des clones ML-DSA-65 dont la clé étendue
  voyage dans le calldata, et non plus des clones ML-DSA-44 à pointeur SSTORE2.
  Aucun contrat de `src/` ne change : le lens reconnaît un clone à son code
  hash, et `hybridPayload` garde sa forme, seul `postQKey` passant de 20 à
  38 112 octets. DECISIONS.md ADR-008.
- `test/SafePQFixture.sol` : clés et signatures produites par
  `scripts/mldsa65.mjs` en `vm.ffi` sur le signeur js d'ETHDILITHIUM, tout
  dérivé d'une seed de 32 octets par détenteur. Le signeur Python du 44 n'est
  plus utilisé.
- `scripts/bootstrap.sh` épingle ETHDILITHIUM sur `mldsa65-calldata`
  (`ETHDILITHIUM_REF` pour surcharger) et installe les paquets npm du signeur.

### Added
- `scripts/mldsa65.mjs` : `key <seed>` rend la clé étendue, `sign <seed> <hash>`
  la signature de 3 309 octets que contrôle l'entrée ISigVerifier.
- `test_nested_exec_2ecdsa_2pq` mesure la taille de transaction et vérifie
  qu'elle reste sous la limite de relais de 128 Ko.

### Measured
| | ML-DSA-44, pointeurs | **ML-DSA-65, calldata** |
|---|---:|---:|
| exécution NESTED, k = 2 | 2 534 864 | **3 844 506** |
| calldata de la transaction | ~3 800 o | **84 580 o** |
| gas de calldata | ~57 000 | **1 084 444** |
| **total transaction** | ~2 613 000 | **4 949 950** |
| payload par owner PQ | 3 820 o | **41 824 o** |
| installation d'une clé | SSTORE2 | **aucune** |

La taille de transaction devient la contrainte dominante : à 41 824 octets par
owner post-quantique, la limite de relais de 128 Ko de geth plafonne le côté PQ
à k = 3 et rend k = 4 impossible sur le chemin mempool.

### Tests
23/23.

## [0.1.0] 2026-09-15 : première version

### Added
- `ZKNOX_SafePQLens` : politiques NESTED et SINGLE, classification des owners (EOA, EOA 7702, clone PQ,
  Safe 1.5.0, autre Safe, contrat), drapeaux de violation, `requireNested` / `requireSingle`.
- `ZKNOX_SafePQSignatures` : `safeMessageHash`, `pqAccountDigest`, `hybridPayload`, `pack` (tri par owner,
  signatures contrat, hash approuvés).
- `ZKNOX_SafePQPlan` : transaction de migration 1.3.0/1.4.1 vers 1.5.0 (L1/L2), batch de reconfiguration
  NESTED et SINGLE terminé par le contrôle du lens.
- `ZKNOX_SafeDeployments` : adresses canoniques Safe.
- Scripts `InspectSafe`, `DeployLens`, `DeployNestedSafes`, `PlanNestedMigration` (plan JSON et dry run),
  `ExecPlannedTx` (signatures EOA brutes ou eth_sign, détection automatique).
- `scripts/bootstrap.sh`, makefile.

### Dependencies
- Le compte du dépôt voisin `pq-account-7702` 0.4.1, ETHDILITHIUM `exp/packed-verifier` @ f85ca80.
  (Depuis la 0.5.0 du dépôt, c'est `../contracts` et un submodule ; voir le VERSION.md racine.)
- safe-smart-account v1.5.0 @ dc437e8 et v1.4.1 @ bf943f8 (tests uniquement).

### Measured
| | gas |
|-|-:|
| `execTransaction` NESTED, 2 ECDSA + 2 hybrides (k1 + ML-DSA-44) | 2 534 864 |
| migration 1.4.1 vers 1.5.0 | 61 046 |
| reconfiguration (4 owners retirés, 1 module, contrôle du lens) | 239 782 |

Tests : 23/23 (nested 12, adversarial 4, migration 4, single 2, scripts 1).
