# DECISIONS.md — architecture decision records

## ADR-001 — 2026-09-05 — Un seul contrat pour EIP-7702 et ERC-4337, état par compte en ERC-7201

**Contexte.** `ZKNOX_ERC4337_account` posait clés, adresses de logique et EntryPoint dans le
constructeur, aux slots 0..4. Une délégation 7702 n'exécute pas de constructeur, et le storage de l'EOA
survit à une re-délégation vers un autre délégué (collision de slots).

**Décision.** Tout ce qui est commun (EntryPoint, vérifieurs, factory) est `immutable`, donc dans le code
du délégué. Tout ce qui est propre au compte (hachés de clés, nonce de relais) vit dans un slot ERC-7201.
Le même bytecode sert de délégué 7702 et d'implémentation des clones ERC-1167 pour les comptes sans EOA
(les immutables sont conservés par `delegatecall`). Une implémentation par couple de vérifieurs ; changer
de vérifieur = re-déléguer, pas mettre à jour une adresse en storage.

**Conséquences.** Plus de factory CREATE2 sur le bytecode du compte ni de `VERSION` dans le sel ; les clés
deviennent des données mutables avec fonctions de rotation et events. `initialize` doit être atomique avec
la délégation (voir ADR-002).

## ADR-002 — 2026-09-05 — `initialize` réservé à l'auto-appel et à la factory

**Contexte.** Après la tx type-4, n'importe qui peut appeler `initialize` avant l'utilisateur et poser
ses propres clés.

**Décision.** `initialize` exige `msg.sender == address(this)` (l'EOA appelle son propre code dans la tx
type-4 elle-même, `to = EOA`) ou `msg.sender == FACTORY` (clone 4337, créé et initialisé dans le même
appel). La factory déploie l'implémentation dans son constructeur pour que `FACTORY` soit un immutable
connu. Alternative écartée : signature ECDSA de l'EOA sur les paramètres d'init (une signature de plus à
gérer côté wallet, pour le même résultat).

## ADR-003 — 2026-09-05 — Hachés de clés en storage, clés dans la signature

**Contexte.** La clé étendue ML-DSA fait ~21 kB ; la clé Falcon compacte 1 kB. Les stocker par compte
coûte des dizaines de SSTORE et rend la rotation chère ; les passer en calldata à chaque tx coûte ~350 k
gas pour ML-DSA et dépasse les tailles de userOp acceptées par les bundlers.

**Décision.** Le compte stocke `keccak256` de la clé normalisée par le vérifieur (sortie de `setKey` :
adresse k1 sur 20 octets, pointeur SSTORE2 sur 20 octets pour ML-DSA et Falcon). La signature transporte
les clés normalisées, comparées aux hachés (2 SLOAD). Les blobs de clés sont écrits une fois par
`verifier.setKey`, par n'importe qui, réutilisables par tous les comptes de cette clé
(`initializeWithKeyRefs`).

**Conséquences.** Le pointeur SSTORE2 dépend du déployeur (CREATE). Suite envisagée : blob
content-addressed (`CREATE2` depuis une factory fixe, sel = haché de la clé FIPS-204 compressée), ce qui
permettrait de stocker le haché de la clé compressée et de migrer sans rotation vers le précompile
EIP-8051 (qui prendra la clé compressée de 1312 octets en entrée). Non fait ici : demande une factory de
blobs partagée par les deux dépôts de vérifieurs.

## ADR-004 — 2026-09-05 — Chemin relayé `executeWithHybridSig` en plus du chemin 4337

**Contexte.** La validation hybride coûte 0,9 à 1,4 M gas ; les bundlers publics plafonnent
`verificationGasLimit` bien en dessous, et la signature ML-DSA fait 2,4 kB.

**Décision.** Le compte expose `executeWithHybridSig(calls, deadline, sig)` : n'importe qui paie le gas,
la signature hybride porte sur un digest EIP-712 (domaine lié à chainId et au compte) couvrant les appels,
un nonce propre au compte et une échéance. L'EntryPoint n'est pas requis. Le même domaine sert à
ERC-1271 : le haché fourni par la dApp est enveloppé (`hashWrapped`) avant vérification, ce qui interdit
le rejeu entre deux comptes partageant une paire de clés.

**Conséquences.** Deux espaces de nonces (EntryPoint et `pqNonce`), documentés. Le wallet doit signer
`hashWrapped(hash)` pour ERC-1271, pas `hash`.

## ADR-005 — 2026-09-05 — Le chemin 7702 est documenté comme second facteur, pas comme résistance quantique

**Contexte.** La clé secp256k1 de l'EOA reste une autorité de niveau protocole : elle envoie des tx qui
contournent le code délégué et peut re-déléguer. Un adversaire quantique la retrouve et retire le délégué.

**Décision.** Le README et le test `test_7702_eoaDirectExecute_bypassesPQ` disent explicitement que,
sous 7702, la signature post-quantique protège contre une fuite classique de la clé ECDSA et pas contre
un adversaire quantique. La résistance quantique passe par le chemin clone 4337 (aucune clé EOA) ou par
une désactivation de la clé EOA au niveau protocole.

## ADR-006 — 2026-09-06 — Pas de court-circuit dans la vérification hybride

**Contexte.** Les bundlers (Pimlico via viem `toSmartAccount.getStubSignature`, Ambire via son mode
`Spoof`) estiment `verificationGasLimit` en simulant `validateUserOp` avec une signature factice et en
ignorant l'échec. Le gas consommé par la factice doit être celui d'une signature valide.

**Décision.** `_verifyHybrid` appelle les deux vérifieurs puis combine les résultats. La factice
recommandée côté wallet est une vraie signature hybride sur un digest fixe : tous les contrôles de
structure passent, seule la comparaison finale échoue, le coût est celui du chemin nominal (test
`test_7702_stubSignature_costsLikeValidOne`). Alternative écartée : un mode spoof gardé par `tx.origin`
comme Ambire, qui ajoute une surface (origine contrôlée en simulation seulement) pour le même résultat.

**Conséquences.** Une signature ECDSA fausse coûte le prix d'une vérification post-quantique complète ;
sans conséquence sur les userOps (le bundler rejette avant inclusion), ni sur `executeWithHybridSig`
(le relayeur paie).

## ADR-007 — 2026-09-07 — Deux pots : vault 4337 sans clé EOA, satellite 7702 lié

**Contexte.** Sous 7702, la clé secp256k1 de l'EOA reste une autorité de niveau protocole sur tout ce qui
est à l'adresse de l'EOA (ADR-005). Aucun code délégué ne peut rendre ces fonds résistants au quantique.

**Décision.** Le pot PQ est un clone 4337 de `ZKNOX_PQAccount7702` (le vault), sans clé EOA. L'EOA
délègue vers un second contrat, le satellite, qui ne fait pas de vérification PQ (elle protégerait un pot
que la clé EOA vide de toute façon, pour 0,8 à 1,3 M gas par opération) mais lie l'EOA au vault :
`sweep` public vers le vault, vault autorisé à exécuter à travers l'EOA, ERC-1271 relayé au vault.
Deux contrats plutôt qu'un seul à deux modes : validations sans rien en commun, et le code PQ n'a pas à
vivre dans le contexte de l'EOA.

**Conséquences.** L'EOA dépense le pot PQ en relayant une signature hybride (`executeWithHybridSig`),
jamais par `msg.sender == EOA`. Pour agir avec `msg.sender == EOA` sous signature hybride, le vault pousse
les fonds vers l'EOA puis appelle `satellite.execute` dans le même batch ; les fonds ne transitent par
l'EOA que le temps de la tx. La fenêtre non-PQ des fonds entrants est le délai entre réception et `sweep`.
Les clés du vault peuvent différer de la clé EOA pour le facteur pré-quantique ; recommandé.

## ADR-008 — 2026-09-07 — Front : un cœur sans React, une UI sans viem, un adaptateur

**Contexte.** La démo vivait dans un seul composant avec sa simulation. Le vrai front doit parler aux
contrats déployés, rester testable sans réseau, et pouvoir être repris par un autre wallet (Kohaku).

**Décision.** `WalletAdapter` est l'interface entre l'UI et la chaîne : `read()` plus une méthode par
action (eoaSend, moveToVault, link, sweep, createVault, vaultSend, sendAsPublic, moveToPublic,
signWrapped, shield/unshield optionnels, faucet optionnel). `SimulationAdapter` et `ViemWalletAdapter`
l'implémentent ; l'UI ne dépend que de l'interface. La référence de clé post-quantique (pointeur SSTORE2)
n'est pas persistée côté client : elle est retrouvée en énumérant `CREATE(verifier, n)` jusqu'à retrouver le
haché stocké, et le vault est retrouvé par l'événement `AccountCreated` de la factory indexé sur le haché de
la clé pré-quantique. Le front est donc sans état au-delà de la mnémonique.

**Conséquences.** Deux tests d'égalité octet pour octet avec le signer Python (blob de clé, signature)
tiennent lieu de contrat entre le front et les vérifieurs ; la dérivation de seed est figée par un vecteur
dans le test, à aligner avec l'app Ledger. Le chemin bundler est écrit sur viem (EntryPoint v0.8) mais seul
le chemin `handleOps` local est couvert par le test anvil.
