# DECISIONS.md : architecture decision records

## ADR-001 (2026-09-15) Politique hybride par la structure des owners, sans code de validation côté Safe

**Contexte.** Objectif : k owners ECDSA ET k owners post-quantiques par transaction, en réutilisant
`ZKNOX_PQAccount7702` tel quel, et sans dégrader la sécurité classique si le vérifieur PQ est faux. Un Safe a
un seul seuil, aveugle au type d'owner.

**Décision.** Deux politiques. NESTED : root 2/2 dont les owners sont `S_ecdsa` (EOA, seuil k) et `S_pq`
(clones PQ, seuil k), sémantique exacte (k parmi n) ET (k parmi n). SINGLE : un Safe, seuil T >= nE + k et
T >= nP + k, plus simple mais T signatures au lieu de 2k. Aucune modification du Safe, aucun guard ni module :
le Safe appelle `isValidSignature` du clone comme pour n'importe quel owner contrat.

**Conséquences.** NESTED est recommandée. Coût mesuré pour k = 2 : 2 534 864 gas par exécution. Les
signatures PQ passent par le handler de `S_pq` (SafeMessage) puis par le wrap EIP-712 du clone.

## ADR-002 (2026-09-15) Safe 1.5.0 requis, root migré en place

**Contexte.** Safe 1.4.1 appelle `isValidSignature(bytes data, bytes sig)` (magic `0x20c13b0b`) ; le compte PQ
n'expose que `isValidSignature(bytes32, bytes)`. Le Safe existant est en 1.4.1.

**Décision.** Tout Safe ayant un owner PQ direct, et le root, sont en 1.5.0. Le root garde son adresse :
migration par DELEGATECALL vers le `SafeMigration` canonique (`migrate[L2]WithFallbackHandler`, saveur L1/L2
conservée), puis reconfiguration. Alternative écartée : un adaptateur legacy sur le compte PQ (code de plus
dans le périmètre audité, pour une version de Safe qu'on quitte de toute façon).

**Conséquences.** Vérifié par `test_safe141_rejectsPQOwner` et `test_migrate141_then_nested`.

## ADR-003 (2026-09-15) Sources Safe compilées à part dans les tests, bytecode canonique en production

**Contexte.** Le projet hérite des réglages de `../contracts` (via-IR, runs 1e6, requis par les noyaux
ML-DSA packés). Safe 1.5.0 ne compile pas en via-IR (stack too deep).

**Décision.** Profil de compilation additionnel `safe` (pipeline legacy, 200 runs) restreint aux sources
Safe et à `test/safe/`. Les tests déploient Safe depuis les artefacts (`deployCode`), résolus par
`compilationTarget` car 1.4.1 et 1.5.0 partagent noms de fichiers et de contrats. `src/` ne dépend que
d'interfaces, jamais des sources Safe ni pq-account.

**Conséquences.** Les tests exercent la logique Safe, pas le bytecode déployé ; les scripts ciblent les
adresses canoniques, surchargeables par variables d'environnement.

## ADR-004 (2026-09-15) Lens sans état plutôt qu'un guard

**Contexte.** Il faut empêcher une configuration qui ne respecte pas la politique (module, handler non fiable,
seuil trop bas, owner PQ qui n'en est pas un).

**Décision.** Contrat de lecture `ZKNOX_SafePQLens`, appelé en dernier dans le batch de reconfiguration
(revert atomique de la transaction Safe) et par les scripts. Pas de guard : la politique découle déjà des
owners et des seuils, un guard ajoute un risque de blocage et ne voit pas le chemin module.

**Conséquences.** Contrôle ponctuel : une transaction ultérieure autorisée par la politique peut changer la
configuration. `signedMessages` et allowances antérieurs restent hors de portée du lens.

## ADR-005 (2026-09-15) Owners PQ : clones épinglés, EOA 7702 refusées

**Contexte.** `checkNSignatures` accepte une signature ECDSA brute de toute adresse owner via `ecrecover`. Une
EOA déléguée en 7702 vers `ZKNOX_PQAccount7702` reste donc signable avec sa seule clé k1.

**Décision.** Côté PQ, seuls les clones ERC-1167 initialisés d'une implémentation donnée sont acceptés.
L'implémentation épingle la paire de vérifieurs. Côté ECDSA, seules les EOA sans code : une EOA déléguée
répondrait aux signatures contrat avec le code de sa délégation.

**Conséquences.** `test_7702DelegatedOwner_bypassesPQ` montre le contournement ; le lens et
`DeployNestedSafes` le refusent. Un clone d'une autre paire de vérifieurs (par exemple défaillante) n'est pas
reconnu comme owner PQ.

## ADR-006 (2026-09-15) Migration et reconfiguration en deux transactions

**Contexte.** `MultiSendCallOnly` refuse les DELEGATECALL internes ; `MultiSend` complet permettrait de tout
enchaîner.

**Décision.** Deux transactions : migration, puis batch `MultiSendCallOnly` d'auto-appels (retrait des
modules, ajout de `S_ecdsa` et `S_pq`, retrait des anciens owners en utilisant `S_ecdsa` comme prédécesseur,
seuil 2, contrôle du lens). Le `safeTxHash` du second pas est calculable avant le premier : type hash et
domaine identiques en 1.4.1 et 1.5.0.

**Conséquences.** Les owners signent les deux hash d'avance ; la version est observable entre les deux pas.
Mesuré : migration 61 046 gas, reconfiguration 239 782 gas (4 owners, 1 module, contrôle du lens).

## ADR-007 (2026-09-15) Pas de chemin de secours ECDSA seul

**Contexte.** Root 2/2 : si le côté PQ devient inutilisable (vérifieur qui rejette des signatures valides,
clés perdues au-delà de n - k), le root est bloqué, remplacer `S_pq` exigeant une signature de `S_pq`. Les
adresses des vérifieurs sont des immutables du clone.

**Décision.** Aucun module de récupération ECDSA seul n'est fourni : il supprimerait la résistance quantique.
La marge de disponibilité se règle par n > k de chaque côté.

**Conséquences.** Arbitrage à trancher explicitement avant mise en production.


## ADR-008 — Signataires post-quantiques en ML-DSA-65, clé dans le calldata

**Contexte**

Les tests tournaient sur ML-DSA-44 avec la clé en pointeur SSTORE2, soit un
`postQKeyRef` de 20 octets. ETHDILITHIUM a depuis retiré le chemin pointeurs du
65 (son ADR-007) : la clé étendue de 38 112 octets voyage dans le calldata de
chaque vérification et rien ne s'installe on-chain.

**Décision**

Les owners post-quantiques du Safe sont des clones ML-DSA-65 à clé calldata.

Aucun contrat de ce dépôt ne change. `ZKNOX_SafePQLens` reconnaît un owner PQ
au code hash de son clone ERC-1167, indépendamment du vérifieur épinglé dans
l'implémentation. `ZKNOX_SafePQSignatures.hybridPayload` garde sa forme,
`abi.encode(preQKey, preQSig, postQKey, postQSig)` : seul `postQKey` passe de
20 à 38 112 octets. `ZKNOX_PQAccount7702` est inchangé, son `postQKeyHash`
portant désormais sur la clé entière.

Ce qui change est l'outillage de test : la fixture produit clés et signatures
par `scripts/mldsa65.mjs`, appelé en `vm.ffi` sur le signeur js d'ETHDILITHIUM,
tout étant dérivé d'une seed de 32 octets par détenteur. Le signeur Python du
44 n'est plus utilisé.

**Conséquences**

- Une exécution NESTED avec k = 2 coûte 4 949 950 gas au total : 21 000
  d'intrinsèque, 1 084 444 de calldata pour 84 580 octets, 3 844 506
  d'exécution.
- **La taille de transaction devient la contrainte dominante.** Chaque owner
  post-quantique ajoute 41 824 octets de payload. geth refuse de relayer
  au-delà de 128 Ko, ce qui plafonne le côté PQ à **k = 3** (environ 126 Ko) et
  rend k = 4 impossible sur le chemin mempool. Le test
  `test_nested_exec_2ecdsa_2pq` contrôle la borne.
- Rien à déposer avant d'ajouter un signataire : créer un clone suffit, là où
  le chemin pointeurs du 65 aurait demandé 59,2 M de gas par clé après
  EIP-8037.
- `scripts/bootstrap.sh` épingle ETHDILITHIUM sur `mldsa65-calldata`
  (`ETHDILITHIUM_REF` pour surcharger) et installe les paquets npm du signeur.
- Le passage au 65 relève la sécurité de la catégorie NIST 2 à la 3, ce qui
  n'était pas le moteur de la décision mais en est le bénéfice.


## ADR-009 — Signeur matériel : le digest, pas le rejeu d'un vecteur

**Contexte**

ETHDILITHIUM `mldsa65-calldata` @ fcfc3fe ajoute des vecteurs produits par l'app
Ledger ecml-signer sous speculos : clé publique du device, digest signé,
signature. On veut démontrer la chaîne du matériel jusqu'à `execTransaction`.

Ce n'est pas rejouable tel quel. Le device a signé un digest choisi à
l'enregistrement du vecteur ; un owner de Safe signe
`nestedOwnerDigest(S_pq, clone, safeTxHash)`, qui dépend des deux adresses de
Safe, de l'adresse du clone, du chain id et de la transaction. Faire coïncider
les deux serait une préimage EIP-712.

**Décision**

Démontrer ce qui tient sans la clé secrète du device, et écrire la pièce qui
manquait plutôt que simuler celle qui manque toujours.

`test/SafePQDeviceKey.t.sol` prend la clé publique du device, en fait un owner
post-quantique d'un Safe, contrôle que le clone l'enregistre, que le lens la
classe en `PQ_CLONE` et que la politique NESTED tient. Il calcule le digest que
le device doit signer pour une transaction donnée et l'affiche. Il vérifie que
les trois signatures du device passent sur le vérifieur ML-DSA-65 qu'utilise le
chemin Safe, et que digest modifié ou bit retourné sont refusés. Il vérifie
enfin qu'une signature portant sur un autre digest ne passe pas l'ERC-1271 du
compte, ce qui est précisément pourquoi le rejeu est impossible.

`Sigs.nestedOwnerDigest(sPq, pqAccount, safeTxHash)` ramène la chaîne complète à
un appel, et `script/PqOwnerDigest.s.sol` l'imprime pour un Safe réel, owner par
owner. L'app ecml-signer signant un digest de 32 octets arbitraire par
`HYBRID_SIGN_HASH`, c'est la seule valeur à lui transmettre, la moitié k1 étant
signée sur les mêmes octets.

**Alternatives écartées**

- *Monter un Safe dont le digest tombe sur celui du vecteur.* Préimage EIP-712.
- *Mocker la vérification pour un test « bout en bout » vert.* Un test qui ne
  prouve rien et qui donne l'illusion inverse.

**Conséquences**

- La boucle se ferme par une exécution du device sur le digest imprimé. Rien
  d'autre ne manque côté contrats.
- `nestedOwnerDigest` est la primitive que tout signeur appellera, matériel ou
  logiciel.
- Le test épingle le chemin de `ecml_device_vectors.json` chez ETHDILITHIUM : si
  ce fichier bouge, le test le dit.


## ADR-010 — Démo : `approveHash` plutôt que la signature en une transaction

**Contexte**

Deux chemins mènent à l'exécution d'une transaction du root. Soit les
signatures voyagent dans le `signatures` de son `execTransaction`, soit chaque
enfant appelle `root.approveHash(safeTxHash)` et le root s'exécute avec deux
créneaux `v = 1` de 65 octets.

Trois faits, relevés dans le code de l'infrastructure Safe au 2026-10-22,
départagent les deux :

- l'endpoint de confirmation du Transaction Service plafonne une signature à
  **5 000 octets** (`SIGNATURE_LENGTH`, `history/serializers.py`), ce qui
  interdit de faire circuler une signature ERC-1271 post-quantique par l'API ou
  le SDK ; l'endpoint de proposition n'a, lui, aucun `max_length` ;
- le Client Gateway, par lequel passe `app.safe.global`, parse le blob
  séquentiellement et suppose qu'une partie dynamique suit immédiatement sa
  partie statique. C'est juste pour **une** signature contrat, faux à partir de
  deux, donc faux pour notre root dont les deux owners sont des Safes. Le
  comportement est derrière le drapeau `FF_SIGNATURE_VERIFICATION_PROPOSAL`,
  dont la valeur en production n'est pas observable ;
- Safe{Wallet} sait en revanche faire signer un Safe owner d'un autre Safe, par
  `approveHash`, qu'il appelle « on-chain signature »
  (`useNestedSafeOwners`, `dispatchOnChainSigning`). La fonctionnalité
  `NESTED_SAFES` est active sur Sepolia, dont la version recommandée est 1.5.0.

**Décision**

Pour la démonstration, passer par `approveHash`. Chaque enfant approuve le
`safeTxHash` du root depuis sa propre transaction, puis le root s'exécute avec
deux créneaux de hash approuvé.

Le poids se déplace là où il ne gêne personne : la transaction du root tombe de
84 166 à **130 octets de signature** et redevient une transaction Safe
ordinaire, exécutable depuis l'interface. Seule la transaction `approveHash` de
`S_pq` porte les deux clés étendues, 84 324 octets de calldata, et part en
direct au RPC.

`ExecNestedTx` reste le chemin en une transaction, pour les cas sans interface.

**Conséquences**

- Mesuré : `S_pq.approveHash` 2 833 882 d'exécution, 3 936 958 au total, soit
  au-dessus du plancher EIP-7623 de 2 726 190 et bien sous le plafond EIP-7825
  de 16 777 216. Le root s'exécute ensuite pour 67 786.
- Le côté ECDSA n'a besoin d'aucun outil : Safe{Wallet} produit son
  `approveHash` nativement.
- Trois transactions au lieu d'une, pour un total de gas un peu supérieur. On
  échange du gas contre l'usage de l'interface, ce qui est le bon arbitrage
  pour une démonstration.
- `checkNSignatures` dispense d'`approveHash` l'owner qui exécute lui-même
  (`executor == currentOwner`), ce qui permet d'économiser une transaction si
  `S_ecdsa` lance l'exécution du root.
- `test_nested_approveHash_path` mesure les deux tailles et encadre la
  transaction de `S_pq` par le plancher et le plafond.


## ADR-011 — Le front recalcule les condensats au lieu de les lire

**Contexte**

`app/apps/safe-signer` doit afficher à chaque détenteur les 32 octets qu'il va
signer. Trois sources étaient possibles : appeler `PqOwnerDigest` côté script,
lire le condensat depuis un RPC (`clone.hashWrapped`), ou le recalculer en
TypeScript à partir des paramètres du Safe.

Le détenteur ne dispose que d'une chose pour se protéger : comparer les 64
caractères à l'écran de son appareil. Cette comparaison ne vaut que si l'écran
et l'appareil tiennent leur valeur de deux chemins indépendants. Un condensat
lu sur un RPC que la page ne contrôle pas ne vaut rien : qui tient le RPC tient
la signature.

**Décision**

Tout est recalculé localement : `safeTxHash`, `safeMessageHash`, `hashWrapped`,
et la clé étendue ML-DSA-65 de 38 112 octets. La chaîne n'est interrogée que
pour ce qu'elle seule sait — nonces, owners, seuils, approbations, `keyHashes`
— et pour **confirmer** le `safeTxHash` dérivé contre le `getTransactionHash`
du Safe lui-même. Tant que les deux ne coïncident pas, la page n'affiche aucun
condensat.

Le prix est une seconde implémentation de `ZKNOX_SafePQSignatures`, qui dérive.
`test/SafePQFrontFixture.t.sol` écrit `test/fixtures/front.json` et
`app/packages/safe/test/fixture.test.ts` le reconstruit depuis les mêmes
graines : condensats des deux chemins, clé étendue, charge hybride, le blob de
83 842 octets par son keccak, et les chiffres de gas affichés avant l'envoi.

**Conséquences**

- Le condensat du chemin `approveHash` est **une** enveloppe du `safeTxHash` de
  `S_pq`, pas la chaîne à trois couches de `nestedOwnerDigest`. Les deux sont
  dans la fixture et le test vérifie qu'ils diffèrent : se tromper produit une
  signature que le Safe rejette sans rien dire.
- La clé étendue est vérifiée avant l'appareil : `keccak256(clé)` contre le
  `postQKeyHash` du clone. Une erreur attrapée là coûte une seconde, attrapée
  sur la chaîne elle coûte un revert à 3,9 M de gas.
- La page n'a pas besoin du Transaction Service ni d'une clé d'API pour
  fonctionner ; l'arrangement voyage dans l'URL.
- `DeployLocalNested.s.sol` déploie les singletons Safe sur anvil, ce qui rend
  le chemin complet jouable hors chaîne publique. Il faut
  `--gas-estimate-multiplier` : forge enregistre le gas de l'appel simulé, qui
  n'inclut pas le coût intrinsèque des 38 Ko de calldata, et la transaction
  partirait avec une limite inférieure à son propre coût intrinsèque — le nœud
  l'accepte et ne peut jamais la miner.


## ADR-012 — Safe App plutôt que fork de Safe{Wallet}

**Contexte**

Pour que la signature post-quantique soit prise en charge « nativement », le
réflexe est de forker `safe-global/safe-wallet-monorepo`. Lecture du code des
trois dépôts le 2026-10-23 :

- `MultisigConfirmation.signature` du Transaction Service est une **colonne**
  plafonnée à 5 000 octets (`utils/constants.py:2`, `history/models.py:1954`).
  L'endpoint de proposition n'a pas de `max_length`, mais sa signature est
  découpée par `SafeSignature.parse_signature` et écrite dans ces mêmes lignes.
  Une signature 1271 de 41 824 octets ne peut donc pas être stockée, quel que
  soit le front ;
- côté UI il n'y a au contraire **aucun plafond ni contrôle de taille** :
  `validateTxSignatures` saute explicitement les signatures contrat. Le mur est
  entièrement côté service ;
- mais le Transaction Service **indexe l'événement `ApproveHash`** et le
  transforme en confirmation ordinaire de 65 octets
  (`history/indexers/tx_processor.py:755`, `SafeSignatureApprovedHash`).

Forker l'UI seule ne débloque donc rien, et le chemin `approveHash` d'ADR-010
n'a besoin de rien : la file du root affiche « 2 of 2 » toute seule.

**Décision**

Pas de fork. `app/apps/safe-signer` est ajouté comme **Safe App personnalisée**
(`AddCustomAppModal` accepte n'importe quelle URL servant un `manifest.json`,
sans revue ni listing), et utilise le SDK pour se configurer :

- `sdk.safe.getInfo()` donne le Safe, la chaîne, les owners, le seuil, le nonce
  et la version ;
- ouverte sur le root, la page trouve les deux enfants et les départage en
  demandant `keyHashes()` à leurs owners. Rien à saisir ;
- toutes les lectures passent par le proxy RPC de l'hôte : plus de champ RPC,
  donc plus d'URL à fournir ni à divulguer.

**Conséquences**

- Le SDK n'expose **pas** `eth_sendRawTransaction`, et le `sendTransactions` de
  l'hôte proposerait une transaction *du Safe affiché*, c'est-à-dire celle qu'on
  est en train de construire. Le dernier pas sort donc du cadre : portefeuille,
  clé de relayeur avec `VITE_RPC_URL_<chainId>`, ou fichier téléchargé — le bac
  à sable de l'hôte autorise `allow-downloads`.
- Ouverte sur `S_pq`, la page reconnaît l'enfant mais pas son parent : un Safe
  ne peut pas être interrogé sur qui le possède. Le root est donné une fois.
- `public/host.html` rejoue le protocole Safe Apps contre un RPC, avec les mêmes
  attributs de bac à sable, pour que le chemin hébergé soit exercé et non
  supposé. Il ne signe rien et n'applique aucune permission.
- Ce qu'un fork coûterait, si la question revient : `apps/web/src` fait 3 823
  fichiers et 401 761 lignes, en **GPL-3.0** ; la zone de signature
  (`apps/web/src/services/tx`) bouge d'environ 21 commits par trimestre. Et il
  faudrait de toute façon forker aussi le Transaction Service (migration de la
  colonne) et le Client Gateway, dont `parseSignaturesByType` suppose qu'une
  partie dynamique suit immédiatement sa partie statique — juste pour une
  signature contrat, faux à partir de deux.

## ADR-013 — L'appareil parle à la page, par WebHID

**Contexte**

Jusqu'ici le signeur matériel passait par `safe/scripts/ecml.mjs` : le porteur
copiait le condensat de la page, lançait une commande, ouvrait le JSON produit
et recollait quatre champs dans un formulaire. Le dernier, la clé étendue, fait
38 112 octets, soit 76 226 caractères hexadécimaux. Éprouvé sur Sepolia le
2026-10-27 : la chaîne complète fonctionne mais ne se montre pas, et chaque
copie est une occasion de tronquer silencieusement la valeur sur laquelle la
transaction entière repose.

Le protocole, lui, n'a rien de spécifique à Node : CLA `0xE0`, cinq
instructions, des lectures par morceaux de 255 octets. Un navigateur Chromium a
WebHID.

**Décision**

Le dialogue APDU est porté dans `app/packages/safe/src/ledger.ts`, avec le
**transport injecté** :

```ts
export type Apdu = (ins, p1, p2, data?) => Promise<Uint8Array>;
```

`app/apps/safe-signer/src/webhid.ts` fournit l'implémentation navigateur par
`@ledgerhq/hw-transport-webhid`, et ne contient rien d'autre que le transport.
`ledgerSigner` rend un `Signer`, la même interface que le porteur logiciel de
`signer.ts`, donc le front traite les deux identiquement.

`LedgerAccounts` garde les comptes lus entre les owners et cherche celui dont
`keccak256(clé étendue)` égale le `postQKeyHash` du clone, en balayant
`m/44'/60'/0'/i'/0'`. Le porteur clique « sign on the device » et n'a plus de
chemin de dérivation à connaître.

**Conséquences**

- Le chemin matériel est **testé** pour la première fois, sans matériel :
  `packages/safe/test/ledger.test.ts` fait tourner 20 tests contre une fausse
  app qui reproduit l'aliasing mémoire du vrai signeur. `GET_PUBLIC_KEY` et
  `KEYGEN_DILITHIUM` partagent une union avec la signature ML-DSA ; l'un des
  deux entre `HYBRID_SIGN_HASH` et les lectures par morceaux détruit ce qui est
  en train d'être lu. La fausse app refuse alors de répondre, donc la règle est
  vérifiée et non documentée.
- `signWithAccount` ne redemande jamais l'adresse k1 à l'appareil après `0x16`,
  justement à cause de cette union : elle vient du compte déjà lu. Et elle
  compare la clé renvoyée après signature à celle lue avant, ce qui attrape un
  appareil qui aurait changé de compte en cours de route.
- Un balayage coûte neuf APDU par compte, environ une seconde. Le cache rend le
  second owner immédiat, puisque c'est presque toujours un autre compte du même
  appareil.
- WebHID exige un contexte sécurisé et un geste de l'utilisateur, et **n'est pas
  accordé à une iframe de bac à sable** : dans Safe{Wallet} le bouton est
  remplacé par la raison. La page le dit et renvoie vers un onglet propre, où le
  lien de `session.ts` porte déjà toute la configuration.
- `@ledgerhq/hw-transport` construit ses trames avec `Buffer`, absent du
  navigateur. Une ligne dans `main.tsx` le pose sur `globalThis`, et nulle part
  ailleurs : le reste de l'application parle `Uint8Array` et `Hex`.
- Les champs de collage restent, derrière « paste from the command line
  instead ». Un porteur sur Firefox, ou un appareil sur une autre machine que
  celle qui tient la page, en a encore besoin — et `ecml.mjs` reste la référence
  contre laquelle le portage a été écrit.

## ADR-014 — Un seul chemin logique, deux moitiés : correction d'ADR-009

**Contexte**

ADR-009 et le client de `safe/scripts/` posaient qu'un chemin devait être
**entièrement durci**, au motif qu'ECML-Signer durcit la dérivation ML-DSA et
pas la secp256k1, et qu'un chemin mixte donnerait deux moitiés étrangères l'une
à l'autre. Lecture du code de l'app le 2026-10-27, `ZKNoxHQ/ecml-signer` à
`e2fee68` :

- `src/crypto/mldsa_derive.c` force `| 0x80000000u` sur chaque composant avant
  `os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10, …)`, parce que
  SLIP-0010 en mode ed25519 l'exige. Son commentaire dit l'intention : « so
  callers can pass a "logical" path (like the standard m/44'/60'/0'/0/0 they use
  for ECDSA) […] ECDSA half sees the raw path, ML-DSA half sees the hardened
  variant » ;
- la moitié k1 passe par `bip32_derive_ecdsa_sign_hash_256` avec
  `G_context.bip32_path` **tel quel** (`src/ui/action/validate.c:45`) ;
- aucun handler ne contrôle le durcissement. `get_public_key.c`,
  `pq_keygen.c`, `hybrid_sign_hash.c` lisent le chemin par
  `buffer_read_bip32_path`, qui ne regarde pas les bits.

Le garde-fou refusait donc exactement l'entrée pour laquelle l'app est écrite.

**Décision**

`packDerivationPath` accepte les deux formes, `requireHardened` passe à `false`
par défaut dans les deux implémentations (`safe/scripts/ecml-core.mjs` et
`app/packages/safe/src/ledger.ts`). Le balayage de `LedgerAccounts` essaie les
deux familles, `m/44'/60'/0'/0/i` d'abord puisque c'est le cas courant, puis
`m/44'/60'/0'/i'/0'`.

**Conséquences**

- Avec un chemin logique, la moitié k1 d'un clone **est** le compte ordinaire
  que Rabby, MetaMask et `forge --ledger` dérivent. L'aller-retour entre
  ECML-Signer et l'app Ethereum, qui a coûté une bonne heure le 2026-10-27,
  n'était pas une contrainte de l'appareil mais une conséquence de ce
  garde-fou.
- La clé ML-DSA ne dépend pas du choix : les deux formes aboutissent au même
  chemin durci. `m/44'/60'/0'/0/0` et `m/44'/60'/0'/0'/0'` donnent la même clé
  post-quantique et deux adresses k1 différentes.
- D'où un piège que `LedgerAccounts.find` doit éviter : chercher l'appareil par
  `postQKeyHash` seul peut rendre la bonne clé ML-DSA avec le mauvais
  partenaire k1. La recherche prend les deux condensats, et le front dit lequel
  des deux a manqué.
- Les clones déjà déployés sur Sepolia et Hoodi restent valides, liés aux
  adresses k1 des chemins durcis. Ils ne sont pas pilotables par un portefeuille
  standard du côté k1, ce qui est sans effet sur l'arrangement — la moitié
  ECDSA de la politique vient de `S_ecdsa`, pas de la moitié k1 des clones.
- Un prochain arrangement se crée avec `m/44'/60'/0'/0/i`. Les défauts de
  `ecml.mjs` gardent la forme durcie, pour qu'une commande sans `--path`
  continue de correspondre aux clones existants.

## ADR-015 — Fork de Safe{Wallet} : le clone devient le wallet connecté (renverse ADR-012)

**Contexte**

ADR-012 écartait le fork : forker l'UI ne déplace pas le plafond de 5 000 octets du Transaction Service, et
le chemin `approveHash` affichait déjà « 2 of 2 » sans rien forker. Deux faits sont venus depuis.

- ADR-013 : WebHID n'est pas accordé à l'iframe d'une Safe App. Dans Safe{Wallet}, `safe-signer` ne peut
  donc pas faire signer l'appareil ; le détenteur doit rouvrir la page dans un onglet à part, avec son lien.
- La démonstration Sepolia du 2026-10-27 a montré le parcours entier, et ce qu'il demande : quitter la file
  de Safe{Wallet} pour signer, rassembler les réponses de chacun, envoyer une transaction de 84 Ko.

Demande du 2026-10-27 : créer les comptes post-quantiques et demander les signatures dans Safe lui-même.

Relecture de `safe-global/safe-wallet-monorepo` à `23b47f4` (2026-10-27) : Safe{Wallet} sait déjà faire
signer un owner **contrat**, sans signature hors chaîne.

- `components/tx/shared/hooks.ts:148` : si le wallet connecté a du code, `signTx` passe par
  `dispatchOnChainSigning`, qui demande au wallet `eth_sendTransaction {to: safe, data: approveHash(h)}`.
- `utils/nested-safe-wallet.ts:95` : même chose pour un owner d'un Safe imbriqué (root ← `S_pq` ← clone) :
  proposition non signée de la transaction de `S_pq`, puis `approveTransactionHash`.
- `dispatchTxExecution` fait de même pour l'exécution, et Safe compte l'exécutant owner comme sa propre
  approbation.
- Le Transaction Service indexe `ApproveHash` en confirmation de 65 octets avec `owner = msg.sender`
  (`history/indexers/tx_processor.py:760`), et la première confirmation rend « trusted » une proposition
  non signée (`history/signals.py:85`).

**Décision**

Fork d'`apps/web` seul, branché sur le Client Gateway et le Transaction Service publics :
`ZKNoxHQ/safe-wallet-monorepo`, branche `zknox/pq`.

- Le compte post-quantique devient un **wallet web3-onboard** dont le compte est le clone.
  `@zknox/pq-provider` (`app/packages/provider`) en est le provider EIP-1193 : il transforme ce
  `eth_sendTransaction` en `clone.executeWithHybridSig([{to, value, data}], deadline, sig)`, signé sur
  l'ECML-Signer et payé par un wallet de navigateur que le détenteur choisit (EIP-6963). Le clone est
  `msg.sender` de l'appel intérieur. **Aucun contrat ne change.**
- Chaque détenteur confirme **seul**, on-chain, comme n'importe quel owner contrat. Plus de collecte, plus
  de coordinateur, rien de plus de 65 octets ne passe par l'API.
- Le condensat `hashExecute` est recalculé localement et confirmé contre celui du clone avant que
  l'appareil ne soit sollicité, pour la raison d'ADR-011.
- Les méthodes de signature hors chaîne répondent 4200 : une signature 1271 de 41,8 Ko ne tient dans
  aucun canal hors chaîne.
- Création : le compte post-quantique se crée dans le dialogue de connexion (`createAccount`, payé par le
  même wallet) ; l'arrangement NESTED par `/new-safe/pq`, dont `planArrangement`
  (`app/packages/safe/src/arrangement.ts`) reprend les sels de `CreateArrangement.s.sol` : mêmes owners,
  mêmes trois adresses, chacun peut finir ce que l'autre a commencé.
- Le code post-quantique est **copié octet pour octet** dans `packages/pq` du fork par
  `packages/pq/scripts/sync.mjs`, qui écrit le commit source dans `src/PIN` et dont `--check` échoue sur
  toute différence. Les tests restent ici, contre la Solidity et sur une chaîne ; une copie ne vaut ces
  tests que si elle porte les mêmes octets.

**Conséquences**

- Mesuré sur anvil (`app/packages/provider/test/provider.anvil.test.ts`) : une confirmation 1,87 M gas pour
  42 212 octets de calldata ; le second détenteur confirme et exécute en une transaction, 1,87 à 1,93 M.
  Le côté `S_pq` d'une transaction du root coûte ~3,8 M pour k = 2, contre 3,94 M groupé (ADR-010).
- **Le plafond k ≤ 3 d'ADR-008 tombe** : chaque transaction fait ~42 Ko, quel que soit k.
- Chaque détenteur a besoin d'un wallet payeur financé. La moitié k1 de l'appareil ne sert pas de payeur :
  elle ne signe une transaction Ethereum qu'en aveugle par `0x16`, au prix d'une ML-DSA calculée pour rien.
- L'appareil signe un condensat (signature aveugle) ; le dialogue l'affiche en huit groupes à comparer.
- Une transaction **proposée** par un détenteur post-quantique arrive non signée, donc non « trusted », et
  le devient à sa première confirmation on-chain.
- WebHID : Chromium seulement. `safe-signer` reste, pour Firefox, pour un appareil branché sur une autre
  machine, et pour le chemin groupé d'ADR-010.
- Empreinte sur le code amont : onze fichiers touchés, une quarantaine de lignes (enregistrement du
  wallet, montage du dialogue, deux points d'entrée, une route, les alias, et l'avertissement de solde que
  Safe{Wallet} affichait pour le clone alors que c'est le payeur qui paie), plus `yarn.lock`. Le reste est
  neuf, dans `apps/web/src/features/pq` et `packages/pq`, ce qui garde le rebase sur l'amont mécanique.
- Ouvert au 2026-10-27 : l'accès du fork, servi sur un autre origin, au Client Gateway public. `curl`
  reçoit 403 avec ou sans origin, ce qui désigne un filtrage de l'user-agent et non une politique CORS ;
  le test décisif est un `fetch` depuis un navigateur. S'il échoue, un relais devant le gateway suffit, le
  reste ne change pas.

## ADR-016 — Vérifier un déploiement : octets, liens, métadonnées

**Contexte**

Au 2026-10-28, rien n'avait comparé les contrats ML-DSA déployés sur Sepolia et Hoodi à leurs sources. La
démonstration prouvait qu'ils acceptent des signatures valides, pas qu'ils exécutent le code de ce dépôt,
et aucune vérification n'était publiée sur un explorateur.

Deux faits relevés en préparant la vérification :

- les métadonnées de **tous** les contrats compilés dans `safe/` portent deux remappings absolus,
  `erc4626-tests/` et `halmos-cheatcodes/`, que Foundry détecte dans les sous-modules d'OpenZeppelin. Le
  bytecode n'en dépend pas, le hash IPFS des métadonnées (trailer CBOR) si ;
- l'implémentation est créée par le constructeur du factory : elle est compilée dans l'unité du factory, où
  son fichier porte un autre nom (`../contracts/src/…`) que dans son propre artefact (chemin absolu, via
  le remapping `pq-account/`). Son trailer diffère donc de celui de son artefact, sur la même machine.

**Décision**

`safe/scripts/verify-deployment.mjs`, Node seul (Keccak-256 compris), sur un `forge build --ast` :

- par contrat : runtime on-chain, immutables masqués, contre l'artefact (`code`) ; chaque immutable relu et
  comparé à l'adresse attendue (liens) ; le CID des métadonnées recalculé et comparé au trailer (`exact`) ;
- l'implémentation est découpée dans le code de création du factory, et ses métadonnées renommées par
  keccak256 des sources de l'unité du factory ;
- `--origin-root` réécrit le chemin du dépôt de la machine de compilation dans les métadonnées avant
  hachage : `exact` devient atteignable depuis n'importe quel répertoire ;
- le helper Keccak est comparé octet pour octet au fichier, et à `F1600_CODEHASH` ;
- les contrats Safe canoniques par code hash (`@safe-global/safe-deployments` 1.37.65), les proxies par
  le runtime que produit `proxyCreationCode` du factory canonique, puis l'arrangement en descendant du root ;
- toutes les lectures épinglées à un bloc.

`make safe-verify-deployed` construit le commit qui a enregistré les déploiements (`bbe9be8`) dans un
worktree `.verify/` et lance la vérification.

**Conséquences**

- Le commit compte : le lens importe `ISafeView.sol`, modifié en `604af99`. Son bytecode est identique à
  `main`, ses métadonnées non.
- Testé sur anvil, au-dessus du runtime Safe 1.5.0 publié sur npm (`@safe-global/safe-smart-account`
  1.5.0, hachages égaux à ceux de safe-deployments) : `exact` partout ; `code` pour les cinq contrats compilés
  depuis un autre répertoire, `exact` avec `--origin-root` ; `MISMATCH` sur un octet modifié du helper ou du
  vérifieur ; `FAIL` sur un immutable réécrit ou un guard posé.
- Le helper `f1600_170.hex` est celui de fireblocks-labs/evm-ml-dsa-verifier à `cca262b`, reconstruit par
  leur `tools/build_f1600_batch.py --check` depuis `f1600_core.hex` ; le cœur lui-même n'a pas de chemin
  de reconstruction (générateur perdu, selon leur README).
- À trancher pour le prochain déploiement : `auto_detect_remappings = false` dans `safe/foundry.toml`
  (tous les remappings nécessaires dans `remappings.txt`), et le commit source écrit dans chaque
  `deployments/*.json`. Les deux rendent `exact` atteignable sans `--origin-root` ni recherche du commit.
