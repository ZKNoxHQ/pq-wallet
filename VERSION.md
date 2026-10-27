# VERSION.md : changelog du dépôt

Ce fichier suit la disposition du dépôt et les pins. Le détail par périmètre reste dans
`contracts/VERSION.md` et `safe/VERSION.md`, et les décisions dans les `DECISIONS.md` correspondants.

## [0.9.0] 2026-10-27 : l'appareil parle à la page

### Added
- `app/packages/safe/src/ledger.ts` : le dialogue APDU de l'ECML-Signer, transport injecté. `ledgerSigner`
  rend un `Signer`, la même interface que le porteur logiciel, et `LedgerAccounts` trouve le compte dont
  `keccak256(clé étendue)` égale le `postQKeyHash` du clone en balayant `m/44'/60'/0'/i'/0'`.
- `app/apps/safe-signer/src/webhid.ts` : l’implémentation navigateur, par `@ledgerhq/hw-transport-webhid`.
  Elle ne contient que le transport, et `webHidObstacle()` dit pourquoi il n'est pas disponible plutôt que
  d'afficher un bouton mort.
- `app/packages/safe/test/ledger.test.ts` : 20 tests contre une fausse app qui reproduit l'aliasing mémoire
  du vrai signeur. Le chemin matériel avait zéro couverture jusqu'ici. Voir ADR-013 dans
  `safe/DECISIONS.md`.

### Changed
- Bloc 3 du front : un bouton « sign on the device » remplace la copie du condensat, la commande dans un
  terminal et le recollage de 76 226 caractères hexadécimaux. Les champs manuels restent derrière
  « paste from the command line instead ».

## [0.8.1] 2026-10-26 : les cibles de test construisent d'abord

### Fixed
- `make test-safe` échouait sur `artifact not found` dans un clone neuf. Les sources Safe sont compilées
  sous leur propre profil et atteintes uniquement par `deployCode` : rien ne les importe, donc `forge test`
  ne les produit pas. `test-safe`, `test-safe-gas`, `safe-front-fixture` et `test-contracts` dépendent
  maintenant de leur cible de construction. Relevé sur un clone depuis zéro, qui est le seul test du dépôt.

## [0.8.0] 2026-10-23 : de quoi faire la démonstration sur Sepolia

### Added
- `safe/SEPOLIA.md` : le parcours complet, de l'installation de l'app Ledger à l'exécution depuis
  Safe{Wallet}, avec ce que chaque étape prouve et la table des pannes probables.
- `safe/scripts/ecml.mjs` et `ecml-core.mjs` : le côté hôte de l'ECML-Signer. L'app ne rend ni l'adresse
  secp256k1 ni la clé étendue, et renvoie la moitié k1 en **DER avec un `v` de parité** là où
  `ECDSAk1Verifier` lit 65 octets `r||s||v` avec v dans {27,28}. Les trois conversions sont isolées dans
  `ecml-core.mjs` et couvertes par 9 tests sans appareil.
- `safe/script/DeployPqStack65.s.sol` : la pile ML-DSA-**65** sur une chaîne qui a déjà Safe 1.5.0. Celle
  de `contracts/` est en ML-DSA-44 et ne convient pas aux owners d'un Safe.
- `safe/script/CreatePqOwner.s.sol` : un clone depuis la clé d'un appareil, lue dans un fichier (38 ko de
  hex ne passent pas confortablement par une variable d'environnement), avec vérification des `keyHashes`.
- `safe/script/CreateRootSafe.s.sol` : le root 2-sur-2, créé par script pour que la version soit
  certaine, avec contrôle de la politique après création.
- `.github/workflows/safe-signer-pages.yml` et `BASE` dans la config Vite : la page publiée sur GitHub
  Pages sous `/<repo>/`.
- Cibles `safe-deploy-pq65`, `safe-create-owner`, `safe-create-root`.

### Changed
- `.gitignore` : seuls les déploiements de chaîne locale sont ignorés. Celui d'un réseau public est le
  relevé de ce qui est en ligne et se commite.

### Vérifié, et ce qui ne l'est pas
Adresses Safe 1.5.0 sur Sepolia confirmées contre `@safe-global/safe-deployments` 1.37.65. Les scripts
compilent et `CreatePqOwner` a été exercé contre un factory local. Le chemin appareil n'est couvert par
aucun test : il n'y a pas de Ledger en intégration continue, et les quatre affirmations qui portent
l'option A restent des lectures de code jusqu'à la démonstration elle-même.

### Tests
contracts 48/48, safe 25/25, app : core 3, ui 2, safe 32, safe-signer 4.

## [0.7.0] 2026-10-23 : le front devient une Safe App

### Added
- `app/apps/safe-signer/src/safeApp.ts` : connexion au SDK Safe Apps, transport viem par-dessus le proxy
  RPC de l'hôte, et `discover()` qui déduit l'arrangement du Safe affiché — ouverte sur le root, la page
  trouve les deux enfants et les départage en demandant `keyHashes()` à leurs owners. Plus de champ RPC,
  plus d'adresses à saisir.
- `app/apps/safe-signer/public/host.html` : hôte de développement qui rejoue le protocole Safe Apps contre
  un RPC, avec les attributs de bac à sable de Safe{Wallet}, pour exercer le chemin hébergé sans
  app.safe.global.
- `app/apps/safe-signer/test/discover.anvil.test.ts` : 4 tests de découverte contre l'arrangement déployé
  (root, S_pq, S_ecdsa, une adresse qui n'est pas un Safe). Ils sautent sans chaîne.
- Bouton « download the transaction » : le bac à sable de l'hôte autorise les téléchargements, et c'est la
  seule sortie quand ni portefeuille ni clé de relayeur n'est joignable.

### Decided
Pas de fork de Safe{Wallet}. `MultisigConfirmation.signature` est une colonne plafonnée à 5 000 octets côté
Transaction Service, donc aucun front ne peut y loger une signature 1271 de 41 824 octets ; mais le service
indexe l'événement `ApproveHash` en confirmation ordinaire de 65 octets, et la file du root affiche « 2 of
2 » sans rien forker. Voir `safe/DECISIONS.md` ADR-012.

### Fixed
- En mode hébergé, l'URL RPC configurée n'est plus effacée : le relayeur en a besoin pour diffuser, et à
  défaut la page le dit au lieu de se rabattre sur le RPC public d'une chaîne.

### Tests
contracts 48/48, safe 25/25, app : core 3, ui 2, safe 23, safe-signer 4.

## [0.6.0] 2026-10-22 : le front qui recueille les signatures post-quantiques

### Added
- `app/packages/safe` (`@zknox/pq-safe`) : le versant TypeScript de `safe/`. ML-DSA-65 et sa clé étendue
  de 38 112 octets, la chaîne de condensats, l'empaquetage des signatures Safe, le plan `approveHash`,
  les lectures de chaîne, le Transaction Service en lecture seule, et un détenteur logiciel pour la
  démonstration. 23 tests.
- `app/apps/safe-signer` : la page, servable aussi comme Safe App. Quatre blocs — l'arrangement et sa
  politique, la transaction du root, les owners post-quantiques avec leur condensat, l'envoi avec la
  taille et le gas annoncés avant le bouton. Voir `safe/DECISIONS.md` ADR-011.
- `safe/test/SafePQFrontFixture.t.sol` et `safe/script/DeployLocalNested.s.sol` : le vecteur contre lequel
  le TypeScript est vérifié, et tout l'arrangement sur anvil pour jouer le chemin complet.
- Cibles : `make safe-signer`, `make safe-deploy-local`, `make safe-front-fixture`.

### Decided
Le front **recalcule** chaque condensat au lieu de le lire. Un condensat lu sur un RPC que la page ne
contrôle pas ne peut pas être vérifié par le détenteur, et cette vérification contre l'écran de
l'appareil est la seule protection qu'il ait. Le prix est une seconde implémentation de
`ZKNOX_SafePQSignatures` ; la fixture Forge l'empêche de dériver, octet par octet.

### Tests
contracts 48/48, safe 25/25, app : core 3 (+12 passés sur anvil), ui 2, safe 23/23.

## [0.5.0] 2026-10-22 : fusion en un dépôt, dépendances en submodules épinglés

### Changed
- `pq-account-7702` et `safe-pq-signers` deviennent un seul dépôt, `pq-wallet` : `contracts/`, `safe/`,
  `app/`, et `lib/` partagé. Voir DECISIONS.md ADR-001.
- Les dépendances passent de deux scripts de bootstrap et d'un lien symbolique à de vrais **submodules
  git épinglés par commit** : ETHDILITHIUM `mldsa65-calldata` @ ccdc874, ETHFALCON
  `exp/pq-verifier-gas` @ 012e080, InterfaceVerifier @ e655a5f, safe-smart-account v1.5.0 @ dc437e8 et
  v1.4.1 @ bf943f8. Un clone construit désormais le même bytecode sans dépendre de la disposition des
  répertoires voisins.
- Un `makefile` racine pilote les trois périmètres ; `contracts/makefile` et `safe/makefile`
  disparaissent. `scripts/bootstrap.sh` remplace les deux anciens.
- Les deux `foundry.toml` pointent `libs = ["../lib"]`, et les remappings suivent. `safe/` atteint le
  compte par `pq-account/=../contracts/src/` au lieu du lien symbolique.

### Fixed
- **ML-DSA-44 en calldata** (ETHDILITHIUM ADR-010) : la fixture de `contracts/` produisait la clé par
  `PythonSigner.getPubKey`, qui passe un troisième argument vide que le générateur rejette désormais.
  Elle demande maintenant explicitement le format `flat`, et lit la clé normalisée comme ce que rend
  `setKey` plutôt qu'en recalculant un pointeur SSTORE2. Falcon, qui dépose toujours sa clé, surcharge
  `_normalizedPostQuantumKey` avec le pointeur. Le compte lui-même est inchangé : il ne garde que le
  `keccak256` de ce que le vérifieur lui rend, quelle qu'en soit la forme.

### Tests
contracts 48/48, safe 25/25.
