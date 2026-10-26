# Une démonstration de bout en bout sur Sepolia

De rien à : un Safe dont les signatures post-quantiques viennent d'un Ledger, exécuté depuis
Safe{Wallet} sans qu'aucun de ses composants ne soit forké.

Ce que la démonstration prouve, et que rien de ce dépôt ne prouve aujourd'hui : que le Transaction Service
indexe bien `ApproveHash` en confirmation ordinaire, que la file du root bascule donc seule à « 2 of 2 »,
que Safe{Wallet} charge la page en Safe App, et qu'un appareil réel produit une signature que la chaîne
accepte. Les quatre reposent pour l'instant sur des lectures de code.

## Ce qu'il faut avant de commencer

| | |
|-|-|
| un Ledger | Nano X, Nano S+, Stax, Flex ou Apex. **Pas de Nano S** (`ledger_app.toml`) |
| des ETH Sepolia | quelques dixièmes sur le déployeur et sur le relayeur |
| un RPC Sepolia | `export RPC=…` ; un nœud public suffit, mais il doit accepter un corps de requête de 85 ko |
| un compte Safe{Wallet} | rien à installer, l'interface web suffit |
| trois EOA | les owners classiques de `S_ecdsa`. Des comptes Ledger ou des clés chaudes de test |

Vérifier d'abord que Safe 1.5.0 est bien là où le dépôt le croit. Les adresses canoniques de
`src/libraries/ZKNOX_SafeDeployments.sol` sont celles de `@safe-global/safe-deployments` et Sepolia les
utilise, mais une vérification coûte une commande :

```bash
cast code 0xFf51A5898e281Db6DfC7855790607438dF2ca44b --rpc-url $RPC | head -c 20
cast code 0x14F2982D601c9458F93bd70B218933A6f8165e7b --rpc-url $RPC | head -c 20
cast code 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4 --rpc-url $RPC | head -c 20
```

Et ce que l'interface annonce pour la chaîne, en particulier la version recommandée et les drapeaux :

```bash
curl -s https://api.safe.global/chains/11155111 | jq '{recommendedMasterCopyVersion, features}'
```

## 1. L'application Ledger

Les artefacts de production sont versionnés dans le dépôt `ZKNoxHQ/ecml-signer`, sous
`build/<target>/bin/app.{elf,apdu}` — `nanos2` pour le Nano S+, `nanox`, `stax`, `flex`, `apex_p`. Pas
besoin de reconstruire.

```bash
git clone https://github.com/ZKNoxHQ/ecml-signer.git
cd ecml-signer
# Linux : les règles udev, une fois
sudo cp .vscode/20-ledger.ledgerblue.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules && sudo udevadm trigger
python3 -m venv .venv && . .venv/bin/activate && pip install ledgerblue
python3 -m ledgerblue.runScript --scp --fileName build/nanos2/bin/app.apdu --elfFile build/nanos2/bin/app.elf
```

Reconstruire plutôt qu'installer le binaire fourni, si tu préfères : l'image
`ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest`, puis `make BOLOS_SDK=$NANOSP_SDK` et
`make load` dans le conteneur.

**Puis, sur l'appareil : ouvrir ECML-Signer, aller dans ses Settings et activer _Blind signing_.** Il est
désactivé à l'installation, et `HYBRID_SIGN_HASH` répond `0xB00A` tant qu'il l'est. C'est l'erreur la plus
probable de toute cette page.

## 2. Lire les clés de l'appareil

```bash
cd ~/Desktop/github/pq-wallet/safe/scripts && npm install && cd ..
node scripts/ecml.mjs key --path "m/44'/60'/0'/0'/0'" --out keys/holder-1.hex
```

Le chemin doit être **entièrement durci**. L'app durcit chaque composant du chemin ML-DSA et aucun du
chemin secp256k1 : avec `m/44'/60'/0'/0/0` les deux moitiés ne viennent pas du même arbre, et le compte
refusera les signatures sans rien expliquer. Le script refuse un chemin non durci.

Il imprime l'adresse secp256k1 — que l'app ne renvoie pas, elle est recalculée côté hôte — et écrit les
38 112 octets de la clé ML-DSA-65 étendue. L'app ne connaît que la forme compacte de 1 952 octets ;
l'expansion est faite ici avec l'encodeur d'ETHDILITHIUM.

Répéter pour chaque détenteur, sur son propre appareil : `holder-2.hex`, `holder-3.hex`. Pour une première
démonstration, un seul appareil et deux chemins différents font l'affaire, à condition d'assumer que le
seuil ne protège alors de rien.

## 3. Déployer la pile ML-DSA-65

`contracts/script/DeployPQAccount7702.s.sol` déploie la pile ML-DSA-**44**, celle du wallet de démo. Le
côté Safe tourne en ML-DSA-**65**, le schéma que l'ECML-Signer produit : il lui faut sa propre factory.

```bash
export RPC=…
export SENDER=0x…            # le compte Ledger qui paie
make safe-deploy-pq65
```

Écrit `safe/deployments/11155111-pq65.json` : le helper f1600, le vérifieur k1, `ZKNOX_dilithium65`, la
factory, l'implémentation clonée et le lens. À commiter, c'est le relevé de ce qui est en ligne.

## 4. Créer un owner post-quantique par détenteur

```bash
export FACTORY=$(jq -r .factory deployments/11155111-pq65.json)
K1_ADDRESS=<celle imprimée à l'étape 2> KEY_FILE=keys/holder-1.hex make safe-create-owner
```

Le script vérifie après coup que le clone stocke bien `keccak256` des deux clés. Une erreur attrapée là
coûte une seconde ; la même, découverte à la première signature, coûte un revert à 3,9 M de gas.

Noter les trois adresses de clones.

## 5. Les deux enfants, puis le root

```bash
export PQ_IMPLEMENTATION=$(jq -r .pqImplementation deployments/11155111-pq65.json)
export LENS=$(jq -r .lens deployments/11155111-pq65.json)

ECDSA_OWNERS=0x…,0x…,0x… PQ_OWNERS=0x…,0x…,0x… K=2 make safe-deploy-children
S_ECDSA=0x… S_PQ=0x… K=2 FUND=100000000000000000 make safe-create-root
```

`DeployNestedSafes` refuse de créer quoi que ce soit si un owner annoncé comme EOA n'en est pas un, ou si
un owner post-quantique n'est pas un clone initialisé de l'implémentation donnée. `CreateRootSafe` vérifie
la politique NESTED après création et échoue plutôt que de laisser un arrangement qui ne tient pas.

Le root est créé par script et non dans l'interface parce que le lens exige **1.5.0** partout, et que la
version créée par Safe{Wallet} dépend de ce que la configuration de la chaîne recommande ce jour-là.

Ouvrir ensuite `https://app.safe.global/home?safe=sep:<root>` : l'indexeur a vu la création du proxy, le
Safe s'ouvre normalement.

## 6. Publier la page

```bash
cd ~/Desktop/github/pq-wallet/app/apps/safe-signer
BASE=/Safe-PQ/ pnpm exec vite build
```

Ou laisser le workflow `.github/workflows/safe-signer-pages.yml` le faire : Settings → Pages → Source :
GitHub Actions, et chaque poussée sur `main` publie. L'URL est alors
`https://zknoxhq.github.io/Safe-PQ/`.

Safe{Wallet} va chercher `<l'URL collée>/manifest.json` depuis le navigateur, donc en cross-origin :

```bash
curl -sI https://zknoxhq.github.io/Safe-PQ/manifest.json | grep -i 'access-control-allow-origin\|^HTTP'
```

S'il n'y a pas d'en-tête CORS, l'ajout échouera sans message utile ; il faut alors servir depuis un hôte
qui en met un.

Dans Safe{Wallet}, sur le root : **Apps → My custom apps → Add custom Safe App**, coller l'URL, accepter.
Aucune revue, aucun référencement.

## 7. Proposer la transaction

Dans Safe{Wallet}, sur le root, une transaction ordinaire : un envoi de 0,01 ETH. La proposer, ne pas
l'exécuter. Relever son `safeTxHash` dans les détails.

## 8. Faire signer les détenteurs

Ouvrir la Safe App depuis le root. Le bloc 1 se remplit seul : elle lit le Safe par le SDK, trouve les deux
enfants et les départage en demandant `keyHashes()` à leurs owners. Dans le bloc 2, onglet « hash only »,
coller le `safeTxHash`.

Le bloc 3 affiche un condensat de 32 octets par owner. Pour chacun :

```bash
cd ~/Desktop/github/pq-wallet/safe
node scripts/ecml.mjs sign --path "m/44'/60'/0'/0'/0'" --digest 0x<le condensat affiché> --out answers/holder-1.json
```

L'appareil affiche `Signer: ECDSA + ML-DSA-65` et le hash. **Comparer les 64 caractères à l'écran avec ceux
de la page avant d'approuver.** C'est la seule protection du détenteur, et toute l'architecture de la page
existe pour la rendre possible : le condensat y est recalculé localement, jamais lu sur un service.

Coller les quatre champs du fichier produit dans le formulaire de l'owner. La page refuse tout de suite une
clé qui ne hache pas vers le `postQKeyHash` du clone.

Deux détenteurs suffisent pour k = 2.

## 9. Envoyer l'approbation de S_pq

Le bloc 4 annonce la taille — autour de 84 ko — et le plancher EIP-7623 avant que le bouton ne fasse quoi
que ce soit. L'envoi sort du cadre de la Safe App : le SDK n'expose pas `eth_sendRawTransaction`. Trois
voies, dans l'ordre de préférence :

- un portefeuille injecté, s'il y en a un dans le navigateur ;
- `VITE_RELAYER_KEY_11155111` et `VITE_RPC_URL_11155111` dans le build, pour une démonstration ;
- « download the transaction », puis `cast send --rpc-url $RPC --ledger --data @…` depuis n'importe où.

Le relayeur paie le gas et n'autorise rien : n'importe quel compte convient.

## 10. Exécuter depuis Safe{Wallet}

Côté ECDSA, Safe{Wallet} sait faire seul : sur `S_ecdsa`, ses owners signent l'`approveHash` du root — ce
que l'interface appelle « on-chain signature ».

Puis retourner sur le root. **C'est ici que la démonstration se joue** : si l'indexeur a fait son travail,
la file affiche « 2 of 2 » sans que personne n'ait rien poussé, parce que les deux `ApproveHash` ont été
transformés en confirmations ordinaires de 65 octets. Exécuter.

```bash
cast call <root> "approvedHashes(address,bytes32)(uint256)" <S_pq> <safeTxHash> --rpc-url $RPC
```

doit rendre `1` pour chacun des deux enfants avant l'exécution.

## Si ça ne marche pas

| symptôme | cause la plus probable |
|-|-|
| `0xB00A` sur `sign` | blind signing désactivé dans les Settings de l'app |
| `0x6d00` | une autre app est ouverte sur l'appareil |
| le compte refuse la signature | chemin non entièrement durci, ou mauvais condensat signé |
| l'ajout de la Safe App échoue | pas d'en-tête CORS sur `manifest.json`, ou URL en http |
| la file reste à « 1 of 2 » après l'approbation de S_pq | c'est le résultat qui invalide l'option A : l'indexeur n'a pas transformé l'événement. Relever le bloc et le hash, c'est la donnée intéressante |
| le RPC refuse la transaction de S_pq | corps de requête trop gros chez ce fournisseur ; en essayer un autre |

## Ce qui reste non couvert après ça

Un relayeur qui paie, donc un lien observable entre lui et le Safe. Le chemin L1, dont l'indexation passe
par les traces et non par les événements. Et la clé de l'appareil qui n'a pas de sauvegarde autre que la
phrase du Ledger : ADR-007 note qu'il n'y a pas de voie de récupération ECDSA seule sur le root 2-sur-2, et
c'est à trancher avant tout usage réel.
