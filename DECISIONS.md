# DECISIONS.md : architecture decision records du dépôt

Les décisions propres à un périmètre restent dans `contracts/DECISIONS.md` et `safe/DECISIONS.md`.

## ADR-001 (2026-10-22) Un dépôt pour le compte, le Safe et le front

**Contexte**

Le compte hybride, son intégration Safe et le front vivaient dans trois dépôts, dont deux n'ont jamais
été poussés. `safe-pq-signers` atteignait `pq-account-7702` par un lien symbolique vers un checkout
voisin, posé par un script de bootstrap qui repointait aussi ETHDILITHIUM par nom de branche.

Deux jours de travail ont montré le couplage réel : le passage de ML-DSA-44 à 65, puis la clé en
calldata, ont tous deux obligé à modifier les deux dépôts ensemble. Le front, lui, a besoin du cœur
ML-DSA du compte et de la chaîne de digests du Safe.

**Décision**

Un seul dépôt, `pq-wallet`, avec `contracts/`, `safe/`, `app/` et un `lib/` partagé en submodules git
épinglés par commit.

Les vérifieurs restent dehors : ETHDILITHIUM, ETHFALCON et InterfaceVerifier sont des bibliothèques avec
leur propre cycle de vie, leur propre public et leurs propres EIP. Ce sont des dépendances, pas des
parties de ce dépôt.

**Alternatives écartées**

- *Trois dépôts avec de vrais submodules.* Résout la fragilité du lien symbolique mais pas le couplage :
  chaque changement de vérifieur resterait trois commits dans trois dépôts, à coordonner à la main.
- *Tout fusionner, vérifieurs compris.* ETHDILITHIUM est public, utilisé ailleurs, et porte les EIP-8051
  et 8052. L'absorber le retirerait à ses autres usages.

**Conséquences**

- Un seul pin d'ETHDILITHIUM pour tout le dépôt, au lieu de deux indirects. Déplacer ce pin se fait par
  un commit de submodule, et les deux suites disent tout de suite ce qui casse : c'est ainsi que la
  rupture du ML-DSA-44 en calldata est apparue en construisant ce dépôt.
- Un `foundry.toml` par périmètre, parce que les sources Safe exigent le pipeline historique quand les
  noyaux ML-DSA exigent via-IR. Les deux coexistent par `additional_compiler_profiles`.
- Le périmètre d'audit se dit à l'auditeur, il ne se code plus en frontière de dépôt. Le besoin de
  Kohaku, un dépôt externe lié avec un avertissement, est satisfait par celui-ci.
- Les pins sont des commits, jamais des noms de branche, y compris sur les branches expérimentales. Un
  clone construit le même bytecode quand la branche aura bougé.
