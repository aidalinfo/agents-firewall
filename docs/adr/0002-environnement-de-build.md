# ADR 0002 — Builds Rust dans un conteneur Linux

- Statut : accepté — 2026-10-30

## Contexte
La règle de session impose de ne pas lancer de build local et de passer par le runner Sève. Le runner Sève fourni ne contient ni `cargo`, ni compilateur C, ni éditeur de liens, ni Docker ; ses sorties réseau sont limitées au port 443. La passerelle dépend de Linux (nftables, `SO_ORIGINAL_DST`) et la recette exige des conteneurs.

## Décision
- Rust : `scripts/cargo.sh` exécute cargo dans l'image officielle `rust:1.91-bookworm` (volumes de cache partagés, `target` isolé par worktree, mémoire bornée). Rien n'est installé sur le poste.
- Console et plugin : `seve run` / `seve test` quand c'est possible (Node 24 présent), sinon conteneur `node:24` / `python:3.12`.
- La recette se fait localement dans Docker, comme demandé.
- CI GitHub Actions (modèle maison) : CI complète sur PR vers `main`, nightly sur `dev`, e2e séparé, aucune release automatique.

## Conséquences
Les résultats de tests cités dans le rapport proviennent de ces conteneurs.
