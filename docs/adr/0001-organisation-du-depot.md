# ADR 0001 — Organisation du dépôt

- Statut : accepté — 2026-10-30

## Contexte
La conception conseille un monorepo Rust + Nuxt (section 14). Plusieurs lots doivent avancer en parallèle sans se marcher dessus.

## Décision
Workspace cargo `crates/*` avec une crate par responsabilité : `afw-core` (contrats), `afw-engine`, `afw-dlp`, `afw-tls`, `afw-gateway`, `afw-api`, `afw-client`, `afw-enroll`, `afw-import`, `afw-cli`, `afw-mcp`. Console dans `console/` (pnpm), plugin dans `integrations/hermes/`, déploiement dans `deploy/`, recette dans `demo/`. Les versions de dépendances sont centralisées dans `[workspace.dependencies]`.

## Conséquences
Chaque lot possède ses répertoires ; les fichiers communs (Cargo.toml racine, afw-core) sont figés en L0 et ne changent qu'au travers d'une PR dédiée.
