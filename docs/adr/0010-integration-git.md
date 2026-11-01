# ADR 0010 — Intégration : branches de lot et PR vers dev

- Statut : accepté — 2026-10-30

## Décision
Un lot = une branche `lot/<id>-<nom>` dans son worktree, une PR vers `dev`, revue indépendante avant fusion. Jamais de push sur `main`. Après chaque fusion, la suite complète (Rust, console, plugin) est relancée sur `dev`.
