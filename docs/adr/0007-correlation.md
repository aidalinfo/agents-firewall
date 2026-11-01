# ADR 0007 — Corrélation intention ↔ flux

- Statut : accepté — 2026-10-30

## Décision
Le plugin Hermes envoie début et fin de chaque appel d'outil à l'API. L'API rattache un flux à l'appel d'outil actif du même agent au moment du flux :
- `certain` : un seul appel actif et le flux commence dans sa fenêtre ;
- `probable` : plusieurs appels actifs, on retient le plus récent ;
- `uncertain` : aucun appel actif, appel le plus proche dans les 5 s précédentes.
L'interface affiche la confiance. eBPF et en-têtes injectés sont écartés (privilèges, contournables).
