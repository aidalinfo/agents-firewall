# Résultats de la recette

Environnement `demo/` (une passerelle, zones `internes`/`clients`, daniel-bot Hermes factice, laurent-bot,
acme-bot, services factices hermétiques), état purgé puis `demo/up.sh` et `demo/scenarios/run-all.sh`, le
2026-10-31, sur `dev` (CLI `afw` et `afw-mcp` fusionnées, PR #17) + correctifs du lot L13 (ADR 0027), avec la CLI
(sessions, publication, installation, « Autoriser », jeton de passerelle, enrôlement) et `afw-mcp` (scénario 10).
Résultat : **20 PASS, 0 FAIL, 0 SKIP**.

| Fichier | Contenu |
|---|---|
| `results.md`, `results.json` | Résultat et preuves de chaque scénario (sortie de `run-all.sh`). |
| `latency.json`, `latency-passes.tsv` | Scénario 12 : p50/p95 par passe et médianes, avec et sans passerelle. |
| `measures.json` | Scénario 20 : refus → flux ouvert ; appel d'outil → agent/conversation/action/contenu/règle. |
| `allow-ui-timing.json` | « Autoriser » dans la console (clic sur le refus → installation → l'agent passe). |

Lecture des mesures :
- **Latence** (HTTPS inspecté par le proxy explicite, 5 × 50 requêtes, médiane des passes) : surcoût p50 4,9 ms /
  p95 5,6 ms en connexion nouvelle, 0,9 ms / 0,7 ms en connexion réutilisée (médianes calculées séparément pour
  chaque statistique, d'où un p95 inférieur au p50 ; à ce niveau, le bruit de mesure domine). Une passe antérieure
  identique donnait 7,2 / 12,3 ms et 0,3 / 1,4 ms. Le service factice (Python) répond en
  ~40 ms, base commune aux deux chemins.
- **Refus → flux ouvert par l'API** : médiane 0,95 s (max 1,1 s), lot d'événements envoyé chaque seconde par la passerelle.
- **Flux → agent, conversation, action, contenu, règle** : médiane 0,83 s (max 0,84 s) après l'appel d'outil ; les deux appels
  d'API eux-mêmes ≈ 60 ms.
- **« Autoriser » dans la console** : 5,8 s du clic sur le refus à l'installation confirmée, 7,2 s jusqu'au premier
  passage effectif de l'agent (critère : < 2 min). Par la CLI (`afw allow` → `afw session publish` → `afw install`,
  scénario 02) : 4 s jusqu'au passage de l'agent.
- **Bot Hermes en une commande** (scénario 11) : `afw enroll … --compose --hermes --publish … --apply` crée l'agent et son
  jeton, transforme le compose, publie et démarre le bot en 6 s ; refusé avant installation, il suit sa zone après.
