# Résultats de la recette

Environnement `demo/` (une passerelle, zones `internes`/`clients`, daniel-bot Hermes factice, laurent-bot,
acme-bot, services factices hermétiques), état purgé puis `demo/up.sh` et `demo/scenarios/run-all.sh`, le
2026-10-31, sur `dev` + correctifs du lot L13 (ADR 0027). Résultat : **19 PASS, 0 FAIL, 1 SKIP** (11, CLI non fusionnée).

| Fichier | Contenu |
|---|---|
| `results.md`, `results.json` | Résultat et preuves de chaque scénario (sortie de `run-all.sh`). |
| `latency.json`, `latency-passes.tsv` | Scénario 12 : p50/p95 par passe et médianes, avec et sans passerelle. |
| `measures.json` | Scénario 20 : refus → flux ouvert ; appel d'outil → agent/conversation/action/contenu/règle. |
| `allow-ui-timing.json` | « Autoriser » dans la console (clic sur le refus → installation → l'agent passe). |

Lecture des mesures :
- **Latence** (HTTPS inspecté par le proxy explicite, 5 × 50 requêtes, médiane des passes) : surcoût p50 7,2 ms /
  p95 12,3 ms en connexion nouvelle, 0,3 ms / 1,4 ms en connexion réutilisée. Le service factice (Python) répond en
  ~40 ms, base commune aux deux chemins.
- **Refus → flux ouvert par l'API** : médiane 0,94 s (max 1,1 s), lot d'événements envoyé chaque seconde par la passerelle.
- **Flux → agent, conversation, action, contenu, règle** : médiane 0,83 s après l'appel d'outil ; les deux appels
  d'API eux-mêmes ≈ 60 ms.
- **« Autoriser » dans la console** : 6,0 s du clic sur le refus à l'installation confirmée, 7,1 s jusqu'au premier
  passage effectif de l'agent (critère : < 2 min). Par l'API (scénario 02) : 2 s.
