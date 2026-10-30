# ADR 0005 — Ordre d'évaluation, flux internes et exemption LLM

- Statut : accepté — 2026-10-30

## Décision
1. Socle commun (ordre de position), non contournable.
2. Règles de la zone de l'agent (première correspondance).
3. Destination interne (réseaux `internal_networks`, défaut RFC 1918 + fc00::/7, ou autre agent) non traitée par une règle : acceptation implicite « interne surveillé », journal détaillé — [Killian] « surveiller seulement ». Une règle de zone explicite peut toujours refuser (EF-07).
4. Nettoyage implicite : refus.

- Une règle portant des classes de données ne correspond que si l'une d'elles est détectée dans le contenu. Les règles à classes de données sont ignorées pour une destination de catégorie `llm_provider` (EF-25) ; le contenu reste masqué dans les journaux.
- Zone en observation : un refus est journalisé `observed` et la connexion passe (EF-12). Le socle « métadonnées cloud » reste appliqué même en observation (choix le plus sûr).
- Agent inconnu (IP non enrôlée) : refus.
- Numéro de règle = rang global (socle puis zone), recalculé à chaque publication.
