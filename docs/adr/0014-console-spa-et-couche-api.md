# ADR 0014 — Console : SPA Nuxt, couche `AfwApi` et données de démonstration

- Statut : accepté — 2026-10-30
- Lot : L3 (console sur maquette, données mock)

## Contexte

La console (Nuxt 4 + Nuxt UI 4, décision [Killian]) doit reproduire la maquette
`docs/design/maquette/project/*.dc.html` avant que l'API (lots L7a/b/c) et le contrat OpenAPI (L0)
n'existent. Elle ne doit porter aucune logique métier : tout ce qu'elle affiche vient de l'API
(« API d'abord », la CLI et le MCP ont la même portée).

## Décisions

1. **SPA servie par Nitro.** `ssr: false`, preset `node-server`. La console est un pur client de l'API ;
   le jeton (OIDC ou jeton d'API) est gardé dans `sessionStorage` et envoyé en `Authorization: Bearer`.
   Pas de rendu serveur : aucun secret ni cookie de session à gérer côté Nitro, et l'image ne contient
   que des fichiers statiques et un petit serveur.
2. **Une interface, deux implémentations.** `app/api/client.ts` définit `AfwApi` (une méthode par
   ressource du §3.4 du plan maître). `app/api/http.ts` l'implémente avec `fetch` vers
   `${NUXT_PUBLIC_API_BASE}/api/v1` (erreurs `application/problem+json` → `ApiError`, 401 → retour à
   l'écran de connexion, flux SSE `logs/stream` lu par `fetch` pour pouvoir envoyer le jeton).
   `app/api/mock.ts` est une implémentation **à état** qui simule le plan de contrôle (insertion d'une
   règle avant le nettoyage avec renumérotation, session, publication de la révision 43, installation,
   chaîne d'audit) sur les données de la maquette (`mock-data.ts`). Le choix se fait par
   `NUXT_PUBLIC_API_MODE=mock|http` (mock par défaut en développement, `http` par défaut dans l'image).
3. **Types miroir, régénérés en L3b.** `app/api/types.ts` reprend les noms snake_case du §3. Points non
   fixés par le §3 et tranchés ici (à confirmer par `docs/api/openapi.yaml`) :
   - énumérations Rust à données étiquetées sur `type` (`NetObjectSpec`, `Layer`, `Detector`) ;
   - vues de lecture propres à l'API : `FlowSummary` (noms d'agent/zone, `rule_label` « S3 » ou « 12 »,
     corrélation), `FlowDetail` (avec `trace` : la **trace d'évaluation** calculée par le moteur,
     `agent_message`, `allow_proposal`), `RuleView` (numéro affiché, compteurs, `in_session`,
     `previous_number`), `NetObjectView`, `ZoneView`, `AgentOverview`, `InternalMap`, `FlowStats` ;
   - `POST /sessions/{id}/allow-from-log` reçoit `{ flow_id, destination: exact|group|wildcard,
     expires_in_days, track }` ; les options proposées viennent de `allow_proposal` dans le détail du flux ;
   - routes ajoutées : `GET /logs/flows/stats`, `POST /alerts/{id}/ack`, `GET /auth/oidc/login`.
   L3b remplace `types.ts` par les types générés (`openapi-typescript`) et adapte `http.ts`.
4. **Thème.** Les jetons de la maquette (`--bg`, `--panel`, `--pri`, `--ok`, `--ko`, `--warn`, `--obs`…)
   sont définis en clair sur `:root` et en sombre sur `.dark` (sombre par défaut, `@nuxtjs/color-mode`),
   exposés à Tailwind 4 (`bg-panel`, `text-text3`…) et reportés sur les variables Nuxt UI (`--ui-*`).
   Polices Geist et Geist Mono via `@nuxt/fonts` (fichiers servis par la console). Icônes lucide
   embarquées (`@iconify-json/lucide`), aucun appel réseau à l'exécution.
5. **Langues.** `@nuxtjs/i18n`, français par défaut quelle que soit la langue du navigateur, anglais
   disponible ; le choix est mémorisé localement. Un test vérifie la parité des clés et que chaque clé
   utilisée existe. Les textes libres renvoyés par l'API (commentaires, résumés) ne sont pas traduits.
   Le message de refus EF-21 (anglais côté protocole) est traduit par l'interface.
6. **Actions de création hors parcours.** Les boutons « Nouvel objet », « Section », « Règle »,
   « Changer de zone » renvoient pour l'instant vers la CLI (toast) : le seul parcours d'écriture
   complet de L3 est « Autoriser… » → session → publier → installer (EF-42), plus la réinstallation
   d'une révision, l'acquittement d'alerte et les commandes de passerelle.

## Conséquences

- La console se développe et se démontre sans plan de contrôle ; les tests de montage rejouent le
  parcours « Autoriser » complet sur le mock.
- Toute divergence entre `types.ts` et le contrat OpenAPI de L0 se règle en L3b, dans `types.ts` et
  `http.ts` uniquement : les pages ne dépendent que de `AfwApi`.
- Le mock contient une simulation simplifiée de la renumérotation et de la vérification : elle ne fait
  pas foi, le moteur (`afw-engine`) et l'API restent la référence.
