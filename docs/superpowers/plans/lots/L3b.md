# L3b — Console branchée sur l'API réelle — plan de lot

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal :** la console (lot L3) consomme exactement le contrat `docs/api/openapi.yaml` : types générés,
client `openapi-fetch` typé, mock réécrit sur les formes du contrat, sessions de politique (`X-Afw-Session`),
gestion 202/401/409/423, journal en direct (SSE réel), formulaires de création et de modification (EF-44),
test d'intégration de bout en bout contre l'API Rust réelle.

**Architecture :** `app/api/schema.d.ts` est généré (`pnpm gen:api`, `openapi-typescript`) et vérifié à jour
par un test. `app/api/types.ts` ne contient plus que des alias vers `components['schemas']` et quelques types
de requête propres à la console. `AfwApi` (`client.ts`) suit les opérations du contrat ; `http.ts` les
implémente avec `openapi-fetch` (`createClient<paths>`), `mock.ts` les simule avec des données de démonstration
aux formes du contrat. Les noms affichés (agent, zone, objet…) sont résolus côté console à partir des listes
de l'API (présentation, aucune décision de politique). La console Nitro peut relayer `/api/**` vers l'API
(`NUXT_API_PROXY_TARGET`) pour rester sur la même origine (CSP `connect-src 'self'`, pas de CORS).

**Tech Stack :** Nuxt 4, Nuxt UI 4, openapi-typescript 7 (MIT, dev), openapi-fetch 0.17 (MIT), Vitest,
Playwright (conteneur `mcr.microsoft.com/playwright` épinglé), Postgres 17, image `deploy/docker/Dockerfile.api`.

## Fichiers

- `console/package.json` (`gen:api`, `test:e2e`), `console/app/api/schema.d.ts` (généré)
- `console/app/api/{types,client,http,mock,mock-data}.ts`
- `console/app/composables/{usePolicySession,useDirectory,useShell,useAuth}.ts`, `app/utils/{problem,oidc}.ts`
- `console/app/components/forms/*.vue` (objet, service, classe de données, zone, règle, section, agent, inspection, canal, jeton)
- pages : toutes adaptées ; nouvelles `settings/tokens.vue`, `settings/channels.vue`, `inspection.vue`
- `console/server/middleware/api-proxy.ts`
- `console/tests/unit/{schema,http,mock,problem,oidc}.test.ts`, `console/tests/nuxt/*.test.ts`
- `console/e2e/` (Playwright + compose + fixtures SQL), `.github/workflows/console-e2e.yml`
- `docs/adr/0014-console-spa-et-couche-api.md` (complété)

## Tâches

- [ ] 1. `openapi-typescript` + `openapi-fetch` ; `pnpm gen:api` ; test « schema.d.ts à jour » (échoue si différent).
- [ ] 2. `types.ts` = alias ; `AfwApi` aligné sur les opérations du contrat (lectures avec session optionnelle,
       écritures avec session requise, publication 201|202, installations `{installs}`, pages sans total…).
- [ ] 3. TDD `http.ts` sur `openapi-fetch` : en-têtes (`X-Afw-Interface`, bearer, `X-Afw-Session`), problem+json
       → `ApiError` (401 → retour connexion, 409, 423 « verrouillé par X »), 202 → approbation, SSE (événement nommé,
       `lagged`, reconnexion).
- [ ] 4. TDD du mock réécrit (formes du contrat, validées par les types générés) : allow-from-log → publication →
       installation ; verrou 423 ; approbation 202.
- [ ] 5. Pages adaptées au contrat (journal, détail de flux, règles, objets, agents, flux internes, alertes,
       révisions, audit, passerelles, connexion OIDC PKCE via `/auth/oidc/config`).
- [ ] 6. Formulaires EF-44 : objet, service, classe de données, zone, règle, section, agent (zone), règle
       d'inspection, canaux d'alerte, jetons d'API ; erreurs de l'API affichées telles quelles.
- [ ] 7. Bannières : approbation en attente (202), verrou (423), conflit (409).
- [ ] 8. e2e Playwright : Postgres + afw-api (image locale) + console (mode http) ; politique de démo importée,
       flux refusé inséré par fixture SQL ; parcours refus → Autoriser → publier → installer ; révision vérifiée.
       Plus un test « contrat » qui appelle chaque méthode de `createHttpApi` contre l'API réelle.
- [ ] 9. Workflow `.github/workflows/console-e2e.yml` séparé (conteneur Playwright épinglé).
- [ ] 10. Captures `console/docs/screenshots/` sur l'API réelle avec données de démo ; ADR 0014 complété ; PR.

## Critères d'acceptation

- `pnpm lint && pnpm typecheck && pnpm test && pnpm build` verts dans `node:24-bookworm-slim`.
- `schema.d.ts` régénéré identique (test), aucune forme de réponse écrite à la main dans `types.ts`.
- Parcours e2e vert contre l'API réelle.
