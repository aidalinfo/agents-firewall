# ADR 0014 — Console : SPA Nuxt, couche `AfwApi` et données de démonstration

- Statut : accepté — 2026-10-30, complété le 2026-10-31 (L3b)
- Lots : L3 (console sur maquette, données mock), L3b (console branchée sur l'API réelle)

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
   - routes ajoutées : `GET /logs/flows/stats`, `GET /policy/status` (révision installée, k/n passerelles
     sur cette révision, latence p95), `POST /alerts/{id}/ack`, `GET /auth/oidc/login?redirect&state` ;
   - `Session` porte `base_revision` et `next_revision` : la console n'invente aucun numéro de révision ;
     `AgentDestination.rule_layer` : le socle se reconnaît par la couche, jamais par le préfixe « S ».
   L3b remplace `types.ts` par les types générés (`openapi-typescript`) et adapte `http.ts` (voir le
   complément L3b ci-dessous : les vues de lecture effectives sont celles du contrat).
4. **Thème.** Les jetons de la maquette (`--bg`, `--panel`, `--pri`, `--ok`, `--ko`, `--warn`, `--obs`…)
   sont définis en clair sur `:root` et en sombre sur `.dark` (sombre par défaut, `@nuxtjs/color-mode`),
   exposés à Tailwind 4 (`bg-panel`, `text-text3`…) et reportés sur les variables Nuxt UI (`--ui-*`).
   Polices Geist et Geist Mono via `@nuxt/fonts` (fichiers servis par la console). Icônes lucide
   embarquées (`@iconify-json/lucide`), aucun appel réseau à l'exécution.
5. **Langues.** `@nuxtjs/i18n`, français par défaut quelle que soit la langue du navigateur, anglais
   disponible ; le choix est mémorisé localement. Un test vérifie la parité des clés et que chaque clé
   utilisée existe. Les textes libres renvoyés par l'API (commentaires, résumés) ne sont pas traduits.
   Le message de refus EF-21 (anglais côté protocole) est traduit par l'interface.
6. **Sécurité du client.**
   - Toutes les requêtes portent `X-Afw-Interface: ui` (l'audit enregistre l'interface) ; l'export d'audit
     est récupéré par `fetch` avec le jeton puis enregistré depuis un `Blob` (jamais de jeton dans une URL).
   - OIDC : `state` aléatoire de 128 bits en `sessionStorage`, à usage unique, vérifié au retour ; la
     redirection après connexion n'accepte qu'un chemin relatif ou une URL de la même origine. Les liens
     reçus de l'API ne sont suivis que s'ils commencent par `/`.
   - Les « équivalent CLI » et « copier en curl » entourent chaque valeur de guillemets simples
     (valeurs issues du trafic des agents : pas d'injection de commande au collage).
   - Nitro (plugin `server/plugins/security-headers.ts`) envoie `X-Content-Type-Options: nosniff`,
     `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` et une CSP stricte calculée au démarrage de la
     requête (origine de `NUXT_PUBLIC_API_BASE` dans `connect-src`) : `default-src 'self'`,
     `img-src 'self' data:`, `style-src 'self' 'unsafe-inline'`, `font-src 'self'`,
     `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`, `form-action 'self'`. Seul
     ajout nécessaire : les scripts en ligne émis par Nuxt (configuration d'exécution, mode de couleur)
     sont autorisés **par empreinte sha256**, calculée sur la page servie. Les icônes sont toutes
     embarquées (`fallbackToApi: false`) pour ne jamais appeler `api.iconify.design`.
7. **Actions de création hors parcours.** Les boutons « Nouvel objet », « Section », « Règle »,
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

## Complément L3b — console branchée sur l'API réelle (2026-10-31)

### Contexte

Le contrat `docs/api/openapi.yaml` (L0, L7a/b/c) et l'API Rust existent. La revue de L3 a recensé les
écarts entre les types écrits à la main et le contrat (où-utilisé `{references}`, `POST /installs` →
`{installs}`, pages sans total, statut de passerelle `online|offline|pending`, `AgentOverview`,
`Alert` enveloppé, `InternalMap`, `Me`, événements SSE, `Correlation`, `Capture`, OIDC…).

### Décisions

1. **Types générés, vérifiés.** `app/api/schema.d.ts` est produit par `openapi-typescript` (MIT, dev)
   depuis le contrat (`pnpm gen:api`) ; `tests/unit/schema.test.ts` régénère dans un répertoire temporaire et
   échoue si le fichier commité diffère. `types.ts` ne contient plus que des alias de
   `components['schemas']` et les objets de requête dérivés de `operations[...]['parameters']['query']`.
   Les deux seuls types propres à la console : `StreamEvent` (nom d'événement SSE + `GatewayEvent`, ou
   avis `lagged`) et `PublishOutcome` (201 révision | 202 approbation).
2. **Client `openapi-fetch` (MIT).** `http.ts` appelle chaque route par son chemin littéral typé. Un
   intergiciel ajoute `X-Afw-Interface: ui` et le jeton, et signale les 401 (retour à `/login`). Les
   réponses `application/problem+json` deviennent `ApiError(status, title, detail)` ; `lockedBy` extrait le
   propriétaire d'un verrou du détail d'un 423 (`locked by <nom>`). Les ressources de politique partagent
   une interface `PolicyCollection` (liste, lecture, création, remplacement, suppression).
3. **Session de politique.** `usePolicySession` appelle `api.setSession(id)` dès qu'une session est ouverte :
   toutes les **lectures** de politique portent alors `X-Afw-Session` (le brouillon s'affiche partout,
   `RuleView.pending_change` marque les règles touchées) ; les **écritures** reçoivent la session
   explicitement. Un 409 à l'ouverture (session déjà ouverte ailleurs) reprend la session existante. Une
   publication 202 affiche la bannière d'approbation (EF-52), 409 « approval pending » s'affiche tel quel ;
   l'étape « Installer » reprend après rechargement grâce à `Session.pending_install`.
4. **Pas de logique métier côté console.** Les noms affichés à la place des identifiants (agent, zone,
   objet, passerelle) sont résolus par `useDirectory` à partir des listes de l'API ; le libellé de la règle
   d'un flux suit la convention de `FlowListItem.rule_label` quand le contrat ne donne que la décision ;
   les formulaires ne traduisent que la saisie (ports « 443, 8000-8100 », détecteurs, date d'expiration) et
   affichent le message de validation de l'API **tel quel**. Les identifiants des ressources créées sont
   choisis par la console (le contrat l'exige) avec `crypto.getRandomValues` (UUID v4, utilisable hors
   contexte sécurisé).
5. **Données absentes du contrat : écrans adaptés, contrat inchangé.** Aucune donnée indispensable à un
   écran ne manquait ; les éléments de la maquette sans source dans le contrat sont retirés ou remplacés
   par ce que l'API fournit, sans modifier l'API :
   - détail de flux : `FlowEvent.content_inspected = false` (relais TCP brut, TLS non inspecté) s'affiche
     « contenu non inspecté (relais TCP) » ; la latence p50/p95 des passerelles vient de `GatewayStats` ;
   - journal : le segment « alertes » devient « observés » (`FlowStats.observed`) ; la colonne méthode +
     chemin montre le protocole et la destination (le chemin est dans le détail, `FlowDetail.http`) ;
   - corrélation : confiance + conversation + appel d'outil (`tool_call`) ; le titre de conversation, la
     source non fiable et le raisonnement de la maquette ne sont pas dans le contrat ;
   - proposition « Autoriser » : choix exact / joker donnés par l'API, plus le groupe « Autorisés depuis le
     journal — zone » (`destination: group`) ; les objets existants sont signalés (« déjà couvert ») ;
   - vue agent : courbe en **flux par heure** (`/logs/flows/stats?agent&bucket=1h`) au lieu des octets ;
     destinations, refus récents, derniers appels d'outil et alertes de `AgentOverview` ; la liste des agents
     lit une vue d'ensemble par agent (compteurs 24 h) ;
   - flux internes : la carte vient de `InternalMap` (arêtes nouvelles / en alerte) ; le tableau des appels
     d'administration est remplacé par la liste des connexions internes ;
   - passerelles : révision active / demandée, statistiques remontées (flux, volume, tampon, durée de
     service), empreinte de la CA ; plus de latence p50 ni « environnement » ;
   - révisions : différences par `GET /revisions/{n}/diff`, installations par `GET /installs?revision=n` ;
     « Réinstaller » (`POST /installs`) et « Revenir à cette révision » (`POST /revisions/{n}/revert`).
6. **Formulaires EF-44.** Objet (tous types de `NetObjectSpec`), service, classe de données, zone,
   règle (couche, position, section, sources, destinations, services, classes, action, trace, expiration),
   section (renomme / attribue la section des règles choisies), déplacement de règle, changement de zone
   d'un agent, règle d'inspection (page « Inspection TLS »), canaux d'alerte et jetons d'API (page
   « Paramètres », secret montré une seule fois). Les écritures de politique vont dans la session (ouverte au
   besoin), les canaux et jetons sont écrits directement (hors session dans le contrat).
7. **Journal en direct.** `GET /logs/stream` est lu par `fetch` (le jeton ne passe jamais dans l'URL) :
   événements nommés `flow|dns|http|alert|rule_hits`, avis `lagged` → rechargement complet, reconnexion avec
   délai croissant (1 s → 30 s) quand le serveur ferme le flux (durée bornée côté API), arrêt sur 401.
8. **OIDC : code d'autorisation + PKCE.** Le contrat n'a pas de route de connexion côté API :
   `GET /auth/oidc/config` donne l'émetteur, le client public et les points de terminaison. La console crée
   le `state` (128 bits) et le vérificateur PKCE (S256), les garde en `sessionStorage` (usage unique), puis
   échange le code au point de terminaison de jetons du fournisseur. Son origine s'ajoute au `connect-src`
   de la CSP par `NUXT_OIDC_CONNECT_SRC`. `crypto.subtle` exige un contexte sécurisé (https).
9. **Même origine.** Nitro peut relayer `/api/**` et `/healthz` vers l'API (`NUXT_API_PROXY_TARGET`,
   variable serveur, `proxyRequest` d'h3, flux SSE transmis tels quels) : le navigateur ne parle qu'à
   l'origine de la console (CSP `connect-src 'self'`, pas de CORS — que l'API n'implémente pas). Derrière
   l'ingress Helm (`/api` → API) la variable reste vide.
10. **Mock fidèle.** `mock.ts` est réécrit sur les types générés (sessions avec verrous 423, publication 201
    ou 202, installations par passerelle avec accusé, allow-from-log, renumérotation, chaîne d'audit, flux
    SSE simulé avec `lagged`, 401) ; `tests/unit/mock.test.ts` valide **chaque réponse** contre les schémas
    JSON du contrat (ajv 2020, mode strict : aucun champ non déclaré). Le même validateur sert au test e2e.
11. **Tests de bout en bout réels** (`console/e2e/`, workflow `console-e2e.yml` séparé) : Postgres +
    afw-api (image de `deploy/docker/Dockerfile.api`, jeton `AFW_BOOTSTRAP_ADMIN_TOKEN`) + console (mode
    http, relais Nitro), Playwright dans `mcr.microsoft.com/playwright:v1.64.1-noble` (même version que
    `@playwright/test`, épinglée). Données : la politique de démonstration est importée par les routes
    publiques (`POST /sessions`, `/import`, `/publish`) ; les événements de passerelle (flux, échange HTTP,
    appel d'outil, alerte, passerelles) par une fixture SQL — l'envoi réel passe par le mTLS d'une
    passerelle enregistrée, hors du périmètre de la console. `contract.spec.ts` appelle **chaque méthode** de
    `createHttpApi` contre l'API et valide les réponses ; `journey.spec.ts` rejoue « refus → Autoriser →
    publier → installer » dans Chromium et vérifie par l'API la révision publiée (règle présente, interface
    `ui`, installation demandée, audit).

### Conséquences

- Toute évolution du contrat se voit à `pnpm gen:api` : le test de fraîcheur et le typage strict signalent
  les écarts ; le mock et le test e2e vérifient les valeurs.
- Le paramètre `NUXT_API_PROXY_TARGET` permet de déployer console et API sans proxy inverse ; la
  configuration Compose (lot L12) peut le renseigner (`http://afw-api:8080`).
- L'API n'implémente pas `AFW_CORS_ORIGINS` (présent dans `deploy/compose`) : sans relais ni ingress commun,
  une console sur une autre origine ne peut pas joindre l'API.
