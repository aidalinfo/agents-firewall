# ADR 0022 — API : authentification, passerelles et ancrage de l'audit (lot L7c)

- Statut : accepté — 2026-10-30

## Contexte
EF-50, EF-51, EF-53, EF-54, ENF-02, ENF-03, EF-23 et EF-60 côté console. Le lot L0 a livré `Principal`,
`audit::record` et les migrations 0003/0004 ; L7c les étend sans casser leurs signatures.

## Décisions

### OIDC
- Validation locale des jetons JWT reçus en `Bearer` (`jsonwebtoken`, MIT) : découverte
  `<issuer>/.well-known/openid-configuration` (l'`issuer` retourné doit être identique), JWKS en cache 10 min,
  rafraîchi sur `kid` inconnu au plus une fois toutes les 30 s (un attaquant ne peut pas faire marteler le
  fournisseur). Vérifiés : signature, `iss`, `aud` (une des `AFW_OIDC_AUDIENCE`, défaut le `client_id`),
  `exp`, `nbf`, `sub` requis, tolérance 60 s.
- Algorithmes **asymétriques seulement**, compatibles avec le type de la clé du JWKS (RSA ⇒ RS*/PS*,
  EC ⇒ ES256/384, OKP ⇒ EdDSA), et égal à son `alg` s'il est fourni ; clés `oct` ignorées. `none` et HS*
  (confusion d'algorithme) sont refusés. URL du fournisseur en HTTPS (HTTP seulement en boucle locale).
- Rôles : la revendication `AFW_OIDC_ROLE_CLAIM` (défaut `groups`, chemin pointé possible) est comparée à
  `AFW_OIDC_{ADMIN,AUDITOR,VIEWER}_GROUPS` ; le rôle le plus élevé gagne. Aucun groupe ⇒ `403`, sauf
  `AFW_OIDC_DEFAULT_ROLE` (viewer ou auditor, jamais admin). OIDC ne donne jamais `mcp_agent`/`agent_plugin`.
- Un jeton au format JWT est d'abord essayé en OIDC, puis en jeton d'API. Les jetons opaques du fournisseur
  ne sont pas pris en charge (pas d'introspection) : la console envoie l'ID token ou un access token JWT.
- `GET /auth/oidc/config` (public) donne à la console `issuer`, `client_id`, `scopes` et les points de
  terminaison pour le flux code + PKCE (client public : aucun secret côté console).

### Jetons d'API
- Secret `afw_<256 bits base64url>` (`afw_at_…` pour les rôles agents), affiché une fois, SHA-256 en base.
  `admin` seul crée, liste, révoque ; `agent_id` obligatoire pour `mcp_agent`/`agent_plugin`, interdit sinon ;
  expiration dans le passé refusée ; second `mcp_agent` actif ⇒ `409`. Chaque création/révocation est
  auditée (sans le secret). Les jetons de rôle humain ont `actor.kind = cli`.

### Passerelles et mTLS
- Le protocole `/gw/v1` n'est servi **que** par l'écouteur TLS dédié (`AFW_GW_LISTEN`, défaut `:8443`) ;
  il a été retiré du routeur public. L'identité vient du certificat client vérifié par rustls
  (`ConsolePki::server_config`), posé en extension typée sur chaque requête de la connexion ; aucun en-tête
  n'est lu.
- Épinglage : l'empreinte SHA-256 du certificat émis à l'enregistrement est stockée ; seul ce certificat
  authentifie la passerelle, et `DELETE /gateways/{id}` la révoque immédiatement (pas de CRL nécessaire).
- Enregistrement : jeton à usage unique (15 min, haché) vérifié avant toute signature ; CSR invalide ou nom
  déjà pris ⇒ jeton non consommé ; consommation atomique (`UPDATE … WHERE used_at IS NULL`) dans la même
  transaction que la création et l'audit.
- Lots d'événements idempotents par `batch_id` (table `gateway_event_batches`), `gateway_id` des événements
  forcé à celui du certificat. Commandes en file livrées une fois avec le battement suivant.
- Statut : `pending` jamais vu, `online` si vu depuis moins de `AFW_GW_OFFLINE_AFTER_SECS` (90 s), sinon
  `offline`.
- Liens avec L7a/L7b par des **ports** (`gateways::ports::{PolicyPort, LogsPort}`) dans `AppState.ports` ;
  l'implémentation par défaut `Unwired` répond « rien d'installé / rien en attente » et refuse les écritures
  (la passerelle garde sa politique et renvoie ses événements plus tard). L'orchestrateur branche
  `policy::install` / `policy::agents` / `logs` à la fusion.

### Audit
- `GET /audit` (viewer ; filtres acteur, interface, action exacte ou préfixe `x.*`, période, curseur = `seq`),
  `GET /audit/verify` (viewer), `GET /audit/export` NDJSON (auditor), `POST /audit/export` (admin, ancre
  immédiate).
- Vérification complète depuis la genèse : `seq` contigus depuis 1, chaînage, empreintes recalculées, et
  accord avec **chaque** ancre exportée (fichier + table `audit_anchors`) ; une réécriture complète, cohérente
  en elle-même, est détectée par l'ancre. `broken_at` = premier `seq` en défaut.
- Ancre `{seq, hash, at}` exportée par une tâche périodique (`AFW_AUDIT_EXPORT_INTERVAL`, défaut 1 h, seulement
  si la tête a bougé) vers un fichier JSONL en ajout seul avec `fsync` (`AFW_AUDIT_EXPORT_DIR`) et, si
  `AFW_AUDIT_S3_*` est configuré, un objet S3 PUT avec `x-amz-object-lock-mode: COMPLIANCE`,
  `x-amz-object-lock-retain-until-date`, somme SHA-256, signé SigV4 écrit à la main (HMAC-SHA256 RFC 2104 sur
  `sha2`, testé sur les vecteurs RFC 4231 et l'exemple AWS) pour éviter un SDK.

### Migrations
0003/0004 sont étendues en place (rien n'est déployé) : `gateways` (dont `desired_revision`, écrite par L7a),
`gateway_registration_tokens`, `gateway_commands`, `gateway_event_batches`, `audit_anchors`. Une base déjà
migrée avec la version L0 doit être recréée (somme de contrôle sqlx).

## Conséquences / limites
- Une commande livrée dont la réponse se perd n'est pas renvoyée (la passerelle peut redemander un état).
- Enrôlement : l'agent (L7a) et le jeton plugin (ici) sont créés dans deux transactions.
- `GET /intent-policy` n'est pas implémenté par ce lot (pas de stockage défini de la politique d'intention).
- Le fichier d'ancres n'est immuable que s'il est sur un support en ajout seul (volume WORM, `chattr +a`) ;
  S3 Object Lock est la garantie forte.
