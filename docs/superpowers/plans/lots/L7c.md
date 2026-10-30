# L7c — API auth, passerelles, audit : plan de lot

> Exécuté en TDD dans `lot/07c-api-auth`. Spécification : plan maître §3.2, §3.4 et §4 L7c ; ADR 0004,
> 0008, 0011, 0013 ; décisions propres au lot : ADR 0022.

**But :** authentifier humains (OIDC), outils (jetons d'API) et passerelles (mTLS), tracer chaque mutation
dans la chaîne d'audit et l'ancrer dans un stockage immuable.

**Périmètre :** `crates/afw-api/src/{auth,gateways,audit}/**`, migrations `0003_auth.sql` et `0004_audit.sql`
(étendues en place : rien n'est encore déployé), ajouts minimaux à `lib.rs` (`AppState`) et `main.rs`.

## Tâches

- [ ] 1. Support de test : base PostgreSQL neuve par test (`tests/support/mod.rs`, `CREATE DATABASE`),
  faux fournisseur OIDC (axum : découverte + JWKS, jetons RS256 signés par `jsonwebtoken`).
- [ ] 2. **Tests de contournement d'abord** (`tests/bypass_auth.rs`, `tests/bypass_gateways.rs`,
  `tests/audit_api.rs`) — ils doivent échouer avant l'implémentation :
  - jetons : révoqué, expiré, inconnu ; OIDC : expiré, mauvaise audience, mauvais émetteur, signature
    d'une autre clé, `alg: none`, HS256 signé avec la clé publique, aucun groupe ⇒ 403 ;
  - rôles : viewer ne crée pas de jeton, auditor non plus, mcp_agent jamais admin, jeton plugin limité ;
  - passerelles : jeton d'enregistrement réutilisé, expiré, inconnu ⇒ 401 ; CSR invalide ⇒ 400 sans
    consommer le jeton ; `/gw/v1/*` sans certificat ⇒ 401 ; certificat d'une autre CA ⇒ poignée de main
    refusée ; certificat valide d'une passerelle supprimée ⇒ 401 ; routes `/gw/v1` absentes de l'écouteur
    public ; en-têtes ne pouvant pas usurper l'identité de passerelle ;
  - audit : ligne modifiée en base ⇒ `/audit/verify` désigne le `seq` ; ligne supprimée ; ancre exportée
    différente ⇒ rupture signalée.
- [ ] 3. Migrations : `api_tokens` (+ `email`), `oidc` rien en base ; `gateways`, `gateway_registration_tokens`,
  `gateway_commands` ; `audit_anchors`.
- [ ] 4. `auth::oidc` : découverte, JWKS en cache (rafraîchi sur `kid` inconnu, borné), validation
  (iss, aud, exp, nbf, algorithmes asymétriques seulement), correspondance groupes → rôle.
  `Principal` : jeton au format JWT ⇒ OIDC, sinon `api_tokens`. `GET /auth/oidc/config` public.
- [ ] 5. `auth::tokens` : `GET/POST /tokens`, `DELETE /tokens/{id}` (secret affiché une fois, haché en base,
  audit) ; `GET /me` ; `POST /enrollments` (création d'agent déléguée à L7a par port, jeton plugin).
- [ ] 6. `gateways` : jetons d'enregistrement, `/gw/v1/register` (CSR signée par `ConsolePki`),
  extracteur `GatewayPeer` alimenté uniquement par l'écouteur TLS (`afw_tls::peer_gateway_id` + empreinte
  du certificat épinglée en base), `/gw/v1/{policy,policy/ack,events,heartbeat,captures/{id}}`,
  `GET /gateways`, `GET/DELETE /gateways/{id}`, `POST /gateways/{id}/commands`. Ports vers L7a/L7b
  (`gateways::ports`) branchés par `AppState`.
- [ ] 7. `audit` : `GET /audit` (filtres acteur, interface, action, période, curseur), `GET /audit/verify`
  (chaîne entière + ancre), `GET /audit/export` (NDJSON), `POST /audit/export` (ancre immédiate), tâche
  périodique (`AFW_AUDIT_EXPORT_INTERVAL`) vers fichier JSONL `fsync` et S3 Object Lock (SigV4 maison).
- [ ] 8. `main.rs` : écouteur mTLS `AFW_GW_LISTEN` (défaut `0.0.0.0:8443`), OIDC, tâche d'export.
- [ ] 9. OpenAPI : ajouts additifs (`/auth/oidc/config`, `POST /audit/export`, filtre `interface`).
- [ ] 10. ADR 0022, fmt, clippy `-D warnings`, tests ; PR vers `dev`.
