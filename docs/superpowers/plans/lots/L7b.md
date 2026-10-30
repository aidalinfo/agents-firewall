# L7b — API journaux : plan détaillé

> Pour les agents : exécuté en autonomie (superpowers:executing-plans), TDD, cases à cocher.

**Objectif :** servir les journaux de la flotte (flux, DNS, HTTP, appels d'outil), la corrélation intention ↔ flux,
les alertes côté console et leurs canaux, les captures pcap, la vue agent et la carte des flux internes, avec
contenus chiffrés au repos et consultation tracée.

**Exigences :** EF-30 à EF-36, EF-41, EF-43, EF-54, EF-80 à EF-83, ENF-04. ADR : 0006, 0007, 0021 (ce lot).

**Architecture :** tout vit dans `crates/afw-api/src/logs/**` et `migrations/0002_logs.sql`.

- `store.rs` : trait `LogStore` (événements volumineux : flux, DNS, HTTP, appels d'outil, corrélations
  matérialisées, agrégats) ; `AnyLogStore` (enum) choisi par `AFW_LOG_STORE=postgres|clickhouse`.
- `postgres.rs` (défaut) et `clickhouse.rs` (HTTP, `JSONEachRow`, via reqwest).
- L'état « console » à faible volume reste toujours dans PostgreSQL, quel que soit le magasin : alertes,
  canaux, captures, compteurs de règles, destinations connues par agent, lots déjà ingérés.
- `crypto.rs` : AES-256-GCM, clé dérivée par HKDF-SHA256 de `AFW_DATA_KEY` (HMAC-SHA256 écrit à la main sur
  `sha2`, testé avec les vecteurs RFC 4231 / RFC 5869) ; enveloppe `v1 || nonce || chiffré`, AAD = id.
- `correlation.rs` : fonction pure ADR 0007 (certain / probable / uncertain).
- `ingest.rs` : `ingest_gateway_events`, `ingest_gateway_batch` (idempotence par `batch_id`), appels d'outil
  (upsert sans jamais remettre `ended_at`/`status` à null, propriété de l'agent du jeton).
- `alerts.rs` (détection console + persistance + diffusion) et `channels.rs` (CRUD, webhook signé
  `X-Afw-Signature`, Teams MessageCard, Pulse Chat `{text}`).
- `captures.rs` : demande, `pending_commands`, `store_capture`, téléchargement audité.
- `views.rs` : vue agent, carte des flux internes, `rule_stats`.
- `stream.rs` : SSE sur `tokio::sync::broadcast`, mêmes filtres.
- `retention.rs` : purge périodique selon `settings.retention_days`.
- `policy_view.rs` : lecture best-effort de la politique publiée (noms d'agents, zones), remplaçable.

## Tâches

- [x] 1. Migration `0002_logs.sql` (tables, index) + `LogsHandle` dans `AppState` (ajout additif).
- [x] 2. Crypto : tests vecteurs HMAC/HKDF, aller-retour, AAD falsifiée refusée, clé absente ⇒ contenu non stocké.
- [x] 3. Corrélation : tests unitaires certain/probable/uncertain/aucun, appels `gated`/`denied` ignorés.
- [x] 4. Ingestion passerelle → `GET /logs/flows` filtré (agent, zone, destination domaine/IP/CIDR, verdict,
      règle, période, q) et paginé par curseur ; `GET /logs/dns` ; idempotence.
- [x] 5. `GET /logs/flows/{id}` : viewer sans contenus, auditor avec contenus et accès audité ; base sans clair.
- [x] 6. `POST /ingest/tool-calls` : début/fin dans les deux ordres, jeton plugin seul, autre agent refusé ;
      corrélation matérialisée et recalculée à la lecture.
- [x] 7. SSE `GET /logs/stream` reçoit un flux ingéré (filtré).
- [x] 8. Alertes console (nouvelle destination, pic de volume, rafale de refus), `GET /alerts`,
      `POST /alerts/{id}/ack` ; canaux CRUD audités ; webhook signé reçu par un serveur de test.
- [x] 9. Captures : `POST /captures` → commande dans `pending_commands`, `store_capture`, téléchargement
      chiffré au repos et audité.
- [x] 10. Vue agent, carte des flux internes, `rule_stats`.
- [x] 11. Rétention : purge par niveau.
- [x] 12. ClickHouse (tests ignorés sans `AFW_TEST_CLICKHOUSE_URL`), une passe réelle en fin de lot.
- [x] 13. ADR 0021, fmt, clippy, tests, PR vers `dev`.
