# ADR 0021 — API journaux : stockage, chiffrement, corrélation, alertes

- Statut : accepté — 2026-10-31
- Lot : L7b (`crates/afw-api/src/logs/**`, `migrations/0002_logs.sql`)

## Contexte
ADR 0006 (trait `LogStore`, PostgreSQL / ClickHouse, contenus chiffrés) et ADR 0007 (corrélation)
laissent au constructeur la frontière entre les deux magasins, le format de chiffrement, la
signature des webhooks et les seuils d'alerte.

## Décisions
1. **Deux familles de données.** Le trait `LogStore` porte les événements volumineux (flux, DNS,
   échanges HTTP, appels d'outil, corrélations matérialisées) et leurs agrégats. L'état « console »
   à faible volume (alertes, canaux, captures, compteurs de règles, destinations connues par agent,
   lots ingérés) reste toujours dans PostgreSQL, quel que soit `AFW_LOG_STORE`. Le trait utilise
   des `async fn` natives (pas de dépendance `async-trait`) ; le magasin configuré est l'enum
   `AnyLogStore`.
2. **ClickHouse par HTTP** (reqwest, `JSONEachRow`, paramètres typés `{p:Type}`, jamais
   d'interpolation). Tables `MergeTree` partitionnées par mois ; appels d'outil et corrélations en
   ajout seul, fusionnés à la lecture (`max(ended_at)`, `max(status)` : jamais remis à null), le
   premier agent qui a déclaré un `id` en est propriétaire. Option de requête
   `prefer_column_name_to_alias=1`. Purge par `DELETE` léger.
3. **Chiffrement.** `AFW_DATA_KEY` (32 octets en base64) ; une clé par usage dérivée par
   HKDF-SHA256 (contenus HTTP, captures) ; AES-256-GCM, nonce aléatoire de 96 bits, l'identifiant
   de l'enregistrement en données associées ; enveloppe `0x01 || nonce || chiffré || tag`.
   En-têtes et corps sont chiffrés ensemble ; méthode, URL, hôte, statut et détections restent en
   clair (recherche). Sans clé, les contenus ne sont **pas stockés** (jamais en clair) et une
   capture échoue. HMAC et HKDF sont écrits sur `sha2` et vérifiés par les vecteurs RFC 4231/5869.
4. **Captures** : pcap chiffré dans PostgreSQL (`bytea`, 256 Mio max) plutôt qu'un stockage objet
   en V1 (simplicité, purge par la même rétention) ; passerelle choisie = celle du dernier flux de
   l'agent ; téléchargement réservé auditeur/admin et audité.
5. **Accès aux contenus** (EF-54) : un lecteur ou l'agent MCP reçoit les échanges sans en-têtes ni
   corps ; auditeur et admin les reçoivent déchiffrés et la consultation est tracée
   (`flow.content_access`). Le flux SSE ne transporte jamais de contenu.
6. **Identifiants choisis par les passerelles** : insertion `ON CONFLICT (id) DO NOTHING`, jamais
   d'écrasement ; le `gateway_id` des événements est remplacé par celui authentifié ; un échange
   HTTP n'est rattaché qu'à un flux de la même passerelle.
7. **Corrélation** (ADR 0007) : calculée à l'ingestion des flux et des appels d'outil (dans les deux
   ordres) et matérialisée (`flows.tool_call_id`, `confidence`), recalculée à la lecture du détail.
   Les appels `gated`/`denied`/`blocked` ne sont jamais candidats ; un appel sans fin déclarée est
   actif au plus 1 h. L'agent d'un appel est celui du jeton du plugin, jamais celui du message.
8. **Alertes console** : destination jamais vue (après 24 h d'historique de l'agent, pour ne pas
   inonder à l'enrôlement ; flux internes exclus, couverts par la passerelle), pic de volume
   (dernière heure > 3 × moyenne horaire sur 7 j et > 10 Mo, une alerte par heure), rafale de refus
   (≥ 20 refus en 60 s, une alerte par 10 min).
9. **Canaux** : webhook générique signé `X-Afw-Timestamp` + `X-Afw-Signature: sha256=<hex
   HMAC-SHA256(AFW_ALERT_WEBHOOK_SECRET, "<ts>.<corps>")>` (la création d'un webhook est refusée
   sans secret) ; Teams (`MessageCard`) ; Pulse Chat via un webhook entrant générique
   `{"text": …}`. Les URL (qui portent des secrets) sont masquées à la lecture.
10. **Vues calculées par l'API** (la console n'a pas de logique métier) : libellés des flux,
    histogramme `/logs/flows/stats`, trace recalculée avec `afw-engine` sur la révision du flux
    (`dst_ip_trusted = true`), message EF-21 reçu par l'agent, proposition « Autoriser ».
    Ajouts additifs au contrat (`FlowListItem`, `FlowStats`, `TraceStep`, `AllowProposal`,
    `MapPeriod`).
11. **Politique** : lue en best-effort dans la table `revisions` du module politique (L7a) via un
    `PolicyLoader` remplaçable ; rétention = `settings.retention_days` de la dernière révision
    (valeurs par défaut sinon), purge horaire.

## Conséquences
Les déploiements à forte volumétrie passent à ClickHouse sans changer l'API ; l'état console reste
transactionnel dans PostgreSQL. Les captures volumineuses devront migrer vers un stockage objet
(S3 compatible) dans une version ultérieure.
