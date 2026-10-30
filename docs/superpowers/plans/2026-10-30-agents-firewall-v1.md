# agents-firewall V1 — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** livrer la V1 complète d'agents-firewall (passerelle, plan de contrôle, console, CLI, MCP, plugin Hermes, déploiement, import egress-guard, documentation) et la démontrer par une recette locale.

**Architecture :** une passerelle Rust par hôte d'agents (interception transparente par route par défaut + nftables, DNS filtrant, proxy HTTP(S) avec inspection TLS, filtrage L4) applique une politique compilée tirée en mTLS depuis le plan de contrôle (API Rust/axum, PostgreSQL pour la configuration et l'audit, ClickHouse ou PostgreSQL pour les journaux). La console Nuxt 4 + Nuxt UI, la CLI `afw` et le serveur MCP sont des clients de la même API REST décrite en OpenAPI.

**Tech Stack :** Rust 1.91 (tokio, hyper 1, rustls 0.23 + ring, rcgen, hickory-proto, axum 0.8, sqlx 0.8, clap 4, rmcp), Nuxt 4 + Nuxt UI 4 + openapi-typescript/openapi-fetch, Python 3.12 (plugin Hermes), PostgreSQL 17, ClickHouse 24, Docker Compose, Helm 3.

**Spec :** `docs/cahier-des-charges.md`, `docs/superpowers/specs/2026-10-30-agents-firewall-design.md`, maquette `docs/design/maquette/project/*.dc.html`.

## Global Constraints

- Licence Apache 2.0 ; dépendances MIT / Apache-2.0 / BSD / ISC / Zlib / Unicode uniquement ; code tiers repris → en-tête conservé + entrée `NOTICE`.
- Décisions **[Killian]** intangibles : Rust pour passerelle/API/CLI/MCP, Nuxt 4 + Nuxt UI pour la console, refus par défaut, socle commun + zones (source d'une règle = une zone, jamais un agent), détail maximal par défaut, flux internes surveillés et autorisés par défaut, fournisseur LLM exempté du blocage par classe de données, un seul agent agréé sur le MCP qui ne modifie jamais ce qui s'applique à lui, audit chaîné par empreinte, rien de propre à Pulse myIT dans le cœur.
- Message de refus HTTP exact (EF-21, en anglais côté protocole, l'interface traduit) : statut `403`, en-tête `X-Agents-Firewall: denied`, corps texte `blocked by agents-firewall: <destination> not allowed for <agent> (rule <n>)`.
- La passerelle ne tombe jamais en mode ouvert : toute erreur interne (politique absente, moteur en erreur, analyse impossible) = refus.
- Code, identifiants, commentaires et commits en anglais ; documentation en français ; UI bilingue FR/EN (FR par défaut).
- Conventional Commits signés (`git commit -s`), jamais de push sur `main`, une PR par lot vers `dev`.
- Builds et tests Rust via `scripts/cargo.sh` (conteneur Linux, ADR 0002) ; console et plugin via `seve run`/`seve test` ou conteneur Node/Python.
- Avant de rendre un lot : `scripts/cargo.sh fmt --all --check`, `scripts/cargo.sh clippy --workspace --all-targets -- -D warnings`, `scripts/cargo.sh test -p <crates du lot>` verts ; console : lint + typecheck + tests verts.
- Rien n'est publié (pas de release, pas d'image poussée dans un registre, pas de paquet).

## Review Focus

1. Agent qui ignore `HTTP_PROXY` et se connecte en direct à une IP publique (sans DNS) → connexion refusée et journalisée, jamais transmise (gateway, test `bypass_direct_ip_is_dropped`).
2. Politique absente, corrompue ou de version inconnue au démarrage de la passerelle → tout refuser, jamais tout accepter (gateway, test `no_policy_denies_everything`).
3. Domaine joker `*.example.com` contre `example.com`, `evil-example.com`, `a.b.example.com`, casse et point final `API.Example.com.` (engine, test `wildcard_domain_matching_edge_cases`).
4. Secret coupé entre deux tampons d'un flux continu ou d'un corps volumineux (dlp, test `streaming_scanner_detects_secret_across_chunks`).
5. Agent MCP agréé qui tente de modifier sa propre zone, une règle dont la source est sa zone, ou de déplacer un agent vers/depuis sa zone (api, test `delegated_agent_cannot_touch_own_zone`).

---

## 1. Organisation du dépôt

```
Cargo.toml                 workspace (members = crates/*), versions partagées
crates/
  afw-core/                contrats : modèle de politique, politique installée, événements, protocole passerelle, API DTO
  afw-engine/              moteur de règles (compilation + évaluation + vérifications avant installation)
  afw-dlp/                 classes de données, détection, masquage, analyse au fil de l'eau
  afw-tls/                 autorité d'inspection par passerelle, certificats feuilles, PKI console (mTLS)
  afw-gateway/             binaire passerelle (plan de données)
  afw-api/                 binaire plan de contrôle (REST, Postgres, journaux, audit, alertes)
  afw-client/              client Rust de l'API (utilisé par CLI et MCP)
  afw-enroll/              enrôlement Docker compose / Coolify / Kubernetes
  afw-import/              import de la politique egress-guard
  afw-cli/                 binaire `afw`
  afw-mcp/                 binaire `afw-mcp` (serveur MCP d'administration)
console/                   Nuxt 4 + Nuxt UI
integrations/hermes/       plugin Hermes (Python)
deploy/compose/            docker compose console + passerelle
deploy/helm/agents-firewall/  chart Helm
deploy/docker/             Dockerfiles
demo/                      environnement de recette (2 zones, 3 agents factices dont 1 Hermes)
docs/api/openapi.yaml      contrat REST (source de vérité, contract-first)
docs/schemas/              schémas JSON (événements, politique installée) générés depuis afw-core
docs/adr/                  décisions d'architecture
docs/rapport/              rapport final
```

## 2. Graphe des lots

```
L0 contrats ─┬─> L5 moteur ──────┐
             ├─> L7a API politique ┐
             ├─> L7b API journaux  ├─> L8 client+CLI ─> L9 MCP
             ├─> L7c API auth/gw   ┘          └─> L10 import egress-guard
             └─> L6 passerelle (+L1, L2, L5)
L1 dlp ──────────> L6
L2 tls ──────────> L6, L7c
L3 console (maquette + mocks) ──> L3b branchement client OpenAPI (après L0)
L4 plugin Hermes (protocole fixé ici) ──────────────┐
L11 enrôlement (après L0) ───────────────────────────┤
L12 déploiement Compose/Helm/Dockerfiles ────────────┼─> L13 recette + rapport
L14 documentation ───────────────────────────────────┘
```

Vague 1 (immédiate, en parallèle) : L0, L1, L2, L3, L4.
Vague 2 (dès L0 fusionné) : L5, L6, L7a, L7b, L7c, L11, L12, L14.
Vague 3 : L8, L9, L10, L3b. Puis L13 (recette, captures, rapport).

Chaque lot : worktree + branche `lot/<id>-<nom>`, plan détaillé du lot dans `docs/superpowers/plans/lots/<id>.md`, TDD (tests de contournement d'abord pour la sécurité), revue indépendante, PR vers `dev`.

## 3. Contrats partagés (L0)

### 3.1 `afw-core` — modèle de politique (`crates/afw-core/src/policy.rs`)

Tous les types sont `Serialize + Deserialize + JsonSchema + Clone + Debug + PartialEq`, `#[serde(rename_all = "snake_case")]`, identifiants `uuid::Uuid`.

- `NetObject { id, name, comment, category: Option<DestCategory>, spec: NetObjectSpec }`
  - `NetObjectSpec::{ Domain { pattern }, Host { ip }, Network { cidr: IpNet }, Range { start, end }, Group { members: Vec<Uuid> }, Any }`
  - `DestCategory::{ LlmProvider, CloudMetadata, Internal }` — `LlmProvider` porte l'exemption EF-25.
- `Service { id, name, comment, protocol: L4Proto, ports: Vec<PortRange>, app: Option<AppMatch> }` ; `L4Proto::{ Tcp, Udp, Any }` ; `PortRange { start: u16, end: u16 }` ; `AppMatch { proto: AppProto, methods: Vec<String>, path_prefixes: Vec<String> }` ; `AppProto::{ Http, Https, Dns, Ssh, Tls, Other }`.
- `DataClass { id, name, comment, category: DataCategory, detectors: Vec<Detector> }` ; `DataCategory::{ Secret, Infra, Commercial, Personal, Custom }` ; `Detector::{ Builtin { id: String }, Regex { name, pattern } }`.
- `Zone { id, name, comment, mode: ZoneMode, delegated_to_mcp: bool }` ; `ZoneMode::{ Enforce, Observe }` (EF-12).
- `Agent { id, name, zone_id, kind: AgentKind, gateway_id: Option<Uuid>, addresses: Vec<IpAddr>, labels: BTreeMap<String,String>, hermes: bool, mcp_admin: bool }` ; `AgentKind::{ DockerCompose, Coolify, Kubernetes, Container }`.
- `Rule { id, name, layer: Layer, section: Option<String>, position: u32, sources: Vec<Uuid> /*zones ; vide = toutes, autorisé seulement dans Baseline*/, destinations: Vec<Uuid> /*objets ; vide = any*/, services: Vec<Uuid> /*vide = any*/, data_classes: Vec<Uuid> /*vide = pas de condition de contenu*/, action: Action, track: Track, expires_at: Option<DateTime<Utc>>, comment, enabled: bool }`
  - `Layer::{ Baseline, Zone { zone_id } }`, `Action::{ Accept, Deny }`, `Track::{ None, Log, Detailed, Capture }` (défaut `Detailed`).
- `InspectionRule { id, name, position, zones: Vec<Uuid>, destinations: Vec<Uuid>, action: InspectionAction::{ Inspect, Bypass } }` — défaut implicite : `Inspect` (EF-09).
- `PolicySettings { internal_networks: Vec<IpNet> /*défaut RFC1918 + fc00::/7*/, max_buffered_body: u64 /*défaut 1 MiB*/, max_stored_body: u64 /*défaut 256 KiB*/, retention_days: Retention { flows: 30, http: 14, captures: 7 } }`
- `PolicyDocument { objects, services, data_classes, zones, agents, rules, inspection_rules, settings }` — l'ensemble publiable.

Ordre d'évaluation figé (moteur) : 1) règles `Baseline` par `position` ; 2) règles de la zone de l'agent par `position` ; 3) si la destination est dans `internal_networks` ou est un autre agent : acceptation implicite « interne surveillé » (`track = Detailed`, `implicit = InternalMonitor`) ; 4) nettoyage implicite `Deny` (`implicit = Cleanup`). Une règle expirée ou désactivée est ignorée. Une règle avec `data_classes` ne correspond que si l'une de ces classes est détectée ; si la destination est `LlmProvider`, les règles avec `data_classes` sont sautées (EF-25). Zone en `Observe` : un refus devient `Allow` avec `observed = true`. Le numéro affiché d'une règle est son rang global (socle puis zone) calculé à la compilation.

### 3.2 Politique installée et protocole passerelle (`installed.rs`, `protocol.rs`)

- `InstalledPolicy { format: u32 /*=1*/, revision: u64, published_at, published_by: String, document: PolicyDocument, sha256: String /*du document JSON canonique*/ }`. La passerelle refuse un `format` inconnu ou une empreinte fausse (tout refuser).
- Routes passerelle (mTLS client, préfixe `/gw/v1`) : `POST /register { token, name, hostname, csr_pem } -> { gateway_id, cert_pem, ca_pem }` (sans certificat client, jeton à usage unique 15 min) ; `GET /policy?have=<rev>` → `200 InstalledPolicy` ou `204` (long-poll 25 s) ; `POST /policy/ack { revision, ok, error }` ; `POST /events { events: Vec<GatewayEvent> }` ; `POST /heartbeat { version, revision, stats: GatewayStats, ca_fingerprint } -> { commands: Vec<GatewayCommand> }` ; `POST /captures/{id}` (pcap brut).
- `GatewayCommand::{ StartCapture { capture_id, agent_id, duration_secs }, Reinstall, SelfTest }`.

### 3.3 Événements (`events.rs`)

- `GatewayEvent` (tag `type`) : `Flow(FlowEvent)`, `Dns(DnsEvent)`, `Http(HttpEvent)`, `Alert(AlertEvent)`, `RuleHits(Vec<RuleHit>)`.
- `FlowEvent { id, gateway_id, agent_id: Option, zone_id: Option, src: SocketAddr, dst: SocketAddr, protocol: L4Proto, app: Option<AppProto>, domain: Option<String>, sni: Option<String>, bytes_out, bytes_in, started_at, ended_at: Option, verdict: Verdict, decision: DecisionRef, internal: bool, llm_provider: bool, tls_inspected: bool, data_classes: Vec<String>, observed: bool }`.
- `Verdict::{ Allow, Deny }` ; `DecisionRef { rule_id: Option<Uuid>, rule_number: Option<u32>, rule_name: String, layer: String /*baseline|zone|implicit*/, reason: String }`.
- `DnsEvent { id, gateway_id, agent_id, at, qname, qtype, answers: Vec<String>, verdict, decision }`.
- `HttpEvent { id, flow_id, gateway_id, agent_id, at, method, url, host, request_headers: Vec<(String,String)>, request_body: Option<Body>, status: Option<u16>, response_headers, response_body: Option<Body>, findings: Vec<Finding>, admin_action: Option<AdminAction>, websocket: bool }` ; `Body { encoding: "utf8"|"base64", data, size: u64, truncated: bool, sha256 }` (déjà masqué) ; `Finding { class: String, category: DataCategory, kind: String, fingerprint: String /*sha256 tronqué 12 hex*/, location: String }` ; `AdminAction { system: "kubernetes"|"coolify"|"docker"|"proxmox", action: String, resource: String }`.
- `AlertEvent { id, at, kind: AlertKind, severity: Severity::{Info,Warning,Critical}, agent_id: Option, summary: String, details: serde_json::Value }` ; `AlertKind::{ NewDestination, VolumeSpike, DenyBurst, CloudMetadata, SecretDetected, PortScan, NewInternalHost, SensitivePort, InternalBurst, UnusualAdminAction }` (EF-36, EF-82).
- `ToolCallEvent { id, agent: String /*nom ou id*/, conversation_id, tool, args_summary, started_at, ended_at: Option, status: Option<String> }` — envoyé par le plugin Hermes à `POST /api/v1/ingest/tool-calls` (jeton d'agent).
- `AuditEntry { seq: i64, at, actor: Actor { kind: ActorKind::{Human,Cli,Agent,System}, id, name }, interface: Interface::{Ui,Cli,Mcp,Api,System}, session_id: Option, action: String, target: String, diff: serde_json::Value, prev_hash: String, hash: String }` ; `hash = sha256(prev_hash || canonical_json(entry sans hash))`.

### 3.4 API REST (`docs/api/openapi.yaml`, préfixe `/api/v1`)

Ressources (CRUD sauf mention) : `objects`, `objects/{id}/where-used`, `services`, `data-classes`, `zones`, `agents`, `rules` (+ `rules/{id}/move`), `inspection-rules`, `sessions` (`POST` ouvrir, `GET current`, `POST {id}/discard`, `POST {id}/publish {comment}`, verrous par objet), `sessions/{id}/allow-from-log { flow_id }` (EF-42), `revisions` (`GET`, `GET {n}`, `GET {n}/diff?against=m`), `verify?revision=n` (EF-11), `installs` (`POST { revision, gateways[] }`, `GET`), `gateways` (+ `POST registration-tokens`, `POST {id}/commands`), `logs/flows` (filtres agent, zone, destination, verdict, rule, from, to, q ; pagination curseur), `logs/flows/{id}` (détail + http + tool_call + correlation), `logs/dns`, `logs/stream` (SSE), `captures` (`POST { agent_id, duration_secs }`, `GET {id}/download`), `alerts`, `alert-channels`, `internal-map`, `agents/{id}/overview` (EF-43), `audit` (+ `audit/verify`, `audit/export`), `approvals` (EF-52), `me`, `tokens` (jetons d'API), `intent-policy` (plugin), `ingest/tool-calls`, `enrollments` (création d'agent + jeton plugin). Erreurs : `application/problem+json`. Auth : `Authorization: Bearer <jeton>` (OIDC ou jeton d'API) ; rôles `admin`, `auditor`, `viewer`, `mcp_agent`.

## 4. Lots

Chaque lot détaille ses tâches dans `docs/superpowers/plans/lots/<id>.md` (writing-plans) avant de coder. Les critères d'acceptation ci-dessous sont les tests qui doivent exister et passer.

### L0 — Contrats
- `afw-core` complet (3.1–3.3) + `canonical_json`, `audit_hash`, `Rule::number` ; génération `docs/schemas/*.json` (schemars) par un test d'instantané ; `docs/api/openapi.yaml` (3.4) validé par un test de parsing ; squelette `afw-api` avec routeur et modules vides (`policy`, `logs`, `auth`, `gateways`) pour que L7a/b/c travaillent dans des fichiers disjoints ; migrations réservées : `0001_policy`, `0002_logs`, `0003_auth`, `0004_audit`.
- Tests : aller-retour JSON de chaque type ; `audit_hash` stable ; rejet d'`InstalledPolicy` à empreinte fausse.

### L1 — `afw-dlp`
- Détecteurs intégrés : clés AWS, jetons GitHub/GitLab, clés Anthropic/OpenAI, JWT, clés privées PEM, mots de passe dans URL, chaînes à forte entropie dans `password=`/`token=`, IBAN, e-mail, inventaire infra (IP privées, noms d'hôtes internes configurables). Repris de l'egress-guard et inspirés de Pipelock (mention NOTICE si code repris).
- `Scanner::scan(&[u8]) -> Vec<Finding>`, `StreamScanner` (fenêtre glissante, chevauchement ≥ longueur max d'un motif), `mask(&str, &[Finding]) -> String` (`[SECRET:aws_access_key:3f9a1c2b7d10]`).
- Tests de contournement : secret coupé entre deux tampons, encodé en base64, en URL-encoding, en majuscules ; faux positif S3 présigné (EF-72) : une URL présignée `X-Amz-Signature` n'est pas un secret.

### L2 — `afw-tls`
- `GatewayCa::load_or_create(dir)` (clé ECDSA P-256, 0600, jamais exportée), `GatewayCa::leaf_for(host) -> Arc<CertifiedKey>` avec cache LRU ; `ConsolePki` (CA console, signature de CSR passerelle, vérificateur de certificat client) ; helpers rustls `ServerConfig`/`ClientConfig` mTLS.
- Tests : feuille valide pour SNI et IP, refusée par un client qui ne fait pas confiance à la CA ; CSR signée → mTLS réussi, certificat d'une autre CA refusé.

### L3 — Console (maquette)
- Nuxt 4 + Nuxt UI 4, pnpm, i18n FR/EN, thèmes clair/sombre (tokens de la maquette), mise en page et 9 écrans fidèles à `docs/design/maquette` : journal + détail + « Autoriser », base de règles + barre de session, objets et zones (où utilisé), vue agent, carte des flux internes + alertes, révisions + différences, audit, passerelles, connexion.
- Couche `useApi()` derrière une interface ; implémentation mock pour développer, implémentation `openapi-fetch` (L3b) ensuite. Tests Vitest des composables et du formatage ; lint + typecheck.

### L3b — Console branchée
- Client généré (`openapi-typescript` depuis `docs/api/openapi.yaml`), suppression des mocks en production, SSE du journal en direct, parcours « Autoriser » → session → publier → installer.

### L4 — Plugin Hermes (`integrations/hermes/afw_hermes`)
- Hooks `pre_tool_call` / `post_tool_call` : envoi `ToolCallEvent` (file locale, envoi groupé, jamais bloquant) ; classes d'actions (suppression, accès, infrastructure, génération payante) avec « gate » = blocage + message, politique `GET /api/v1/intent-policy` mise en cache, repli sur la dernière politique connue. Tests pytest.

### L5 — `afw-engine`
- `CompiledPolicy::compile(&InstalledPolicy, now) -> Result<CompiledPolicy, CompileError>` ; `CompiledPolicy::evaluate(&FlowContext) -> Decision` ; `FlowContext { agent_id: Option<Uuid>, src_ip, dst_ip: Option<IpAddr>, dst_port: u16, l4: L4Proto, app: Option<AppProto>, host: Option<String>, method: Option<String>, path: Option<String>, data_classes: Vec<Uuid>, now }` ; `Decision { verdict, rule_id, rule_number, rule_name, layer, implicit: Option<Implicit::{InternalMonitor,Cleanup,UnknownAgent,NoPolicy}>, track, inspect_tls: bool, observed: bool, llm_provider: bool, internal: bool }` ; `resolve_agent(src_ip) -> Option<&Agent>` ; `verify(&PolicyDocument, now) -> Vec<VerifyFinding::{ Shadowed{rule, by}, UnusedObject{id}, Expired{rule} }>` (EF-11).
- Tests : ordre et première correspondance, socle prioritaire, nettoyage, expiration, observation, exemption LLM, joker, CIDR/plage, services avec méthode/chemin, interne surveillé, agent inconnu refusé, règles masquées.

### L6 — `afw-gateway`
- Écoutes : TCP transparent (nftables `redirect` vers `:15001`, destination d'origine par `SO_ORIGINAL_DST`), proxy explicite `:3128` (CONNECT + HTTP absolu), DNS `:53` UDP/TCP (hickory-proto ; répond avec les adresses réelles résolues en amont, journalise, refuse NXDOMAIN-REFUSED si refusé), santé `:9090`.
- Détection d'application par lecture du premier paquet (ClientHello → SNI ; requête HTTP → Host) ; inspection TLS selon `inspect_tls` (rustls serveur avec `GatewayCa::leaf_for`, client amont vérifié par webpki-roots + CA supplémentaires configurables) ; HTTP/1.1 et HTTP/2 via hyper ; corps mis en tampon jusqu'à `max_buffered_body` puis `StreamScanner` ; WebSocket inspecté trame par trame ; coupure dès détection.
- Connexion amont toujours vers le nom contrôlé par la politique (SNI/Host), résolu par la passerelle, jamais vers l'IP choisie par l'agent quand un nom est présent ; Host incohérent avec le SNI = refus.
- Réponse de refus EF-21 ; refus TCP = RST + événement ; politique persistée sur disque (`/var/lib/afw/policy.json`), conservée si console injoignable (EF-23) ; démarrage sans politique valide = tout refuser ; client console mTLS (enregistrement, long-poll, ack, heartbeat, envoi groupé d'événements avec tampon disque borné) ; captures pcap par agent et durée (format pcap, sans libpcap : écriture des segments reconstruits) ; alertes locales (métadonnées cloud, rafale de refus, balayage de ports, port sensible, nouvel hôte interne, secret détecté) ; reconnaissance des actions d'administration Kubernetes/Coolify/Docker/Proxmox à partir de méthode + chemin.
- Script `nftables` d'entrée de la passerelle (`deploy/docker/gateway-entrypoint.sh`) : `ip_forward=1`, redirection TCP depuis l'interface interne, UDP 53 vers le DNS, tout autre forward `drop`.
- Tests de contournement d'abord (`tests/bypass.rs`) : IP directe, port non HTTP, DNS vers un résolveur externe, proxy ignoré, CONNECT vers hôte refusé, Host ≠ SNI (domain fronting), HTTP/1.0 sans Host, secret dans corps/chunked/WebSocket, politique absente.

### L7a — API politique
- Objets/services/classes/zones/agents/règles/inspection, sessions avec verrous (un objet modifié dans une session est verrouillé pour les autres), publication → révision numérotée (document complet + diff JSON lisible), vérification, installations par passerelle (désirée/active/résultat), retour arrière, « Autoriser » depuis un flux, approbations EF-52, audit de chaque mutation.

### L7b — API journaux
- Trait `LogStore` (Postgres par défaut, ClickHouse via HTTP) : ingestion des événements passerelle et des appels d'outil, requêtes filtrées, SSE, corrélation (fenêtre temporelle par agent, confiance `certain|probable|uncertain`), contenus chiffrés AES-256-GCM au repos, consultation tracée (EF-54), rétention, alertes côté console (destination jamais vue, pic de volume, rafale de refus), canaux webhook (générique, Teams, Pulse Chat optionnels), vue agent, carte des flux internes, compteurs de règles.

### L7c — API auth et passerelles
- OIDC générique (découverte, PKCE côté console, validation des jetons), jetons d'API, rôles, l'agent MCP (`mcp_agent`) restreint aux zones `delegated_to_mcp` et jamais à la sienne (EF-51), contrôle des élargissements (EF-52), enregistrement des passerelles par jeton à usage unique + signature de CSR, routes `/gw/v1` mTLS, audit chaîné + vérification + export périodique des empreintes vers un stockage objet (fichier en append-only + S3 Object Lock optionnel).

### L8 — `afw-client` + CLI `afw`
- Toutes les ressources de 3.4 (`afw objects|zones|rules|session|publish|install|revisions|logs|agents|gateways|audit|alerts|captures|tokens …`), sortie tableau ou `--json`, configuration `~/.config/afw/config.toml`.

### L9 — `afw-mcp`
- Serveur MCP stdio et HTTP (rmcp) exposant les mêmes outils que la CLI pour l'agent agréé ; chaque appel porte `Interface::Mcp` dans l'audit.

### L10 — Import egress-guard
- `afw import egress-guard <fichier.yaml> --zone <nom>` : hôtes autorisés/refusés → objets + règles, classes de sensibilité → classes de données, matrice → règles de contenu, classes d'actions → politique d'intention ; rapport d'import. Fichier d'exemple anonymisé dans `examples/`.

### L11 — `afw-enroll`
- Transformation `docker-compose.yml` (réseau interne, conteneur de réseau `afw-net-<agent>` avec `NET_ADMIN` qui pose la route par défaut vers la passerelle, `network_mode: service:afw-net-<agent>` pour l'agent, variables de proxy, montage de la CA, DNS), inverse exacte pour `unenroll` ; client API Coolify (lecture et mise à jour du compose de l'application/service) ; manifestes Kubernetes (passerelle par namespace, NetworkPolicy n'autorisant que la passerelle, ConfigMap CA, variables de proxy) ; installation du plugin Hermes.

### L12 — Déploiement
- Dockerfiles (`afw-gateway`, `afw-api`, `console`), `deploy/compose/docker-compose.yml` (console, API, Postgres, ClickHouse), `deploy/compose/gateway.yml`, chart Helm (`helm lint` + `helm template` testés), environnement `demo/` (zones `internes` et `clients`, agents `daniel-bot` (Hermes), `laurent-bot`, `acme-bot`, service interne `internal-db`, faux fournisseur LLM, cible d'exfiltration).

### L13 — Recette et rapport
- Scénarios du §8 du cahier des charges joués par `demo/scenarios/*.sh` ; captures d'écran de chaque écran ; mesure de latence (p50/p95 avec et sans passerelle) ; tableau de conformité EF/ENF ; rapport PDF (thème classic) dans `docs/rapport/`.

### L14 — Documentation
- `docs/installation.md`, `docs/enrolement.md`, `docs/modele-de-politique.md`, `docs/exploitation.md`, `docs/securite.md` (dont la limite des agents à privilèges), `docs/api.md`, README à jour.
