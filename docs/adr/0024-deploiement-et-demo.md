# ADR 0024 — Déploiement (images, Compose, Helm) et environnement de démo

- Statut : accepté — 2026-10-30
- Lot : L12

## Contexte
ENF-06 et le §9 du cahier demandent des images, des fichiers `docker compose` et un chart Helm ; la recette (§8)
doit se jouer localement, sur un poste de 8 Go partagé, sans dépendre d'aucun service Internet. Les binaires
(passerelle, API, console, CLI, plugin) sont construits en parallèle par d'autres lots : le déploiement doit être
prêt avant eux et ne fixer qu'en un seul endroit ce qu'il suppose de leur configuration.

## Décisions

### Images
- `deploy/docker/Dockerfile.api` et `Dockerfile.cli` : multi-étapes `rust:1.91-bookworm` → `debian:bookworm-slim`,
  utilisateur `10001`, caches BuildKit, `SQLX_OFFLINE=true` ; les migrations sont embarquées par `sqlx::migrate!`.
  L'image CLI contient `afw` et `afw-mcp` (utilisée par la démo). Rien n'est poussé dans un registre.
- Dockerfiles de la passerelle et de la console : **réattribués**. `deploy/docker/Dockerfile.gateway` est écrit
  par le lot L6, `console/Dockerfile` par le lot L3 ; ce lot les référence (compose, `deploy/tests/images.sh`)
  sans les écrire.
- `deploy/docker/Dockerfile.netinit` : conteneur « pause » `afw-net-<agent>` (ADR 0003), alpine + iproute2 +
  ca-certificates (`ip`, `awk`, `/etc/ssl/certs/ca-certificates.crt`). Sa logique est **exactement**
  `afw_enroll::netinit_script` (ADR 0023, source de vérité), recopiée dans `deploy/docker/netinit.sh` entre deux
  marqueurs ; `deploy/tests/enroll-sync.sh` la régénère avec la crate et échoue au moindre écart. Seules les
  adresses viennent de l'environnement (`AFW_GATEWAY_IP`, `AFW_AGENT_IP`, validées). Toutes les 10 s : interfaces
  étrangères coupées, route `/32` puis route par défaut vers la passerelle, **toutes les autres routes
  supprimées** (aucun chemin direct entre agents), autre famille d'adresses vidée, paquet de CA
  (`bundle.pem` = racines système + CA de la passerelle, `gateway.crt`) reconstruit dans `afw-ca-<agent>`,
  monté en lecture seule dans l'agent ; sain seulement quand tout est correct. afw-enroll pose en plus
  `accept_redirects=0`. La revue demandait un intervalle de 2 s : l'intervalle appartient à
  `netinit_script` (10 s, lot L11) et n'est pas redéfini ici, pour ne pas diverger de la source de vérité.

### Compose
- `deploy/compose/docker-compose.yml` : console, API, PostgreSQL 17 ; ClickHouse 24.8 seulement avec le profil
  `clickhouse` (ADR 0006). Réseau `backend` interne ; ports publiés sur `127.0.0.1` sauf l'entrée passerelle
  `:8443` (mTLS), qui doit être joignable des hôtes d'agents.
- `deploy/compose/gateway.yml` : une passerelle par hôte d'agents, réseau `afw-internal` (`internal: true`,
  sous-réseau fixe) + réseau de sortie, `NET_ADMIN`, `ip_forward`, volume d'état (identité, CA d'inspection,
  dernière politique) et répertoire public de la CA.

### Helm
Chart `deploy/helm/agents-firewall` : API (une seule réplique en V1 : la PKI console vit sur son volume ; la
contrainte est vérifiée par le chart), console, PostgreSQL intégré (simple StatefulSet, désactivable au profit
d'une base externe), Ingress (console + `/api`), secrets dont la clé de contenu générée une fois et conservée
aux mises à jour (`lookup`) — et **refus explicite** (`fail`) quand `lookup` est indisponible (`helm template`,
`--dry-run`, GitOps) sans `secrets.dataKey`/`existingSecret`, plutôt qu'une clé régénérée à chaque rendu —, service distinct pour l'entrée passerelle (jamais terminée par l'Ingress).
Passerelles par namespace optionnelles (`gateway.instances`) : Deployment (root, car la passerelle a besoin de
capacités réseau ; donc pas de `runAsNonRoot`, mais `readOnlyRootFilesystem`, toutes les autres capacités
retirées, état sur PVC, `/tmp` en `emptyDir`) + Service (proxy, DNS, ports
transparents), PVC conservé, ConfigMap `afw-gateway-ca`, et NetworkPolicy `afw-enrolled-egress` : les pods
`afw.enrolled=true` ne sortent que vers leur passerelle (proxy, écoute transparente, DNS). Vérifié par
`helm lint --strict`, `helm template` et kubeconform.

### Démo (`demo/`)
- Quatre réseaux : `control` (10.76.0.0/24, seul publié, sur 127.0.0.1), `afw-internal` (10.77.0.0/24, interne),
  `lan` (10.78.0.0/24, interne, `internal-db`), `wan` (198.18.0.0/24, interne, « Internet » simulé). La plage
  198.18.0.0/15 (RFC 2544) n'est pas dans les réseaux internes par défaut de la politique : les fausses
  destinations publiques sont traitées comme Internet sans changer les réglages.
- DNS de démo CoreDNS (Apache 2.0) : noms de démo → faux services ; tout le reste NXDOMAIN, aucun `forward`
  vers l'extérieur. CA de démo générée par openssl (image `afw-demo-tools`), à laquelle seule la passerelle
  fait confiance en amont. Faux services Python (bibliothèque standard) qui journalisent ce qu'ils reçoivent :
  preuve que rien n'est arrivé chez la cible.
- Agents : `demo/agents.base.yml` (avant enrôlement) → `demo/docker-compose.agents.yml`, **généré par
  `afw_enroll::enroll_compose`** (outil `deploy/tools/demo-enroll`, vérifié par `enroll-sync.sh`) ; seules
  adaptations : le réseau interne est défini par le compose principal et la CA de la passerelle vient de son
  volume public (`gateway.crt`). `daniel-bot` est l'agent Hermes factice du lot L4 ; son jeton de plugin
  (rôle `agent_plugin`) vient de `POST /enrollments` (`EnrollmentRequest`).
- Réseaux : `control` est interne ; seuls l'API et la console sont sur `publish` (ports sur 127.0.0.1) ;
  la passerelle n'est que sur des réseaux internes : elle ne joint rien hors de la démo et ne résout que par
  `AFW_UPSTREAM_DNS`.
- Secrets : le jeton d'administration et `AFW_DATA_KEY` sont générés par `up.sh` dans `demo/.state/secrets.env`
  (0600, jamais commités) ; aucune valeur par défaut dans le compose.
- Politique : le socle n'ouvre la console qu'à la zone de `daniel-bot` et aux seuls chemins
  `/api/v1/ingest/tool-calls` et `/api/v1/intent-policy`, puis refuse tout le plan de contrôle (10.76.0.0/24) :
  sans cela l'acceptation implicite « interne surveillé » laisserait un agent administrer la politique.
- PKI : la clé de la CA de démo n'existe que dans un volume monté par le seul job PKI ; les faux services ont
  leur certificat, la passerelle le seul certificat de la CA.
- `demo/lib.sh` est le **seul** endroit qui connaît les chemins de l'API, les charges utiles et la syntaxe de
  la CLI (CLI d'abord, repli `curl`) ; les scénarios n'appellent que ses fonctions. La politique de démo est un
  `PolicyDocument` à identifiants fixes, chargé ressource par ressource avec réécriture des références vers les
  identifiants rendus par l'API.
- Chaque scénario rend PASS, FAIL ou SKIP (dépendance absente) avec ses preuves. Un résultat « bloqué » n'est
  accepté qu'après un témoin positif (un marqueur envoyé à la destination autorisée et **reçu**) et la lecture
  effective du journal de réception de la cible : un journal illisible fait échouer le scénario.
- Toutes les routes appelées par `demo/lib.sh` et les scénarios sont vérifiées contre `docs/api/openapi.yaml`.
- Mémoire : pas de ClickHouse, limites mémoire par service ; une seule image outillage pour tous les faux services.

## Hypothèses sur la configuration des autres lots (à confirmer à leur fusion)
- Passerelle : exporte le certificat public de sa CA d'inspection dans `/var/lib/afw/public/gateway.crt`.
- API (L7) : `AFW_LISTEN` (existe), `DATABASE_URL` (existe), `AFW_GW_LISTEN` (entrée mTLS `:8443`),
  `AFW_PUBLIC_URL`, `AFW_PUBLIC_HOSTNAMES` (SAN du certificat de l'entrée passerelle), `AFW_STATE_DIR`,
  `AFW_CONSOLE_CA_EXPORT` (certificat public de la CA console), `AFW_DATA_KEY`, `AFW_BOOTSTRAP_ADMIN_TOKEN`,
  `AFW_CORS_ORIGINS`, `AFW_LOG_STORE`, `AFW_CLICKHOUSE_*`, `AFW_OIDC_*`, `AFW_AUDIT_EXPORT_DIR` ; `/healthz`.
- Passerelle (L6) : `AFW_CONSOLE_URL`, `AFW_CONSOLE_CA_FILE`, `AFW_REGISTRATION_TOKEN`, `AFW_GATEWAY_NAME`,
  `AFW_STATE_DIR=/var/lib/afw`, `AFW_CA_EXPORT` (certificat public de la CA d'inspection, `gateway.crt`),
  `AFW_INTERNAL_SUBNETS`, `AFW_UPSTREAM_DNS`, `AFW_UPSTREAM_CA_FILE`, `AFW_INTERCEPT=proxy-dns` (Kubernetes) ;
  écoutes 3128, 15001, 53, santé 9090 `/healthz`.
- Console (L3) : `NUXT_PUBLIC_API_MODE`, `NUXT_PUBLIC_API_BASE`, port 3000.
- CLI/MCP (L8/L9) : `AFW_URL`, `AFW_TOKEN` ; syntaxe des commandes et noms des outils MCP surchargeables
  (`AFW_CLI_*`, `MCP_TOOL_*`, `AFW_ENROLL_ARGS`).
- Plugin Hermes (L4, fusionné) : `integrations/hermes/demo/Dockerfile.demo`, serveur de commande `127.0.0.1:8080/run`.
Si un lot retient d'autres noms, on corrige les fichiers de `deploy/` et `demo/lib.sh`, pas les scénarios.

## Alternatives écartées
- Démo branchée sur Internet (vrais fournisseurs) : non reproductible, dépend de clés et du réseau.
- Sous-chart Bitnami PostgreSQL : dépendance externe lourde ; un StatefulSet simple ou une base externe suffit.
- Scénarios écrits directement en `curl` : chaque évolution de l'API aurait touché douze scripts.
