# ADR 0023 — Enrôlement des agents (crate `afw-enroll`)

- Statut : accepté — 2026-10-30 (révisé après la revue indépendante de la PR #6)
- Exigences : EF-60, EF-61, EF-63, EF-64 ; applique l'ADR 0003.

## Contexte
L'enrôlement doit raccorder un agent conteneurisé à la passerelle sans toucher à son image, pour
trois environnements (compose manuel, Coolify, Kubernetes) et un conteneur isolé (`docker run`),
et être réversible. La crate est autonome (pas de dépendance à `afw-core`) : la CLI (L8) et l'API
l'appellent. La revue de la PR #6 a démontré des contournements (dont un sur un vrai Docker) ;
ses tests sont gardés comme tests de non-régression (`tests/review_bypass.rs`).

## Décisions

### Conteneur réseau `afw-net-<agent>` (motif « pause », ADR 0003)
- `cap_drop: [ALL]` puis `cap_add: [NET_ADMIN]`, IP fixe sur le réseau interne de la passerelle,
  `dns: [<passerelle>]`, `restart: unless-stopped`, étiquettes `afw.enrolled=true` et
  `afw.agent=<nom>`, `sysctls` `net.ipv4.conf.{all,default}.accept_redirects=0` (la passerelle
  relaie entre agents d'un même sous-réseau : une redirection ICMP ne doit jamais créer de chemin
  direct).
- Son script, **source de vérité** exposée par `netinit_script(spec)` (l'image netinit du lot L12
  doit l'exécuter tel quel), tourne toutes les 10 s, sans fenêtre où la route par défaut manque :
  1. trouve l'interface qui porte l'adresse de l'agent et met **hors service toute autre interface**
     sauf `lo` (un réseau ajouté plus tard, par Coolify par exemple, est coupé en moins de 10 s) ;
  2. `ip route replace <gw>/32 dev <iface> scope link`, puis `ip route replace default via <gw>` ;
  3. **supprime toute autre route**, en particulier celle du sous-réseau interne : un agent ne
     joint plus directement un autre agent, tout passe par la passerelle ;
  4. vide les routes de l'autre famille d'adresses ;
  5. construit `/afw-ca/bundle.pem` (racines système de l'image + CA de la passerelle) et
     `/afw-ca/gateway.crt` dans le volume `afw-ca-<agent>`.
  Le fichier `/tmp/afw-ready` n'existe que si les routes sont conformes ; il sert de `healthcheck`.
  Avant le premier passage, le réseau `internal` n'a aucune route par défaut (fermeture par défaut).
  Le `$` du script est écrit `$$` dans le compose (échappement de l'interpolation Compose).
- Vérifié sur un vrai Docker (OrbStack, deux agents enrôlés, réseau `internal` 10.80.0.0/24) :
  table de routes de l'agent réduite à `default via 10.80.0.2` et `10.80.0.2 dev eth0` ; sans
  passerelle, `nc` de l'agent b vers l'agent a échoue (avant correction : succès, voisinage ARP
  direct) ; `ip route add` refusé dans l'agent ; un réseau `internal` branché à chaud sur le
  conteneur réseau passe à `DOWN` en moins de 12 s et sa cible devient injoignable ;
  `accept_redirects` vaut 0 sur `all` et `eth0` ; paquet de CA construit et monté.
  `docker network connect` d'un réseau non `internal` est de toute façon refusé par Docker
  (« failed to set gateway: file exists ») car la route par défaut existe déjà.

### Agent (Docker Compose)
- `network_mode: service:afw-net-<agent>`, **`cap_drop: [NET_RAW]`** ajouté (ARP/IP spoofing sur
  le réseau interne), aucune capacité ajoutée, `depends_on: afw-net-<agent>: service_healthy`
  (une liste `depends_on` existante devient un dictionnaire `service_started`).
- Les clés que Docker refuse avec ce mode sont **déplacées** sur `afw-net` (`expose`,
  `hostname`, `domainname`, `mac_address`, `extra_hosts`, `dns_search`, `dns_opt`) ; `networks`,
  `dns`, `links` et les `sysctls` `net.*` sont retirés (avertissements `LinksRemoved`,
  `NetSysctlsRemoved`).
- **Ports publiés (révision, issue #22).** La première version déplaçait `ports` sur `afw-net`
  avec un simple avertissement : sur un réseau `internal`, Docker garde le `PortBindings` dans les
  métadonnées mais **ne crée aucun écouteur** sur l'hôte ; les rappels entrants étaient coupés en
  silence. Ajouter un second réseau à `afw-net` est exclu (netinit le coupe ; actif, il
  contournerait la passerelle). Décision : un **relais d'entrée** `afw-in-<agent>` (image netinit,
  `cap_drop: [ALL]`, `cap_add: [NET_ADMIN, NET_BIND_SERVICE]`, `depends_on` l'agent) reprend
  `ports` **à l'identique** et les réseaux d'origine de l'agent, plus le réseau d'entrée
  `afw-ingress` (`internal: true`) de la passerelle ; il pose `ip route replace <agent>/32 via
  <passerelle côté entrée>` et lance un `socat` par port de conteneur vers le même port de l'agent.
  La passerelle (`AFW_INGRESS_SUBNETS`/`AFW_INGRESS_IFACE`) n'accepte en `forward` que les
  **nouvelles connexions TCP entrée → interne**, plus `ct state established,related`, et les
  **masque** (`masquerade`) : l'agent voit la passerelle comme pair et répond par sa route unique,
  le trajet retour est symétrique. Aucune nouvelle connexion de l'entrée vers la passerelle
  elle-même. L'agent garde une interface et deux routes ; passerelle arrêtée, sorties et entrées
  sont coupées. Avertissement `PortsRelayed` (décrit le mécanisme au `--dry-run`). Refus
  explicites : UDP, port de conteneur non littéral, plus de 64 ports, spec sans `ingress`.
  Le transfert DNAT par la passerelle seule a été écarté : il imposerait de republier les ports
  sur la passerelle (redémarrage commun à tous les agents) et une table de correspondance par
  agent ; le proxy transparent a aussi été écarté (source inconnue refusée, TLS entrant intercepté).
  Limites : flux entrants ni inspectés ni journalisés, l'agent ne voit pas l'adresse du client,
  tout conteneur du réseau `afw-ingress` peut joindre les agents. Vérifié par
  `deploy/tests/ingress.sh` (Docker réel : ports joignables avant/après, pair = passerelle,
  adresse d'hôte conservée, aucune sortie de contournement, passerelle arrêtée, désenrôlement
  identique au fichier d'origine).
- **Ports publiés, chemin relayé (révision, issue #24).** Sur un hôte qui filtre le trafic des
  ponts (`br_netfilter`), Docker installe pour chaque réseau `internal` les règles
  `! -s <sous-réseau> -o <pont> -j DROP` et `! -d <sous-réseau> -i <pont> -j DROP` : le SYN du
  relais, adressé à l'agent (hors du sous-réseau d'entrée), était supprimé sur le pont d'entrée
  avant d'atteindre la passerelle. Décision : plus aucun paquet ne quitte le sous-réseau de son
  pont. La passerelle expose un **relais d'entrée** (`AFW_INGRESS_PORT`, 15002 ; module
  `afw-gateway::ingress`) : `CONNECT <ip>:<port>` HTTP/1.x, IP littérale des sous-réseaux internes
  seulement (`AFW_INGRESS_TARGETS`, déduits par l'entrypoint), jamais une adresse de la passerelle,
  en-tête limité à 4 Kio, 4096 connexions simultanées. L'entrypoint ne l'ouvre que sur les
  interfaces d'entrée (`counter accept`, refus ailleurs) et **supprime le `forward` et le
  `masquerade`** : la passerelle ne route plus rien entre les réseaux. Le relais `afw-in-<agent>`
  perd `NET_ADMIN` (aucune route) et lance `socat … PROXY:<passerelle>:<agent>:<port>,proxyport=15002`.
  L'agent voit toujours la passerelle comme pair ; passerelle arrêtée, entrées et sorties sont
  coupées. Écartés : rendre `afw-ingress` non `internal` (Docker pourrait y choisir la route par
  défaut de la passerelle ou des relais, et casser le retour des ports publiés ; l'hôte deviendrait
  routeur de ce réseau), modifier les règles de l'hôte (`DOCKER-USER` : hors de portée de
  l'enrôlement, perdu au redémarrage de Docker), un tunnel IP-in-IP (module noyau, routage de
  retour par marque), le DNAT par agent (table de correspondance dans la passerelle). Le proxy
  transparent reste écarté pour l'entrée : ce relais est un écouteur distinct, qui n'évalue pas la
  politique de sortie. Même règle d'isolation, conséquence connue : une sortie de l'agent qui
  ignore le proxy vers une adresse hors du sous-réseau interne est supprimée par Docker avant
  l'interception transparente (refus sans journal, toujours sans contournement). Vérifié par
  `deploy/tests/ingress.sh`, qui active `br_netfilter` si besoin, contrôle la règle d'isolation
  installée sur l'hôte et le compteur du relais d'entrée côté passerelle.
- Variables : `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` et leurs formes minuscules,
  `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` → `…/afw/bundle.pem` (paquet complet :
  les destinations exemptées d'inspection restent vérifiables), `NODE_EXTRA_CA_CERTS` →
  `…/afw/gateway.crt` (Node l'ajoute à ses propres racines). Le volume `afw-ca-<agent>` est monté
  **en lecture seule comme répertoire** sur `/usr/local/share/ca-certificates/afw` (repris par
  `update-ca-certificates`) ; le fichier CA de l'hôte n'est monté que dans `afw-net`.
- `NO_PROXY = localhost,127.0.0.1,::1`, plus l'hôte de la console pour un agent Hermes : le plugin
  parle à la console sans le proxy explicite. La route par défaut passe malgré tout par la
  passerelle : ce trafic reste **filtré par la politique** et **le socle doit autoriser la
  console** (règle de socle « agents → console », ajoutée dans la politique de démo).
- Hermes (EF-61) : plugin monté en lecture seule dans `$HERMES_HOME/plugins/agents-firewall`
  (défaut `/opt/data/plugins/agents-firewall`, modifiable), `AFW_CONSOLE_URL`, `AFW_AGENT_NAME` et
  `AFW_AGENT_TOKEN=${<variable>}` : le jeton n'est **jamais écrit** dans le fichier. Pour
  `docker run`, `-e AFW_AGENT_TOKEN` sans valeur (hérité, jamais visible dans `ps`).

### Analyse et avertissements
- Les clés de fusion YAML (`<<`) sont **résolues avant l'analyse** (`apply_merge`) : une capacité
  cachée derrière une ancre est vue. `extends` est **refusé** (clés héritées d'un autre fichier,
  impossibles à analyser) : le résoudre avant d'enrôler.
- Le service agent **et tout service qui rejoint son espace réseau** (`network_mode:
  service:<agent>`, `container:<container_name>`, ou celui d'`afw-net`) sont analysés
  (`JoinsAgentNetwork` + leurs propres avertissements).
- `network_mode: host` est une **erreur** ; tout autre `network_mode` déjà posé est refusé.
  Avertissements (l'enrôlement a lieu, [Killian] a écarté le refus des conteneurs privilégiés) :
  `privileged`, capacités `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`,
  `SYS_PTRACE`, `BPF`, `DAC_READ_SEARCH`, `ALL` ; sockets d'exécution (Docker, Podman, containerd,
  CRI-O, tout `*.sock`, `/var/run`, `/run`) ; espaces de noms de l'hôte (`pid`, `ipc`, `uts`,
  `userns_mode`, `cgroup`) ; `pid`/`ipc` partagés avec un autre conteneur ; `volumes_from`.

### Réversibilité
L'état d'origine (définition complète du service, déclaration du réseau, présence ou valeur nulle
des clés `networks` et `volumes`) est gardé dans l'extension de premier niveau `x-afw-original`.
`unenroll` restaure ces valeurs à leur place ; testé : `enroll` puis `unenroll` = YAML d'origine
sémantiquement égal, y compris `networks:` nul, deux agents désenrôlés dans n'importe quel ordre,
sur le même réseau ou non. Limites : une modification faite à la main sur le service enrôlé est
perdue ; un fichier avec `<<` est restauré sous sa forme fusionnée ; commentaires et ancres sont
perdus (serde_yaml). Un deuxième enrôlement est une erreur claire (« already enrolled »).

### Coolify (EF-64)
La modification vit **dans Coolify** (`docker_compose_raw`), sinon un redéploiement l'écraserait.
API v4 vérifiée dans le code de Coolify (`routes/api.php`, `ServicesController`) : `GET
/api/v1/{applications|services}/{uuid}` (compose en clair, visible seulement avec la permission
`read:sensitive`), `PATCH` du même chemin avec `docker_compose_raw` **en base64**, `POST
…/restart` (repli `GET` sur 405).
- Ordre : lire → transformer → écrire → **relire et vérifier** qu'`afw-net` n'est attaché qu'au
  réseau de la passerelle et que l'agent est toujours dans son espace réseau → redémarrer. Si la
  vérification ou le **redémarrage échoue, le compose d'origine est réécrit** et une erreur est
  renvoyée (`CoolifyRejected` ou l'erreur HTTP). Si la restauration échoue elle aussi, un nouvel
  `enroll_coolify` avec les mêmes paramètres (annotation identique) **reprend au redémarrage**
  sans réécrire.
- Coolify peut ajouter son propre réseau aux services au déploiement (hors `docker_compose_raw`) :
  le script d'`afw-net` coupe toute interface autre que celle de la passerelle (fenêtre ≤ 10 s).
- Jeton Hermes : le compose référence `${<agent_token_env>}` ; la valeur se pose comme variable
  d'environnement de la ressource avec `CoolifyClient::set_env` (`PATCH …/envs/bulk`,
  `{"data":[{"key","value"}]}`), ou à la main dans l'interface Coolify (Environment Variables).
- Hypothèses non vérifiables sans instance réelle : le `PATCH` d'une *application* accepte
  `docker_compose_raw` comme celui d'un *service* ; `envs/bulk` crée la variable si elle manque ;
  pour une application dont le compose vient de Git, Coolify relit le dépôt (préférer les services
  « Docker Compose Empty »).

### Kubernetes (EF-64)
- Passerelle **dans un namespace dédié** (`afw-gw-<namespace>` par défaut, distinct de celui des
  agents) : un agent qui peut créer des pods dans son namespace ne peut pas se faire passer pour
  elle. Manifestes : Namespace, ConfigMap de la CA publique (dans le namespace des agents), PVC
  d'état, Deployment (non root, `drop: [ALL]`, `net.ipv4.ip_unprivileged_port_start=0` pour
  écouter 53/80/443 sans capacité), Service `ClusterIP` fixe. Le jeton d'enregistrement est lu
  dans un **Secret existant** (`secretKeyRef`), jamais écrit en clair dans les manifestes.
- `NetworkPolicy` d'egress (namespace des agents) pour les pods `afw.enrolled=true` : une seule
  règle, un seul pair qui combine `namespaceSelector` (`kubernetes.io/metadata.name`) **et**
  `podSelector` de la passerelle, ports TCP 3128, 15001, 80, 443 et UDP/TCP 53 ; ni `ipBlock` ni
  pair large. Une seconde NetworkPolicy limite l'entrée de la passerelle aux pods enrôlés.
- **Les NetworkPolicy sont additives** : toute autre politique qui sélectionne les pods enrôlés et
  autorise une sortie élargit l'egress et contourne la passerelle. `check_networkpolicies(&[…])`
  signale ces politiques (règle sans `to`, `ipBlock`, pair qui n'est pas la passerelle) ; la CLI
  doit l'appeler sur les politiques existantes du namespace avant d'enrôler.
- `patch_pod_template` : étiquette `afw.enrolled=true` (sélecteur immuable non modifié),
  annotation `afw.agent`, `automountServiceAccountToken: false`, `dnsPolicy: None` + `dnsConfig`
  vers la passerelle, variables de proxy, `NET_RAW` retiré de chaque conteneur, conteneur
  d'initialisation `afw-ca-bundle` (non root, sans capacité) qui construit le paquet dans un
  `emptyDir` monté **comme répertoire** (pas de `subPath`) en lecture seule. `hostNetwork: true`
  est une erreur ; `privileged`, capacités dangereuses, `hostPID`, `hostIPC`, `hostPath` (et
  sockets d'exécution) donnent un avertissement.
- Prérequis : un CNI qui applique les NetworkPolicy (Calico, Cilium…) en évaluant l'egress après
  la traduction d'adresse du Service. Le plugin Hermes n'est pas monté en Kubernetes (il est dans
  l'image de l'agent).

## Conséquences
- `enroll_compose` et `patch_pod_template` renvoient `EnrollOutcome { yaml, warnings }` ;
  `k8s_manifests` renvoie un `Result` ; `EnrollWarning` porte le service concerné.
- Le lot L12 aligne `deploy/docker/netinit.sh` sur `netinit_script` ; l'image doit fournir `ip`,
  `awk` et `/etc/ssl/certs/ca-certificates.crt`. La passerelle (L6) devrait aussi désactiver
  l'envoi de redirections ICMP (`send_redirects=0`) sur l'interface interne.
- Si `afw-net-<agent>` est recréé, l'agent perd son espace réseau et doit être redémarré.
