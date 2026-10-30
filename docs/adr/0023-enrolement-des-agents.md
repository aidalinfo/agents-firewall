# ADR 0023 — Enrôlement des agents (crate `afw-enroll`)

- Statut : accepté — 2026-10-30
- Exigences : EF-60, EF-61, EF-63, EF-64 ; applique l'ADR 0003.

## Contexte
L'enrôlement doit raccorder un agent conteneurisé à la passerelle sans toucher à son image, pour
trois environnements (compose manuel, Coolify, Kubernetes) et un conteneur isolé (`docker run`),
et être réversible. La crate est autonome (pas de dépendance à `afw-core`) : la CLI (L8) et l'API
l'appellent.

## Décisions

### Docker Compose
- **Motif « pause »** (ADR 0003) : service `afw-net-<agent>` (image `afw-netinit:local`,
  `cap_add: [NET_ADMIN]`, IP fixe sur le réseau interne de la passerelle, `dns: [<passerelle>]`,
  `restart: unless-stopped`, étiquettes `afw.enrolled=true` et `afw.agent=<nom>`). Sa commande est
  une boucle `sh` qui repose `ip route replace default via <passerelle>` toutes les 10 s (même
  comportement que l'image netinit du lot L12, qui reçoit aussi `AFW_GATEWAY_IP`). Le `$` du script
  est écrit `$$` pour échapper à l'interpolation de Compose. Le réseau interne n'ayant pas de route
  par défaut, tant que la route n'est pas posée l'agent n'a aucun réseau (fermeture par défaut).
- L'agent passe en `network_mode: service:afw-net-<agent>`, sans aucune capacité ajoutée. Les clés
  que Docker refuse avec ce mode sont **déplacées** sur `afw-net` (`ports`, `expose`, `hostname`,
  `domainname`, `mac_address`, `extra_hosts`, `dns_search`, `dns_opt`) ; `networks`, `dns` et `links`
  sont retirées (avertissement pour `links`).
- Variables : `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` **et leurs formes minuscules** (curl ne lit
  que `http_proxy`), `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`.
  La forme d'origine de `environment`/`labels` (liste ou dictionnaire) est conservée, une variable
  existante est remplacée à sa place.
- `NO_PROXY = localhost,127.0.0.1,::1`, plus **l'hôte de la console** pour un agent Hermes : le plugin
  parle à la console sans passer par le proxy explicite. La route par défaut passe malgré tout par
  la passerelle : ce trafic reste **filtré par la politique** et le socle doit autoriser la console
  (règle de socle « agents → console », ajoutée dans la politique de démo).
- Hermes (EF-61) : plugin monté en lecture seule dans `$HERMES_HOME/plugins/agents-firewall`
  (défaut `/opt/data/plugins/agents-firewall`, `HERMES_HOME=/opt/data` dans les images Hermes ;
  modifiable par `HermesSpec::plugin_dir_container`), `AFW_CONSOLE_URL`, `AFW_AGENT_NAME` et
  `AFW_AGENT_TOKEN=${<variable>}` : le jeton n'est **jamais écrit** dans le fichier, Compose
  l'interpole depuis l'environnement de l'hôte. Pour `docker run`, `-e AFW_AGENT_TOKEN` sans valeur
  (hérité de l'environnement, jamais sur la ligne de commande visible dans `ps`).
- Réseau de la passerelle déclaré `external: true` (il est créé `internal: true` par le
  déploiement de la passerelle).
- **Réversibilité** : l'état d'origine (définition complète du service, déclaration du réseau,
  présence de la clé `networks`) est gardé dans l'extension de premier niveau `x-afw-original`
  (ignorée par Compose). `unenroll` restaure ces valeurs à leur place ; testé : `enroll` puis
  `unenroll` = YAML d'origine sémantiquement égal, y compris avec deux agents désenrôlés dans
  n'importe quel ordre (le dernier agent qui utilise le réseau restaure sa déclaration d'origine).
  Une modification faite à la main sur le service enrôlé est perdue au désenrôlement.
- Idempotence : un deuxième enrôlement du même agent ou du même service est une erreur claire
  (« already enrolled »).
- **Privilèges** : `network_mode: host` est une **erreur** (isolement impossible) ; tout autre
  `network_mode` déjà posé est refusé (non pris en charge). `privileged: true`, capacités
  `NET_ADMIN`/`SYS_ADMIN`/`ALL`, socket Docker monté, espaces de noms de l'hôte (`pid`, `ipc`, `uts`,
  `userns_mode`) donnent un **avertissement** (`EnrollWarning`) et l'enrôlement a lieu : le refus des
  conteneurs privilégiés a été écarté par [Killian] ; la limite est documentée et seulement signalée.
- Traitement par `serde_yaml::Value` : l'ordre des clés est conservé, `afw-net-<agent>` est inséré
  juste avant l'agent. Les **commentaires et ancres YAML sont perdus** (limite de serde_yaml ; un
  éditeur YAML préservant les commentaires n'existe pas sous licence compatible et maintenu).

### CA d'inspection
La CA est montée sur `/usr/local/share/ca-certificates/afw-gateway.crt` et les variables
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` pointent dessus (`NODE_EXTRA_CA_CERTS`
s'ajoute aux racines de Node). Ces trois variables **remplacent** les racines système : pour les
destinations en `Bypass` d'inspection, l'agent verrait le vrai certificat et ne pourrait pas le
valider. Recommandation : passer en `ca_path_host` un **paquet complet** (racines système + CA de
la passerelle) produit sur l'hôte ; la CLI pourra le générer.

### Coolify (EF-64)
La modification vit **dans Coolify** (champ `docker_compose_raw`), sinon un redéploiement
l'écraserait. API v4 vérifiée dans le code de Coolify (`routes/api.php`, `ServicesController`) :
`GET /api/v1/{applications|services}/{uuid}` (compose en clair, visible seulement si le jeton a la
permission `read:sensitive`), `PATCH` du même chemin avec `docker_compose_raw` **encodé en base64**
(Coolify répond 422 sinon), `POST …/restart` (repli `GET` sur 405 pour les versions v4 plus
anciennes). Ordre : lire → transformer → écrire → redémarrer ; rien n'est écrit si la
transformation échoue, rien n'est redémarré si l'écriture échoue. Le jeton n'apparaît pas dans le
`Debug` du client.
Hypothèses non vérifiables sans instance réelle : le `PATCH` d'une *application* (build pack
`dockercompose`) accepte `docker_compose_raw` comme celui d'un *service* ; pour une application dont
le compose vient d'un dépôt Git, Coolify relit le fichier du dépôt au déploiement, la modification
doit alors être faite dans le dépôt (préférer les services Coolify « Docker Compose Empty ») ; le
parseur de Coolify respecte `network_mode: service:…` sans ajouter son propre réseau au service.

### Kubernetes (EF-64)
- Passerelle **par namespace** : Secret (jeton d'enregistrement), ConfigMap (CA publique, vide et
  annotée `afw.ca-pending` tant qu'elle n'est pas connue), PVC d'état (clé de CA conservée au
  redémarrage, jamais exportée), Deployment (1 réplique, `Recreate`, non root, `drop: [ALL]` +
  `NET_BIND_SERVICE`), Service `ClusterIP` **fixe** (adresse DNS des pods).
- `NetworkPolicy` d'egress pour les pods `afw.enrolled=true` : une seule règle, vers les pods de la
  passerelle uniquement, ports TCP 3128, 15001, 80, 443 et UDP/TCP 53 ; ni `ipBlock` ni
  `namespaceSelector`. Une seconde NetworkPolicy limite l'entrée de la passerelle aux pods enrôlés.
  Les ports 80/443 servent au trafic qui ignore le proxy et suit la résolution DNS de la passerelle.
- `patch_pod_template` (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod) :
  étiquette `afw.enrolled=true` sur le gabarit (le sélecteur, immuable, n'est pas modifié),
  annotation `afw.agent`, `dnsPolicy: None` + `dnsConfig` vers la passerelle, variables de proxy,
  CA montée par `subPath` dans chaque conteneur et conteneur d'initialisation. `hostNetwork: true`
  est une erreur ; conteneur `privileged` ou socket d'exécution en `hostPath` : avertissement.
  `NET_ADMIN` n'est pas signalé : la NetworkPolicy est appliquée hors du pod par le CNI.
- Prérequis : un CNI qui applique les NetworkPolicy (Calico, Cilium…) en évaluant l'egress après
  la traduction de l'adresse du Service. Le plugin Hermes n'est pas monté en Kubernetes (il est
  dans l'image de l'agent).

### Vérification sur Docker
Essai réel (Docker 27, réseau `internal` 10.80.0.0/24, image `alpine` à la place de netinit) du
compose enrôlé : dans l'agent, `default via 10.80.0.2`, adresse 10.80.0.11, `HTTPS_PROXY` posé, CA
montée, et `ip link add` refusé (« Operation not permitted ») faute de `NET_ADMIN`. Le résolveur
embarqué de Docker (127.0.0.11) relaie vers la passerelle (`dns:`), depuis l'espace réseau de
l'agent.

## Conséquences
- `enroll_compose` et `patch_pod_template` renvoient `EnrollOutcome { yaml, warnings }` (au lieu
  d'une simple chaîne) pour porter les avertissements ; `k8s_manifests` renvoie un `Result`
  (validation des noms DNS-1123).
- Si `afw-net-<agent>` est recréé, l'agent perd son espace réseau et doit être redémarré (limite
  de Docker pour `network_mode: service:`) ; `restart: unless-stopped` limite ce cas.
