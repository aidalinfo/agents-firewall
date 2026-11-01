# Enrôlement des agents

**Enrôler** un agent, c'est le placer derrière la passerelle de son hôte : à partir de là, il n'a plus d'autre chemin vers le réseau, son trafic est journalisé et la politique de sa zone s'applique. **Désenrôler**, c'est revenir exactement à l'état d'avant.

Ce guide suppose qu'une passerelle est déjà installée et enregistrée sur l'hôte (voir [installation.md](installation.md#3-installer-une-passerelle-sur-un-hôte-dagents)).

> Le mécanisme réseau est fixé par l'[ADR 0003](adr/0003-isolement-reseau.md), sa mise en œuvre (crate `afw-enroll`) par l'[ADR 0023](adr/0023-enrolement-des-agents.md). Toutes les options : `afw enroll --help` et [cli.md](cli.md#enrôlement-ef-60-ef-64).

## En bref

| Environnement | Ce que fait l'enrôlement | Où vit la modification |
|---|---|---|
| Docker Compose géré à la main | réécrit le `docker-compose.yml` de l'agent | dans le fichier compose |
| Conteneur géré par Coolify | lit et réécrit le compose **par l'API Coolify**, puis redéploie | dans Coolify, donc conservée aux redéploiements |
| Pod Kubernetes | passerelle par namespace, NetworkPolicy, patch du gabarit de pod | dans les manifestes du namespace |
| Conteneur lancé par `docker run` | fournit les arguments à ajouter | dans votre commande ou votre outil |
| Agent Hermes | tout ce qui précède, plus le plugin Hermes | idem + dossier du plugin |

Dans tous les cas, l'enrôlement **crée l'objet agent** dans la console et **l'affecte à une zone**. Un agent appartient à une seule zone.

## Ce que fait la commande, pas à pas

```sh
afw enroll <service> --zone <zone> --ip <adresse> --compose docker-compose.yml [--apply] [--publish "commentaire"]
afw unenroll <agent> --compose docker-compose.yml [--apply] [--publish "commentaire"]
```

Pour un agent Docker Compose, `afw enroll` :

1. **transforme le fichier localement** et l'analyse (avertissements, refus) ; si cette étape échoue, rien n'est modifié ;
2. **crée l'agent** dans votre session d'édition (`POST /api/v1/enrollments`), dans la zone choisie, avec son **adresse IP fixe** sur le réseau interne de la passerelle (`--ip`, obligatoire). Cette adresse est son identité : c'est par elle que la passerelle sait quel agent parle ;
3. **écrit le fichier** : un petit conteneur réseau `afw-net-<agent>` est ajouté (voir ci-dessous), l'agent est rattaché à son espace réseau et perd ses propres réseaux et DNS (ses ports et son nom d'hôte sont déplacés sur `afw-net`), les variables de proxy et le paquet de certificats de l'autorité d'inspection sont posés ;
4. **garde l'état d'origine** du service dans l'extension `x-afw-original` du fichier compose, pour que `afw unenroll` puisse tout défaire ;
5. avec `--apply`, lance `docker compose -f <fichier> up -d` ; sinon, c'est à vous de le faire.

Si l'écriture ou le démarrage échoue, l'agent est retiré de la session. L'agent n'est protégé par la politique qu'après **publication** (`--publish` ou `afw session publish`) puis **installation** (`afw install`). Enrôler deux fois le même agent est refusé avec un message clair (« already enrolled »).

## Le motif afw-net, ou pourquoi un conteneur de plus

Un agent pourrait vouloir changer sa route par défaut pour contourner la passerelle. Pour l'en empêcher sans lui donner aucun privilège, on reprend le motif du conteneur « pause » de Kubernetes :

```
                 réseau Docker interne (internal: true, aucune sortie)
  ┌──────────────────────────────┐            ┌──────────────────────┐
  │ afw-net-mon-agent            │            │ passerelle           │──▶ Internet,
  │  NET_ADMIN, IP fixe          │── route ──▶│  nftables + proxy    │    LAN…
  │  pose : default via passerelle            │  + DNS filtrant      │
  │  ┌────────────────────────┐  │            └──────────────────────┘
  │  │ mon-agent              │  │
  │  │ network_mode:          │  │
  │  │  service:afw-net-…     │  │
  │  │ (sans NET_ADMIN)       │  │
  │  └────────────────────────┘  │
  └──────────────────────────────┘
```

- `afw-net-<agent>` est le seul à posséder `NET_ADMIN` (toutes les autres capacités retirées). Toutes les 10 secondes, il pose la route par défaut vers la passerelle, supprime toute autre route (y compris celle du sous-réseau interne : un agent ne joint jamais directement un autre agent), coupe toute autre interface que celle de la passerelle, et construit le paquet de certificats de l'agent. Il ne fait rien d'autre.
- L'agent partage l'espace réseau de ce conteneur (`network_mode: "service:afw-net-<agent>"`). Il n'a pas `NET_ADMIN`, et `NET_RAW` lui est retiré : il ne peut ni modifier la route, ni toucher au pare-feu, ni usurper une adresse.
- Si l'agent redémarre, il retrouve le même espace réseau, donc la même adresse et la même route. Si `afw-net-<agent>` est recréé, l'agent doit être redémarré.
- Le réseau interne est déclaré `internal: true` : sans la passerelle, il n'existe aucune sortie. **Si la passerelle s'arrête, l'agent n'a plus de réseau** (fermeture par défaut).
- Les variables `HTTP_PROXY` / `HTTPS_PROXY` ne sont qu'un confort : elles permettent d'attribuer plus finement le nom de destination pour les clients qui les respectent. Un programme qui les ignore passe quand même par la passerelle, par la route.

## Docker Compose

### Avant / après

Avant :

```yaml
services:
  mon-agent:
    image: exemple/mon-agent:1.4
    ports:
      - "8080:8080"
    networks: [default]
```

Après `afw enroll mon-agent --zone clients --ip 10.77.0.21 --compose docker-compose.yml` (extrait abrégé ; le fichier réel est produit par l'outil, voir par exemple `demo/docker-compose.agents.yml`) :

```yaml
services:
  afw-net-mon-agent:
    image: afw-netinit:local
    restart: unless-stopped
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    command: [sh, -c, "…"]            # script de routage, rejoué toutes les 10 s
    networks:
      afw-internal:
        ipv4_address: 10.77.0.21      # adresse fixe de l'agent
    dns: [10.77.0.2]                  # la passerelle
    sysctls:
      net.ipv4.conf.all.accept_redirects: 0
      net.ipv4.conf.default.accept_redirects: 0
    ports:
      - "8080:8080"                   # déplacés ici, mais plus publiés (réseau interne)
    volumes:
      - /etc/agents-firewall/gateway.crt:/afw-ca-src/gateway.crt:ro   # CA de la passerelle (--ca-path), monté ici seulement
      - afw-ca-mon-agent:/afw-ca                # paquet de certificats construit pour l'agent
    healthcheck: { … }                # prêt seulement si les routes sont conformes
    labels:
      afw.enrolled: "true"
      afw.agent: mon-agent

  mon-agent:
    image: exemple/mon-agent:1.4
    network_mode: service:afw-net-mon-agent
    cap_drop: [NET_RAW]
    depends_on:
      afw-net-mon-agent:
        condition: service_healthy
    environment:
      HTTP_PROXY: http://10.77.0.2:3128          # et http_proxy, https_proxy, no_proxy
      HTTPS_PROXY: http://10.77.0.2:3128
      NO_PROXY: localhost,127.0.0.1,::1
      REQUESTS_CA_BUNDLE: /usr/local/share/ca-certificates/afw/bundle.pem
      SSL_CERT_FILE: /usr/local/share/ca-certificates/afw/bundle.pem
      CURL_CA_BUNDLE: /usr/local/share/ca-certificates/afw/bundle.pem
      NODE_EXTRA_CA_CERTS: /usr/local/share/ca-certificates/afw/gateway.crt
    volumes:
      - afw-ca-mon-agent:/usr/local/share/ca-certificates/afw:ro
    labels:
      afw.enrolled: "true"
      afw.agent: mon-agent

networks:
  afw-internal:
    external: true

x-afw-original: { … }                 # état d'origine, pour unenroll
```

Les ports déplacés sur `afw-net` sont sur un réseau interne : Docker ne les publie plus (avertissement), l'accès entrant passe par la passerelle. Les variables de certificat couvrent les environnements les plus courants (Python `requests`, OpenSSL, Node.js, curl) ; `bundle.pem` contient les racines du système plus l'autorité de la passerelle. Une application qui embarque sa propre liste d'autorités ou qui épingle un certificat refusera l'inspection : voir [modele-de-politique.md](modele-de-politique.md#politique-dinspection-https).

### Avertissements et refus

| Situation | Effet |
|---|---|
| `network_mode: host` (ou tout autre `network_mode` déjà posé), `extends` | **refus** : avec `host`, l'agent partagerait la pile réseau de l'hôte ; l'isolement est impossible, l'enrôlement mentirait donc sur la protection (choix du constructeur, [ADR 0023](adr/0023-enrolement-des-agents.md)) ; `extends` doit être résolu avant d'enrôler |
| `privileged: true`, capacités `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`… | **avertissement** : un conteneur privilégié peut modifier le réseau ; l'agent est enrôlé, mais la protection n'est plus garantie |
| socket d'exécution monté (`/var/run/docker.sock`, Podman, containerd…) | **avertissement** : l'agent peut lancer d'autres conteneurs hors de la passerelle |
| espaces de noms de l'hôte (`pid`, `ipc`…), `volumes_from` | **avertissement** |

Les conteneurs privilégiés ou ayant le socket Docker sont seulement **signalés par un avertissement** : leur refus à l'enrôlement a été volontairement écarté (on prévient, on surveille, on ne bloque pas). Seul `network_mode: host` est refusé, parce que l'isolement y est impossible ([ADR 0023](adr/0023-enrolement-des-agents.md)). Voir les limites dans [securite.md](securite.md#limites-connues).

## Coolify

Coolify régénère le fichier compose à chaque redéploiement : une modification faite à la main sur l'hôte serait écrasée. L'enrôlement passe donc par l'**API Coolify v4** :

1. lecture de l'application ou du service (`/api/v1/applications/{uuid}` ou `/api/v1/services/{uuid}`, champ `docker_compose_raw`) ;
2. transformation identique au cas Docker Compose ;
3. écriture du compose modifié dans Coolify, puis relecture pour vérifier le résultat ;
4. redémarrage par Coolify. Si la vérification ou le redémarrage échoue, le compose d'origine est réécrit.

```sh
export AFW_COOLIFY_TOKEN=…                 # jeton d'API Coolify (permissions read:sensitive et write)
afw enroll mon-agent --zone clients --ip 10.77.0.21 \
    --coolify <uuid> [--coolify-service] --coolify-url https://coolify.example.com
```

La modification vit dans Coolify et survit donc aux redéploiements suivants (`--coolify-url` peut aussi venir de `AFW_COOLIFY_URL` ; `--coolify-service` quand l'UUID est celui d'un service et non d'une application). Le désenrôlement suit le même chemin à l'envers (`afw unenroll mon-agent --coolify <uuid>`). Pour un agent Hermes, le jeton du plugin est référencé dans le compose par une variable (`${AFW_TOKEN_<AGENT>}`) dont la valeur se pose dans les variables d'environnement de la ressource Coolify ; il n'est jamais écrit dans le compose.

Limites connues ([ADR 0023](adr/0023-enrolement-des-agents.md)) : vérifié sur le code de Coolify v4, pas sur une instance réelle ; pour une application dont le compose vient de Git, Coolify relit le dépôt (préférez les services « Docker Compose Empty »).

## Kubernetes

Sur Kubernetes, l'isolement ne repose pas sur une route mais sur une **NetworkPolicy** :

- une **passerelle par namespace** d'agents, placée dans un namespace dédié (`afw-gw-<namespace>`) pour qu'un agent qui peut créer des pods ne puisse pas se faire passer pour elle : Deployment, PVC d'état, Service `ClusterIP` fixe, ConfigMap du certificat public de l'autorité d'inspection (dans le namespace des agents) ; le jeton d'enregistrement est lu dans un Secret existant (`afw-gateway-registration` par défaut) ;
- une **NetworkPolicy** qui, pour les pods marqués `afw.enrolled=true`, n'autorise en sortie **que la passerelle** (TCP 3128, 15001, 80, 443 ; DNS en UDP et TCP 53). Aucune autre règle de sortie n'est ajoutée ;
- un **patch du gabarit de pod** de l'agent : variables de proxy, `dnsPolicy: None` avec la passerelle comme seul serveur DNS, conteneur d'initialisation qui construit le paquet de certificats, `NET_RAW` retiré, `automountServiceAccountToken: false`, label `afw.enrolled=true` et annotation `afw.agent`. `hostNetwork: true` est refusé.

Un programme qui ignore le proxy résout ses noms par la passerelle ; une connexion directe vers une adresse IP est bloquée par la NetworkPolicy.

> **Prérequis.** Le CNI du cluster doit appliquer les NetworkPolicy (Calico, Cilium…). Sans cela, les pods ne sont pas isolés : vérifiez-le avant de vous reposer sur l'enrôlement.
>
> **Les NetworkPolicy s'additionnent** : toute autre politique qui sélectionne les pods enrôlés et autorise une sortie contourne la passerelle. Non fait en V1 : la CLI ne contrôle pas les NetworkPolicy existantes du namespace ; vérifiez-les vous-même avant d'enrôler.

```sh
afw enroll mon-agent --zone clients --k8s deployment.yaml --gateway-cluster-ip 10.96.0.53 \
    [--namespace agents] [--with-gateway] [-o deployment.afw.yaml]
kubectl apply -f deployment.afw.yaml
```

La CLI écrit le gabarit modifié (sur la sortie standard ou dans `-o`) sans toucher au fichier d'origine ; `--with-gateway` y ajoute les manifestes de la passerelle du namespace. Le chart Helm peut aussi déployer ces passerelles (`gateway.instances`, voir [installation.md](installation.md#2-installer-la-console-avec-helm)). Le plugin Hermes n'est pas monté en Kubernetes : il doit être dans l'image de l'agent.

## Conteneur lancé avec `docker run`

Pour un agent qui n'est ni dans un compose ni sous Coolify, `afw enroll <conteneur> --zone <zone> --ip <adresse>` sans `--compose`, `--coolify` ni `--k8s` crée l'agent puis affiche les deux commandes à lancer : `docker run` du conteneur `afw-net-<agent>`, puis `docker run` de l'agent avec `--network container:afw-net-<agent>`, les variables d'environnement et le montage du certificat. Le principe est identique au cas Compose.

## Agents Hermes

Pour un agent Hermes, la même commande avec `--hermes` pose **l'enrôlement réseau et le plugin** :

- montage en lecture seule du plugin (`--hermes-plugin-dir`, défaut `./integrations/hermes`) dans `$HERMES_HOME/plugins/agents-firewall` (`/opt/data/plugins/agents-firewall`) ;
- variables `AFW_CONSOLE_URL` (`--console-url`, défaut : l'URL configurée de la CLI), `AFW_AGENT_NAME` et `AFW_AGENT_TOKEN`, cette dernière sous la forme `${AFW_TOKEN_<AGENT>}` (ou `--token-env`) : le jeton propre à l'agent (rôle `agent_plugin`, renvoyé une seule fois par `POST /api/v1/enrollments`) est écrit dans `--env-file` (mode 0600) ou affiché, **jamais dans le compose** ;
- l'hôte de la console est ajouté à `NO_PROXY` ; le trafic du plugin passe tout de même par la passerelle, donc **le socle doit autoriser les agents vers la console** (c'est le cas dans la politique de démo).

L'enrôlement ne modifie pas la configuration de Hermes : si votre image n'active pas déjà le plugin, activez-le (`hermes plugins enable afw-hermes` ou `plugins.enabled`, voir `integrations/hermes/README.md`).

Le plugin apporte deux choses :

1. la **corrélation** : il envoie le début et la fin de chaque appel d'outil (`POST /api/v1/ingest/tool-calls`), ce qui permet à la console d'afficher « tel outil, dans telle conversation, a ouvert ces connexions » ([ADR 0007](adr/0007-correlation.md)) ;
2. l'**étage intention** : les classes d'actions (suppression, accès, infrastructure, génération payante) et leur « gate » (blocage avec un message à l'agent), selon une politique servie par la console (`GET /api/v1/intent-policy`), mise en cache, avec repli sur la dernière politique connue.

Le plugin n'est jamais bloquant pour la corrélation : si la console est injoignable, les événements sont mis en file et envoyés plus tard.

> **Attention.** L'étage intention s'exécute **dans l'agent** : il guide l'agent et alimente la corrélation, mais il se contourne par construction (un script ou un serveur MCP qui agit hors des outils surveillés n'y passe pas). Ce n'est pas une barrière de sécurité. La protection réelle, sur les destinations et le contenu, est portée par la passerelle. Voir [securite.md](securite.md#létage-intention-du-plugin-hermes-nest-pas-une-barrière).

Objectif : un nouvel agent Hermes est protégé et visible dans la console **en une commande** (scénario 11 de la démo) :

```sh
afw enroll mon-bot --hermes --zone internes --ip 10.77.0.30 --compose docker-compose.yml \
    --env-file .env --apply --publish "Enrôle mon-bot"
afw install <révision> --all
```

## Désenrôlement

```sh
afw unenroll <agent> (--compose docker-compose.yml [--apply] | --coolify <uuid>) [--keep-agent] [--publish "commentaire"]
```

- **Compose** : le service retrouve son état d'origine (réseaux, ports, DNS, variables), restauré depuis l'extension `x-afw-original`, et le conteneur `afw-net-<agent>` est retiré. Une modification faite à la main sur le service enrôlé est perdue ; commentaires et ancres YAML ne sont pas conservés.
- **Coolify** : même opération par l'API Coolify, suivie d'un redémarrage.
- **Kubernetes** : non fait en V1 par la CLI (pas de `afw unenroll --k8s`) : réappliquez votre manifeste d'origine, que `afw enroll --k8s` n'a pas modifié, puis supprimez l'agent (`afw unenroll <agent>` sans cible le fait). La passerelle du namespace reste en place tant que d'autres agents l'utilisent.
- Dans la console, l'agent est supprimé dans votre session (sauf `--keep-agent`) ; publiez puis installez. Son historique de journaux et l'audit sont conservés.

Attention : un agent désenrôlé retrouve un accès réseau **sans contrôle**. Le désenrôlement est tracé dans l'audit.

## Vérifier qu'un agent est bien protégé

Depuis le conteneur de l'agent :

```sh
# 1. Destination non autorisée : refus explicite, immédiat (403)
curl -sS http://exfil.exemple.com/
# blocked by agents-firewall: exfil.exemple.com not allowed for mon-agent (rule default-deny)

# En HTTPS par le proxy, le CONNECT est refusé en 403 ; le message est dans l'en-tête
curl -sS -v https://exfil.exemple.com/ 2>&1 | grep -i x-agents-firewall-reason

# 2. Même chose en ignorant le proxy : toujours bloqué
curl -sS --noproxy '*' https://exfil.exemple.com/

# 3. Connexion directe à une IP publique : refusée
nc -vz -w 3 203.0.113.10 443
```

Chaque tentative apparaît dans le journal de la console, avec l'agent, la zone et la règle appliquée. Les scénarios de contournement de la démo (`demo/scenarios/03` à `05`, `13`, `15`, `18`) automatisent ces vérifications.
