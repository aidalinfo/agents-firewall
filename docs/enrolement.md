# Enrôlement des agents

**Enrôler** un agent, c'est le placer derrière la passerelle de son hôte : à partir de là, il n'a plus d'autre chemin vers le réseau, son trafic est journalisé et la politique de sa zone s'applique. **Désenrôler**, c'est revenir exactement à l'état d'avant.

Ce guide suppose qu'une passerelle est déjà installée et enregistrée sur l'hôte (voir [installation.md](installation.md#3-installer-une-passerelle-sur-un-hôte-dagents)).

> **État d'avancement.** La bibliothèque d'enrôlement (`afw-enroll`) et la CLI `afw` sont en cours de construction (à venir). Le mécanisme réseau décrit ici est figé par l'[ADR 0003](adr/0003-isolement-reseau.md) ; les options exactes des commandes seront données par `afw enroll --help`.

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

Forme prévue :

```sh
afw enroll <conteneur>      # options : zone, passerelle, fichier compose… (à venir)
afw unenroll <conteneur>
```

Pour un agent Docker Compose, `afw enroll` :

1. **crée l'agent** dans la console (`POST /api/v1/enrollments`), le place dans la zone choisie et lui attribue une **adresse IP fixe** sur le réseau interne de la passerelle. Cette adresse est son identité : c'est par elle que la passerelle sait quel agent parle ;
2. **ajoute un petit conteneur réseau** `afw-net-<agent>` (voir ci-dessous) ;
3. **rattache l'agent** à l'espace réseau de ce conteneur, et lui retire ses propres réseaux, ports publiés et DNS ;
4. **pose les variables de proxy** et **monte le certificat de l'autorité d'inspection** de la passerelle dans le conteneur de l'agent ;
5. **garde l'état d'origine** du service dans une annotation `x-afw-original` du fichier compose, pour que `afw unenroll` puisse tout défaire ;
6. **redémarre** le service.

Enrôler deux fois le même agent est refusé avec un message clair (« déjà enrôlé »).

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

- `afw-net-<agent>` est le seul à posséder `NET_ADMIN`. Il pose la route par défaut vers la passerelle et son DNS, puis la vérifie et la repose toutes les 10 secondes. Il ne fait rien d'autre.
- L'agent partage l'espace réseau de ce conteneur (`network_mode: "service:afw-net-<agent>"`). Il n'a pas `NET_ADMIN` : il ne peut ni modifier la route ni toucher au pare-feu.
- Si l'agent redémarre, il retrouve le même espace réseau, donc la même adresse et la même route.
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

Après `afw enroll mon-agent` (forme indicative, le format exact est produit par l'outil) :

```yaml
services:
  afw-net-mon-agent:
    image: afw-netinit:local
    cap_add: [NET_ADMIN]
    networks:
      afw-internal:
        ipv4_address: 172.30.0.21     # adresse fixe de l'agent
    dns: [172.30.0.2]                 # la passerelle
    ports:
      - "8080:8080"                   # les ports publiés sont déplacés ici
    restart: unless-stopped
    labels:
      afw.enrolled: "true"
      afw.agent: mon-agent

  mon-agent:
    image: exemple/mon-agent:1.4
    network_mode: "service:afw-net-mon-agent"
    environment:
      HTTP_PROXY: http://172.30.0.2:3128
      HTTPS_PROXY: http://172.30.0.2:3128
      NO_PROXY: localhost,127.0.0.1
      REQUESTS_CA_BUNDLE: /usr/local/share/ca-certificates/afw-gateway.crt
      SSL_CERT_FILE: /usr/local/share/ca-certificates/afw-gateway.crt
      NODE_EXTRA_CA_CERTS: /usr/local/share/ca-certificates/afw-gateway.crt
      CURL_CA_BUNDLE: /usr/local/share/ca-certificates/afw-gateway.crt
    volumes:
      - /var/lib/afw/ca.crt:/usr/local/share/ca-certificates/afw-gateway.crt:ro
    x-afw-original: { … }             # état d'origine, pour unenroll

networks:
  afw-internal:
    external: true
```

Les variables de certificat couvrent les environnements les plus courants (Python `requests`, OpenSSL, Node.js, curl). Une application qui embarque sa propre liste d'autorités ou qui épingle un certificat refusera l'inspection : voir [modele-de-politique.md](modele-de-politique.md#politique-dinspection-https).

### Avertissements et refus

| Situation | Effet |
|---|---|
| `network_mode: host` | **refus** : l'agent partagerait la pile réseau de l'hôte ; l'isolement est impossible, l'enrôlement mentirait donc sur la protection (choix du constructeur, ADR 0023 (lot L11, à venir)) |
| `privileged: true` | **avertissement** : un conteneur privilégié peut modifier le réseau ; l'agent est enrôlé, mais la protection n'est plus garantie |
| socket Docker monté (`/var/run/docker.sock`) | **avertissement** : l'agent peut lancer d'autres conteneurs hors de la passerelle |

Les conteneurs privilégiés ou ayant le socket Docker sont seulement **signalés par un avertissement** : leur refus à l'enrôlement a été volontairement écarté (on prévient, on surveille, on ne bloque pas). Seul `network_mode: host` est refusé, parce que l'isolement y est impossible (ADR 0023 (lot L11, à venir)). Voir les limites dans [securite.md](securite.md#limites-connues).

## Coolify

Coolify régénère le fichier compose à chaque redéploiement : une modification faite à la main sur l'hôte serait écrasée. L'enrôlement passe donc par l'**API Coolify v4** :

1. lecture de l'application ou du service (`/api/v1/applications/{uuid}` ou `/api/v1/services/{uuid}`, champ `docker_compose_raw`) ;
2. transformation identique au cas Docker Compose ;
3. écriture du compose modifié dans Coolify ;
4. redéploiement par Coolify.

La modification vit dans Coolify et survit donc aux redéploiements suivants. Il faut fournir l'URL de l'instance Coolify et un jeton d'API Coolify autorisé à modifier l'application (option exacte à venir). Le désenrôlement suit le même chemin à l'envers.

## Kubernetes

Sur Kubernetes, l'isolement ne repose pas sur une route mais sur une **NetworkPolicy** :

- une **passerelle par namespace** d'agents (Deployment, Service ClusterIP, ConfigMap contenant le certificat public de l'autorité d'inspection, Secret pour l'identité de la passerelle) ;
- une **NetworkPolicy** qui, pour les pods marqués `afw.enrolled=true`, n'autorise en sortie **que la passerelle** (proxy et écoute transparente en TCP, DNS en UDP et TCP 53). Aucune autre règle de sortie n'est ajoutée ;
- un **patch du gabarit de pod** de l'agent : variables de proxy, `dnsPolicy: None` avec la passerelle comme seul serveur DNS, volume du certificat, label `afw.enrolled=true` et annotation `afw.agent`.

Un programme qui ignore le proxy résout ses noms par la passerelle ; une connexion directe vers une adresse IP est bloquée par la NetworkPolicy.

> **Prérequis.** Le CNI du cluster doit appliquer les NetworkPolicy (Calico, Cilium…). Sans cela, les pods ne sont pas isolés : vérifiez-le avant de vous reposer sur l'enrôlement.

Les manifestes peuvent être produits par la CLI (à venir) ou par le chart Helm (option « passerelle par namespace »).

## Conteneur lancé avec `docker run`

Pour un agent qui n'est ni dans un compose ni sous Coolify, l'enrôlement fournit la liste des arguments à ajouter : création du conteneur `afw-net-<agent>`, puis `--network container:afw-net-<agent>`, les variables d'environnement et le montage du certificat. Le principe est identique au cas Compose.

## Agents Hermes

Pour un agent Hermes, la même commande pose **l'enrôlement réseau et le plugin** :

- copie du plugin `afw_hermes` dans le dossier des plugins de Hermes, et activation du plugin dans la configuration de Hermes (`plugins.enabled`) ;
- variables `AFW_CONSOLE_URL`, `AFW_AGENT_TOKEN` (jeton propre à l'agent, créé par `POST /api/v1/enrollments`), `AFW_AGENT_NAME` et `AFW_CA_FILE` (certificat de l'autorité d'inspection, pour que le plugin joigne la console à travers la passerelle).

Le plugin apporte deux choses :

1. la **corrélation** : il envoie le début et la fin de chaque appel d'outil (`POST /api/v1/ingest/tool-calls`), ce qui permet à la console d'afficher « tel outil, dans telle conversation, a ouvert ces connexions » ([ADR 0007](adr/0007-correlation.md)) ;
2. l'**étage intention** : les classes d'actions (suppression, accès, infrastructure, génération payante) et leur « gate » (blocage avec un message à l'agent), selon une politique servie par la console (`GET /api/v1/intent-policy`), mise en cache, avec repli sur la dernière politique connue.

Le plugin n'est jamais bloquant pour la corrélation : si la console est injoignable, les événements sont mis en file et envoyés plus tard.

> **Attention.** L'étage intention s'exécute **dans l'agent** : il guide l'agent et alimente la corrélation, mais il se contourne par construction (un script ou un serveur MCP qui agit hors des outils surveillés n'y passe pas). Ce n'est pas une barrière de sécurité. La protection réelle, sur les destinations et le contenu, est portée par la passerelle. Voir [securite.md](securite.md#létage-intention-du-plugin-hermes-nest-pas-une-barrière).

Objectif : un nouvel agent Hermes est protégé et visible dans la console **en une commande**.

## Désenrôlement

```sh
afw unenroll <conteneur>
```

- **Compose** : le service retrouve exactement son état d'origine (réseaux, ports, DNS, variables), restauré depuis l'annotation `x-afw-original`, et le conteneur `afw-net-<agent>` est retiré.
- **Coolify** : même opération par l'API Coolify, suivie d'un redéploiement.
- **Kubernetes** : le patch du gabarit de pod est retiré ; la passerelle du namespace reste en place tant que d'autres agents l'utilisent.
- Dans la console, l'objet agent est retiré de la politique (modalités exactes à venir) ; son historique de journaux et l'audit sont conservés.

Attention : un agent désenrôlé retrouve un accès réseau **sans contrôle**. Le désenrôlement est tracé dans l'audit.

## Vérifier qu'un agent est bien protégé

Depuis le conteneur de l'agent :

```sh
# 1. Destination non autorisée : refus explicite, immédiat
curl -sS https://exfil.exemple.com/
# blocked by agents-firewall: exfil.exemple.com not allowed for mon-agent (rule default-deny)

# 2. Même chose en ignorant le proxy : toujours bloqué
curl -sS --noproxy '*' https://exfil.exemple.com/

# 3. Connexion directe à une IP publique : refusée
nc -vz -w 3 203.0.113.10 443
```

Chaque tentative apparaît dans le journal de la console, avec l'agent, la zone et la règle appliquée. Les scénarios de contournement de la démo (`demo/scenarios/`, à venir) automatisent ces vérifications.
