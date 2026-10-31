# Installation

Ce guide explique comment installer la **console** (le plan de contrôle : API, interface web, bases) puis une **passerelle** sur chaque hôte d'agents, et comment les relier. L'enrôlement des agents eux-mêmes fait l'objet d'un guide à part : [enrolement.md](enrolement.md).

> **Images.** Ce dépôt ne publie aucune image : `afw-api`, `afw-console` et `afw-gateway` se construisent depuis les sources (`deploy/docker/`, `console/Dockerfile`) ; les fichiers Compose le font eux-mêmes (`build:`), et pour Helm il faut les pousser dans votre propre registre. Choix de déploiement : [ADR 0024](adr/0024-deploiement-et-demo.md).

## Vue d'ensemble

```
   Console (un seul déploiement)                Hôte d'agents (un par serveur)
 ┌───────────────────────────────┐          ┌──────────────────────────────────┐
 │ console web (Nuxt)            │          │ passerelle afw-gateway           │
 │ afw-api (REST /api/v1 :8080,  │◀─ mTLS ──│   proxy :3128, transparent       │
 │   passerelles /gw/v1 :8443)   │          │   :15001, DNS :53, santé :9090   │
 │ PostgreSQL (config, audit)    │          │        ▲ seule sortie            │
 │ ClickHouse (journaux, option) │          │ [agent A] [agent B] [agent C]    │
 └───────────────────────────────┘          └──────────────────────────────────┘
```

- La **console** se déploie une seule fois (Docker Compose ou Helm).
- Chaque **hôte d'agents** reçoit une passerelle. C'est toujours la passerelle qui appelle la console (modèle « pull ») : aucune connexion entrante n'est nécessaire vers l'hôte d'agents.
- Les échanges passerelle ↔ console sont chiffrés et authentifiés des deux côtés (mTLS). Voir [ADR 0004](adr/0004-politique-installee-et-protocole.md).

## Prérequis

| Élément | Console | Passerelle |
|---|---|---|
| Système | Linux, Docker Engine avec le plugin Compose, ou un cluster Kubernetes avec Helm 3 | Linux (nftables et `SO_ORIGINAL_DST` sont nécessaires), Docker Engine |
| Ressources (ordre de grandeur, à confirmer par la mesure) | 2 vCPU, 4 Go de RAM avec PostgreSQL seul ; prévoir davantage avec ClickHouse | 1 vCPU, 512 Mo de RAM pour quelques agents |
| Réseau | Joignable en HTTPS par les passerelles et par les administrateurs | Sortie Internet ; accès HTTPS à la console |
| Identité | Un fournisseur OIDC (Keycloak, Authentik, Entra ID, Google…) pour les humains ; facultatif au départ grâce au jeton d'administration initial | — |

La passerelle a besoin de la capacité `NET_ADMIN` dans son propre conteneur (pour activer le routage et poser ses règles nftables). Les agents, eux, n'ont jamais cette capacité.

## 1. Installer la console avec Docker Compose

Les fichiers sont dans `deploy/compose/` :

| Fichier | Contenu |
|---|---|
| `deploy/compose/docker-compose.yml` | console web, `afw-api`, PostgreSQL 17, ClickHouse (profil `clickhouse`), volumes |
| `deploy/compose/.env.example` | variables à recopier dans `.env` |
| `deploy/compose/gateway.yml`, `deploy/compose/gateway.env.example` | la passerelle et ses variables, à déployer sur chaque hôte d'agents (étape 3) |

### Étapes

```sh
cd deploy/compose
cp .env.example .env
# Éditer .env : remplacer chaque CHANGE_ME (mot de passe PostgreSQL, clé de chiffrement), URL publique, OIDC
docker compose up -d                          # construit les images si besoin ; journaux dans PostgreSQL
# ou, pour une flotte importante (avec AFW_LOG_STORE=clickhouse dans .env) :
docker compose --profile clickhouse up -d     # journaux dans ClickHouse
```

Ports publiés (variables `AFW_*_BIND` / `AFW_*_PORT` du `.env`) :

| Port | Service | Liaison par défaut |
|---|---|---|
| 3000 | console web | `127.0.0.1` (derrière votre reverse proxy) |
| 8080 | API `/api/v1` (HTTP, TLS assuré par le reverse proxy) | `127.0.0.1` |
| 8443 | routes des passerelles `/gw/v1` (TLS et mTLS terminés par `afw-api`) | `0.0.0.0` : doit être joignable depuis chaque hôte d'agents |

### Variables importantes

Le fichier `deploy/compose/.env.example` fait foi pour la liste complète (`AFW_PUBLIC_URL`, `AFW_PUBLIC_HOSTNAMES`, `AFW_CONSOLE_URL`, `AFW_POSTGRES_*`, `AFW_OIDC_ISSUER` / `_CLIENT_ID` / `_AUDIENCE`, `AFW_LOG_STORE`, `AFW_CLICKHOUSE_*`, ports, images). Deux variables méritent une attention particulière :

- **`AFW_DATA_KEY`** : clé de chiffrement AES-256-GCM des contenus HTTP et des captures stockés ([ADR 0006](adr/0006-stockage-des-journaux.md)). Générez-la une fois (par exemple `openssl rand -base64 32`), conservez-la dans votre coffre-fort de secrets et **sauvegardez-la à part** : sans elle, les contenus déjà stockés sont illisibles.
- **`AFW_BOOTSTRAP_ADMIN_TOKEN`** : jeton d'administration initial, utile pour configurer la console avant que l'OIDC soit en place (c'est ce qu'utilise la démo). Supprimez-le une fois un premier administrateur OIDC créé et un jeton d'API nominatif émis.

### Choisir le stockage des journaux

| | PostgreSQL (défaut) | ClickHouse (profil `clickhouse`) |
|---|---|---|
| Pour qui | tests, démo, quelques agents | flotte d'agents, détail maximal sur la durée |
| Mémoire | faible | plus élevée |
| Ce qui change | rien côté usage : l'API expose les mêmes requêtes | idem |

La configuration et l'audit restent toujours dans PostgreSQL. En V1, les captures pcap sont aussi stockées chiffrées dans PostgreSQL (pas de stockage sur fichiers ni S3 pour les captures).

### Mettre la console derrière un reverse proxy

Publiez la console en HTTPS (Traefik, Caddy, nginx…). Deux familles de routes passent par la même API :

- `/api/v1/…` : l'API d'administration (console web, CLI, MCP) ;
- `/gw/v1/…` : les routes des passerelles, protégées par certificat client. Elles sont servies sur un **port dédié, 8443**, dont le TLS se termine sur `afw-api` lui-même avec l'autorité de la console : ne le faites pas passer par un proxy qui terminerait le TLS (sinon le certificat client de la passerelle ne peut pas être vérifié) ; publiez-le directement ou en passage TCP. Les noms inscrits dans son certificat viennent de `AFW_PUBLIC_HOSTNAMES` (à défaut, l'hôte de `AFW_PUBLIC_URL`, `localhost` et `127.0.0.1`).

Le certificat **public** de l'autorité de la console est exporté dans le volume d'état de l'API (`/var/lib/afw-api/public/console-ca.crt`, volume `api-state`) ; les passerelles en ont besoin au premier contact (étape 3.2).

## 2. Installer la console avec Helm

Le chart est dans `deploy/helm/agents-firewall/`. Il déploie l'API (une seule réplique en V1) et la console, un Ingress (`ingress.enabled`), les secrets (`secrets.*` ou `secrets.existingSecret`), et au choix un PostgreSQL simple (StatefulSet, `postgres.enabled`) ou une base existante (`externalDatabase`). Le fichier `values.yaml` est commenté. Les images (`api.image`, `console.image`, `gateway.image`) doivent être construites et poussées dans votre registre. Le point d'accès des passerelles (`api.gatewayService`, port 8443) ne doit pas passer par l'Ingress : exposez-le directement (LoadBalancer, NodePort) si des passerelles tournent hors du cluster.

```sh
helm install agents-firewall deploy/helm/agents-firewall \
  --namespace agents-firewall --create-namespace \
  -f mes-valeurs.yaml
```

Pour vérifier un fichier de valeurs avant de l'appliquer :

```sh
helm lint deploy/helm/agents-firewall -f mes-valeurs.yaml
helm template agents-firewall deploy/helm/agents-firewall -f mes-valeurs.yaml | less
```

En production, préférez un PostgreSQL géré ou opéré par votre équipe (sauvegardes, haute disponibilité) au StatefulSet intégré.

Le chart peut aussi déployer une **passerelle par namespace** d'agents (`gateway.instances`) ; c'est le mode Kubernetes décrit dans [enrolement.md](enrolement.md#kubernetes).

## 3. Installer une passerelle sur un hôte d'agents

Une passerelle protège tous les agents d'un même hôte. Son installation se fait en trois temps : obtenir un jeton d'enregistrement, démarrer le conteneur, vérifier.

### 3.1 Obtenir un jeton d'enregistrement

Le jeton est **à usage unique** et **valable 15 minutes**. Il se crée depuis l'écran « Passerelles » de la console, avec la CLI ou directement par l'API :

```sh
afw gateways token --name hote-agents-1
# ou
curl -sS -X POST "$AFW_URL/api/v1/gateways/registration-tokens" \
  -H "Authorization: Bearer $AFW_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name": "hote-agents-1"}'
```

`$AFW_URL` est l'adresse de la console et `$AFW_TOKEN` un jeton d'API administrateur (voir [api.md](api.md#authentification)). Seul un administrateur peut créer ce jeton d'enregistrement. Sa création est inscrite dans l'audit.

### 3.2 Démarrer la passerelle

Le fichier `deploy/compose/gateway.yml` définit :

- le conteneur de la passerelle, avec `cap_add: [NET_ADMIN]` ;
- le réseau **interne** `afw-internal`, déclaré `internal: true` avec un sous-réseau fixe : les agents y sont attachés et n'ont aucune autre sortie ;
- le réseau **de sortie** `afw-egress`, par lequel la passerelle joint Internet et la console ;
- un volume d'état monté sur `/var/lib/afw` : politique installée (`/var/lib/afw/policy.json`), clé et certificat de la passerelle (`identity/`), autorité d'inspection, tampon d'événements ;
- un répertoire de l'hôte (`AFW_CA_PUBLIC_DIR`, défaut `/etc/agents-firewall`) monté sur `/var/lib/afw/public`, où la passerelle exporte le certificat public de son autorité d'inspection (`gateway.crt`), monté ensuite en lecture seule par les agents enrôlés.

Copiez `gateway.env.example` en `gateway.env` et renseignez :

| Variable | Valeur |
|---|---|
| `AFW_CONSOLE_URL` | point d'accès des passerelles, par exemple `https://afw.example.com:8443` |
| `AFW_CONSOLE_CA_FILE` | chemin, **dans le conteneur**, du certificat `console-ca.crt` de la console (étape 1). Le plus simple : le copier dans `AFW_CA_PUBLIC_DIR` sur l'hôte et indiquer `/var/lib/afw/public/console-ca.crt` |
| `AFW_REGISTRATION_TOKEN` | le jeton de l'étape 3.1 |
| `AFW_GATEWAY_NAME` | nom affiché dans la console |
| `AFW_INTERNAL_NETWORK`, `AFW_INTERNAL_SUBNET`, `AFW_GATEWAY_IP` | réseau interne des agents (défaut `afw-internal`, `10.77.0.0/24`, `10.77.0.2`) |
| `AFW_UPSTREAM_DNS`, `AFW_UPSTREAM_CA_FILE` | résolveur amont et CA amont supplémentaires (vide : valeurs du système) |

puis :

```sh
cd deploy/compose
docker compose --env-file gateway.env -f gateway.yml up -d
```

Au premier démarrage, la passerelle :

1. crée sa propre **autorité d'inspection TLS** (clé ECDSA P-256, fichier en `0600`), qui ne quittera jamais l'hôte ;
2. génère sa clé de client et une demande de certificat (CSR) ;
3. appelle `POST /gw/v1/register` avec le jeton, son nom, son nom d'hôte et la CSR ;
4. reçoit son **certificat client** signé par l'autorité de la console, et le certificat de cette autorité ;
5. récupère la politique (`GET /gw/v1/policy`), l'applique, puis accuse réception.

Le jeton est alors consommé : le relancer ne sert à rien. En cas d'échec (jeton expiré, horloge décalée), créez-en un nouveau.

> **Fermeture par défaut.** Tant qu'aucune politique valide n'est installée, la passerelle **refuse tout**. Un hôte fraîchement installé ne laisse donc rien passer : c'est voulu.

### 3.3 Ports de la passerelle

| Port | Rôle | Exposé à |
|---|---|---|
| 3128/tcp | proxy HTTP(S) explicite (CONNECT et URL absolues), pour les clients qui respectent `HTTP_PROXY` | réseau interne des agents |
| 15001/tcp | écoute transparente : tout autre TCP des agents y est redirigé par nftables | réseau interne des agents |
| 53/udp et 53/tcp | DNS filtrant | réseau interne des agents |
| 9090/tcp | santé de la passerelle | supervision locale |

Aucun de ces ports n'a besoin d'être publié sur l'hôte. Tout autre trafic transféré depuis le réseau interne (UDP autre que DNS, ICMP…) est abandonné (drop).

### 3.4 Vérifier

- Dans la console, écran **Passerelles** : la passerelle apparaît avec son nom, sa version, la révision active et la date de son dernier battement de cœur.
- Par l'API : `GET /api/v1/gateways`.
- Par la CLI : `afw gateways list`.
- Sur l'hôte : `docker compose --env-file gateway.env -f gateway.yml logs` (depuis `deploy/compose`) doit montrer l'enregistrement puis l'installation de la révision ; la santé répond sur `http://127.0.0.1:9090/healthz` dans le conteneur.

Vous pouvez ensuite enrôler des agents : [enrolement.md](enrolement.md).

## 4. Connexion des administrateurs

- **Humains** : connexion OIDC générique (découverte automatique, PKCE côté console). L'écran de connexion accepte aussi un jeton d'API, ce qui permet d'entrer avec `AFW_BOOTSTRAP_ADMIN_TOKEN` avant que l'OIDC soit configuré. Rôles : `admin`, `auditor` (lecture de tout, contenus compris), `viewer` (lecture sans les contenus). Le détail est dans [securite.md](securite.md#rôles-et-droits).
- **Scripts et CLI** : jetons d'API (`/api/v1/tokens`), passés en `Authorization: Bearer <jeton>`. Voir [api.md](api.md).
- **Agent d'administration agréé** : un seul, par le serveur MCP. Voir [mcp.md](mcp.md).

## 5. Essayer en local : l'environnement de démonstration

Le dossier `demo/` assemble tout sur un seul poste, sans aucun accès Internet nécessaire : console, API, PostgreSQL, une passerelle avec deux zones (`internes` et `clients`), trois agents factices dont un agent Hermes, un faux fournisseur LLM, une cible d'exfiltration, un faux S3, une base interne et un DNS de démonstration.

Prérequis : Docker avec le plugin Compose v2, `curl` ; `jq` est facultatif (pris dans une image d'outils s'il manque).

```sh
demo/up.sh                 # construit les images en local, démarre, enregistre la passerelle, installe la politique de démo
demo/scenarios/run-all.sh  # joue les 20 scénarios de recette (PASS/FAIL/SKIP avec preuves)
demo/down.sh               # arrête (--purge efface aussi volumes et état)
```

La console est alors disponible sur `http://localhost:3000` et l'API sur `http://127.0.0.1:8080/api/v1`. Le jeton d'administration de la démo est la variable `AFW_DEMO_ADMIN_TOKEN` du fichier `demo/.state/secrets.env` (généré au premier `up.sh`, mode 0600). Les résultats des scénarios sont écrits dans `demo/.state/results.md` et `demo/.state/results.json`. Détails : [demo/README.md](../demo/README.md) et [ADR 0027](adr/0027-recette-de-bout-en-bout.md).
