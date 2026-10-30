# Installation

Ce guide explique comment installer la **console** (le plan de contrôle : API, interface web, bases) puis une **passerelle** sur chaque hôte d'agents, et comment les relier. L'enrôlement des agents eux-mêmes fait l'objet d'un guide à part : [enrolement.md](enrolement.md).

> **État d'avancement.** La V1 est en cours de construction. Les fichiers de déploiement (`deploy/`, `demo/`) et les images sont livrés par des lots en cours : ce qui en dépend est marqué « (à venir) ». Les principes décrits ici (architecture, enregistrement, ports, fermeture par défaut) sont figés par les décisions d'architecture.

## Vue d'ensemble

```
   Console (un seul déploiement)                Hôte d'agents (un par serveur)
 ┌───────────────────────────────┐          ┌──────────────────────────────────┐
 │ console web (Nuxt)            │          │ passerelle afw-gateway           │
 │ afw-api (REST /api/v1,        │◀─ mTLS ──│   proxy :3128, transparent       │
 │          passerelles /gw/v1)  │          │   :15001, DNS :53, santé :9090   │
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
| Identité | Un fournisseur OIDC (Keycloak, Authentik, Entra ID, Google…) pour les humains | — |

La passerelle a besoin de la capacité `NET_ADMIN` dans son propre conteneur (pour activer le routage et poser ses règles nftables). Les agents, eux, n'ont jamais cette capacité.

## 1. Installer la console avec Docker Compose (à venir)

Les fichiers sont dans `deploy/compose/` (livrés par le lot de déploiement) :

| Fichier | Contenu |
|---|---|
| `deploy/compose/docker-compose.yml` | console web, `afw-api`, PostgreSQL 17, ClickHouse (profil `clickhouse`), volumes |
| `deploy/compose/.env.example` | variables à recopier dans `.env` |
| `deploy/compose/gateway.yml` | la passerelle, à déployer sur chaque hôte d'agents (étape 3) |

### Étapes

```sh
cd deploy/compose
cp .env.example .env
# Éditer .env : mots de passe, URL publique, fournisseur OIDC, clé de chiffrement
docker compose up -d                          # journaux dans PostgreSQL
# ou, pour une flotte importante :
docker compose --profile clickhouse up -d     # journaux dans ClickHouse
```

### Variables importantes

Le fichier `.env.example` fait foi pour la liste complète (à venir). Deux variables méritent une attention particulière :

- **`AFW_DATA_KEY`** : clé de chiffrement AES-256-GCM des contenus HTTP et des captures stockés ([ADR 0006](adr/0006-stockage-des-journaux.md)). Générez-la une fois (par exemple `openssl rand -base64 32`), conservez-la dans votre coffre-fort de secrets et **sauvegardez-la à part** : sans elle, les contenus déjà stockés sont illisibles.
- **`AFW_BOOTSTRAP_ADMIN_TOKEN`** : jeton d'administration initial, utile pour configurer la console avant que l'OIDC soit en place (c'est ce qu'utilise la démo). Supprimez-le une fois un premier administrateur OIDC créé et un jeton d'API nominatif émis.

### Choisir le stockage des journaux

| | PostgreSQL (défaut) | ClickHouse (profil `clickhouse`) |
|---|---|---|
| Pour qui | tests, démo, quelques agents | flotte d'agents, détail maximal sur la durée |
| Mémoire | faible | plus élevée |
| Ce qui change | rien côté usage : l'API expose les mêmes requêtes | idem |

La configuration et l'audit restent toujours dans PostgreSQL. Les captures pcap sont stockées chiffrées sur un système de fichiers ou un stockage objet compatible S3.

### Mettre la console derrière un reverse proxy

Publiez la console en HTTPS (Traefik, Caddy, nginx…). Deux familles de routes passent par la même API :

- `/api/v1/…` : l'API d'administration (console web, CLI, MCP) ;
- `/gw/v1/…` : les routes des passerelles, protégées par certificat client. **Le TLS de ces routes doit se terminer sur `afw-api` lui-même** (passage TCP/TLS sans terminaison au niveau du proxy), sinon le certificat client de la passerelle ne peut pas être vérifié. La méthode recommandée (port dédié ou passage SNI) sera précisée avec les fichiers de déploiement (à venir).

## 2. Installer la console avec Helm (à venir)

Le chart est dans `deploy/helm/agents-firewall/`. Il déploie l'API et la console, un Ingress, les secrets, et au choix un PostgreSQL simple (StatefulSet) ou une référence à un PostgreSQL existant. Le fichier `values.yaml` est documenté ligne à ligne.

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

Le chart peut aussi déployer une **passerelle par namespace** d'agents ; c'est le mode Kubernetes décrit dans [enrolement.md](enrolement.md#kubernetes).

## 3. Installer une passerelle sur un hôte d'agents

Une passerelle protège tous les agents d'un même hôte. Son installation se fait en trois temps : obtenir un jeton d'enregistrement, démarrer le conteneur, vérifier.

### 3.1 Obtenir un jeton d'enregistrement

Le jeton est **à usage unique** et **valable 15 minutes**. Il se crée depuis l'écran « Passerelles » de la console, avec la CLI (`afw gateways …`, à venir) ou directement par l'API :

```sh
curl -sS -X POST "$AFW_URL/api/v1/gateways/registration-tokens" \
  -H "Authorization: Bearer $AFW_TOKEN"
```

`$AFW_URL` est l'adresse de la console et `$AFW_TOKEN` un jeton d'API administrateur (voir [api.md](api.md#authentification)). Seul un administrateur peut créer ce jeton d'enregistrement. Sa création est inscrite dans l'audit.

### 3.2 Démarrer la passerelle

Le fichier `deploy/compose/gateway.yml` (à venir) définit :

- le conteneur de la passerelle, avec `cap_add: [NET_ADMIN]` ;
- le réseau **interne** `afw-internal`, déclaré `internal: true` avec un sous-réseau fixe : les agents y sont attachés et n'ont aucune autre sortie ;
- le réseau **de sortie** `egress`, par lequel la passerelle joint Internet et la console ;
- un volume d'état monté sur `/var/lib/afw` : politique installée (`/var/lib/afw/policy.json`), clé et certificat de la passerelle, autorité d'inspection, tampon d'événements.

Renseignez l'URL de la console et le jeton (noms exacts des variables dans le fichier, à venir), puis :

```sh
docker compose -f deploy/compose/gateway.yml up -d
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

Aucun de ces ports n'a besoin d'être publié sur l'hôte. Tout autre trafic transféré depuis le réseau interne (UDP autre que DNS, ICMP…) est rejeté.

### 3.4 Vérifier

- Dans la console, écran **Passerelles** : la passerelle apparaît avec son nom, sa version, la révision active et la date de son dernier battement de cœur.
- Par l'API : `GET /api/v1/gateways`.
- Sur l'hôte : `docker compose -f deploy/compose/gateway.yml logs` doit montrer l'enregistrement puis l'installation de la révision.

Vous pouvez ensuite enrôler des agents : [enrolement.md](enrolement.md).

## 4. Connexion des administrateurs

- **Humains** : connexion OIDC générique (découverte automatique, PKCE côté console). Rôles : `admin`, `auditor` (lecture de tout, contenus compris), `viewer` (lecture sans les contenus). Le détail est dans [securite.md](securite.md#rôles-et-droits).
- **Scripts et CLI** : jetons d'API (`/api/v1/tokens`), passés en `Authorization: Bearer <jeton>`. Voir [api.md](api.md).
- **Agent d'administration agréé** : un seul, par le serveur MCP. Voir [mcp.md](mcp.md).

## 5. Essayer en local : l'environnement de démonstration (à venir)

Le dossier `demo/` assemble tout sur un seul poste, sans aucun accès Internet nécessaire : console, API, PostgreSQL, une passerelle avec deux zones (`internes` et `clients`), trois agents factices dont un agent Hermes, un faux fournisseur LLM, une cible d'exfiltration, un faux S3, une base interne et un DNS de démonstration.

```sh
demo/up.sh                 # construit les images, démarre, crée et installe la politique de démo
demo/scenarios/run-all.sh  # joue les scénarios de recette (PASS/FAIL avec preuve)
demo/down.sh               # arrête et nettoie
```

La console est alors disponible sur `http://localhost:3000`. Les résultats des scénarios sont écrits dans `demo/.state/results.md`.
