<div align="center">

# agents-firewall

**Pare-feu open source pour agents IA : contrôle centralisé des sorties réseau, visibilité complète des flux et audit pour des flottes d'agents LLM.**

[![Licence : Apache 2.0](https://img.shields.io/badge/Licence-Apache_2.0-blue.svg)](LICENSE)
[![Statut : V1 non publiée](https://img.shields.io/badge/statut-V1%20non%20publi%C3%A9e-yellow.svg)](#statut)

[English](README.md) · [Documentation](#documentation) · [Cahier des charges](docs/cahier-des-charges.md) · [Conception](docs/superpowers/specs/2026-10-30-agents-firewall-design.md) · [Contribuer](CONTRIBUTING.md) · [Sécurité](SECURITY.md)

</div>

---

## Pourquoi

Un agent IA lit du contenu non fiable (mails, pages web, documents) et dispose d'outils qui sortent sur le réseau : terminal, requêtes web, mail, serveurs MCP, scripts qu'il écrit lui-même. Une seule **injection de prompt** suffit à lui faire exfiltrer des données. Quand un agent cumule *accès à des données privées*, *exposition à du contenu non fiable* et *capacité à communiquer vers l'extérieur* (la *lethal trifecta*), une fuite n'est qu'une question de temps.

Le moyen le plus fiable de casser cette combinaison est de **contrôler ce qui sort**. Les garde-fous placés *dans* l'agent (consignes, hooks qui lisent les arguments des outils) se contournent par l'agent lui-même : une URL dans une variable, un script ou un serveur MCP qui fait ses propres appels passe à côté.

**agents-firewall** applique la politique **sur le réseau**, hors de l'agent, et se gère comme un pare-feu d'entreprise.

## Ce qu'il fait

- **Contrôle des sorties impossible à contourner**, pour tout le trafic réseau d'un agent enrôlé : il ne sort que par la passerelle (voir les [limites connues](docs/securite.md#limites-connues)). Refus par défaut, immédiat et explicite.
- **Modèle de politique d'entreprise**, inspiré de Check Point : objets, zones (façon VLAN), base de règles ordonnée avec socle commun, sessions, publication et installation, révisions, retour arrière, compteurs.
- **Visibilité maximale** : chaque flux, requête DNS, requête et réponse HTTP (inspection TLS), captures à la demande, **rattachés à l'appel d'outil et à la conversation** de l'agent.
- **Règles sur le contenu** : refus selon la classe de donnée (secrets, inventaire d'infrastructure, données commerciales). Secrets masqués avant stockage.
- **Surveillance des flux internes** : agent → agent, LAN, bases, API d'administration Kubernetes/Coolify/Docker, détection de mouvement latéral.
- **API d'abord** : tout ce que fait la console est faisable par l'API, la CLI `afw` et un **serveur MCP**, pour qu'un agent d'administration agréé puisse piloter le pare-feu. Chaque modification est auditée.
- **Enrôlement en une commande** : Docker Compose, conteneurs gérés par Coolify, pods Kubernetes. Intégration native avec les agents [Hermes](https://github.com/NousResearch).

## Architecture

```
          ┌────────────── Console (plan de contrôle) ──────────────────┐
          │  afw-api : REST /api/v1 (OpenAPI) · passerelles /gw/v1     │
          │  console web Nuxt · CLI `afw` · serveur MCP                │
          │  PostgreSQL (config, audit, journaux) · ClickHouse (option)│
          └──────────────▲─────────────────────────▲───────────────────┘
     politique (tirée,   │ mTLS                    │ événements,
     révision vérifiée)  │                         │ battement de cœur
   ┌──── Hôte d'agents ──┴─────────────────────────┴───────────────────┐
   │  afw-gateway (une par hôte, Rust)                                 │
   │   proxy :3128 · TCP transparent :15001 · DNS :53                  │
   │   inspection TLS · moteur de règles · masquage · capture pcap     │
   │        ▲ seule sortie (réseau Docker interne ou NetworkPolicy) ;  │
   │        │ passerelle arrêtée = plus de réseau                      │
   │   [agent A]   [agent B]   [agent C]   + plugin Hermes (intention) │
   └───────────────────────────────────────────────────────────────────┘
```

| Composant | Technologie | Emplacement |
|---|---|---|
| Passerelle (plan de données) | Rust | `crates/afw-gateway` |
| API du plan de contrôle | Rust (axum, sqlx) | `crates/afw-api` |
| CLI `afw`, serveur MCP | Rust | `crates/afw-cli`, `crates/afw-mcp` |
| Moteur de règles, DLP, TLS, enrôlement | bibliothèques Rust | `crates/afw-engine`, `afw-dlp`, `afw-tls`, `afw-enroll` |
| Console web | Nuxt 4 + Nuxt UI | `console/` |
| Intégration agents | plugin Hermes (Python) ; mode réseau seul pour tout conteneur | `integrations/hermes/` |
| Déploiement | Docker Compose, chart Helm | `deploy/` |

Les choix d'architecture sont consignés dans les [ADR](docs/adr/README.md).

## Statut

**V1 réalisée, non publiée.** Tous les composants de la V1 (passerelle, API, console, CLI `afw`, serveur MCP, enrôlement, plugin Hermes, import de l'egress-guard, déploiement Compose et Helm) sont fusionnés dans la branche `dev` et passent la recette de bout en bout sur la démo locale : 20 scénarios sur 20 ([résultats](docs/rapport/recette/results.md), [ADR 0027](docs/adr/0027-recette-de-bout-en-bout.md)). Aucune version n'est étiquetée et aucune image n'est publiée : les images se construisent depuis les sources. La migration des agents réels de production reste à faire.

## Démarrage rapide (démo locale)

La démo fait tout tourner sur un seul poste, sans accès Internet : console, API, PostgreSQL, une passerelle avec deux zones (`internes`, `clients`), trois agents (`daniel-bot`, agent Hermes, `laurent-bot` et `acme-bot`), un LAN simulé et un « Internet » simulé (faux fournisseur LLM, cible d'exfiltration, API autorisée, faux S3, DNS de démo).

Prérequis : Docker avec le plugin Compose v2, `curl`, bash (3.2 et plus, macOS compris). `jq` est facultatif (pris dans une image d'outils s'il manque). Le premier lancement construit toutes les images en local (compilations Rust et Nuxt : comptez plusieurs minutes ; images de base et dépendances téléchargées une fois). `demo/screenshots.sh` télécharge aussi l'image Playwright.

```sh
demo/up.sh                    # construit les images, démarre, enregistre la passerelle, publie et installe la politique de démo
demo/scenarios/run-all.sh     # joue les 20 scénarios de recette -> demo/.state/results.md et results.json
demo/scenarios/run-all.sh 01 05   # ou seulement certains
demo/screenshots.sh           # facultatif, après run-all.sh : captures de la console (docs/rapport/captures par défaut)
demo/down.sh                  # arrête (--purge efface aussi les volumes et demo/.state)
```

- Console : <http://localhost:3000>. Connexion avec le jeton d'administration : la variable `AFW_DEMO_ADMIN_TOKEN` du fichier `demo/.state/secrets.env` (généré au premier `demo/up.sh`, mode 0600, jamais commité).
- API : <http://127.0.0.1:8080/api/v1>, avec le même jeton (`Authorization: Bearer …`).

Détails et liste des scénarios : [demo/README.md](demo/README.md).

## Documentation

| Guide | Contenu |
|---|---|
| [Installation](docs/installation.md) | console (Compose, Helm), passerelle, jeton d'enregistrement |
| [Enrôlement](docs/enrolement.md) | Docker Compose, Coolify, Kubernetes, Hermes, désenrôlement |
| [Modèle de politique](docs/modele-de-politique.md) | objets, zones, socle, ordre d'évaluation, inspection, classes de données, publication et installation |
| [Exploitation](docs/exploitation.md) | journal, « Autoriser », alertes, captures, rétention, sauvegarde, mise à jour, pannes |
| [Sécurité](docs/securite.md) | modèle de menace, fermeture par défaut, isolement, audit, limites connues |
| [API](docs/api.md) · [CLI](docs/cli.md) · [MCP](docs/mcp.md) | interfaces d'automatisation |
| [Migrer depuis l'egress-guard](docs/migration-egress-guard.md) | d'un hook dans l'agent au contrôle réseau |

Pour aller plus loin : [cahier des charges](docs/cahier-des-charges.md), [conception](docs/superpowers/specs/2026-10-30-agents-firewall-design.md), [plan d'implémentation V1](docs/superpowers/plans/2026-10-30-agents-firewall-v1.md), [contribuer](CONTRIBUTING.md).

## Licence

[Apache 2.0](LICENSE). Copyright © 2026 Aidalinfo / Pulse myIT et contributeurs.
