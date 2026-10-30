<div align="center">

# agents-firewall

**Pare-feu open source pour agents IA : contrôle centralisé des sorties réseau, visibilité complète des flux et audit pour des flottes d'agents LLM.**

[![Licence : Apache 2.0](https://img.shields.io/badge/Licence-Apache_2.0-blue.svg)](LICENSE)
[![Statut : V1 en construction](https://img.shields.io/badge/statut-V1%20en%20construction-orange.svg)](#statut)

[English](README.md) · [Documentation](#documentation) · [Cahier des charges](docs/cahier-des-charges.md) · [Conception](docs/superpowers/specs/2026-10-30-agents-firewall-design.md) · [Contribuer](CONTRIBUTING.md) · [Sécurité](SECURITY.md)

</div>

---

## Pourquoi

Un agent IA lit du contenu non fiable (mails, pages web, documents) et dispose d'outils qui sortent sur le réseau : terminal, requêtes web, mail, serveurs MCP, scripts qu'il écrit lui-même. Une seule **injection de prompt** suffit à lui faire exfiltrer des données. Quand un agent cumule *accès à des données privées*, *exposition à du contenu non fiable* et *capacité à communiquer vers l'extérieur* (la *lethal trifecta*), une fuite n'est qu'une question de temps.

Le moyen le plus fiable de casser cette combinaison est de **contrôler ce qui sort**. Les garde-fous placés *dans* l'agent (consignes, hooks qui lisent les arguments des outils) se contournent par l'agent lui-même : une URL dans une variable, un script ou un serveur MCP qui fait ses propres appels passe à côté.

**agents-firewall** applique la politique **sur le réseau**, hors de l'agent, et se gère comme un pare-feu d'entreprise.

## Ce qu'il fait

- **Contrôle des sorties impossible à contourner** : un agent enrôlé ne sort que par la passerelle. Refus par défaut, immédiat et explicite.
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

🚧 **V1 en construction.** Le cahier des charges, la conception, le plan d'implémentation et les décisions d'architecture sont écrits ; les composants sont construits en parallèle et fusionnés dans la branche `dev`. Rien n'est encore prêt pour la production, et aucune version ni image n'est publiée.

## Démarrage rapide (démo locale, à venir)

Dès la V1 livrée, un environnement de démonstration fera tout tourner sur un seul poste, sans accès Internet : console, API, une passerelle avec deux zones, trois agents factices dont un agent Hermes, un faux fournisseur LLM et une cible d'exfiltration.

```sh
demo/up.sh                 # construit les images, démarre, crée et installe la politique de démo
# console : http://localhost:3000
demo/scenarios/run-all.sh  # joue les scénarios de recette (contournements, « Autoriser » en moins de 2 min…)
demo/down.sh
```

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
