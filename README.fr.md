<div align="center">

# agents-firewall

**Pare-feu open source pour agents IA : contrôle centralisé des sorties réseau, visibilité complète des flux et audit pour des flottes d'agents LLM.**

[![Licence : Apache 2.0](https://img.shields.io/badge/Licence-Apache_2.0-blue.svg)](LICENSE)
[![Statut : conception](https://img.shields.io/badge/statut-conception-orange.svg)](#statut)

[English](README.md) · [Cahier des charges](docs/cahier-des-charges.md) · [Conception](docs/superpowers/specs/2026-10-30-agents-firewall-design.md) · [Contribuer](CONTRIBUTING.md) · [Sécurité](SECURITY.md)

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

## Statut

🚧 **Phase de conception.** Le cahier des charges et le document de conception sont rédigés ; la réalisation démarre.

## Licence

[Apache 2.0](LICENSE). Copyright © 2026 Aidalinfo / Pulse myIT et contributeurs.
