# CLI `afw`

La CLI `afw` couvre **tout le périmètre** de la console, enrôlement compris. Elle est écrite en Rust et s'appuie sur le même client que le serveur MCP (`afw-client`), lui-même branché sur l'API REST ([api.md](api.md)).

> **État d'avancement.** La CLI est en cours de construction (à venir). Ce document décrit les **groupes de commandes prévus** par le plan d'implémentation. Les sous-commandes et options exactes seront données par `afw --help` et `afw <commande> --help` ; elles ne sont pas inventées ici.

## Configuration

La configuration est lue dans `~/.config/afw/config.toml` : adresse de la console et jeton d'API (format exact à venir). Toutes les commandes acceptent `--json` pour une sortie exploitable par un script ; sinon, la sortie est un tableau lisible.

Chaque modification faite par la CLI est inscrite dans l'audit avec l'interface `cli` et l'identité du jeton utilisé.

## Groupes de commandes

| Commande | Rôle | Routes de l'API |
|---|---|---|
| `afw objects` | objets destination, « où est-il utilisé ? » | `objects`, `objects/{id}/where-used` |
| `afw zones` | zones et leur mode (application, observation) | `zones` |
| `afw rules` | base de règles : ajout, modification, déplacement | `rules`, `rules/{id}/move` |
| `afw session` | ouvrir, consulter, abandonner une session ; « Autoriser » depuis un flux | `sessions`, `sessions/{id}/allow-from-log` |
| `afw publish` | publier la session en révision | `sessions/{id}/publish` |
| `afw install` | installer une révision sur une ou plusieurs passerelles ; suivre le résultat | `installs` |
| `afw revisions` | historique, détail, différences, vérification | `revisions`, `revisions/{n}/diff`, `verify` |
| `afw logs` | recherche dans le journal, détail d'un flux, suivi en direct | `logs/flows`, `logs/dns`, `logs/stream` |
| `afw agents` | agents, changement de zone, vue agent | `agents`, `agents/{id}/overview` |
| `afw gateways` | passerelles, jetons d'enregistrement, commandes | `gateways` |
| `afw audit` | journal d'audit, vérification, export | `audit`, `audit/verify`, `audit/export` |
| `afw alerts` | alertes et canaux | `alerts`, `alert-channels` |
| `afw captures` | lancer et télécharger une capture | `captures` |
| `afw tokens` | jetons d'API | `tokens` |
| `afw enroll <conteneur>` | enrôler un agent (Compose, Coolify, Kubernetes, Hermes) | `enrollments` |
| `afw unenroll <conteneur>` | désenrôler | — |
| `afw import egress-guard <fichier.yaml> --zone <nom>` | importer une politique egress-guard | session + objets, règles, classes |

Les classes de données, services et règles d'inspection sont manipulés de la même façon (sous-commandes à venir).

## Parcours type

Corriger un refus, de bout en bout (forme prévue, options à confirmer par `--help`) :

```sh
afw logs …                 # retrouver le flux refusé et son identifiant
afw session …              # ouvrir une session et préparer la règle depuis le flux
afw publish …              # publier avec un commentaire -> révision n
afw revisions …            # vérifier la révision (règles masquées, objets inutilisés)
afw install …              # installer la révision n sur la passerelle
```

Enrôler un agent :

```sh
afw enroll mon-agent       # zone, passerelle, fichier compose : voir afw enroll --help
```

Voir aussi [enrolement.md](enrolement.md) et [exploitation.md](exploitation.md).
