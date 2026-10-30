# Serveur MCP d'administration

`afw-mcp` expose l'administration du pare-feu à **un seul agent agréé**, par le protocole MCP (*Model Context Protocol*). Il offre les mêmes outils que la CLI ([cli.md](cli.md)) et passe par la même API : un agent peut donc consulter le journal, préparer une règle, publier et installer, dans les limites décrites ici.

> **État d'avancement.** Le serveur MCP est en cours de construction (à venir). Les garde-fous décrits ci-dessous sont figés par la conception et le contrat de l'API.

## Pourquoi un agent d'administration

Un agent d'exploitation peut traiter les demandes courantes (« ouvre l'accès à telle API pour la zone `clients` ») sans attendre un humain, tout en restant **sous contrôle** : périmètre limité, validation humaine pour ce qui est risqué, audit de chaque action.

## Transports

- **stdio** : l'agent lance `afw-mcp` comme processus local ;
- **HTTP** : `afw-mcp` tourne comme service et l'agent s'y connecte.

Dans les deux cas, `afw-mcp` s'authentifie auprès de l'API avec un jeton rattaché au rôle `mcp_agent`. Les paramètres de lancement exacts (adresse de la console, emplacement du jeton) seront documentés avec le binaire (à venir).

Exemple de déclaration côté client MCP, en stdio (forme générique) :

```json
{
  "mcpServers": {
    "agents-firewall": {
      "command": "afw-mcp"
    }
  }
}
```

## Désigner l'agent agréé

1. L'agent est enrôlé comme les autres et appartient à **sa propre zone** (par exemple `ops`).
2. Un administrateur marque cet agent comme agréé (indicateur `mcp_admin`) et lui crée un jeton de rôle `mcp_agent`.
3. Un administrateur indique quelles zones lui sont **déléguées** (indicateur `delegated_to_mcp` sur chaque zone).

Il n'y a qu'un seul agent agréé.

## Ce que l'agent peut faire

- lire la politique, le journal, les alertes, les révisions ;
- dans une session : créer ou modifier des objets, des règles **des zones déléguées**, préparer une règle depuis un flux refusé (« Autoriser ») ;
- publier et installer ;
- lancer une vérification de révision.

## Ce qu'il ne peut jamais faire

L'agent agréé ne peut **jamais modifier ce qui s'applique à lui-même** :

- sa propre zone (mode, délégation, nom) ;
- une règle dont la source est sa zone ;
- déplacer un agent vers sa zone ou hors de sa zone ;
- le socle commun ;
- une zone qui ne lui est pas déléguée.

Ces refus sont appliqués par l'API (réponse `403`), pas seulement par le serveur MCP : passer directement par l'API avec le même jeton ne change rien.

## Élargissements soumis à validation

Certaines modifications élargissent fortement l'accès. Demandées par l'agent agréé, elles sont mises **en attente de validation humaine** (`/api/v1/approvals`) et ne peuvent pas être publiées avant :

- un joker large sur Internet (par exemple `*.com`) ;
- une règle vers « toute destination » ;
- une autorisation de sortie d'une classe de données de catégorie secret.

Un administrateur humain les accepte ou les refuse depuis la console ou l'API.

## Audit

Chaque appel d'outil MCP qui modifie quelque chose est inscrit dans l'audit avec :

- l'acteur (l'agent agréé, avec son identité) ;
- l'interface `mcp` ;
- la session ;
- la différence appliquée.

Voir [securite.md](securite.md#audit-chaîné-et-export-immuable).
