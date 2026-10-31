# Serveur MCP d'administration

`afw-mcp` expose l'administration du pare-feu à **un seul agent agréé**, par le protocole MCP (*Model Context Protocol*, EF-46). Il offre les mêmes opérations que la CLI ([cli.md](cli.md)) et passe par la même API et le même client (`afw-client`) : un agent peut consulter le journal, préparer une règle, publier et installer, dans les limites décrites ici. Choix techniques : [ADR 0025](adr/0025-cli-client-et-serveur-mcp.md).

## Pourquoi un agent d'administration

Un agent d'exploitation peut traiter les demandes courantes (« ouvre l'accès à telle API pour la zone `clients` ») sans attendre un humain, tout en restant **sous contrôle** : périmètre limité, validation humaine pour ce qui est risqué, audit de chaque action.

## Lancement

Le serveur s'authentifie auprès de l'API avec un jeton de rôle `mcp_agent`, donné par `AFW_TOKEN` ou `--token-file` (jamais en argument). Chaque appel porte `X-Afw-Interface: mcp`.

| Option | Variable | Rôle |
|---|---|---|
| `--url` | `AFW_URL` | URL de la console (obligatoire) |
| — | `AFW_TOKEN` | jeton `mcp_agent` |
| `--token-file` | `AFW_TOKEN_FILE` | fichier contenant le jeton |
| `--ca-cert` | `AFW_CA_CERT` | CA supplémentaire (PEM) |
| — | `AFW_MCP_LOG` | niveau de journal (sur stderr), défaut `warn` |

**stdio** (défaut) : l'agent lance `afw-mcp` comme processus local.

```json
{
  "mcpServers": {
    "agents-firewall": {
      "command": "afw-mcp",
      "args": ["stdio"],
      "env": { "AFW_URL": "https://afw.example.org", "AFW_TOKEN_FILE": "/run/secrets/afw-mcp-token" }
    }
  }
}
```

**HTTP** (*streamable HTTP*, chemin `/mcp`) : `afw-mcp http [--listen 127.0.0.1:8765]` (`AFW_MCP_LISTEN`). Quiconque atteint ce point d'accès agirait comme l'agent agréé : il exige donc le jeton d'écoute `AFW_MCP_LISTEN_TOKEN` (16 caractères au moins), que le client MCP envoie en `Authorization: Bearer …` ; sans lui le serveur refuse de démarrer, et toute requête sans le bon jeton reçoit `401`.

## Outils

| Outil | Rôle |
|---|---|
| `whoami` | identité, rôle, zones modifiables |
| `list_resources`, `get_resource` | objets, services, classes de données, zones, agents, règles, règles d'inspection (`kind`) |
| `create_resource`, `update_resource`, `delete_resource` | modifications dans la session (`update_resource` : champs à remplacer) |
| `where_used`, `move_rule`, `get_rulebase` | « où est-il utilisé ? », déplacement, base de règles complète |
| `open_session`, `current_session`, `discard_session`, `publish_session` | session d'édition |
| `allow_from_log` | règle préremplie depuis un flux refusé (EF-42) |
| `verify_policy`, `list_revisions`, `diff_revision` | vérification et révisions |
| `install_revision`, `list_installs`, `list_gateways`, `policy_status` | installation et passerelles |
| `search_flows`, `get_flow`, `search_dns` | journal (filtres agent, zone, destination, verdict, règle, période, texte) |
| `agent_overview`, `internal_map` | vue agent, carte des flux internes |
| `list_alerts`, `ack_alert` | alertes |
| `list_audit`, `verify_audit`, `list_approvals` | audit et approbations |

Les écritures utilisent la session ouverte de l'agent, ou en ouvrent une. Aucun outil ne permet de décider une approbation ni de gérer des jetons : ces actions restent humaines.

## Désigner l'agent agréé

1. L'agent est enrôlé comme les autres et appartient à **sa propre zone** (par exemple `ops`).
2. Un administrateur le marque comme agréé (`afw agents update ops-bot --mcp-admin true`) et lui crée un jeton : `afw tokens create --name ops-bot --role mcp_agent --agent ops-bot`.
3. Un administrateur indique les zones **déléguées** (`afw zones update clients --delegated-to-mcp true`).

L'API n'accepte qu'**un seul jeton `mcp_agent` actif à la fois**.

## Ce que l'agent peut faire

- lire la politique, le journal, les alertes, les révisions, l'audit ;
- dans une session : créer ou modifier des objets et des règles **des zones déléguées**, préparer une règle depuis un flux refusé ;
- publier et installer ;
- lancer une vérification.

## Ce qu'il ne peut jamais faire

L'agent agréé ne peut **jamais modifier ce qui s'applique à lui-même** (EF-51) :

- sa propre zone (mode, délégation, nom) ;
- une règle dont la source est sa zone ;
- déplacer un agent vers sa zone ou hors de sa zone ;
- le socle commun ;
- une zone qui ne lui est pas déléguée.

Ces refus sont appliqués **par l'API** (réponse `403`) : `afw-mcp` ne fait aucun contrôle lui-même et passer directement par l'API avec le même jeton ne change rien. Le serveur rend le refus lisible : le résultat de l'outil est en erreur, reprend le détail du problème et demande de ne pas réessayer. Les descriptions des outils d'écriture et les instructions du serveur rappellent ces limites à l'agent.

## Élargissements soumis à validation

Demandés par l'agent agréé, ces changements sont mis **en attente de validation humaine** (EF-52) : un joker large sur Internet, une règle vers « toute destination », une sortie autorisée pour une classe de données de catégorie secret. `publish_session` répond alors `PENDING HUMAN APPROVAL` avec l'identifiant de l'approbation (réponse `202` de l'API) ; la session n'est pas publiée. Un administrateur décide depuis la console ou par `afw approvals approve|reject <id>`, puis l'agent publie à nouveau.

## Audit

Chaque modification faite par MCP est inscrite dans l'audit avec l'acteur (l'agent agréé), l'interface `mcp`, la session et la différence appliquée : `afw audit list --interface mcp`. Voir [securite.md](securite.md#audit-chaîné-et-export-immuable).
