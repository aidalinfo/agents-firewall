# CLI `afw`

La CLI `afw` couvre **tout le périmètre** de la console, enrôlement et import compris (EF-40, EF-45). Elle est écrite en Rust et s'appuie sur le même client que le serveur MCP (`afw-client`), branché sur l'API REST ([api.md](api.md), contrat `docs/api/openapi.yaml`). Les choix sont décrits dans l'[ADR 0025](adr/0025-cli-client-et-serveur-mcp.md).

L'aide de chaque commande est donnée par `afw --help` et `afw <commande> [<sous-commande>] --help` ; ce document en est le résumé.

## Connexion et configuration

```sh
afw login --url https://afw.example.org [--ca-cert ca-console.pem]   # jeton saisi sans écho
printf '%s\n' "$JETON" | afw login --url https://afw.example.org     # ou lu sur un tube
afw me                      # identité, rôle, zones modifiables
afw config show             # le jeton n'est jamais affiché
afw config path
```

`afw login` lit le jeton d'API sur l'entrée standard (sans écho sur un terminal, jamais en argument), refuse une URL `http://` vers un hôte non local sauf `--insecure-http`, vérifie le jeton par `GET /me`, puis écrit `~/.config/afw/config.toml` (ou `$XDG_CONFIG_HOME/afw/config.toml`) en mode `0600` :

```toml
url = "https://afw.example.org"
token = "…"
ca_cert = "/chemin/ca-console.pem"   # facultatif, CA privée de la console
```

Options globales (toutes les commandes) et variables d'environnement :

| Option | Variable | Rôle |
|---|---|---|
| `--json` | — | sortie JSON au lieu de tableaux |
| `--config <fichier>` | `AFW_CONFIG` | autre fichier de configuration |
| `--url <url>` | `AFW_URL` | URL de la console |
| — | `AFW_TOKEN` | jeton d'API (remplace celui du fichier) |
| `--ca-cert <fichier>` | `AFW_CA_CERT` | CA supplémentaire (PEM) |
| `--session <id>` | `AFW_SESSION` | session d'édition à utiliser |

Chaque appel porte l'en-tête `X-Afw-Interface: cli` : les modifications apparaissent dans l'audit avec l'interface `cli` et l'identité du jeton.

## Sessions

Toute modification de politique se fait dans une **session d'édition** : `--session`, sinon votre session ouverte, sinon une nouvelle session ouverte automatiquement (message sur la sortie d'erreur). Les lectures (`list`, `show`, `rulebase`, `where-used`) voient le brouillon de votre session ouverte.

```sh
afw session open [--name N]
afw session show [ID]       # verrous, changements en attente, approbation
afw session list
afw session discard [ID]
afw session publish -m "commentaire" [ID]
```

`publish` affiche la révision créée, ou, pour un élargissement demandé par l'agent MCP, l'approbation humaine en attente (EF-52).

## Politique

Commandes communes à `objects`, `services`, `data-classes`, `zones`, `agents`, `rules`, `inspection-rules` et `alert-channels` :

```sh
afw <ressource> list
afw <ressource> show <nom|id>
afw <ressource> create [-f fichier.json|yaml|-] [options]
afw <ressource> update <nom|id> [-f …] [options]   # seules les options données changent
afw <ressource> delete <nom|id>
```

Le corps est construit à partir de valeurs par défaut, du fichier `-f`, puis des options ; il est validé localement avant envoi. Les références (zones, objets, services, classes) s'écrivent par nom ou par identifiant.

| Ressource | Options principales |
|---|---|
| `objects` | `--name`, `--comment`, `--category llm-provider\|cloud-metadata\|internal\|none`, une forme : `--domain`, `--host`, `--network`, `--range A-B`, `--group a,b`, `--any` |
| `services` | `--protocol tcp\|udp\|any`, `--port 443` ou `--port 8000-8100` (répétable), `--app`, `--method`, `--path-prefix` |
| `data-classes` | `--category`, `--builtin <id>`, `--regex NOM=MOTIF` |
| `zones` | `--mode enforce\|observe`, `--delegated-to-mcp true\|false` |
| `agents` | `--zone` (change de zone), `--kind`, `--gateway`, `--address`, `--label K=V`, `--hermes`, `--mcp-admin` |
| `rules` | `--zone Z` ou `--baseline`, `--section`, `--position` (défaut : en fin de couche), `--source`, `--destination`, `--service`, `--data-class`, `--action accept\|deny`, `--track`, `--expires 7d\|<RFC 3339>\|never`, `--enabled` |
| `inspection-rules` | `--position`, `--zone`, `--destination`, `--action inspect\|bypass` |
| `alert-channels` | `--kind webhook\|teams\|pulse_chat`, `--target-url`, `--min-severity`, `--enabled` |

Autres commandes :

```sh
afw rules move <règle> --position N [--zone Z | --baseline] [--section S]
afw rulebase                      # base complète par couche et section, numéros, compteurs
afw where-used <objet>
afw agents overview <agent>       # vue agent (EF-43)
afw intent-policy show | set -f politique.yaml
afw settings show
afw settings set [-f réglages.yaml] [--internal-network CIDR …] [--max-buffered-body N] [--max-stored-body N] \
    [--retention-flows J] [--retention-http J] [--retention-captures J]      # dans la session
```

## Corriger un refus, de bout en bout

```sh
afw logs flows --verdict deny --agent laurent-bot --from 1h
afw logs show <flow-id>                         # trace des règles, message reçu par l'agent, proposition
afw allow <flow-id> [--destination exact|wildcard|group] [--expires-in-days 30] [--track detailed]
afw verify                                      # règles masquées, objets inutilisés (brouillon)
afw session publish -m "autorise api.github.com pour clients"
afw install <révision> --all                    # attend le résultat de chaque passerelle
```

## Révisions et installation

```sh
afw revisions list [--limit N] [--cursor C]
afw revisions show <n>
afw revisions diff <n> [--against m]
afw revisions revert <n>          # ouvre une session au contenu de n ; publier pour revenir en arrière
afw verify [--revision n]
afw status                        # révision publiée / installée, passerelles à jour
afw install <n> (--gateway G … | --all) [--no-wait] [--timeout 120]
afw installs list [--revision n] [--gateway G]
```

`afw install` sort en code 1 si une passerelle échoue ou ne confirme pas dans le délai.

## Passerelles

```sh
afw gateways list | show <g> | delete <g>
afw gateways token [--name N]                 # jeton d'enregistrement à usage unique (15 min)
afw gateways command <g> reinstall|self-test
```

## Journal, carte, alertes, captures

Filtres du journal (EF-41) : `--agent`, `--zone`, `--destination`, `--verdict allow|deny`, `--rule`, `--from`, `--to` (RFC 3339 ou durée passée : `15m`, `2h`, `7d`), `-q` (texte libre), `--limit`, `--cursor`.

```sh
afw logs flows [filtres]
afw logs dns [filtres]
afw logs stats [filtres] [--bucket 1m|5m|1h]
afw logs show <flow-id>
afw logs tail [--agent --zone --destination --verdict --rule]   # direct (SSE), --json = une ligne JSON par événement
afw internal-map [--period 1h|24h|7d] [--from --to] [--zone Z]
afw alerts list [--agent --severity --acknowledged true|false --from --to]
afw alerts ack <id>
afw captures start <agent> [--duration 60]
afw captures list | show <id>
afw captures download <id> [-o fichier.pcap]    # fichier écrit en 0600
```

## Audit, approbations, jetons

```sh
afw audit list [--order desc|asc] [--from-seq --actor --action --interface cli|mcp|ui|api|system --from --to]   # plus récentes d'abord par défaut
afw audit verify                     # vérifie la chaîne côté serveur (code 1 si rompue)
afw audit anchor                     # exporte la tête de chaîne vers le stockage immuable maintenant
afw audit export [--from-seq N] [-o audit.ndjson]   # et revérifie la chaîne localement
afw approvals list [--status pending|approved|rejected] | show <id>
afw approvals approve <id> [-m commentaire]
afw approvals reject <id> [-m commentaire]
afw tokens list
afw tokens create --name N --role admin|auditor|viewer|mcp_agent|agent_plugin [--agent A] [--expires 90d]
afw tokens revoke <id>
```

Le secret d'un jeton créé est affiché une seule fois.

## Enrôlement (EF-60, EF-64)

```sh
afw enroll <service|conteneur> --zone Z [--ip 10.77.0.11] [--gateway G] [--name agent] \
    (--compose docker-compose.yml [--apply] | --coolify <uuid> [--coolify-service] | --k8s workload.yaml --gateway-cluster-ip IP) \
    [--hermes [--env-file .env]] [--publish "commentaire"] [--dry-run]
afw unenroll <agent> (--compose f [--apply] | --coolify <uuid>) [--keep-agent] [--publish "…"]
```

- `--compose` : transforme le fichier (conteneur `afw-net-<agent>`, réseau interne, proxy, CA ; ADR 0023) ; `--apply` lance ensuite `docker compose -f <fichier> up -d` (exécutable `AFW_DOCKER`, défaut `docker`).
- `--coolify` : modifie le compose dans Coolify et redémarre (`--coolify-url` / `AFW_COOLIFY_URL`, jeton `AFW_COOLIFY_TOKEN`).
- `--ip` : adresse fixe de l'agent sur le réseau interne, obligatoire sauf avec `--k8s`.
- `--k8s` : écrit le gabarit de pod modifié (stdout ou `-o`), sans modifier le fichier d'origine ; `--gateway-cluster-ip` (ClusterIP fixe du Service de la passerelle) est obligatoire ; `--with-gateway` ajoute les manifestes de la passerelle du namespace (`--namespace`, `--gateway-image`, `--registration-secret`). Pas de `afw unenroll --k8s` en V1.
- sans cible (`docker run`) : crée l'agent et affiche les deux commandes `docker run` à utiliser (`afw-net-<agent>`, puis l'agent).
- Réseau : `--gateway-ip` (défaut `10.77.0.2`), `--network` (`afw-internal`), `--proxy-url`, `--ca-path` (`/etc/agents-firewall/gateway.crt`), `--netinit-image`.
- `--hermes` : monte le plugin (`--hermes-plugin-dir`) ; le jeton du plugin, renvoyé une seule fois par l'API, est écrit dans `--env-file` (0600, variable `AFW_TOKEN_<AGENT>` ou `--token-env`) ou affiché ; il n'est jamais écrit dans le compose.

Ordre : transformation locale (rien n'est modifié si elle échoue) → création de l'agent dans la session (`POST /enrollments`, puis adresse de l'agent) → modification de l'infrastructure. Si cette dernière échoue, l'agent est retiré de la session. Publier puis installer pour l'appliquer. Voir [enrolement.md](enrolement.md).

## Import egress-guard (EF-70)

```sh
afw import egress-guard politique.yaml --zone assistant [--mode observe|enforce] [--downgrade]
afw import egress-guard politique.yaml --zone assistant --apply [--force] [--intent-policy]
```

Sans `--apply`, affiche le rapport d'import (Markdown) sans rien changer. `--apply` fusionne le plan dans votre session (`POST /sessions/{id}/import`) ; un plan qui n'applique pas tous les refus de la source est refusé sauf `--force` ; `--intent-policy` remplace en plus toute la politique d'intention du plugin Hermes. Voir [migration-egress-guard.md](migration-egress-guard.md).

## Codes de sortie

`0` succès ; `1` erreur (refus de l'API avec le problème et un indice, installation échouée, chaîne d'audit rompue…) ; `2` erreur d'utilisation.

Voir aussi [exploitation.md](exploitation.md) et [mcp.md](mcp.md).
