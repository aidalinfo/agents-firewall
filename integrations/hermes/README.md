# afw-hermes — plugin agents-firewall pour Hermes Agent

Plugin Python (bibliothèque standard uniquement, Python ≥ 3.11) qui relie un agent
[Hermes Agent](https://hermes-agent.nousresearch.com/) à la console agents-firewall :

1. **Corrélation** (EF-34, EF-61, ADR 0007) : début et fin de chaque appel d'outil envoyés à
   `POST {console}/api/v1/ingest/tool-calls` ; la console rattache ensuite les flux réseau vus par
   la passerelle à l'appel d'outil et à la conversation qui les ont déclenchés.
2. **Étage intention** (EF-62) : les classes d'actions de l'egress-guard (suppression irréversible,
   partage et droits d'accès, infrastructure destructive, génération payante) avec leur décision
   `allow | log | gate | deny`. « gate » bloque l'appel et renvoie à l'agent le message
   « action soumise à validation humaine : … ». La politique est servie par la console
   (`GET {console}/api/v1/intent-policy`), rafraîchie toutes les 60 s, avec repli sur la dernière
   politique connue (mémoire puis disque) et enfin sur une politique intégrée prudente.

Les destinations et les classes de données (contenu réellement envoyé) ne sont **pas** évaluées ici :
c'est la passerelle qui les porte (conception §15). Le plugin n'est pas une barrière réseau : il
inspecte le texte des arguments, contournable par construction ; la barrière est la passerelle.

## Installation

### Automatique

`afw enroll --hermes <conteneur>` (lot enrôlement) fera, en une commande : l'enrôlement réseau,
la création de l'agent et de son jeton d'agent dans la console, l'installation de ce plugin dans
le conteneur (copie dans `~/.hermes/plugins/afw-hermes/`), l'ajout de `afw-hermes` à
`plugins.enabled`, et la pose des variables `AFW_CONSOLE_URL`, `AFW_AGENT_TOKEN`,
`AFW_AGENT_NAME` et `AFW_CA_FILE`.

### Manuelle — plugin Hermes (recommandé)

Copie du paquet dans le dossier des plugins (même mécanisme que `pulse-chat`) :

```sh
cp -r afw_hermes ~/.hermes/plugins/afw-hermes
hermes plugins enable afw-hermes          # ou plugins.enabled: [afw-hermes] dans config.yaml
```

ou par pip (point d'entrée `hermes_agent.plugins`) :

```sh
pip install ./integrations/hermes
hermes plugins enable afw-hermes
```

Le plugin enregistre `pre_tool_call` (décision + début) et `post_tool_call` (fin) via
`ctx.register_hook`. Aucun hook n'attend le réseau : les événements partent d'une file en mémoire
bornée, envoyée par lots en tâche de fond, avec réessais (backoff exponentiel) et file disque bornée
quand la console est injoignable.

### Manuelle — hook en ligne de commande (remplacement de l'egress-guard)

Pour remplacer l'egress-guard sans changer de mécanisme, `pip install` le paquet puis remplacer la
commande `hook_entry.py` dans `data/config.yaml` :

```yaml
hooks:
  pre_tool_call:
    - command: "python -m afw_hermes.hook"   # ou afw-hermes-hook
      matcher: "terminal|fetch|mail.*|teams.*|glpi.*|coolify.*|freepik.*"
      timeout: 5
      fail_closed: true
  post_tool_call:
    - command: "python -m afw_hermes.hook"
```

Entrée (stdin) : la charge des hooks shell Hermes (`hook_event_name`, `tool_name`, `tool_input`,
`session_id`, `extra`) ou celle de l'egress-guard (`tool`, `args`). Sortie (stdout) : un objet JSON
avec `afw_decision` (`allow|log|gate|deny`) et `afw_class` ; en cas de blocage, aussi
`{"action": "block", "message": …}` et `{"decision": "block", "reason": …}`, avec le code de sortie 2.
Une erreur interne sort en code 1 : Hermes applique alors `fail_closed`.

Le hook n'appelle jamais le réseau : il lit la politique en cache et écrit les événements dans la
file disque ; un processus détaché (`python -m afw_hermes.flush`) les envoie et rafraîchit la politique.

## Configuration

Variables d'environnement (prioritaires), sinon fichier `$HERMES_HOME/afw-hermes.yaml` (clés
`clé: valeur` à plat) ou `afw-hermes.json`, ou le fichier désigné par `AFW_HERMES_CONFIG` :

| Variable | Clé de fichier | Défaut | Rôle |
|---|---|---|---|
| `AFW_CONSOLE_URL` | `console_url` | — | URL de la console (sans elle : rien n'est envoyé, politique intégrée) |
| `AFW_AGENT_TOKEN` | `agent_token` | — | jeton d'agent (`Authorization: Bearer`) |
| `AFW_AGENT_NAME` | `agent_name` | nom d'hôte | nom de l'agent dans les événements |
| `AFW_CA_FILE` | `ca_file` | — | CA (PEM) de la console |
| `AFW_STATE_DIR` | `state_dir` | `$HERMES_HOME/afw` | cache de politique, file disque |
| `AFW_HOOK_TIMEOUT_MS` | `hook_timeout_ms` | 50 (plafond) | délai maximal côté hook |
| `AFW_SEND_TIMEOUT_MS` | `send_timeout_ms` | 5000 | délai d'envoi d'un lot (tâche de fond) |
| `AFW_POLICY_TIMEOUT_MS` | `policy_timeout_ms` | 5000 | délai de lecture de la politique (tâche de fond) |
| `AFW_FLUSH_INTERVAL_MS` | `flush_interval_ms` | 1000 | regroupement des envois |
| `AFW_BATCH_SIZE` | `batch_size` | 100 | événements par lot |
| `AFW_QUEUE_SIZE` | `queue_size` | 10000 | file mémoire (au-delà : le plus ancien est perdu) |
| `AFW_SPOOL_MAX_BYTES` | `spool_max_bytes` | 5000000 | file disque |
| `AFW_POLICY_REFRESH_SECS` | `policy_refresh_secs` | 60 | rafraîchissement de la politique |

## Format des événements

```json
{"id": "uuid4", "agent": "daniel-bot", "conversation_id": "…", "tool": "terminal",
 "args_summary": "command: curl -H 'Authorization: Bearer ***' https://…",
 "started_at": "2026-10-30T12:00:00.123Z", "ended_at": null, "status": null}
```

Le même `id` est envoyé au début (`ended_at`/`status` nuls) puis à la fin (`status` = `ok`,
`error`, ou statut fourni par Hermes) ; un appel bloqué n'est envoyé qu'une fois, avec
`status` = `gated` ou `denied`. `args_summary` est limité à 500 caractères, secrets évidents masqués.
`conversation_id` : `session_id` de Hermes, sinon `HERMES_SESSION_ID`/`HERMES_SESSION_CHAT_ID` du
contexte de session, sinon `task_id`.

## Politique d'intention

```json
{"version": 3, "action_classes": [
  {"id": "irreversible", "name": "Suppression irréversible", "tools": [],
   "patterns": ["(?i)\\bdrop\\s+table\\b"], "decision": "gate"}]}
```

Une classe s'applique si `tools` (globs, insensibles à la casse) est vide ou contient l'outil, et
si `patterns` (regex Python) est vide ou que l'un d'eux trouve une correspondance dans le *sujet* :
nom de l'outil en première ligne, puis une ligne par argument (`clé: valeur`), normalisé NFKC
(`\A` ancre donc sur le nom de l'outil). Décision la plus stricte retenue (deny > gate > log > allow).
Une politique invalide est rejetée en entier et la précédente conservée.

## Développement

```sh
docker run --rm -v "$PWD":/w -w /w/integrations/hermes python:3.12-slim \
  bash -c "pip install -q -e '.[dev]' && pytest -q"
```

Démo (faux agent Hermes piloté en HTTP) :

```sh
docker build -f demo/Dockerfile.demo -t afw-demo-hermes integrations/hermes
docker run --rm -p 8080:8080 -e AFW_CONSOLE_URL=… -e AFW_AGENT_TOKEN=… afw-demo-hermes
curl -s localhost:8080/run -d '{"tool":"terminal","args":{"command":"curl -s https://example.com"},"conversation_id":"c1"}'
```
