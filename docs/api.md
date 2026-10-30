# API REST

Tout ce que fait la console passe par cette API : la CLI `afw`, le serveur MCP et vos propres scripts ont donc exactement les mêmes possibilités. Aucune fonction n'existe seulement dans l'interface.

> **Contrat.** La référence est le fichier OpenAPI `docs/api/openapi.yaml` (à venir, lot des contrats), écrit avant l'implémentation ([ADR 0008](adr/0008-api-contract-first.md)). Ce document en donne la carte et des exemples ; en cas de divergence, le fichier OpenAPI fait foi.

## Conventions

| Sujet | Règle |
|---|---|
| Préfixe | `/api/v1` |
| Format | JSON (`application/json`), noms de champs en `snake_case`, identifiants UUID |
| Dates | ISO 8601 en UTC, par exemple `2026-11-02T09:15:00Z` |
| Erreurs | `application/problem+json` (RFC 9457) : `type`, `title`, `status`, `detail` |
| Pagination | par curseur sur les journaux |
| Temps réel | journal en direct en Server-Sent Events (`/logs/stream`) |
| Modifications de politique | toujours dans une **session**, appliquées seulement après publication puis installation |

## Authentification

Toutes les requêtes portent un jeton :

```
Authorization: Bearer <jeton>
```

- **Humains** : jeton OIDC obtenu par la console (fournisseur OIDC générique).
- **Scripts, CLI, intégrations** : jeton d'API créé par `/api/v1/tokens`, rattaché à un rôle et révocable.
- **Plugin Hermes** : jeton propre à l'agent, créé à l'enrôlement ; il ne donne accès qu'à `ingest/tool-calls` et `intent-policy`.

Rôles : `admin`, `auditor`, `viewer`, `mcp_agent` (voir [securite.md](securite.md#rôles-et-droits)). `GET /api/v1/me` renvoie l'identité et le rôle du jeton utilisé.

Les exemples ci-dessous supposent :

```sh
export AFW_URL=https://afw.exemple.com
export AFW_TOKEN=<votre jeton d'API>
H="Authorization: Bearer $AFW_TOKEN"
```

## Carte des ressources

### Politique

| Ressource | Opérations |
|---|---|
| `objects` | CRUD des objets destination ; `objects/{id}/where-used` |
| `services` | CRUD |
| `data-classes` | CRUD |
| `zones` | CRUD |
| `agents` | CRUD ; `agents/{id}/overview` (vue agent) |
| `rules` | CRUD ; `rules/{id}/move` (changer la position) |
| `inspection-rules` | CRUD de la politique d'inspection HTTPS |
| `sessions` | `POST` ouvrir, `GET current`, `POST {id}/discard`, `POST {id}/publish` |
| `sessions/{id}/allow-from-log` | préparer une règle depuis un flux refusé |
| `revisions` | liste, `GET {n}`, `GET {n}/diff?against=m` |
| `verify?revision=n` | règles masquées, objets inutilisés, règles expirées |
| `installs` | `POST` installer une révision sur des passerelles, `GET` état |
| `approvals` | élargissements de l'agent MCP en attente de validation humaine |

### Journaux et alertes

| Ressource | Opérations |
|---|---|
| `logs/flows` | recherche filtrée : `agent`, `zone`, `destination`, `verdict`, `rule`, `from`, `to`, `q` |
| `logs/flows/{id}` | détail : HTTP, appel d'outil, corrélation |
| `logs/dns` | requêtes DNS |
| `logs/stream` | journal en direct (SSE) |
| `captures` | `POST` lancer une capture, `GET {id}/download` |
| `alerts`, `alert-channels` | alertes et canaux d'envoi |
| `internal-map` | carte des flux internes |

### Administration

| Ressource | Opérations |
|---|---|
| `gateways` | liste et état ; `POST registration-tokens` ; `POST {id}/commands` (capture, réinstallation, auto-test) |
| `audit` | journal d'audit ; `audit/verify` ; `audit/export` |
| `tokens` | jetons d'API |
| `me` | identité courante |
| `enrollments` | création d'un agent et de son jeton de plugin |
| `intent-policy` | politique d'intention servie au plugin Hermes |
| `ingest/tool-calls` | réception des appels d'outil du plugin Hermes |

Les routes `/gw/v1/…` sont réservées aux passerelles (certificat client) et ne font pas partie de l'API d'administration ; voir [ADR 0004](adr/0004-politique-installee-et-protocole.md).

## Exemples

Les corps de requête ci-dessous montrent les champs figés par les contrats ; les champs complets de chaque ressource sont dans le fichier OpenAPI (à venir).

### Qui suis-je ?

```sh
curl -sS "$AFW_URL/api/v1/me" -H "$H"
```

### Chercher les refus d'une zone

```sh
curl -sS -G "$AFW_URL/api/v1/logs/flows" -H "$H" \
  --data-urlencode "zone=clients" \
  --data-urlencode "verdict=deny" \
  --data-urlencode "from=2026-11-02T00:00:00Z"
```

### Où un objet est-il utilisé ?

```sh
curl -sS "$AFW_URL/api/v1/objects/<id>/where-used" -H "$H"
```

### Du refus à l'autorisation installée

```sh
SESSION=$(curl -sS -X POST "$AFW_URL/api/v1/sessions" -H "$H" | jq -r .id)

curl -sS -X POST "$AFW_URL/api/v1/sessions/$SESSION/allow-from-log" -H "$H" \
  -H 'Content-Type: application/json' -d '{"flow_id": "<id du flux refusé>"}'

curl -sS -X POST "$AFW_URL/api/v1/sessions/$SESSION/publish" -H "$H" \
  -H 'Content-Type: application/json' -d '{"comment": "Autorise api.partenaire.exemple"}'

curl -sS "$AFW_URL/api/v1/verify?revision=42" -H "$H"

curl -sS -X POST "$AFW_URL/api/v1/installs" -H "$H" \
  -H 'Content-Type: application/json' -d '{"revision": 42, "gateways": ["<id passerelle>"]}'

curl -sS "$AFW_URL/api/v1/installs" -H "$H"     # résultat par passerelle
```

### Comparer deux révisions et revenir en arrière

```sh
curl -sS "$AFW_URL/api/v1/revisions/42/diff?against=41" -H "$H"

# Retour arrière = installer la révision précédente
curl -sS -X POST "$AFW_URL/api/v1/installs" -H "$H" \
  -H 'Content-Type: application/json' -d '{"revision": 41, "gateways": ["<id passerelle>"]}'
```

### Abandonner une session

```sh
curl -sS -X POST "$AFW_URL/api/v1/sessions/$SESSION/discard" -H "$H"
```

### Enregistrer une nouvelle passerelle

```sh
curl -sS -X POST "$AFW_URL/api/v1/gateways/registration-tokens" -H "$H"
```

### Capturer le trafic d'un agent

```sh
curl -sS -X POST "$AFW_URL/api/v1/captures" -H "$H" \
  -H 'Content-Type: application/json' -d '{"agent_id": "<id agent>", "duration_secs": 60}'
```

### Vérifier l'intégrité de l'audit

```sh
curl -sS "$AFW_URL/api/v1/audit/verify" -H "$H"
```

## Erreurs

Exemple de réponse d'erreur :

```http
HTTP/1.1 409 Conflict
Content-Type: application/problem+json

{
  "type": "about:blank",
  "title": "Conflict",
  "status": 409,
  "detail": "object 'API partenaire' is locked by another session"
}
```

Cas fréquents (indicatifs ; le contrat OpenAPI fait foi) : `401` jeton absent ou invalide ; `403` rôle insuffisant (ou agent MCP hors de ses zones déléguées) ; `404` ressource inconnue ; `409` objet verrouillé par une autre session ; `422` politique invalide (par exemple une règle de zone sans source).
