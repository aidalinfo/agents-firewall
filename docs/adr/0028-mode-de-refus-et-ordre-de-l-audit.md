# ADR 0028 — Mode de refus des flux, ordre de l'audit et session MCP abandonnée

- Statut : accepté — 2026-10-31
- Lot : L19 (finitions après la recette, ADR 0027)

## Contexte

La recette a relevé trois écarts :

1. Un `CONNECT` refusé sur le proxy explicite (`:3128`) était journalisé comme un flux TCP vers
   `0.0.0.0:443` sans application, et la console l'affichait « RST » alors que l'agent avait reçu
   un `403` avec le message EF-21.
2. La console déduisait le libellé du refus de l'application : une requête HTTP refusée en `403`
   pouvait apparaître « RST ».
3. L'audit était listé du plus ancien au plus récent : la console et la CLI montraient d'abord
   des entrées vieilles de plusieurs jours.

S'y ajoutait `discard_session` côté MCP, qui échouait (`409 session is not open`) quand la session
mémorisée par le client avait été fermée ailleurs (abandonnée par un administrateur, publiée
après une approbation), laissant croire que la session n'était pas abandonnée.

## Décisions

- **`FlowEvent.deny_mode`** (additif, `http_403 | tcp_reset | dns_refused`, `null` pour un flux
  autorisé ou une passerelle plus ancienne) : la passerelle dit comment elle a refusé, au moment
  où elle refuse. La console et `agent_message` de l'API le suivent ; sans le champ, on retombe sur
  l'ancienne déduction par application. `dns_refused` est défini pour la complétude du contrat :
  les refus DNS restent des `DnsEvent`.
- **`CONNECT` refusé** : journalisé avec l'application `https`, le nom et le port demandés
  (`domain`, port de `dst`), l'adresse résolue quand la passerelle l'a résolue (un nom refusé par
  la politique n'est jamais résolu, ADR 0018 : l'adresse reste alors non spécifiée et la console
  affiche `nom:port`), et `deny_mode = http_403`.
- **En-tête `X-Agents-Firewall-Reason`** sur toute réponse `403` de refus, avec le même texte que
  le corps (réduit à l'ASCII visible) : les clients HTTPS derrière un proxy n'affichent souvent
  que le statut et les en-têtes de la réponse au `CONNECT`.
- **`GET /audit`** : ordre décroissant de `seq` par défaut, paramètre `order=asc|desc` ; le
  curseur poursuit dans le même ordre. La CLI (`afw audit list --order`) et l'outil MCP
  `list_audit` (`order`) suivent. L'export NDJSON et la vérification restent croissants.
- **Session mémorisée par le client** (`afw-client`) : avant de l'utiliser, le client vérifie
  qu'elle est encore ouverte ; sinon il l'oublie et cherche la session ouverte de l'appelant.
  `discard_session` sans session ouverte répond « No open session » au lieu d'une erreur.
- **Accès aux contenus via MCP** : l'API trace `flow.content_access` quelle que soit l'interface
  (en-tête `X-Afw-Interface`). Le rôle `mcp_agent` ne voit jamais les contenus : un `get_flow` fait
  avec ce rôle ne renvoie que les métadonnées et n'a donc rien à tracer.

## Conséquences

- Contrat additif : schémas JSON, OpenAPI et types de la console régénérés.
- Changement de comportement de `GET /audit` sans `order` : les clients qui supposaient l'ordre
  croissant (aucun dans le dépôt après ce lot) doivent passer `order=asc`.
