# ADR 0011 — Contrats partagés (lot L0)

- Statut : accepté — 2026-10-30

## Contexte
Le plan maître (§3) fixe les types partagés ; plusieurs détails restaient à trancher pour que les lots
parallèles (moteur, passerelle, API, CLI, MCP, console, plugin) travaillent sur un contrat figé.

## Décisions
1. **Format des fils** : JSON `snake_case` ; énumérations sans champ = chaînes (`"llm_provider"`) ;
   énumérations porteuses de champs = objets étiquetés par `type` (`{"type":"zone","zone_id":…}`).
   Tous les types de politique, `InstalledPolicy`, les DTO d'écriture de l'API et les requêtes
   passerelle `register`/`policy/ack` sont en `deny_unknown_fields` : une faute de frappe
   (`destination` au lieu de `destinations`) est une erreur, jamais un « any » silencieux. Les
   événements (passerelle, plugin) restent tolérants pour permettre des versions décalées.
2. **`GatewayEvent::RuleHits`** devient une variante structure `{ "type": "rule_hits", "hits": [...] }`
   (serde ne sait pas étiqueter en interne une séquence). `RuleHit { rule_id, revision, hits, last_hit_at }`.
3. **En-têtes HTTP** : `Vec<(String, String)>` côté Rust, sérialisé en paires `[nom, valeur]` ; le schéma
   publié est `array<array<string>[2]>` (le tuple JSON Schema draft-07 n'est pas valide en OpenAPI 3.1).
4. **JSON canonique** (`afw_core::canonical_json`) : clés triées par octets, aucun espace, chaînes et
   nombres formatés par `serde_json` ; indépendant de la fonctionnalité `preserve_order`.
   Empreinte d'une révision (`Revision.sha256`, `document_sha256`) = SHA-256 du JSON canonique de
   `document`. Empreinte d'une politique installée (`InstalledPolicy.sha256`, `installed_sha256`) =
   SHA-256 du JSON canonique de `{"document", "revision", "rollback"}` : numéro de révision et drapeau
   de retour arrière sont couverts.
5. **Audit** : `hash = sha256_hex(prev_hash ‖ canonical_json(entrée sans le champ hash))`, premier
   `prev_hash` = 64 zéros (`GENESIS_HASH`). `verify_chain` vérifie une tranche contiguë (seq consécutifs,
   chaînage, empreintes) ; l'appelant vérifie le premier `prev_hash` (genèse ou ancre exportée).
   Côté API, `audit::record` sérialise la chaîne par `pg_advisory_xact_lock`, calcule `seq` = dernier + 1
   dans la transaction de la modification (pas de trou après un rollback), tronque l'horodatage à la
   microseconde (précision PostgreSQL). La table `audit_log` refuse UPDATE/DELETE/TRUNCATE (déclencheurs).
6. **Numérotation des règles** (`PolicyDocument::rule_numbers`) : socle par position, puis zones triées par
   nom (puis id), règles par position ; égalité départagée par id ; règles désactivées/expirées numérotées.
7. **OpenAPI** : chemins écrits à la main ; `components.schemas` **générés** depuis afw-core (schemars,
   références `#/components/schemas/…`, schémas booléens `true` remplacés par `{}` pour l'outillage).
   `AFW_UPDATE_SCHEMAS=1 scripts/cargo.sh test -p afw-api --test openapi` régénère ; sans la variable, le
   test échoue en cas d'écart. Idem `docs/schemas/*.json` avec `-p afw-core`. Les pages génériques
   s'appellent `Page_for_<T>`.
8. **API REST** : les mutations de politique portent la session dans l'en-tête `X-Afw-Session` ;
   `/settings` (GET/PUT) et `POST /revisions/{n}/revert` (retour arrière = nouvelle session) ajoutés ;
   les alertes s'acquittent par `POST /alerts/{id}/ack` ; le flux SSE `logs/stream` émet `event: <type>`
   et `data: <GatewayEvent JSON>` ; l'export d'audit est en NDJSON.
9. **Rôles** (révisé après revue) : `Admin > Auditor > Viewer` pour `Principal::require` ;
   `McpAgent` ne passe que `Viewer` (il n'est **jamais** admin) ; `require_policy_write()` accepte
   `Admin` et `McpAgent`, et l'appelant DOIT ensuite contrôler chaque zone touchée avec
   `require_zone_write(zone, zone_propre, zones_déléguées)` : `Admin` passe, `McpAgent` seulement si la
   zone est déléguée au MCP et n'est pas la sienne ; zone propre inconnue ⇒ refus. Zone propre et zones
   déléguées sont **calculées à chaque requête depuis la politique** (`Agent.zone_id`,
   `Zone.delegated_to_mcp`, `Principal::zone_scope`), jamais stockées sur le jeton (source unique).
   Un seul jeton `mcp_agent` actif (index unique partiel). `AgentPlugin` (jeton du plugin Hermes)
   n'accède qu'à `/ingest/tool-calls` et `/intent-policy` (`require_plugin`). Seuls `Admin`/`Auditor`
   voient les contenus. Jetons : `expires_at` (jeton expiré refusé), `created_by`, `last_used_at` ;
   schéma `Bearer` insensible à la casse ; le jeton d'amorçage révoqué n'est jamais réactivé.
   **`X-Afw-Interface` est déclaratif** (défaut `api`, forcé à `mcp` pour `mcp_agent`) : il est tracé
   dans l'audit mais ne doit porter **aucune** décision d'autorisation.
10. **Versions** : `schemars` 0.8 (déjà fixé au workspace) ; `rmcp` 0.8 et les autres versions du
    `Cargo.toml` racine résolvent sans modification.

11. **Politique d'intention** : `IntentPolicy` reprend exactement le format déjà consommé par le
    plugin Hermes fusionné (ADR 0015) : `{version, action_classes: [{id, name, tools, patterns,
    decision: allow|log|gate|deny}]}`.
12. **Événements** : `DecisionRef.revision` (révision qui a décidé), `DnsEvent.zone_id`,
    `MapEdge.first_seen_at` + `new`, `EventBatch.batch_id` (clé d'idempotence : un lot renvoyé après
    une expiration n'est ingéré qu'une fois).

## Complément au contrat passerelle (ADR 0004) : anti-retour arrière
La passerelle refuse d'installer une politique dont `revision` est **inférieure** à celle de sa
politique active (`InstalledPolicy::may_replace`), sauf si la console l'a marquée `rollback: true`
(`InstalledPolicy::as_rollback`, utilisé uniquement par un retour arrière explicite). Le drapeau et le
numéro étant couverts par l'empreinte, ni l'un ni l'autre ne peut être modifié sans invalider le
document. Réinstaller la même révision est permis (commande `Reinstall`). L'ordre est : `verify()`
puis `may_replace()` ; tout échec ⇒ politique active conservée (ou tout refuser s'il n'y en a pas).

## Limites de l'audit
- La chaîne détecte une modification, une suppression ou une réécriture partielle, pas une
  réécriture **complète** par quelqu'un qui a les droits en base : d'où l'export périodique de la
  tête de chaîne vers un stockage externe immuable (lot L7c), qui sert d'ancre à `verify_chain`.
- Les déclencheurs append-only ne protègent que si le rôle applicatif ne possède pas la table : en
  production, l'API se connecte avec un rôle sans `DROP`, `ALTER`/`DISABLE TRIGGER` ni `TRUNCATE`,
  les migrations étant appliquées par un rôle propriétaire distinct.
- L'écriture est sérialisée par `pg_advisory_xact_lock` sous isolement READ COMMITTED : la lecture
  du dernier maillon se fait après l'obtention du verrou, donc voit le maillon validé précédent ; tout
  enregistrement doit passer par `audit::record` (une insertion directe casserait la chaîne).
- Les valeurs JSONB sont relues par PostgreSQL : des nombres hors de la précision f64 dans `diff`
  pourraient changer de forme ; les lots n'y mettent que des entiers et des chaînes.

## Conséquences
Changer un champ d'afw-core impose de régénérer schémas et OpenAPI dans la même PR (les tests l'exigent),
ce qui rend toute dérive de contrat visible en revue.
