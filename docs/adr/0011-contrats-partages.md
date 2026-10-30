# ADR 0011 — Contrats partagés (lot L0)

- Statut : accepté — 2026-10-30

## Contexte
Le plan maître (§3) fixe les types partagés ; plusieurs détails restaient à trancher pour que les lots
parallèles (moteur, passerelle, API, CLI, MCP, console, plugin) travaillent sur un contrat figé.

## Décisions
1. **Format des fils** : JSON `snake_case` ; énumérations sans champ = chaînes (`"llm_provider"`) ;
   énumérations porteuses de champs = objets étiquetés par `type` (`{"type":"zone","zone_id":…}`).
2. **`GatewayEvent::RuleHits`** devient une variante structure `{ "type": "rule_hits", "hits": [...] }`
   (serde ne sait pas étiqueter en interne une séquence). `RuleHit { rule_id, revision, hits, last_hit_at }`.
3. **En-têtes HTTP** : `Vec<(String, String)>` côté Rust, sérialisé en paires `[nom, valeur]` ; le schéma
   publié est `array<array<string>[2]>` (le tuple JSON Schema draft-07 n'est pas valide en OpenAPI 3.1).
4. **JSON canonique** (`afw_core::canonical_json`) : clés triées par octets, aucun espace, chaînes et
   nombres formatés par `serde_json` ; indépendant de la fonctionnalité `preserve_order`.
   Empreinte de politique = SHA-256 hex minuscule du JSON canonique de `document`.
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
9. **Rôles** : `Admin > Auditor > Viewer` ; `McpAgent` compte comme `Admin` pour `require`, ses
   restrictions de zone (EF-51) s'appliquent dans les handlers ; seuls `Admin`/`Auditor` voient les contenus.
   Interface : en-tête `X-Afw-Interface` (défaut `api`), forcée à `mcp` pour `mcp_agent`.
10. **Versions** : `schemars` 0.8 (déjà fixé au workspace) ; `rmcp` 0.8 et les autres versions du
    `Cargo.toml` racine résolvent sans modification.

## Conséquences
Changer un champ d'afw-core impose de régénérer schémas et OpenAPI dans la même PR (les tests l'exigent),
ce qui rend toute dérive de contrat visible en revue.
