# Lot L7a — API politique : plan détaillé

Exigences : EF-01, EF-02, EF-03, EF-05, EF-06, EF-09, EF-10, EF-11, EF-12, EF-42, EF-51, EF-52, EF-53,
EF-64 (agents), EF-70 (import via API). ADR : 0020. Périmètre : `crates/afw-api/src/policy/**`,
`crates/afw-api/migrations/0001_policy.sql`, tests `crates/afw-api/tests/policy_*.rs`.

## Modèle de stockage (ADR 0020)
- État publié = `revisions.document` de la dernière révision (document complet, empreinte
  `document_sha256`) ; aucune révision ⇒ document vide avec réglages par défaut.
- Brouillon = état publié + `policy_session_changes` (une ligne par entité et par session, état
  « après » complet). Le type d'opération est recalculé par rapport à l'état publié ; une entité revenue
  à son état publié n'a plus de ligne.
- Verrous `policy_locks(kind, entity_id)` (clé primaire) : une entité modifiée dans une session ouverte
  est verrouillée pour les autres ⇒ 423 `Locked{by}`. Libérés à la publication et à l'abandon.
- Publication : verrou consultatif, contrôle de structure (références, couche de zone, cycles de
  groupes), vérification (moteur), révision n+1 avec diff lisible, audit.
- Installation : `installs` + `gateway_policy_state(desired_revision, rollback, active_revision)`.
  `installed_policy_for` / `record_install_ack` pour L7c.
- Approbations EF-52 : `approvals` liées à l'empreinte du brouillon.

## Étapes (TDD, contournements d'abord)
1. Support de test : base PostgreSQL dédiée par test (`CREATE DATABASE`), jetons par rôle, routeur.
2. Tests de contournement MCP (rouges) : propre zone, socle, zone non déléguée, objet partagé utilisé par
   une règle de sa zone, auto-délégation (`delegated_to_mcp`), `mcp_admin`, réglages, déplacement d'une
   règle vers sa zone, inspection « toutes zones », retour arrière, installation d'une ancienne révision,
   décision d'approbation par le MCP, élargissements soumis à approbation (Any, `*.com`, `*`, Secret).
3. Tests fonctionnels (rouges) : CRUD de chaque ressource + lecture brouillon/publié, where-used,
   verrou entre deux sessions, abandon, publication ⇒ révision n+1 + diff, verify, install + ack +
   rollback, allow-from-log, import, audit de chaque mutation (interface + session), droits viewer.
4. Implémentation : `store.rs` (sessions, brouillon, verrous), `authz.rs` (EF-51/52), `validate.rs`,
   `engine.rs` (aides de graphe ; vérification et where-used par afw-engine), `diff.rs`, `handlers.rs`
   (ressources), `sessions.rs`, `revisions.rs`, `install.rs`, `allow.rs`, `approvals.rs`.
5. OpenAPI : amendements additifs (202 de publication, `POST /sessions/{id}/import`).
6. fmt, clippy `-D warnings`, tests ; PR vers `dev`.
