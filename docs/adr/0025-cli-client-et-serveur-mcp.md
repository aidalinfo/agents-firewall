# ADR 0025 — Client Rust, CLI `afw` et serveur MCP `afw-mcp`

- Statut : accepté — 2026-10-31 (lots L8 et L9)
- Exigences : EF-40, EF-41, EF-42, EF-45, EF-46, EF-51, EF-52, EF-60, EF-64, EF-70.

## Contexte
La CLI et le serveur MCP sont deux clients de la même API (`docs/api/openapi.yaml`), développée
en parallèle par les lots L7a/b/c. Il fallait un client partagé, tolérant aux ajouts du contrat,
et des choix sur la session d'édition, le stockage du jeton, l'enrôlement et l'exposition MCP.

## Décisions

### Client `afw-client`
1. **Une méthode par opération**, types d'`afw-core` en entrée et en sortie. Erreurs
   `application/problem+json` → `ClientError::Api { status, problem }` (corps non conforme : problème
   synthétisé avec le texte reçu).
2. **Décodage tolérant des vues** : `Rule` refuse les champs inconnus ; les listes de règles
   (`RuleView` = règle + `number`, `hits`…) sont décodées en `RuleEntry` (vue séparée de la règle),
   ce qui marche avec une règle nue comme avec une vue. Les listes de flux et le détail d'un flux
   ont aussi une variante JSON brute (`list_flows_raw`, `get_flow_raw`) pour afficher les champs
   d'affichage (`agent_name`, `rule_label`, `trace`, `allow_proposal`…).
3. **Publication** : `PublishOutcome::Published { revision }` (201) ou
   `PendingApproval { approval }` (202, EF-52) ; la session reste active tant qu'elle n'est pas publiée.
4. **Session** : en-tête `X-Afw-Session` quand une session est active ; `GET /sessions/current`
   peut renvoyer la dernière session publiée (reprise de l'installation) : seule une session à l'état
   `open` est réutilisée. Le client ne décide d'aucune autorisation.
5. **Faux serveur** (`afw_client::fake`, feature `fake`) : routes → réponses construites avec les
   DTO d'`afw-core` (donc conformes aux schémas générés), requêtes enregistrées. Tests de bout en bout
   en plus contre le vrai `afw-api` (PostgreSQL de test, ignorés sans `AFW_TEST_DATABASE_URL`).

### CLI `afw`
6. **Session implicite** : une modification utilise `--session`, sinon la session ouverte de
   l'appelant, sinon en ouvre une (message sur stderr). Les lectures voient le brouillon de la session
   ouverte. Les noms sont résolus en identifiants dans ce brouillon.
7. **Corps validés localement** : défauts + fichier `-f` (JSON ou YAML) + options, puis désérialisation
   dans le type `afw-core` avant tout appel : une erreur de saisie n'ouvre pas de session.
8. **Configuration** `~/.config/afw/config.toml` (ou `$XDG_CONFIG_HOME`), écrite en 0600 (dossier 0700)
   de façon atomique ; le jeton est lu sur l'entrée standard par `afw login` (jamais en argument),
   vérifié par `GET /me`, jamais affiché ; `AFW_TOKEN` le remplace. Avertissement si le fichier est
   lisible par d'autres.
9. **Enrôlement** : transformation locale d'abord (`afw-enroll`, valide tout), puis `POST /enrollments`
   dans la session et ajout de l'adresse de l'agent, puis modification de l'infrastructure (compose
   réécrit atomiquement, Coolify, manifeste Kubernetes). Si l'infrastructure échoue, seul l'agent est
   retiré de la session (les autres changements sont gardés). Le jeton du plugin Hermes est écrit dans
   un fichier `.env` en 0600 (`--env-file`) ou affiché une fois ; jamais dans le compose.
10. **Import egress-guard** : le plan est calculé sur le brouillon courant ; sans `--apply`, rapport
    seulement ; un plan qui n'applique pas tous les refus de la source est refusé sauf `--force` ;
    la politique d'intention n'est remplacée qu'avec `--intent-policy`.
11. **Sortie** : tableaux (cellules nettoyées des caractères de contrôle : les données de l'API ne
    pilotent pas le terminal) ou `--json`. `afw install` attend le résultat de chaque passerelle
    (code de sortie 1 en cas d'échec ou de délai dépassé).

### Serveur `afw-mcp`
12. **Table d'outils déclarative** (pas de macros rmcp) : nom, description, schéma JSON, exécution par
    `afw-client` avec `Interface::Mcp`. Ressources de politique par outils génériques
    (`list/get/create/update/delete_resource` avec `kind`). Pas d'outil de décision d'approbation ni
    de gestion de jetons (réservés aux humains).
13. **Aucun contrôle d'autorisation côté MCP** : l'API est l'autorité (EF-51/52). Les refus sont rendus
    lisibles : 403 → résultat d'outil en erreur expliquant la délégation et « ne pas réessayer » ;
    publication 202 → « PENDING HUMAN APPROVAL ». Les descriptions des outils d'écriture et les
    instructions du serveur rappellent que l'agent ne peut jamais modifier sa propre zone.
14. **Transport HTTP** (streamable HTTP, `/mcp`) : quiconque l'atteint agit comme l'agent agréé ; il
    exige donc un jeton d'écoute `AFW_MCP_LISTEN_TOKEN` (16 caractères au moins, comparaison à temps
    constant) et écoute par défaut sur `127.0.0.1:8765`. Le jeton d'API ne passe jamais en argument
    (`AFW_TOKEN` ou `--token-file`).

## Conséquences
- Un ajout de champ au contrat ne casse ni la CLI ni le MCP ; un renommage reste une rupture de
  contrat (ADR 0011).
- `afw-api` est une dépendance de développement d'`afw-cli` et `afw-mcp` (tests de bout en bout).
