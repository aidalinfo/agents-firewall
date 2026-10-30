# ADR 0020 — API politique : stockage, sessions, droits de l'agent MCP

- Statut : accepté — 2026-10-30 (lot L7a)

## Contexte
Le lot L7a sert les ressources de politique (EF-01 à EF-12), les sessions avec verrous, la
publication en révisions, l'installation par passerelle, « Autoriser depuis le journal » (EF-42) et
les droits de l'agent d'administration MCP (EF-51, EF-52). Plusieurs choix restaient ouverts.

## Décisions
1. **Source unique de l'état publié : le document de la dernière révision** (`revisions.document`,
   `PolicyDocument` complet, empreinte `document_sha256`). Pas de tables par entité : la publication
   est atomique, l'installation sert exactement le document publié, le diff est calculé entre deux
   documents. Aucune révision ⇒ politique vide (réglages par défaut).
2. **Brouillon de session** = état publié + `policy_session_changes` (une ligne par entité et par
   session, état « après » complet, `NULL` = supprimée). Le type d'opération (`create|update|delete`)
   est recalculé par rapport à l'état publié ; une entité revenue à son état publié n'a plus de ligne.
   Lecture avec l'en-tête `X-Afw-Session` = brouillon de la session (si elle est ouverte).
3. **Verrous** `policy_locks(kind, entity_id)` en clé primaire : toute entité modifiée dans une session
   ouverte est verrouillée pour les autres ⇒ **423** (`Locked{by}` = nom du propriétaire). Libérés à la
   publication et à l'abandon. Placer une règle renumérote sa couche (positions 1..n) et verrouille
   les règles déplacées. Une session ouverte par appelant (index unique partiel, 409 sinon) ; seul le
   propriétaire écrit et publie ; un admin humain peut abandonner la session d'un autre.
4. **Chemin d'écriture unique** (`store::apply`) : autorisation (même pour une écriture sans effet,
   fail closed), verrou, changement, `audit::record` dans la même transaction (action
   `<type>.<create|update|delete>`, cible `<type>:<id>`, diff `{before, after}`, session). Ouverture,
   abandon, publication, demandes et décisions d'approbation, installations sont aussi audités.
5. **Publication** : verrou consultatif, contrôle de structure bloquant (références cassées, source
   d'une règle de zone ≠ sa zone, cycle de groupes, adresse d'agent partagée) ⇒ 409 ; les constats de
   `verify` (masquage, objets inutilisés, expiration) ne bloquent pas. Révision n+1 avec diff lisible
   (`Change` : ajouts, suppressions, modifications avec avant/après). Retour arrière = nouvelle
   session dont le brouillon égale la révision n (`POST /revisions/{n}/revert`), puis publication, ou
   installation d'une révision antérieure (`rollback` vrai dans la politique installée).
6. **Droits de l'agent MCP (EF-51)**, contrôlés à chaque écriture ET re-contrôlés à la publication
   sur le diff contre l'état publié courant (la délégation a pu être retirée entre-temps). Zone propre
   = zone de son agent dans le publié OU dans le brouillon ; zone déléguée = déléguée dans les deux ;
   agent inconnu du publié ⇒ refus. Refusé : sa zone (même déléguée), le socle, une zone non déléguée,
   la création de zone, le changement de `delegated_to_mcp`, l'octroi de `mcp_admin`, son propre
   agent, les réglages globaux, l'import, le retour arrière, l'installation d'une révision autre que
   la dernière, les décisions d'approbation, une règle d'inspection « toutes zones », la modification
   d'un objet/service/classe utilisé (directement ou via un groupe) par une règle hors de ses zones
   modifiables. Toute adresse d'agent est unique dans la politique (sinon un agent d'une zone
   déléguée pourrait revendiquer l'adresse de l'agent MCP et faire passer son trafic dans cette zone).
7. **Élargissements (EF-52)** : règle Accept active dont la destination est vide (Any), un objet Any,
   `*`, un joker de premier niveau (`*.com`), un réseau `/0` (y compris via des groupes), ou une classe
   de catégorie Secret, nouvelle ou différente (règle, destinations résolues, classes) de l'état
   publié ; suppression d'une règle de socle. Publication par le MCP ⇒ approbation `pending` liée à
   l'empreinte du brouillon et **202** ; publier de nouveau ⇒ 409 tant qu'elle est en attente ou
   rejetée ; un admin humain (jamais le demandeur) décide par `POST /approvals/{id}/decision` ; toute
   modification ultérieure du brouillon exige une nouvelle approbation.
8. **Installation** : `installs` (pending → installed/failed par l'accusé) et
   `gateway_policy_state(desired_revision, rollback, active_revision)` propre au lot, pour ne pas
   dépendre de l'ordre des migrations avec la table `gateways` du lot L7c (lue si elle existe pour
   « toutes les passerelles » et pour vérifier les identifiants). Fonctions pour L7c :
   `installed_policy_for`, `record_install_ack`, `gateway_policy_state`.
9. **Vues de lecture** (décision de l'orchestrateur : la console n'a pas de logique métier) :
   `GET /rules` renvoie des `RuleView` (règle aplatie + numéro, compteurs, expiration, verrou,
   changement en attente), `GET /rulebase` la base par couche et section avec le numéro d'affichage
   de la règle de nettoyage implicite ; `GET /sessions/current` retrouve la révision publiée non
   installée (`pending_install`). Compteurs et recherche de flux passent par les traits
   `RuleStatsSource` et `FlowLookup` d'`AppState`, à brancher sur le lot L7b.
10. **Moteur** : `GET /verify` et `where-used` appellent directement `afw_engine::verify` et
    `afw_engine::where_used` (lot L5) ; la publication ne bloque que sur les erreurs de structure.

11. **Politique d'intention Hermes** (ADR 0015) : table versionnée `intent_policy` indépendante des
    révisions de la politique réseau (elle est servie au plugin, pas installée sur les passerelles) ;
    sans version, la politique intégrée du plugin (version 0, copie de `DEFAULT_POLICY_DOC` dans
    `src/policy/intent_default.json`). Lecture : jeton du plugin ou rôle de lecture ; écriture
    (`PUT /intent-policy`) : admin humain seulement (l'agent MCP ne peut pas assouplir le contrôle qui
    s'applique à lui), auditée, version attribuée par le serveur.
12. **Lien avec le lot L7c** : aucune clé étrangère vers `gateways` (0001 passe avant 0003) ; la
    révision désirée/active est recopiée par valeur dans `gateways` quand la table existe. Le trait
    `PolicyPort` de L7c est implémenté par `policy::port::PolicyPortImpl`.

## Conséquences
- Amendements additifs du contrat : 202 sur la publication, `POST /sessions/{id}/import`,
  `GET /rulebase`, filtres `zone_id`/`q` de `GET /rules`, corps optionnel de `POST /sessions`,
  DTO `RuleView`, `Rulebase`, `SessionChange`, `ChangeOp`, `OpenSessionRequest`,
  `AllowDestination`, champs `Session.name` / `Session.pending_install`, options d'`allow-from-log`.
- `GET /rules` renvoie un sur-ensemble de `Rule` : un client qui désérialise `Rule` avec
  `deny_unknown_fields` doit utiliser `RuleView`.
