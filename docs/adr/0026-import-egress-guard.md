# ADR 0026 — Import de la politique egress-guard (`afw-import`)

- Statut : accepté — 2026-10-31
- Lot : L10 (`crates/afw-import`, `examples/egress-guard/`)

## Contexte
EF-70 (import de la politique egress-guard), EF-71 (observation avant application), EF-72 (faux positif S3
présigné) ; conception §2, §5.4, §11 et §15 ; ADR 0005 (ordre d'évaluation), 0012 (afw-dlp), 0015 (plugin
Hermes), 0016 (moteur). Le fichier réel `pulse-mcp-guardrails.yaml` n'est pas disponible : seule sa
description l'est (« v2 egress-first » : expéditeurs autorisés, classes de données par regex, destinations
allow/deny avec refus par défaut, matrice classe × tier → allow/log/gate/deny, classes d'actions).

## Décisions

### Format reconstruit et tolérance
1. Le format accepté est décrit et illustré par `examples/egress-guard/guardrails.example.yaml` (anonymisé,
   aucun élément réel) : `version`, `profile`/`name`/`description`, `senders`, `tiers`, `data_classes`,
   `destinations` (`default`, `allow`, `deny`), `matrix`, `action_classes`, `logging`. Les hôtes s'écrivent en
   chaîne simple ou `{host, tier, ports, comment}` ; les motifs en chaîne ou `{name, regex}` (alias `pattern`).
2. **Erreur** seulement si le fichier n'est pas du YAML (message avec ligne et colonne) ou n'a pas la forme
   attendue (racine non associative, type faux : `allow: 42`, `patterns: 7`…), avec le chemin fautif.
3. **Tout le reste va au rapport**, jamais ignoré en silence : champ inconnu → avertissement avec son chemin
   (`destinations.allow[0].ttl`) ; élément sans équivalent ou rejeté → « non converti » ; approximation →
   avertissement. Les champs inconnus sont recueillis par `#[serde(flatten)]` sur chaque structure.

### Destinations
4. Hôte autorisé → objet domaine (minuscules, point final retiré), hôte ou réseau CIDR ; un tier → un groupe
   `egress-guard/<zone>/<tier>` portant la catégorie du tier (`internal`, `llm_provider`), reprise aussi sur les
   objets créés. Un hôte sans tier va dans le tier `default`.
5. Joker : `*.domaine` = sous-domaines seulement (sémantique du moteur, ADR 0016) ; un avertissement rappelle
   que le domaine lui-même n'est pas couvert. Joker global (`*`), joker ailleurs qu'en tête et nom non ASCII
   ne sont **pas** convertis (jamais d'objet « any » issu d'un joker).
6. Une règle d'acceptation par tier (hôtes sans ports, tous services), et une par liste de ports avec un
   service `tcp/<ports>` : `ports` restreint, il n'est jamais ignoré.
7. Hôtes refusés → un groupe et **une règle du socle** `Deny`, dont la source est **la zone importée** : le
   socle n'est pas contournable par les règles de zone, mais l'import d'un bot ne doit pas bloquer
   immédiatement les autres zones (qui peuvent être en application). Le rapport invite à élargir la source
   si la liste vaut pour toute la flotte. Un hôte à la fois autorisé et refusé reste refusé.
8. `default: deny` = règle de nettoyage implicite. Toute autre valeur est signalée et **non reprise** :
   agents-firewall refuse toujours par défaut ; c'est le mode observation qui évite les blocages au début.

### Classes de données et EF-72
9. Chaque classe devient une classe de données (catégorie explicite ou déduite du nom : secret, infra,
   commercial, personal, sinon custom) avec ses motifs. Chaque motif est compilé avec `afw-dlp` (comme la
   passerelle) : un motif invalide pour le moteur Rust (par exemple un lookbehind Python) est « non converti ».
10. **EF-72.** Chaque motif est essayé sur des URL de dépôt présignées représentatives (S3 SigV4 avec jeton de
    session, S3 SigV2, GCS V4), en URL, en corps brut, en JSON et décodées : un motif qui s'y déclenche est
    retiré, avec un avertissement. La classe de catégorie `secret` reçoit en plus les 14 détecteurs intégrés de
    la classe `secrets` d'`afw-dlp`, qui excluent `X-Amz-Signature`/`X-Amz-Credential`… mais reconnaissent une
    vraie clé, y compris glissée dans une URL présignée. Les motifs propres non concernés (format de clé
    interne…) sont conservés. Plutôt que remplacer aveuglément toute la classe, on garde ainsi ce qui n'a pas
    causé le faux positif.

### Matrice → règles de contenu (zone)
11. `deny` → règle `Deny` avec la classe, vers les groupes des tiers concernés (une règle par couple
    classe × décision). `gate` → règle `Deny` aussi : la passerelle n'a pas de file de validation en V1 (§15),
    le « gate » métier reste porté par les classes d'actions du plugin ; signalé comme approximation.
12. `log` → règle `Accept` avec la classe et `track = detailed`, dédiée pour que les envois de cette classe
    soient attribués à une règle identifiable ; elle reprend exactement les destinations **et ports** des
    règles d'acceptation des tiers. `allow` → pas de règle (la règle du tier suffit).
13. **Ordre** : toutes les règles de refus de la matrice, puis les règles `log`, puis les acceptations par tier.
    Sinon une règle `log` (accept) placée avant pourrait laisser passer un contenu contenant aussi une classe
    refusée (première correspondance). Testé dans `tests/bypass.rs`.
14. Tiers spéciaux : `any`/`*` = toutes les destinations listées (jamais une destination non listée pour un
    `log`) ; `unlisted`/`unknown`/`other` = déjà refusé par défaut. Tier de catégorie `llm_provider` : les
    règles de contenu y sont sans effet (EF-25), une case `deny`/`gate` n'est donc pas traduite et le rapport le
    dit. Une décision inconnue est traitée comme `deny` (la plus stricte), avec avertissement.

### Classes d'actions → politique d'intention
15. Chaque classe devient un `ActionClass` (format ADR 0015) : `id` normalisé en snake_case, `name`, `tools`,
    `patterns`, `decision` (`ask`/`confirm`/`approval` → `gate` ; `block`/`refuse` → `deny` ; absente →
    `gate` ; inconnue → `deny`). Version 1. Les motifs sont vérifiés avec le moteur Rust à titre indicatif
    seulement (le plugin compile en Python) : un échec donne un avertissement, le motif est gardé. Une classe
    standard absente (`irreversible`, `access`, `infra_destructive`, `paid_generation`) est signalée, car la
    politique servie remplace la politique intégrée du plugin.
16. La politique d'intention n'est pas une ressource de session : `ImportPlan::intent_policy` est séparé de
    `to_session_changes()`. L'API V1 n'expose que `GET /intent-policy` ; son écriture est à la charge de la
    CLI / de l'API (lot L8 ou suivant).
17. `senders` (expéditeurs autorisés) : pas d'équivalent réseau → « non converti ». `logging` : remplacé par le
    journal de la console.

### Zone, dédoublonnage et application
18. Zone créée (ou réutilisée si le nom existe) en mode **observation par défaut** (`ImportOptions::new`,
    EF-71). Réutiliser une zone existante dans un autre mode la passe au mode demandé, avec avertissement.
19. Dédoublonnage avec la politique existante : objet feuille de même domaine (casse et point final
    ignorés) / adresse / réseau → réutilisé ; groupe de même nom → complété (union) ; service TCP de mêmes
    ports → réutilisé ; classe de données de même nom → réutilisée telle quelle ; règle de même nom dans la
    même couche → conservée. Un second import du même fichier ne produit donc aucune opération.
20. `ImportPlan::to_session_changes()` donne les opérations dans l'ordre des dépendances (services, objets
    feuilles, groupes, classes de données, zone, règles du socle puis de zone) avec `endpoint()` (méthode et
    chemin de l'API). `merged_into()` calcule le document résultant (aperçu, tests). Les règles sont
    numérotées de 10 en 10 après les règles existantes de la couche.

## Conséquences et limites
- Le format exact du fichier réel peut différer : un champ inattendu apparaît dans le rapport, un type
  inattendu arrête l'import avec son chemin. Adapter le format reste local à `egress_guard/format.rs`.
- Les motifs Python non compatibles avec `regex` (lookaround, références arrière) ne sont pas convertis
  côté passerelle ; ils sont listés pour réécriture.
- Le contrôle EF-72 repose sur des URL d'exemple : un motif ne se déclenchant que sur une variante non
  couverte passerait ; le rapport liste de toute façon chaque motif conservé.
- La sémantique des jokers de l'egress-guard (domaine compris ou non) n'est pas connue : avertissement à
  chaque joker plutôt qu'un élargissement automatique.
- Les tests vérifient la traduction avec le vrai moteur (`afw-engine`) et le vrai détecteur (`afw-dlp`).
