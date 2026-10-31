# ADR 0016 — Moteur de règles (`afw-engine`) : sémantique de correspondance et refus en cas de doute

- Statut : accepté — 2026-10-30
- Lot : L5

## Contexte
Le plan maître (§3.1) et l'ADR 0005 figent l'ordre d'évaluation. Restaient à trancher la sémantique exacte des
correspondances (noms, chemins, informations manquantes) et quelques cas que les contrats d'`afw-core` ne couvrent pas.

## Décisions
1. **Logique à trois valeurs.** Une condition vaut oui / non / incertain. Un hôte mal formé (non ASCII, étiquette vide,
   caractère interdit) ou un chemin mal formé (échappement percent invalide, octet nul ou de contrôle, UTF-8 invalide,
   chemin non absolu) est « incertain » : il satisfait une règle **Deny** mais jamais une règle **Accept**. Une
   information absente (`None` : pas de méthode, pas de chemin, pas d'hôte) ne satisfait aucune condition qui en a
   besoin ; la passerelle réévalue les requêtes HTTP(S) avec méthode et chemin, et le contenu avec les classes détectées.
2. **Noms.** Insensibles à la casse, un point final ignoré. `*.example.com` correspond aux sous-domaines à toute
   profondeur, jamais à `example.com` ni à `evilexample.com`. **Pas d'IDN** : pas de dépendance `idna` ; un motif non
   ASCII est refusé à la compilation et un hôte non ASCII est « incertain » (la passerelle doit transmettre la forme
   punycode). Un hôte qui est un littéral IP (y compris `[v6]`) est traité comme une adresse si `dst_ip` est absent ;
   les adresses IPv4 mappées en IPv6 sont ramenées à IPv4.
3. **Chemins.** Requête et fragment retirés, décodage percent unique, `\` traité comme `/`, segments vides et `.`
   supprimés, `..` résolu sans remonter au-dessus de la racine. Préfixe **par segment** : `/v1` couvre `/v1` et
   `/v1/x`, pas `/v1x`. Les chemins sont sensibles à la casse ; les méthodes non.
4. **Compilation stricte** (toute erreur = « pas de politique valide » côté passerelle) : empreinte, identifiants en
   double, références inconnues ou de mauvais type, cycle de groupes, motif de domaine invalide, plage d'adresses
   inversée ou de familles mixtes, plage de ports inversée, méthode/chemin sur un service non HTTP, règle de zone dont
   la source n'est pas exactement sa zone, agent dans une zone inconnue, **même adresse pour deux agents**.
5. **Métadonnées cloud.** En plus des objets de catégorie `cloud_metadata`, `169.254.169.254`, `fd00:ec2::254`,
   `metadata.google.internal` et `metadata.goog` sont toujours considérés comme métadonnées. Une telle destination
   (ou une destination incertaine) n'est **jamais** acceptée implicitement : ni par le mode observation, ni par
   l'acceptation implicite « interne surveillé » (`fd00:ec2::254` est dans `fc00::/7`). Seule une règle Accept
   explicite peut l'autoriser.
6. **Interne.** Est interne une adresse de `internal_networks`, l'adresse d'un agent, ou une destination d'un objet de
   catégorie `internal`.
7. **Catégories et groupes.** La catégorie d'un groupe s'applique à tous ses membres résolus.
8. **Expiration** évaluée avec `FlowContext::now` (une règle peut expirer pendant que la politique est active).
9. **Trace d'évaluation** : `evaluate` renvoie toujours la liste des règles examinées (identifiant, numéro, couche,
   motif), sans nom pour limiter les allocations ; une seule allocation dimensionnée à l'avance.
10. **Écarts avec les contrats d'`afw-core`** (non modifiés) : `afw_core::api::VerifyFinding` n'a que `Shadowed`,
    `UnusedObject` et `Expired`. Les services et classes de données inutilisés sont rapportés en `UnusedObject` ;
    « zone sans agent » et « pas de règle de socle métadonnées cloud » sont exposés par `verify_warnings`
    (`VerifyWarning`, propre au moteur). `Decision` porte en plus `revision` pour remplir `DecisionRef::revision`.
11. **Masquage (EF-11)** conservateur : une règle n'est signalée masquée que si une règle active plus haute de la même
    couche, sans classe de données, couvre prouvablement sa source, sa destination (feuilles résolues) et son service.

## Compléments après revue (PR #10)
12. **Contrat passerelle — `FlowContext::dst_ip_trusted`.** `true` quand `dst_ip` est l'adresse que la passerelle a
    elle-même résolue pour `host` (ou qu'il n'y a pas de nom) et vers laquelle elle se connecte réellement ; `false`
    quand c'est l'adresse d'origine choisie par l'agent alors qu'un nom est présent. Avec un nom et une adresse non
    fiable : aucune acceptation par objet IP/réseau/plage, pas d'acceptation implicite « interne surveillé », pas de
    contournement d'inspection ni d'exemption LLM fondés sur l'adresse. Les règles Deny par adresse s'appliquent
    toujours. **La passerelle résout le nom, se connecte à cette adresse et passe `dst_ip_trusted = true`.**
13. **Chemins** : les paramètres `;…` de chaque segment sont retirés avant la résolution de `..` (`/x/..;/admin` →
    `/admin`) ; un `%` restant après le décodage (double encodage) rend le chemin incertain.
14. **Hôtes « presque IP »** : formes numériques (`2852039166`, `0xa9fea9fe`, `0251.0376.0251.0376`, `169.254.43518`)
    et tout hôte contenant `[`, `]`, `:` ou `%` (port, identifiant de zone IPv6) sont incertains pour tout ensemble
    (noms comme adresses) : Deny possible, Accept impossible.
15. **Adresses canoniques** : IPv4 mappée, NAT64 `64:ff9b::/96` et IPv4 compatible (`::a.b.c.d`) ramenées à IPv4 ;
    les objets réseau et `internal_networks` IPv4 mappés en IPv6 sont normalisés de même.
16. **Métadonnées** : liste intégrée étendue à tout `169.254.0.0/16` (lien local sensible : `169.254.170.2`,
    `169.254.169.253`…), `100.100.100.200` et `fd00:ec2::254`. Une destination de métadonnées n'est acceptée que par
    une règle dont la destination contient explicitement cette adresse (adresse fiable) ou un objet `cloud_metadata`,
    jamais par un domaine ni par « any » (`TraceOutcome::MetadataProtected`).
17. **`Decision::needs_l7`** : au stade connexion (ni méthode ni chemin), si une règle plus haute que la règle
    décisive dépend de la méthode ou du chemin, `needs_l7 = true` ; la passerelle doit alors inspecter (MITM HTTPS) et
    réévaluer chaque requête. Si l'une de ces règles est un Accept et que la décision est un refus, le verdict devient
    un `Allow` **provisoire** destiné uniquement à permettre l'évaluation par requête. Si la requête ne pourra jamais
    être vue (HTTPS non inspecté ou protocole non HTTP), les conditions de méthode/chemin sont incertaines : un Deny
    par chemin s'applique à toute la connexion, un Accept par chemin jamais.
18. Un groupe vide ne produit pas de faux masquage.
19. **`Decision::content_rules_apply`** (ajout, revue de la PR #15) : au stade connexion sans contenu analysé, vrai si
    une règle Deny à classes de données, plus haute que la règle décisive, correspondrait à ce flux si l'une de ses
    classes était détectée. Un flux dont le contenu ne sera jamais analysé (TCP brut) doit alors être refusé par la
    passerelle (ADR 0017), sauf destination interne ou `Decision::explicit_non_http` (la règle décisive est un Accept dont
    tous les services sont non HTTP : SSH/Other, ou protocole et ports explicites sans 80/443/8080/8443).

## Limites
- Chemins sensibles à la casse : `/ADMIN` ne correspond pas à un préfixe `/admin` (un serveur insensible à la casse
  peut donc contourner un Deny par chemin ; écrire les variantes ou refuser plus largement).
- Un `%25` légitime dans un chemin rend la requête incertaine : une règle Accept par chemin ne s'y applique pas.

## Conséquences
- Un encodage, une casse ou un point final ne permettent pas d'échapper à une règle Deny ni d'élargir une règle Accept.
- La passerelle doit fournir des hôtes en ASCII/punycode et évaluer chaque requête HTTP(S) inspectée.
- Performance mesurée (release, 2 000 règles, 10 000 objets, aucune correspondance) : p50 ≈ 5 µs, p99 ≈ 8 à 90 µs selon la charge du poste partagé.
