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

## Conséquences
- Un encodage, une casse ou un point final ne permettent pas d'échapper à une règle Deny ni d'élargir une règle Accept.
- La passerelle doit fournir des hôtes en ASCII/punycode et évaluer chaque requête HTTP(S) inspectée.
- Performance mesurée (release, 2 000 règles, 10 000 objets, aucune correspondance) : p50 ≈ 5 µs, p99 ≈ 8 µs.
