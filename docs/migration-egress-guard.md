# Migrer depuis l'egress-guard

Ce guide décrit le passage d'un agent Hermes protégé par l'**egress-guard** (le hook `pre_tool_call` qui inspecte les arguments des outils) à agents-firewall. Il prend l'exemple de **Daniel**, le premier bot qui en était équipé ; la démarche est la même pour les autres agents (Laurent, Vulcain…).

> **État d'avancement.** La conversion (crate `afw-import`, [ADR 0026](adr/0026-import-egress-guard.md)) est disponible ; la commande `afw import egress-guard` qui l'applique dans une session est livrée avec la CLI.

## Pourquoi migrer

L'egress-guard a posé de bons principes : décision par du code déterministe, hors du modèle de langage ; raisonnement par classe de donnée et par destination ; matrice de risque ; classes d'actions. Mais :

| Limite de l'egress-guard | Réponse d'agents-firewall |
|---|---|
| Il ne lit que le texte des arguments : une URL dans une variable, un script ou un serveur MCP qui fait ses propres appels passe | contrôle sur le **réseau réel**, hors de l'agent, y compris si l'agent ignore le proxy |
| Aucune trace des flux réels (DNS, connexions, volumes) | journal complet des flux, du DNS et du HTTP, rattaché à l'appel d'outil |
| Politique locale, éditée à la main, propre à Daniel | politique centrale, sessions, révisions, audit, pour toute la flotte |
| « Gate » sans circuit | « gate » conservé dans le plugin, avec une politique servie par la console |
| Faux positif quotidien sur les envois S3 présignés | les URL présignées (`X-Amz-Signature`) ne sont plus prises pour des secrets |

## Correspondance

| egress-guard (`pulse-mcp-guardrails.yaml`) | agents-firewall |
|---|---|
| hôtes autorisés | objets destination, un groupe par tier (`egress-guard/<zone>/<tier>`), une règle `accept` par tier dans la zone de l'agent (et une par liste de ports) |
| hôtes refusés | objets + une règle `deny` du **socle commun**, limitée à la zone importée (à élargir si elle vaut pour toute la flotte) |
| refus par défaut | règle de nettoyage implicite (toujours active, quelle que soit la valeur de `default`) |
| classes de sensibilité (regex : secrets, inventaire infra, commercial) | classes de données ; la classe des secrets reçoit les détecteurs intégrés, les motifs qui attrapaient les URL présignées sont retirés |
| matrice « classe de donnée × tier de destination » | règles de contenu de la zone, portées par la **passerelle** : `deny` et `gate` → refus, `log` → acceptation journalisée par une règle dédiée, `allow` → rien |
| classes d'actions (irréversible, accès, infra destructive, génération payante) et « gate » | **politique d'intention** du plugin Hermes |
| expéditeurs autorisés | non converti (pas d'équivalent réseau), signalé dans le rapport |
| journal JSONL `data/logs/egress-guard.log` | journal de la console (flux, DNS, HTTP, appels d'outil) |

La matrice n'est **pas** dupliquée dans le plugin : la passerelle voit le contenu réellement envoyé, c'est elle qui décide sur les destinations et les données. Le plugin ne garde que les classes d'actions. Comme la passerelle n'a pas de file de validation en V1, un « gate » de la matrice devient un refus (le rapport le signale) ; les fournisseurs de LLM restent exemptés du blocage par classe de données.

Le format accepté est décrit et illustré par le fichier d'exemple anonymisé [`examples/egress-guard/guardrails.example.yaml`](../examples/egress-guard/guardrails.example.yaml). Tout champ inconnu est signalé dans le rapport, jamais ignoré en silence.

## Étapes

### 1. Préparer

- Console et passerelle installées sur l'hôte des bots ([installation.md](installation.md)).
- Une copie du fichier `data/pulse-mcp-guardrails.yaml` de Daniel.

### 2. Importer la politique dans une zone en observation

```sh
afw import egress-guard pulse-mcp-guardrails.yaml --zone daniel
```

L'import ouvre une session, crée les objets, classes de données et règles, prépare la politique d'intention, puis affiche un **rapport d'import** en trois parties : converti, avertissements (à relire : approximations, jokers, motifs retirés, champs inconnus) et non converti. Relisez la session avant de la publier. Un second import du même fichier ne crée rien de plus (objets, classes et règles existants sont réutilisés).

La zone `daniel` est créée en **mode observation** par défaut ; une zone existante garde son mode (l'import ne la fait jamais repasser en observation sans demande explicite). Si le rapport contient une section **Bloquant** (un refus de l'egress-guard que l'import n'a pas pu traduire), corrigez avant de publier. Publiez et installez.

La politique d'intention (classes d'actions) est appliquée séparément : elle **remplace** toute la politique d'intention servie aux plugins.

> Pourquoi une zone dédiée ? Il n'y a pas d'exception par agent : un bot aux besoins particuliers reçoit sa propre zone. Si plusieurs bots ont les mêmes besoins, ils peuvent la partager.

### 3. Enrôler Daniel (réseau + plugin)

```sh
afw enroll daniel-bot      # zone daniel ; options exactes : afw enroll --help
```

Une seule commande pose l'enrôlement réseau et le plugin Hermes ([enrolement.md](enrolement.md#agents-hermes)). **L'egress-guard reste actif** pendant cette période : les deux protections se cumulent.

### 4. Observer quelques jours

En observation, rien n'est bloqué (sauf les métadonnées cloud) mais tout ce qui **aurait été refusé** apparaît dans le journal, marqué `observed`. Chaque jour :

- passez en revue les flux observés de Daniel ;
- pour chaque usage légitime, utilisez **« Autoriser »** et publiez ;
- vérifiez que les envois de PDF vers le stockage S3 ne déclenchent plus de faux positif ;
- surveillez les alertes (nouvelle destination, secret détecté).

### 5. Basculer en application

Quand plus aucun flux légitime n'apparaît comme `observed` :

1. passez la zone `daniel` en mode `enforce` ;
2. publiez, vérifiez, installez ;
3. surveillez le journal de près les premiers jours ; un refus légitime se corrige en moins de deux minutes depuis le journal ([exploitation.md](exploitation.md#corriger-un-refus-légitime-bouton-autoriser)).

### 6. Retirer l'egress-guard

Une fois la zone stable en application :

1. retirez l'appel au hook `pre_tool_call` vers `data/workspace/tools/egress-guard/hook_entry.py` dans `data/config.yaml` ;
2. archivez `data/pulse-mcp-guardrails.yaml` et le journal `data/logs/egress-guard.log` ;
3. redémarrez le bot et vérifiez dans la console que ses appels d'outil et ses flux remontent toujours.

### 7. Recommencer pour les autres bots

Même démarche pour Laurent, Vulcain et les suivants : zone existante si les besoins sont identiques, sinon zone dédiée ; observation, puis application.

## Retour arrière

À tout moment pendant la migration :

- remettre la zone en observation (publier, installer) rétablit le fonctionnement sans blocage ;
- installer une révision antérieure annule une modification de règles ;
- tant que l'étape 6 n'est pas faite, l'egress-guard continue de protéger l'agent.
