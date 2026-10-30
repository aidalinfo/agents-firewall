# Migrer depuis l'egress-guard

Ce guide décrit le passage d'un agent Hermes protégé par l'**egress-guard** (le hook `pre_tool_call` qui inspecte les arguments des outils) à agents-firewall. Il prend l'exemple de **Daniel**, le premier bot qui en était équipé ; la démarche est la même pour les autres agents (Laurent, Vulcain…).

> **État d'avancement.** L'outil d'import et la CLI sont en cours de construction (à venir). La correspondance décrite ci-dessous est celle fixée par le plan d'implémentation.

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
| hôtes autorisés | objets destination + règles `accept` de la zone de l'agent |
| hôtes refusés | objets + règles `deny` (zone ou socle commun) |
| refus par défaut | règle de nettoyage implicite |
| classes de sensibilité (regex : secrets, inventaire infra, commercial) | classes de données |
| matrice « classe de donnée × tier de destination » | règles de contenu (règles avec classes de données), portées par la **passerelle** |
| classes d'actions (irréversible, accès, infra destructive, génération payante) et « gate » | **politique d'intention** du plugin Hermes |
| journal JSONL `data/logs/egress-guard.log` | journal de la console (flux, DNS, HTTP, appels d'outil) |

La matrice n'est **pas** dupliquée dans le plugin : la passerelle voit le contenu réellement envoyé, c'est elle qui décide sur les destinations et les données. Le plugin ne garde que les classes d'actions.

## Étapes

### 1. Préparer

- Console et passerelle installées sur l'hôte des bots ([installation.md](installation.md)).
- Une copie du fichier `data/pulse-mcp-guardrails.yaml` de Daniel.

### 2. Importer la politique dans une zone en observation

```sh
afw import egress-guard pulse-mcp-guardrails.yaml --zone daniel
```

L'import ouvre une session, crée les objets, classes de données et règles, prépare la politique d'intention, puis affiche un **rapport d'import** (ce qui a été converti, ce qui demande une relecture). Relisez la session avant de la publier. Un fichier d'exemple anonymisé sera fourni dans `examples/` (à venir).

Placez la zone `daniel` en **mode observation**, puis publiez et installez.

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
