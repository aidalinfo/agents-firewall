# agents-firewall — document de conception

- **Date** : 30 octobre 2026
- **Auteur** : Killian Stein, rédigé avec Claude
- **Statut** : à valider
- **Nom** : `agents-firewall` est provisoire. « Leash » est écarté (déjà pris par StrongDM, même domaine). Le nom définitif sera choisi à part.

Convention : chaque décision est marquée **[Killian]** quand elle vient de lui, **[proposition]** quand c'est un choix de conception fait pendant la rédaction et non encore validé. Le reste est laissé au constructeur (section 14).

---

## 1. Intention

Les agents IA (bots Hermes comme Daniel, Laurent, Vulcain, et demain d'autres) ont des outils qui sortent sur le réseau : terminal, fetch, mail, MCP, scripts qu'ils écrivent eux-mêmes. Une injection de prompt suffit à leur faire exfiltrer une donnée. Il faut un **pare-feu d'agents** :

- **impossible à contourner depuis l'agent** : le contrôle se fait sur le réseau réel, pas sur ce que l'agent déclare ;
- **géré comme un vrai firewall d'entreprise**, façon Check Point : console centrale, base de règles, objets, zones, publication et installation de politique, révisions, journaux détaillés ;
- **avec le maximum de visibilité** sur ce qui sort : chaque flux, chaque requête, rattachés à l'agent et à l'action qui les a déclenchés ;
- **pilotable par une UI simple, une CLI et un MCP**, pour qu'un agent d'administration agréé puisse aussi le gérer ;
- **open source** **[Killian]**, licence Apache 2.0 **[Killian]**, générique (rien de propre à Pulse myIT dans le cœur).

### Pourquoi maintenant

Daniel dispose déjà d'un garde-fou, l'**egress-guard** écrit par l'équipe (section 2). Il prouve l'intérêt d'une décision déterministe hors du LLM, mais il est contournable, local à un seul bot, sans trace des flux réels. L'état de l'art open source (section 13) a les briques (proxys d'agent, détection) mais pas la console centrale de flotte avec un modèle de politique de firewall d'entreprise.

---

## 2. Existant : egress-guard de Daniel

Observé en octobre 2026 sur l'hôte des bots Hermes internes.

- Hook Hermes `pre_tool_call` (`data/config.yaml`) qui appelle `data/workspace/tools/egress-guard/hook_entry.py` pour une liste d'outils (terminal, fetch, mail, Teams, GLPI, Coolify, Freepik).
- Politique YAML `data/pulse-mcp-guardrails.yaml` (« v2 egress-first ») : expéditeurs autorisés, classes de données par regex (secrets, inventaire infra, commercial), destinations (allow/deny, refus par défaut), matrice classe de donnée × tier de destination → allow / log / gate / deny, classes d'actions (irréversible, accès, infra destructive, génération payante).
- Journal JSONL `data/logs/egress-guard.log` (log/gate/deny seulement, entrée tronquée à 200 caractères).

**Limites** : aucune couche réseau (nftables vide, DOCKER-USER sans règle, pas de proxy) ; inspection textuelle des arguments, donc une URL dans une variable, un script ou un MCP qui fait ses propres appels passe ; pas de trace des flux réels ; « gate » = blocage + message à l'agent, pas de vraie validation ; faux positifs quotidiens (uploads S3 présignés) ; seul Daniel est couvert.

**À conserver** : décision hors LLM, raisonnement par classe de donnée et de destination, matrice de risque, classes d'actions, tests.

---

## 3. Objectifs, non-objectifs, anti-objectifs

### Objectifs (tous dans la V1 [Killian])

1. Tout trafic sortant d'un agent enrôlé passe par une passerelle qui applique la politique ; l'agent n'a aucune autre route.
2. Politique centrale façon Check Point : objets, zones, base de règles ordonnée, sessions, publication, installation, révisions, compteurs.
3. Visibilité maximale **[Killian]** : métadonnées de flux, DNS, requêtes et réponses HTTP complètes (déchiffrement TLS), captures à la demande.
4. Corrélation entre l'action de l'agent (appel d'outil, conversation) et les flux réels.
5. UI Nuxt centralisée, CLI, serveur MCP d'administration, tous adossés à la même API.
6. Enrôlement et désenrôlement d'un bot en une commande.
7. Audit complet et infalsifiable de chaque modification **[Killian]**.
8. Intégration Hermes facile **[Killian]**, et Daniel migré depuis l'egress-guard actuel.
9. Multi-hôtes : une console, plusieurs hôtes d'agents.

### Non-objectifs

- Filtrer les entrées (ingress) vers les agents : c'est le rôle de Traefik/CrowdSec existants.
- Remplacer la sandbox fichiers/processus d'un agent (à la Leash) : ici, le réseau et les actions sortantes.
- Juger le contenu par un LLM : toutes les décisions sont déterministes.
- Exceptions de règle par agent **[Killian]** : uniquement socle commun + zones.

### Anti-objectifs (ce qui ferait échouer le projet même s'il fonctionne) [Killian]

- Une UI pénible : comprendre un refus et ouvrir le flux doit se faire en quelques clics depuis le journal.
- Un déploiement ou une gestion des bots difficile.
- Un produit pilotable seulement par l'UI : tout doit être faisable en CLI et en MCP.

Ajout **[proposition]** : ralentir sensiblement les agents (surcoût de latence visible) ou casser leurs usages légitimes sans message compréhensible.

---

## 4. Architecture

```
            ┌──────────────── Console (plan de contrôle) ────────────────┐
            │  API Rust (REST + OpenAPI)   UI Nuxt 4 / Nuxt UI           │
            │  PostgreSQL (config, audit)  Stockage journaux (volume)    │
            │  CLI `afw`  ·  serveur MCP d'administration                │
            └───────────────▲───────────────────────────▲────────────────┘
                 politique  │ installée                 │ événements, journaux
                            │                           │
   ┌──────── Hôte d'agents (ex. hôte des bots Hermes) ──┴──────────────────┐
   │  Passerelle Rust (1 par hôte)                                         │
   │   proxy HTTP(S) + inspection TLS · DNS filtrant · filtrage L4         │
   │   application des règles · capture · masquage · envoi groupé          │
   │        ▲ seule route sortante (réseau interne + nftables)             │
   │  ┌─────┴──────┐ ┌────────────┐ ┌────────────┐                         │
   │  │ daniel-bot │ │ laurent-bot│ │ vulcain-bot│  + plugin Hermes        │
   │  └────────────┘ └────────────┘ └────────────┘    (intention)          │
   └───────────────────────────────────────────────────────────────────────┘
```

### 4.1 Composants

| Composant | Techno | Rôle |
|---|---|---|
| Passerelle | Rust **[Killian]** | Plan de données, une instance par hôte d'agents. Applique la politique installée, produit les journaux. Doit continuer à appliquer la dernière politique installée si la console est injoignable. |
| API du plan de contrôle | Rust **[proposition, validée par délégation de Killian]** | Objets, zones, règles, sessions, révisions, installation, agents, journaux, audit, RBAC. Décrite en OpenAPI. |
| UI | Nuxt 4 + Nuxt UI **[Killian]** | Interface seule, sans logique métier. Client TypeScript généré depuis l'OpenAPI. |
| CLI `afw` | Rust **[proposition]** | Même périmètre que l'UI. Sert aussi à l'enrôlement. |
| Serveur MCP | Rust **[proposition]** | Même périmètre que l'API, exposé à **un seul agent agréé** (section 8). |
| Plugin Hermes | Python | Étage « intention » : signale les appels d'outil à la passerelle pour la corrélation ; reprend l'egress-guard (matrice, gate) avec une politique servie par la console. |
| Stockage config/audit | PostgreSQL **[proposition]** | |
| Stockage journaux | **[proposition]** ClickHouse pour les événements, stockage objet (S3 compatible) pour les corps de requêtes et captures | Volume élevé du fait du détail maximal. |

### 4.2 Principe « API d'abord » [Killian, déduit des anti-objectifs]

Toute action possible dans l'UI l'est par l'API, donc par la CLI et le MCP. Aucune fonction n'existe uniquement dans l'UI.

---

## 5. Modèle de politique (inspiré de Check Point)

### 5.1 Objets

Réutilisables, nommés, commentés, avec la fonction « où est-il utilisé ? » :

- **Hôtes et domaines** : nom de domaine exact, joker (`*.pulsemyit.fr`), IP, réseau CIDR, plage.
- **Groupes d'objets** (ex. « M365 » = graph.microsoft.com + login.microsoftonline.com).
- **Services** : HTTPS, HTTP, DNS, SSH, TCP/UDP port quelconque, et pour HTTP(S) des critères optionnels de méthode et de chemin d'URL.
- **Agents** : chaque agent enrôlé est un objet, rattaché à une zone.
- **Classes de données** : motifs de détection (secrets, inventaire infra, commercial…), repris de l'egress-guard et de Pipelock.

### 5.2 Zones [Killian : « comme des VLAN »]

Groupes d'agents ayant les mêmes autorisations. Un agent appartient à **une seule** zone. Exemples : « bots internes Pulse », « bots clients », « ops ». Les zones règlent aussi les flux **entre** agents et vers les réseaux internes (LAN, autres VM), pas seulement vers Internet **[proposition]**.

### 5.3 Base de règles

Structure en deux couches **[Killian : « règle de base » puis zones]** :

1. **Socle commun**, évalué en premier pour tous les agents, non contournable par les règles de zone : interdiction des métadonnées cloud (169.254.169.254, metadata.google.internal…), deny-list globale, règles sur les classes de données (un secret ne sort jamais).
2. **Règles de zone**, ordonnées, évaluées de haut en bas, **première règle qui correspond appliquée**, et une **règle de nettoyage** finale « tout refuser » toujours présente.

Pas d'exceptions par agent **[Killian]**.

Chaque règle comporte : numéro, nom, source (zone ; voir 15), destination (objets), service, **action** (accepter, refuser), **inspection HTTPS** (oui/non, voir 5.5), **niveau de trace** (aucun, journal, journal détaillé avec contenu, capture), **date d'expiration** optionnelle, commentaire, et un **compteur d'utilisations** avec date de dernière utilisation.

Les règles peuvent être regroupées en **sections** nommées pour la lisibilité.

### 5.4 Contenu et classes de données

Au-delà de la destination, les requêtes inspectées sont analysées par les classes de données. Une règle peut refuser selon la classe détectée dans le contenu sortant (ex. « secret vers n'importe où : refuser »). La matrice classe × destination de l'egress-guard est reproduite par des règles du socle et des zones **[proposition]**.

### 5.5 Politique d'inspection HTTPS

Politique à part entière, comme chez Check Point : quelles zones et quelles destinations sont déchiffrées. Par défaut, tout est déchiffré **[Killian : détail maximal]**. Les destinations qui refusent un certificat qui n'est pas le leur (épinglage de certificat) sont placées en contournement explicite et ne fournissent que les métadonnées.

### 5.6 Sessions, publication, installation, révisions

- Un administrateur (humain ou agent agréé) travaille dans une **session** : ses modifications ne sont visibles et applicables qu'à la publication. Les objets en cours de modification sont verrouillés pour les autres sessions.
- **Publier** crée une **révision** numérotée, avec auteur, date, commentaire et différence lisible.
- **Installer** pousse une révision publiée sur une ou plusieurs passerelles. Le résultat de l'installation est tracé par passerelle (succès, échec, version active).
- **Retour arrière** : installer une révision antérieure.
- **Vérification avant installation** **[proposition]** : règles masquées par une règle plus haute, objets inutilisés, règles expirées.

---

## 6. Comportement d'application

- **Refus immédiat** de tout ce qui n'est pas autorisé **[Killian : « comme l'actuel »]**. Pas de mise en attente côté réseau.
- Pour HTTP(S), la passerelle renvoie une réponse d'erreur explicite et lisible par l'agent, du type `403` avec un corps « bloqué par agents-firewall : <destination> non autorisée pour <agent> (règle <n>) ». Pour le reste (TCP, DNS), la connexion est refusée et le refus journalisé.
- Dans l'UI, chaque refus du journal propose **« Autoriser »** **[proposition]** : ouvre une session avec une règle préremplie (source = zone de l'agent, destination = objet existant ou nouvel objet), à relire, publier et installer.
- Le **« gate »** de l'egress-guard (validation humaine d'une action irréversible : suppression, déploiement, génération payante) reste dans l'**étage intention** (plugin Hermes) et n'existe pas au niveau réseau.

### 6.1 Isolement réseau des agents

Un agent enrôlé n'a **aucune route** vers l'extérieur sauf la passerelle. Le mécanisme exact (réseau Docker `internal` avec la passerelle comme seule sortie, nftables, redirection transparente) est laissé au constructeur, avec deux exigences :

- le trafic HTTP(S) d'un agent qui ignore les variables de proxy doit quand même être intercepté (interception transparente) ;
- le trafic non HTTP (SSH, TCP brut, DNS) est filtré au niveau L4 par la même politique.

---

## 7. Visibilité (« trames ») [Killian : maximum de détail]

### 7.1 Ce qui est capturé

| Niveau | Contenu | Par défaut |
|---|---|---|
| Flux | Agent, zone, hôte, IP/port source et destination, domaine (SNI), protocole, octets émis/reçus, durée, règle appliquée, verdict | Toujours |
| DNS | Requêtes et réponses, verdict | Toujours |
| HTTP | Méthode, URL complète, en-têtes, corps de requête et de réponse | Activé par le niveau de trace de la règle ; défaut « journal détaillé avec contenu » [Killian] |
| Capture | pcap rejouable | À la demande, par agent et pour une durée limitée |

Taille maximale de corps stockée configurable ; au-delà, troncature signalée et empreinte du contenu complet **[proposition]**.

### 7.2 Protection des données capturées [proposition]

Le détail maximal implique que les journaux contiennent secrets et données clients :

- **Masquage des secrets avant stockage** : les valeurs détectées par les classes « secrets » sont remplacées par leur type et une empreinte (permet de savoir qu'un même secret est sorti plusieurs fois sans le stocker).
- Chiffrement au repos des corps et captures.
- Durée de conservation configurable par niveau (flux, HTTP, capture).
- Accès aux contenus restreint par rôle (section 8) et lui-même audité.

### 7.3 Corrélation intention ↔ flux

Le plugin Hermes envoie à la passerelle les événements d'appel d'outil (agent, conversation, outil, arguments résumés, début, fin, identifiant). La passerelle rattache les flux à l'appel d'outil en cours pour cet agent. Méthode exacte (fenêtre temporelle, identifiant de processus via eBPF, en-tête injecté) laissée au constructeur ; l'UI doit indiquer quand une attribution est incertaine.

Vue cible : « Daniel · conversation X · `terminal: python envoi.py` → 3 connexions vers api.exemple.com, 4,1 Mo envoyés, refusées par la règle 12 ».

### 7.4 Vues de l'UI (façon SmartLog) [proposition]

- **Journal en direct** filtrable (agent, zone, destination, verdict, règle, période), recherche plein texte.
- **Détail d'un flux** : métadonnées, requête/réponse, appel d'outil associé, lien vers la règle.
- **Vue agent** : ses destinations habituelles, volumes, refus récents.
- **Base de règles** avec compteurs, sections, objets, « où est-il utilisé ? ».
- **Révisions** et différences.
- **Audit** des modifications.
- **Alertes** : nouvelle destination jamais vue pour un agent, pic de volume sortant, rafale de refus, tentative vers les métadonnées cloud, secret détecté. Envoi vers des canaux configurables (webhook générique ; Pulse Chat et Teams comme intégrations optionnelles).

---

## 8. Administration, droits et audit

- **Humains** : connexion OIDC générique (le Hub 360 Pulse n'est qu'un fournisseur parmi d'autres). Rôles **[proposition]** : administrateur, auditeur (lecture de tout, y compris contenus), lecteur (lecture sans contenus).
- **Un seul agent agréé** a accès au MCP d'administration **[Killian]**. Ses droits sont limités aux zones qui lui sont déléguées, et il ne peut jamais modifier une zone ou une règle qui s'applique à lui-même **[proposition, approuvée dans l'échange]**.
- **Audit de chaque modification** **[Killian]** : qui (humain, CLI ou agent, avec identité), quoi (différence), quand, depuis quelle interface, dans quelle session. Journal en ajout seul, chaîné par empreinte pour être infalsifiable (comme Pipelock) **[proposition]**.
- **[proposition]** Les modifications de l'agent agréé qui élargissent fortement l'accès (joker sur Internet, « toute destination », autorisation d'une classe « secrets ») exigent la validation d'un humain avant publication.

---

## 9. Enrôlement et intégration Hermes

Trois niveaux, cumulables :

1. **Réseau, sans toucher à l'agent** : `afw enroll <conteneur>` produit et applique la modification du `docker-compose.yml` (réseau interne, variables de proxy, montage du certificat d'autorité dans le magasin de certificats du conteneur), crée l'objet agent et le place dans une zone. `afw unenroll` défait tout proprement.
2. **Plugin Hermes** : installé dans le même mécanisme que les plugins existants (`pulse-chat`, `teams-platform`). Fournit la corrélation (7.3).
3. **Étage intention** : l'egress-guard existant devient une partie du plugin, avec sa matrice de risque et son « gate », mais sa politique est servie par la console au lieu du YAML local.

Standard pour un bot Hermes : niveaux 1 + 2 posés ensemble par une seule commande **[proposition]**. Un agent qui n'est pas sous Hermes a au minimum le niveau 1.

Le certificat d'autorité d'inspection est **propre à chaque passerelle** **[proposition]** ; sa clé privée ne quitte pas l'hôte.

---

## 10. Déploiement

- **Console** : `docker compose` (API, UI, PostgreSQL, stockage des journaux). **[proposition]** Chart Helm pour Kubernetes.
- **Passerelle** : conteneur par hôte d'agents, installée et enregistrée auprès de la console par la CLI (jeton d'enregistrement à usage unique). Communication passerelle ↔ console chiffrée et authentifiée mutuellement.
- **Premier déploiement** : console sur l'infrastructure interne (emplacement à choisir), passerelle sur l'hôte des bots Hermes, bots internes enrôlés.

---

## 11. Migration de Daniel

- Importer `pulse-mcp-guardrails.yaml` : allow/deny hosts → objets et règles de la zone de Daniel et du socle ; classes de sensibilité → classes de données ; matrice et classes d'actions → plugin intention.
- **[proposition]** Démarrer chaque bot en **mode observation** (tout est journalisé, la règle de nettoyage journalise au lieu de refuser) quelques jours, construire les règles à partir des flux vus, puis passer en refus par défaut. L'egress-guard actuel reste actif pendant cette période.
- Corriger au passage le faux positif S3 présigné.

---

## 12. Qualité attendue

- Surcoût de latence de la passerelle négligeable pour l'agent **[proposition : cible à mesurer et fixer lors du prototype]**.
- La passerelle n'échoue jamais en mode ouvert : si elle tombe, l'agent n'a plus de réseau.
- Tests : moteur de règles (ordre, première correspondance, socle, nettoyage, expiration), classes de données, isolement réseau (un agent ne peut pas sortir sans passerelle, y compris en ignorant le proxy), installation et retour arrière, droits de l'agent agréé.

---

## 13. Inspirations

- **Check Point** (SmartConsole, SmartLog) : objets, base de règles ordonnée, couches, sessions, publication/installation, révisions, compteurs, « où est-il utilisé ? ».
- **Pipelock** (Apache 2.0, Go) : proxy d'agent, pipeline de détection (secrets, injection, SSRF), journal chaîné et signé, inspection MCP/WebSocket. Code réutilisable avec mention dans `NOTICE`.
- **StrongDM Leash** (Apache 2.0) : agent en conteneur, observateur MCP, corrélation télémétrie réseau/MCP.
- **egress-guard interne** : matrice classe de donnée × destination, classes d'actions.
- Smokescreen (Stripe), mitmproxy, `rama`, `pingora` comme références techniques.

---

## 14. Laissé au constructeur

- Choix des bibliothèques Rust (framework de proxy, TLS, DNS, interception transparente, eBPF éventuel).
- Mécanisme exact d'isolement réseau et d'interception transparente sur un hôte Docker.
- Méthode de corrélation intention ↔ flux.
- Format de la politique installée sur les passerelles et protocole console ↔ passerelle.
- Schéma des bases, choix final du stockage des journaux.
- Découpage interne de la V1 en étapes testables.
- Organisation du dépôt (monorepo Rust + Nuxt conseillé).

## 15. Précisions issues de la relecture (30/10/2026)

- **Périmètre d'exécution** : chaque bot est un conteneur distinct ; identité réseau d'un agent = son conteneur. Tous les agents de Killian tournent en conteneur. **[Killian : « il faut tout prévoir »]** La V1 couvre tous les environnements de conteneurs : Docker avec compose manuel, conteneurs gérés par Coolify (enrôlement via l'API Coolify, sinon le redéploiement écrase la modification) et pods Kubernetes (passerelle par nœud ou par namespace, sortie imposée par NetworkPolicy).
- **Source d'une règle** : uniquement une zone. Pas d'objet agent en source (cohérent avec « pas d'exceptions »). Un bot aux besoins spécifiques reçoit sa propre zone. **[proposition]** (corrige 5.3, où « objet agent » apparaissait en source.)
- **Répartition des décisions** **[proposition]** : la passerelle porte destinations et classes de données (contenu réellement envoyé) ; le plugin d'intention porte uniquement les classes d'actions (irréversible, accès, infra destructive, génération payante) et leur « gate ». La matrice de l'egress-guard est donc entièrement portée par la passerelle ; le plugin ne la duplique pas.
- **« Gate »** : conservé tel qu'aujourd'hui en V1 (blocage + message à l'agent). Une vraie file de validation est une évolution ultérieure. **[proposition]**
- **Analyse du contenu et gros corps** **[proposition]** : la requête est mise en mémoire tampon et analysée avant envoi jusqu'à une taille configurable ; au-delà (gros uploads), et pour les flux continus (WebSocket, streaming), analyse au fil de l'eau avec coupure dès détection quand c'est possible, sinon alerte. Inspection WebSocket et MCP distants incluses en V1.
- **Périmètre V1** : tous les éléments marqués [proposition] dans ce document font partie de la V1 **[Killian : « la V1 doit tout faire »]**, sous réserve de sa relecture.
- **Audit infalsifiable** **[proposition]** : chaîne d'empreintes en base, plus export périodique des empreintes vers un stockage objet verrouillé (rétention immuable), pour résister aussi à un accès direct à la base.

- **Trafic vers les fournisseurs de LLM** **[Killian, 30/10]** : catégorie de destinations « fournisseur LLM » journalisée en détail mais exemptée du blocage par classe de données (le contexte des conversations contient forcément des secrets lus). Les secrets restent masqués dans les journaux.

- **Flux internes [Killian, 30/10]** : V1 = **surveillance uniquement** (« je veux juste qu'on surveille le flux »). Flux agent → agent, LAN, VM, bases, Kubernetes passés par la passerelle, journalisés au même niveau de détail, autorisés par défaut ; appels aux API d'administration journalisés par action ; détection de mouvement latéral ; carte des flux internes. **Écartés par Killian** : relais SSH détenant les clés, filtrage par action des API d'administration, politique imposée aux charges créées par un agent, refus des conteneurs privilégiés à l'enrôlement. La limite (un agent à privilèges peut faire sortir des données via une charge lancée ailleurs) est documentée et seulement détectée. Détail : cahier des charges, section 5.8.

## 16. Questions ouvertes (à trancher par Killian)

- **Agents à privilèges d'infrastructure** (agent d'exploitation : accès Kubernetes, SSH, Coolify) : un agent qui peut lancer un pod ou une commande ailleurs sort par un autre chemin. Est-ce dans le périmètre « impossible à contourner », et faut-il refuser à l'enrôlement les conteneurs privilégiés, avec socket Docker ou `network_mode: host` ?
- Nom définitif du projet et emplacement du dépôt public.
- Emplacement de la console pour le premier déploiement interne.
