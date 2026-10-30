# Cahier des charges — Pare-feu d'agents IA

| | |
|---|---|
| **Projet** | Pare-feu d'agents IA (nom provisoire : *agents-firewall*) |
| **Version** | 0.1 — 30 octobre 2026 |
| **Rédaction** | Killian Stein, avec l'assistance de Claude |
| **Statut** | Projet de cahier des charges, à relire et valider |
| **Licence visée** | Open source, Apache 2.0 |

## 1. Contexte

Pulse myIT exploite plusieurs agents IA permanents (bots Hermes : Daniel, Laurent, Vulcain…) qui travaillent pour les équipes : comptes rendus de réunion, mails, tickets GLPI, documents, opérations d'infrastructure. Pour cela, ils disposent d'outils qui **sortent sur le réseau** : terminal, requêtes web, envoi de mails, messages Teams, serveurs MCP, et scripts qu'ils écrivent eux-mêmes.

Un agent IA obéit au texte qu'il lit. Un mail, une page web ou un document piégé peut lui faire envoyer des données vers l'extérieur (injection de prompt). La combinaison « accès à des données privées + exposition à du contenu non fiable + capacité à communiquer vers l'extérieur » est connue sous le nom de *lethal trifecta* : quand les trois sont réunies, une fuite n'est qu'une question de temps. Le moyen le plus fiable de casser cette combinaison est de **contrôler la sortie** (l'egress).

Ce n'est pas théorique : la diffusion d'informations internes par un agent a déjà été constatée en production.

## 2. Pourquoi ce projet

### 2.1 L'existant : l'egress-guard de Daniel

L'équipe a mis en place pour l'un des bots un **pare-feu applicatif d'agent** (« egress-guard ») :

- un hook exécuté **avant chaque appel d'outil sensible**, qui décide *autoriser / journaliser / demander validation / refuser* ;
- une politique YAML claire : destinations autorisées (refus par défaut), classes de données sensibles détectées par motifs (secrets, inventaire infra, informations commerciales), matrice « type de donnée × niveau de confiance de la destination », classes d'actions (suppression, déploiement, génération payante…) ;
- un journal des décisions.

Ses principes sont bons et seront conservés : **la décision est prise par du code déterministe, hors du LLM**, et raisonne par type de donnée et de destination plutôt que par « qui demande ».

### 2.2 Ses limites

| Limite | Constat (octobre 2026) | Conséquence |
|---|---|---|
| Aucune couche réseau | Pas de règles de pare-feu sur l'hôte, pas de proxy : les conteneurs sortent librement | Le hook est la seule barrière |
| Inspection du texte de la commande | Une URL placée dans une variable, dans un script, ou un serveur MCP qui fait ses propres appels n'est pas vue | Contournable en une ligne par une injection un peu habile |
| Aucune trace des flux réels | Pas de journal DNS, des connexions ni des volumes ; les autorisations ne sont pas tracées | Impossible de répondre à « qu'est-ce qui est vraiment sorti ? » |
| Validation sans circuit | « Demander validation » bloque l'action et demande à l'agent d'aller voir un humain | Friction, pas de traçabilité de l'accord |
| Faux positifs | Envois de PDF vers le stockage S3 bloqués presque quotidiennement | Travail bloqué |
| Local et manuel | Politique propre à Daniel, éditée à la main ; les autres bots ne sont pas couverts | Pas de vue d'ensemble, dérive entre agents |

### 2.3 Ce qui existe ailleurs

Des briques open source existent (StrongDM *Leash*, *Pipelock*, proxys d'egress pour agents), mais elles visent surtout **un développeur et son agent de code sur son poste**. Aucune solution identifiée n'offre une **console centrale pour une flotte d'agents permanents sur plusieurs serveurs**, avec un **modèle de politique de pare-feu d'entreprise** (objets, zones, base de règles, publication et installation de politique) et un **pilotage par des agents via MCP**. C'est l'espace visé, en open source.

## 3. Objectifs

1. **Rendre la sortie des agents incontournable** : tout trafic d'un agent enrôlé passe par une passerelle qui applique la politique ; l'agent n'a aucune autre route.
2. **Gérer comme un pare-feu d'entreprise**, sur le modèle de Check Point : console centrale, objets, zones, base de règles ordonnée, sessions, publication, installation, révisions.
3. **Tout voir** : chaque flux, chaque requête DNS, chaque requête HTTP avec son contenu, rattachés à l'agent et à l'action qui les a déclenchés.
4. **Être simple à exploiter** : interface claire, enrôlement d'un bot en une commande, pilotage complet en ligne de commande et par MCP.
5. **Être réutilisable par d'autres** : produit open source, générique, sans dépendance à l'environnement Pulse myIT.

### Ce qui ferait échouer le projet, même s'il fonctionne

- une interface pénible : comprendre un refus et ouvrir le flux doit se faire en quelques clics ;
- un déploiement ou une gestion des bots difficile ;
- un produit pilotable uniquement par l'interface ;
- des agents sensiblement ralentis, ou bloqués sans message compréhensible.

## 4. Périmètre

### 4.1 Inclus dans la V1

La V1 couvre **l'ensemble des fonctions décrites dans ce document** (pas de version minimale) : tous les bots, la console, la passerelle, l'interface, la CLI, le MCP, l'intégration Hermes et la migration de Daniel.

### 4.2 Exclu

- Le filtrage des flux **entrants** vers les agents (déjà assuré par Traefik et CrowdSec).
- Le confinement des fichiers et processus à l'intérieur de l'agent.
- Toute décision prise par un LLM : les décisions sont déterministes.
- Les exceptions de règles propres à un agent : uniquement un socle commun et des zones.

## 5. Exigences fonctionnelles

### 5.1 Politique de filtrage

| Réf. | Exigence |
|---|---|
| EF-01 | Objets nommés et réutilisables : domaines (exacts ou avec joker), IP, réseaux, plages, groupes d'objets, services (HTTPS, HTTP, DNS, SSH, ports TCP/UDP, méthode et chemin HTTP), agents, classes de données. |
| EF-02 | Fonction « où cet objet est-il utilisé ? ». |
| EF-03 | **Zones** (à la manière de VLAN) : chaque agent appartient à une seule zone ; une zone regroupe des agents aux autorisations identiques. |
| EF-04 | **Socle commun** évalué en premier pour tous les agents et non contournable : interdiction des services de métadonnées cloud, liste de refus globale, interdiction de sortie des secrets. |
| EF-05 | **Base de règles par zone**, ordonnée, évaluée de haut en bas, première règle correspondante appliquée, règle finale « tout refuser » obligatoire. |
| EF-06 | Chaque règle : numéro, nom, source (zone), destination, service, action, inspection HTTPS, niveau de trace, date d'expiration optionnelle, commentaire, compteur d'utilisations et date de dernière utilisation. Regroupement en sections. |
| EF-07 | Les règles s'appliquent aussi aux flux **entre agents** et vers les **réseaux internes**, pas seulement vers Internet. |
| EF-08 | Refus selon le **contenu** : une règle peut refuser une requête selon la classe de donnée détectée (ex. « un secret ne sort jamais »). |
| EF-09 | Politique d'**inspection HTTPS** distincte : déchiffrement par défaut, contournement explicite pour les destinations qui l'empêchent. |
| EF-10 | **Sessions** de modification avec verrouillage, **publication** en révision numérotée (auteur, date, commentaire, différences), **installation** sur une ou plusieurs passerelles avec résultat par passerelle, **retour** à une révision antérieure. |
| EF-11 | Vérification avant installation : règles masquées par une règle plus haute, objets inutilisés, règles expirées. |
| EF-12 | **Mode observation** par zone : tout est journalisé, rien n'est refusé, pour construire les règles à partir du trafic réel avant le passage en refus par défaut. |

### 5.2 Application

| Réf. | Exigence |
|---|---|
| EF-20 | Tout ce qui n'est pas autorisé est **refusé immédiatement**, sans mise en attente. |
| EF-21 | En HTTP(S), l'agent reçoit une erreur explicite indiquant la destination, l'agent et la règle (ex. « bloqué par le pare-feu d'agents : api.exemple.com non autorisé pour daniel-bot, règle 12 »). |
| EF-22 | Le trafic HTTP(S) est intercepté même si l'agent ignore la configuration de proxy ; le trafic non HTTP (SSH, TCP, DNS) est filtré par la même politique. |
| EF-23 | Si la passerelle est indisponible, l'agent n'a plus d'accès réseau (fermeture par défaut). Si la console est injoignable, la passerelle continue d'appliquer la dernière politique installée. |
| EF-24 | Contenus volumineux et flux continus (WebSocket, streaming) : analyse avant envoi jusqu'à une taille configurable, puis analyse au fil de l'eau avec coupure dès détection quand c'est possible, sinon alerte. |
| EF-25 | Catégorie de destinations **« fournisseur LLM »** (API Anthropic, OpenAI…) : trafic journalisé en détail, mais **exempté du blocage par classe de données**, puisqu'il contient par nature tout le contexte des conversations, secrets lus compris. Les secrets restent masqués dans les journaux (EF-35). |

### 5.3 Visibilité des flux (« trames »)

| Réf. | Exigence |
|---|---|
| EF-30 | Pour chaque flux : agent, zone, hôte, adresses et ports, domaine, protocole, volumes émis et reçus, durée, règle appliquée, verdict. |
| EF-31 | Journal de toutes les requêtes et réponses DNS. |
| EF-32 | Requêtes et réponses HTTP complètes (méthode, URL, en-têtes, corps), selon le niveau de trace de la règle ; **niveau de détail maximal par défaut**. |
| EF-33 | Capture réseau rejouable (pcap) à la demande, par agent et pour une durée limitée. |
| EF-34 | **Corrélation** : chaque flux est rattaché à l'appel d'outil et à la conversation de l'agent qui l'ont déclenché ; l'interface signale les rattachements incertains. |
| EF-35 | Masquage des secrets avant stockage (type + empreinte), chiffrement au repos des contenus, durées de conservation configurables par niveau. |
| EF-36 | **Alertes** : destination jamais vue pour un agent, pic de volume sortant, série de refus, tentative vers les métadonnées cloud, secret détecté. Envoi par webhook générique ; Teams et Pulse Chat en intégrations optionnelles. |

### 5.4 Interface, CLI et MCP

| Réf. | Exigence |
|---|---|
| EF-40 | **API d'abord** : toute action de l'interface est disponible dans l'API, la CLI et le MCP. |
| EF-41 | Journal en direct filtrable (agent, zone, destination, verdict, règle, période) avec recherche ; détail d'un flux avec contenu, appel d'outil associé et lien vers la règle. |
| EF-42 | Depuis un refus du journal, bouton **« Autoriser »** qui prépare la règle correspondante dans une session, à relire, publier et installer. |
| EF-43 | Vue par agent : destinations habituelles, volumes, refus récents. |
| EF-44 | Écrans base de règles, objets, zones, révisions et différences, état des passerelles, audit. |
| EF-45 | CLI `afw` couvrant tout le périmètre, y compris l'enrôlement. |
| EF-46 | Serveur MCP d'administration, accessible à **un seul agent agréé**. |

### 5.5 Droits et audit

| Réf. | Exigence |
|---|---|
| EF-50 | Authentification des humains par OIDC générique (le Hub 360 Pulse est un fournisseur parmi d'autres). Rôles : administrateur, auditeur (accès aux contenus), lecteur (sans contenus). |
| EF-51 | L'agent agréé n'agit que sur les zones qui lui sont déléguées et **ne peut jamais modifier une règle ou une zone qui s'applique à lui-même**. |
| EF-52 | Les élargissements importants demandés par l'agent agréé (joker sur Internet, toute destination, autorisation de sortie de secrets) exigent la validation d'un humain avant publication. |
| EF-53 | **Audit de chaque modification** : auteur (humain, CLI ou agent), différence, date, interface, session. Journal en ajout seul, chaîné par empreinte, empreintes exportées périodiquement vers un stockage immuable. |
| EF-54 | La consultation des contenus capturés est elle-même tracée. |

### 5.6 Enrôlement et intégration Hermes

| Réf. | Exigence |
|---|---|
| EF-60 | `afw enroll <conteneur>` : raccorde le conteneur à la passerelle (réseau, proxy, certificat d'inspection), crée l'agent et l'affecte à une zone. `afw unenroll` défait tout proprement. |
| EF-61 | **Plugin Hermes** installé comme les plugins existants : envoie les événements d'appel d'outil pour la corrélation (EF-34). Standard pour un bot Hermes : enrôlement réseau + plugin en une commande. |
| EF-62 | Le plugin reprend les **classes d'actions** de l'egress-guard (suppression, accès, infrastructure, génération payante) et leur « demande de validation », avec une politique servie par la console. Les règles de destination et de contenu sont portées par la passerelle. |
| EF-63 | Tout agent en conteneur, même hors Hermes, peut être protégé au niveau réseau. |
| EF-64 | L'enrôlement couvre **tous les environnements de conteneurs** des agents : Docker avec `docker compose` géré à la main, conteneurs gérés par **Coolify** (modification via l'API Coolify, pour ne pas être écrasée au redéploiement) et pods **Kubernetes** (passerelle par nœud ou par namespace, sortie imposée par NetworkPolicy). |

### 5.7 Migration de Daniel

| Réf. | Exigence |
|---|---|
| EF-70 | Import de la politique egress-guard actuelle (YAML) en objets, zones, règles et classes de données. |
| EF-71 | Passage de chaque bot en mode observation quelques jours, l'egress-guard restant actif, puis bascule en refus par défaut. |
| EF-72 | Correction du faux positif sur les envois S3 présignés. |

### 5.8 Surveillance des flux internes

Une injection ne cherche pas seulement à sortir vers Internet : un agent compromis peut **rebondir à l'intérieur** (autre agent, base de données, serveur SSH, API Kubernetes ou Coolify). La V1 doit **voir** ces flux internes avec le même niveau de détail que les flux vers Internet. Il s'agit de **surveillance** : par défaut, les flux internes ne sont pas bloqués (le filtrage reste possible par des règles, EF-07).

| Réf. | Exigence |
|---|---|
| EF-80 | Tous les flux internes d'un agent (vers un autre agent, le LAN, les VM, les bases de données, le cluster Kubernetes) passent par la passerelle et sont **journalisés avec le même détail** que les flux sortants. Par défaut, ils sont autorisés et surveillés. |
| EF-81 | Les appels aux **API d'administration** (Kubernetes, Coolify, Docker, Proxmox…) sont journalisés avec l'action et la ressource visée (ex. création de pod, `exec`, redéploiement). Les sessions SSH sont journalisées au niveau du flux (hôte, compte si visible, durée, volumes). |
| EF-82 | **Détection de mouvement latéral** : alerte sur balayage d'adresses ou de ports, nouvel hôte interne contacté, accès à un port sensible (base de données, administration), rafale de connexions internes, action d'administration inhabituelle. |
| EF-83 | Vue **« carte des flux internes »** : quels agents parlent à quels systèmes internes, avec les volumes et les nouveautés. |

## 6. Exigences non fonctionnelles

| Réf. | Exigence |
|---|---|
| ENF-01 | **Performance** : surcoût de latence imperceptible pour l'agent ; cible chiffrée fixée lors du prototype. Passerelle écrite en **Rust**. |
| ENF-02 | **Sûreté** : fermeture par défaut, aucun mode « tout ouvert » en cas de panne ; la clé du certificat d'inspection ne quitte pas l'hôte de la passerelle. |
| ENF-03 | **Sécurité des échanges** : communication passerelle–console chiffrée, authentification mutuelle, enregistrement d'une passerelle par jeton à usage unique. |
| ENF-04 | **Volumétrie** : stockage des journaux dimensionné pour le détail maximal sur toute la flotte. |
| ENF-05 | **Open source** : licence Apache 2.0, aucun élément propre à Pulse myIT dans le cœur (exemples de politique fournis à part), documentation d'installation et d'utilisation, mention des codes réutilisés (fichier NOTICE). |
| ENF-06 | **Déploiement** : console en `docker compose` et en chart Helm ; passerelle en conteneur par hôte d'agents. |
| ENF-07 | **Tests** : moteur de règles, classes de données, isolement réseau (un agent ne peut pas sortir sans la passerelle, même en ignorant le proxy), installation et retour arrière, droits de l'agent agréé. |

## 7. Architecture cible et choix techniques

| Composant | Technologie | Rôle |
|---|---|---|
| Passerelle (une par hôte d'agents) | Rust | Proxy HTTP(S) avec inspection TLS, DNS filtrant, filtrage des autres protocoles, application de la politique, capture et envoi des journaux |
| Plan de contrôle (API) | Rust, REST décrite en OpenAPI | Objets, zones, règles, sessions, révisions, installation, agents, journaux, audit, droits |
| Interface | Nuxt 4 + Nuxt UI | Interface uniquement, client généré depuis l'OpenAPI |
| CLI `afw` et serveur MCP | Rust | Même périmètre que l'API |
| Plugin Hermes | Python | Corrélation et classes d'actions |
| Configuration et audit | PostgreSQL | |
| Journaux et contenus | ClickHouse + stockage objet compatible S3 | Volume élevé |

Le détail des bibliothèques, du mécanisme d'isolement réseau, de la méthode de corrélation et du protocole passerelle–console est laissé à l'équipe de réalisation. Le document de conception associé (`docs/superpowers/specs/2026-10-30-agents-firewall-design.md`) en précise les contours.

## 8. Critères de réussite

- Un agent enrôlé **ne peut joindre aucune destination non autorisée**, quelle que soit la méthode employée (outil, script, variable, MCP, proxy ignoré) — vérifié par une batterie de tests de contournement.
- Pour n'importe quel flux sorti dans les dernières heures, on retrouve en moins d'une minute **quel agent, quelle conversation, quelle action, quel contenu et quelle règle**.
- Un refus légitime se corrige en **moins de deux minutes** depuis le journal.
- Un nouveau bot Hermes est protégé et visible dans la console en **une commande**.
- Daniel, Laurent et Vulcain sont migrés, l'egress-guard actuel est retiré, sans régression sur leurs usages.
- L'agent agréé peut administrer ses zones par MCP, et chacune de ses modifications apparaît dans l'audit.

## 9. Livrables

- Code source (passerelle, API, CLI, MCP, interface, plugin Hermes) dans un dépôt public sous licence Apache 2.0.
- Images de conteneur, fichiers `docker compose` et chart Helm.
- Documentation : installation, enrôlement, modèle de politique, exploitation, sécurité.
- Politique d'exemple et outil d'import de la politique de Daniel.
- Rapport de tests de contournement et mesure du surcoût de latence.

## 10. Points à arbitrer

| Sujet | Question | Proposition |
|---|---|---|
| Agents à privilèges d'infrastructure | Un agent d'exploitation (accès Kubernetes, SSH, Coolify) peut faire sortir des données en lançant une tâche ailleurs. | V1 : surveillance et alertes (section 5.8), sans blocage ni changement des accès ; la limite est documentée |
| Nom du projet | « Leash » est déjà pris (StrongDM) | À choisir |
| Premier déploiement | Emplacement de la console pour le premier déploiement interne | À choisir |

## 11. Annexe — références

- Politique et code de l'egress-guard interne (non publiés).
- Inspirations : Check Point (console, SmartLog), Pipelock (Apache 2.0), StrongDM Leash (Apache 2.0), Smokescreen (Stripe), mitmproxy.
- Notions : *lethal trifecta* (S. Willison) ; OWASP Agentic Top 10.
