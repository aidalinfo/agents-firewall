# Sécurité

Ce document explique ce contre quoi agents-firewall protège, comment, et surtout **ce contre quoi il ne protège pas**. Pour signaler une vulnérabilité, suivez [SECURITY.md](../SECURITY.md) (jamais d'issue publique).

## Modèle de menace

### Ce que l'on cherche à empêcher

Un agent IA lit du contenu non fiable (mails, pages web, documents, réponses d'outils). Une **injection de prompt** peut lui faire :

- envoyer des données privées vers une destination contrôlée par l'attaquant (exfiltration) ;
- rebondir vers d'autres systèmes internes (autre agent, base de données, API d'administration) ;
- contourner les garde-fous placés dans l'agent : URL cachée dans une variable, script écrit pour l'occasion, serveur MCP qui fait ses propres appels, client qui ignore le proxy.

### Hypothèses

- **L'agent est considéré comme hostile.** Tout ce qui tourne dans son conteneur (le modèle, ses outils, les scripts qu'il écrit) peut tenter de contourner le contrôle.
- L'hôte Docker, le moteur de conteneurs, le nœud Kubernetes et son CNI sont **de confiance**. Un attaquant qui les contrôle contrôle aussi la passerelle.
- La console et sa base sont administrées par des personnes de confiance ; l'audit chaîné sert à détecter une modification après coup, pas à empêcher un administrateur légitime d'agir.
- Les décisions sont **déterministes** : aucun modèle de langage ne juge le trafic.

### Ce qui est hors périmètre

- le filtrage des flux **entrants** vers les agents (rôle de votre reverse proxy et de vos outils existants) ;
- le confinement des fichiers et des processus à l'intérieur de l'agent ;
- la protection contre un administrateur malveillant de l'hôte.

## Fermeture par défaut

La passerelle **ne laisse jamais tout passer** :

| Situation | Comportement |
|---|---|
| Aucune politique installée au démarrage | tout est refusé |
| Politique corrompue, empreinte SHA-256 fausse, format inconnu | document rejeté ; la dernière politique valide est conservée, ou tout est refusé s'il n'y en a aucune |
| Erreur interne du moteur, analyse de contenu impossible | refus |
| Agent inconnu (adresse non enrôlée) | refus |
| Passerelle arrêtée | les agents n'ont plus de route : aucun réseau |
| Console injoignable | la passerelle continue d'appliquer la dernière politique installée |

Le refus est **immédiat et explicite** (réponse `403` avec la destination, l'agent et la règle), pour que l'agent puisse expliquer ce qui s'est passé au lieu de réessayer sans fin.

## Isolement des agents

Détail technique : [ADR 0003](adr/0003-isolement-reseau.md) et [enrolement.md](enrolement.md#le-motif-afw-net-ou-pourquoi-un-conteneur-de-plus).

- **Docker.** L'agent est sur un réseau `internal: true`, sans sortie. Sa route par défaut est posée par un conteneur voisin `afw-net-<agent>` qui seul détient `NET_ADMIN` ; l'agent n'a pas ce droit et ne peut pas la changer. Sur la passerelle, nftables redirige tout le TCP vers l'écoute transparente, l'UDP 53 vers le DNS filtrant, et **rejette tout le reste**.
- **Kubernetes.** Une NetworkPolicy n'autorise en sortie que la passerelle du namespace ; le DNS du pod est la passerelle.
- **Identité.** Un agent est identifié par son adresse sur le réseau interne, fixée à l'enrôlement. Il ne peut pas la changer sans `NET_ADMIN`.

Contournements couverts par des tests (« tests de contournement ») : connexion directe à une IP publique sans DNS, port non HTTP, résolveur DNS externe, proxy ignoré (`--noproxy`), CONNECT vers un hôte refusé, **domain fronting** (Host différent du SNI : refusé), HTTP/1.0 sans Host, secret dans un corps découpé, *chunked* ou WebSocket, politique absente.

La passerelle se connecte toujours vers le **nom contrôlé par la politique** (SNI ou Host), qu'elle résout elle-même : un agent ne peut pas annoncer un nom autorisé et viser une autre adresse.

## Inspection TLS et clé d'inspection

- Chaque passerelle possède **sa propre autorité d'inspection** (clé ECDSA P-256), créée sur son hôte, stockée en `0600`, **jamais exportée** ni envoyée à la console. Compromettre une passerelle ne compromet donc pas les autres.
- Seul le **certificat public** de cette autorité est monté dans les conteneurs des agents.
- Les certificats de chaque site sont générés à la volée et mis en cache.
- Côté amont, la passerelle vérifie les certificats des serveurs avec les autorités publiques habituelles (plus des autorités supplémentaires configurables pour vos services internes). Un serveur au certificat invalide n'est pas joint.
- Protégez le volume `/var/lib/afw` de la passerelle : qui lit cette clé peut usurper n'importe quel site **auprès des agents de cet hôte**.

## Communication passerelle ↔ console (mTLS)

- La console a sa propre autorité de certification.
- Une passerelle s'enregistre avec un **jeton à usage unique valable 15 minutes** et une demande de certificat ; elle reçoit un certificat client. Sa clé privée ne quitte jamais son hôte.
- Toutes les routes `/gw/v1` exigent ce certificat client. Un certificat d'une autre autorité est refusé.
- La passerelle tire sa politique et vérifie son empreinte avant de l'appliquer.

## Rôles et droits

| Rôle | Peut |
|---|---|
| `admin` | tout : politique, sessions, publication, installation, passerelles, jetons, contenus |
| `auditor` | tout lire, **y compris les contenus** (corps HTTP, captures), et l'audit ; aucune modification |
| `viewer` | lire la politique et les journaux, **sans les contenus** |
| `mcp_agent` | rôle de l'agent d'administration agréé, restreint (voir ci-dessous) |

- Humains : OIDC générique (n'importe quel fournisseur conforme).
- Scripts et CLI : jetons d'API, révocables, rattachés à un rôle.
- La **consultation des contenus** (corps HTTP, téléchargement de capture) est elle-même inscrite dans l'audit.
- Les contenus sont **masqués avant stockage** (secrets remplacés par type et empreinte) puis **chiffrés au repos** (AES-256-GCM, clé `AFW_DATA_KEY`).

## L'agent MCP agréé

Un seul agent peut administrer le pare-feu par le serveur MCP ([mcp.md](mcp.md)). Garde-fous :

- il n'agit que sur les **zones qui lui sont déléguées** (`delegated_to_mcp`) ;
- il ne peut **jamais** modifier sa propre zone, une règle dont la source est sa zone, ni déplacer un agent vers ou depuis sa zone ;
- les **élargissements importants** (joker sur Internet, « toute destination », autorisation de sortie de secrets) attendent la **validation d'un humain** avant publication ;
- chacune de ses actions est inscrite dans l'audit avec l'interface `mcp`.

## Audit chaîné et export immuable

- Chaque modification (politique, session, publication, installation, jetons, enrôlement, consultation de contenu) produit une entrée d'audit : **qui** (humain, CLI, agent, système), **quoi** (différence), **quand**, **depuis quelle interface** (`ui`, `cli`, `mcp`, `api`, `system`), **dans quelle session**.
- Le journal est en **ajout seul** et **chaîné par empreinte** : chaque entrée contient l'empreinte de la précédente, `hash = sha256(prev_hash || json_canonique(entrée sans hash))`. Modifier ou supprimer une entrée casse la chaîne.
- `GET /api/v1/audit/verify` recalcule la chaîne et signale la première rupture.
- Pour résister à un accès direct à la base, les empreintes sont **exportées périodiquement** vers un stockage externe : un fichier en ajout seul, et en option un stockage objet S3 avec verrouillage (*Object Lock*) en rétention immuable. `GET /api/v1/audit/export` permet aussi un export à la demande.

## Limites connues

Ces limites sont assumées en V1. Elles sont détectées ou documentées, pas bloquées.

### Agents à privilèges d'infrastructure

Un agent d'exploitation qui dispose d'accès Kubernetes, SSH, Coolify, Proxmox ou du socket Docker peut **lancer une charge ailleurs** (un pod, un conteneur, une commande sur une autre machine) qui, elle, n'est pas enrôlée. Cette charge peut faire sortir des données sans passer par la passerelle.

Choix de la V1 :

- **pas de blocage** de ces accès ni de filtrage action par action des API d'administration ;
- **surveillance** : les appels aux API d'administration passent par la passerelle et sont journalisés avec l'action et la ressource (création de pod, `exec`, redéploiement) ; une action inhabituelle déclenche une alerte ;
- à l'enrôlement, un conteneur **privilégié** ou ayant le **socket Docker** reçoit un **avertissement**, pas un refus ; seul `network_mode: host` est refusé.

Recommandations : réservez ces accès à des agents dédiés, placés dans une zone dédiée ; limitez leurs droits côté Kubernetes ou Coolify (comptes de service restreints) ; enrôlez aussi les charges qu'ils lancent quand c'est possible ; suivez les alertes « action d'administration inhabituelle ».

### Destinations autorisées et fournisseurs LLM

Le pare-feu contrôle **où** les données vont et **quelles classes** de données sortent. Il ne peut pas empêcher une fuite vers une destination autorisée par un canal qu'aucun détecteur ne reconnaît : données chiffrées ou obfusquées par l'agent, information reformulée, dépôt public sur un service autorisé en écriture.

Les fournisseurs LLM sont, par décision, **exemptés du blocage par classe de données** : un secret envoyé à `api.anthropic.com` passe (masqué dans le journal). Limitez la catégorie `llm_provider` aux points d'accès d'API réellement utilisés, et autorisez l'écriture vers les autres services au plus juste.

### Épinglage de certificat

Une application qui n'accepte que le certificat attendu du serveur (épinglage) refuse l'inspection. Il faut alors mettre la destination en **contournement d'inspection** : la passerelle ne voit plus que les métadonnées (nom SNI, adresses, volumes), ni le contenu, ni la méthode, ni le chemin. Les règles de classes de données et les critères de méthode ou de chemin ne s'y appliquent plus. Gardez cette liste courte et justifiée.

### QUIC, HTTP/3 et autre UDP

Seuls le TCP et le DNS (UDP/TCP 53) sont pris en charge. **Tout autre UDP est rejeté**, y compris QUIC (HTTP/3). Les navigateurs et la plupart des bibliothèques reviennent alors en HTTPS sur TCP, qui est inspecté. Un usage qui exige UDP (VoIP, certains VPN, jeux) ne fonctionnera pas derrière la passerelle : c'est voulu.

### DNS chiffré

Un agent peut tenter de résoudre ses noms par DNS sur HTTPS (DoH). Ce trafic est du HTTPS ordinaire : il n'est possible que si le résolveur est une destination autorisée, ce qu'il vaut mieux éviter. Même dans ce cas, la passerelle décide sur le nom présenté (SNI ou Host) et ne se connecte qu'au nom contrôlé par la politique.

### Mode observation

Une zone en observation **ne bloque rien** (hormis les métadonnées cloud). Ne la laissez pas dans ce mode au-delà de la période de mise en place.

### Corrélation

Le rattachement d'un flux à un appel d'outil repose sur une fenêtre de temps. Il est **indicatif** : la console signale `probable` ou `uncertain` quand plusieurs appels se chevauchent ou qu'aucun n'est actif. Un agent sans plugin Hermes n'a que la vue réseau.

### Fenêtre de mise à jour

Pendant le redémarrage d'une passerelle, ses agents n'ont plus de réseau. C'est la conséquence directe de la fermeture par défaut.
