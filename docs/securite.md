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
| Corps au-delà de `max_buffered_body`, flux continu (WebSocket, streaming) | analyse au fil de l'eau : coupure dès la détection, mais **un fragment déjà transmis ne peut pas être rappelé** (voir les limites) |
| Agent inconnu (adresse non enrôlée) | refus |
| Passerelle arrêtée | les agents n'ont plus de route : aucun réseau |
| Console injoignable | la passerelle continue d'appliquer la dernière politique installée |
| Tampon d'événements plein (console longtemps injoignable) | les nouveaux flux sont refusés plutôt que de passer sans être journalisés ; une alerte est levée |

Le refus est **immédiat et explicite**, pour que l'agent puisse expliquer ce qui s'est passé au lieu de réessayer sans fin : en HTTP(S), réponse `403` avec la destination, l'agent et la règle, dans le corps et dans l'en-tête `X-Agents-Firewall-Reason` (y compris pour un `CONNECT` refusé par le proxy explicite) ; en TCP brut, réinitialisation de la connexion (RST) ; en DNS, réponse `REFUSED`. Tous ces refus sont journalisés, avec leur forme (`deny_mode`).

## Isolement des agents

Détail technique : [ADR 0003](adr/0003-isolement-reseau.md) et [enrolement.md](enrolement.md#le-motif-afw-net-ou-pourquoi-un-conteneur-de-plus).

- **Docker.** L'agent est sur un réseau `internal: true`, sans sortie. Sa route par défaut est posée par un conteneur voisin `afw-net-<agent>` qui seul détient `NET_ADMIN` ; l'agent n'a pas ce droit et ne peut pas la changer. Sur la passerelle, nftables redirige tout le TCP vers l'écoute transparente, l'UDP 53 vers le DNS filtrant, et **abandonne (drop) tout le reste**.
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
| `agent_plugin` | jeton du plugin Hermes d'un agent : seulement `POST /ingest/tool-calls` et `GET /intent-policy` |

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
- `GET /api/v1/audit` liste les entrées, **les plus récentes d'abord** par défaut (`order=asc` pour l'ordre croissant des numéros ; `afw audit list --order asc`, outil MCP `list_audit` avec `order`). Voir [ADR 0028](adr/0028-mode-de-refus-et-ordre-de-l-audit.md).
- `GET /api/v1/audit/verify` (`afw audit verify`) recalcule la chaîne, la compare aux têtes exportées et signale la première rupture.
- Pour résister à un accès direct à la base, la tête de chaîne est **exportée périodiquement** (toutes les heures par défaut, `AFW_AUDIT_EXPORT_INTERVAL`) vers un stockage externe : un fichier en ajout seul (`AFW_AUDIT_EXPORT_DIR`), et en option un stockage objet S3 avec verrouillage (*Object Lock*) en rétention immuable (`AFW_AUDIT_S3_ENDPOINT`, `_BUCKET`, `_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY`, `_REGION`, `_PREFIX`, `_RETENTION_DAYS` ; ces variables ne figurent pas dans `deploy/compose/.env.example` : ajoutez-les à l'environnement d'`afw-api`, ou à `api.extraEnv` avec Helm). `POST /api/v1/audit/export` (`afw audit anchor`) force cet export ; `GET /api/v1/audit/export` (`afw audit export`) exporte tout le journal en lignes JSON.

## Limites connues

Ces limites sont assumées en V1. Elles sont détectées ou documentées, pas bloquées.

### Agents à privilèges d'infrastructure

Un agent d'exploitation qui dispose d'accès Kubernetes, SSH, Coolify, Proxmox ou du socket Docker peut **lancer une charge ailleurs** (un pod, un conteneur, une commande sur une autre machine) qui, elle, n'est pas enrôlée. Cette charge peut faire sortir des données sans passer par la passerelle.

Choix de la V1 :

- **pas de blocage** de ces accès ni de filtrage action par action des API d'administration ;
- **surveillance** : les appels aux API d'administration passent par la passerelle et sont journalisés avec l'action et la ressource (création de pod, `exec`, redéploiement) ; une action inhabituelle déclenche une alerte ;
- à l'enrôlement, un conteneur **privilégié** ou ayant le **socket Docker** reçoit seulement un **avertissement**, pas un refus. Seul `network_mode: host` est refusé : dans ce mode, l'isolement réseau est impossible et l'enrôlement mentirait sur la protection (choix du constructeur, [ADR 0023](adr/0023-enrolement-des-agents.md)).

Recommandations : réservez ces accès à des agents dédiés, placés dans une zone dédiée ; limitez leurs droits côté Kubernetes ou Coolify (comptes de service restreints) ; enrôlez aussi les charges qu'ils lancent quand c'est possible ; suivez les alertes « action d'administration inhabituelle ».

### L'étage intention du plugin Hermes n'est pas une barrière

Les classes d'actions et leur « gate » (plugin Hermes) s'exécutent **dans l'agent**. Elles se contournent par construction, exactement comme l'egress-guard qu'elles remplacent : un script, une variable ou un serveur MCP qui agit hors des outils surveillés n'y passe pas. Elles servent à guider l'agent et à corréler ses actions, pas à protéger. **La seule barrière est la passerelle**, qui voit le trafic réseau réel.

### Flux internes acceptés par défaut

Par décision, les flux vers les réseaux internes et les autres agents sont **acceptés et surveillés, pas bloqués**, tant qu'aucune règle de zone ne les refuse. Un agent compromis peut donc joindre une base, une API d'administration ou un autre agent : le flux est journalisé en détail, la carte des flux internes le montre et la détection de mouvement latéral peut lever une alerte, mais rien n'est empêché. Écrivez des règles de zone `deny` vers les systèmes internes sensibles.

### Analyse au fil de l'eau des gros corps et des flux continus

Jusqu'à `max_buffered_body` (1 Mio par défaut), un corps est analysé en entier **avant** d'être envoyé. Au-delà, et pour les WebSocket et le streaming, l'analyse se fait au fil de l'eau : la connexion est coupée dès la détection, mais **la partie déjà transmise est partie**. Un secret placé après un long préambule peut donc sortir en partie avant la coupure ; l'événement est journalisé et une alerte est levée. Augmentez `max_buffered_body` pour les zones sensibles si la mémoire le permet.

### Exfiltration lente par DNS

La passerelle filtre les noms demandés, mais si un domaine est autorisé avec un joker (par exemple `*.exemple.com`), un agent peut encoder des données dans des sous-domaines (`c2VjcmV0.exemple.com`) et les faire sortir lentement, requête après requête, vers le serveur qui fait autorité pour ce domaine. Chaque requête est journalisée, mais les détecteurs de classes de données ne voient que des fragments courts. Préférez des domaines exacts aux jokers et surveillez les alertes « nouvelle destination » et le volume de requêtes DNS par agent.

### Destinations autorisées et fournisseurs LLM

Le pare-feu contrôle **où** les données vont et **quelles classes** de données sortent. Il ne peut pas empêcher une fuite vers une destination autorisée par un canal qu'aucun détecteur ne reconnaît : données chiffrées ou obfusquées par l'agent, information reformulée, dépôt public sur un service autorisé en écriture.

Les fournisseurs LLM sont, par décision, **exemptés du blocage par classe de données** : un secret envoyé à `api.anthropic.com` passe (masqué dans le journal). Limitez la catégorie `llm_provider` aux points d'accès d'API réellement utilisés, et autorisez l'écriture vers les autres services au plus juste.

### Épinglage de certificat

Une application qui n'accepte que le certificat attendu du serveur (épinglage) refuse l'inspection. Il faut alors mettre la destination en **contournement d'inspection** : la passerelle ne voit plus que les métadonnées (nom SNI, adresses, volumes), ni le contenu, ni la méthode, ni le chemin. Les règles de classes de données et les critères de méthode ou de chemin ne s'y appliquent plus. Gardez cette liste courte et justifiée.

### QUIC, HTTP/3 et autre UDP

Seuls le TCP et le DNS (UDP/TCP 53) sont pris en charge. **Tout autre UDP est abandonné (drop)**, y compris QUIC (HTTP/3). Les navigateurs et la plupart des bibliothèques reviennent alors en HTTPS sur TCP, qui est inspecté. Un usage qui exige UDP (VoIP, certains VPN, jeux) ne fonctionnera pas derrière la passerelle : c'est voulu.

### DNS chiffré

Un agent peut tenter de résoudre ses noms par DNS sur HTTPS (DoH). Ce trafic est du HTTPS ordinaire : il n'est possible que si le résolveur est une destination autorisée, ce qu'il vaut mieux éviter. Même dans ce cas, la passerelle décide sur le nom présenté (SNI ou Host) et ne se connecte qu'au nom contrôlé par la politique.

### Mode observation

Une zone en observation **ne bloque rien** (hormis les métadonnées cloud). Ne la laissez pas dans ce mode au-delà de la période de mise en place.

### Corrélation

Le rattachement d'un flux à un appel d'outil repose sur une fenêtre de temps. Il est **indicatif** : la console signale `probable` ou `uncertain` quand plusieurs appels se chevauchent ou qu'aucun n'est actif. Un agent sans plugin Hermes n'a que la vue réseau.

### Fenêtre de mise à jour

Pendant le redémarrage d'une passerelle, ses agents n'ont plus de réseau. C'est la conséquence directe de la fermeture par défaut.
