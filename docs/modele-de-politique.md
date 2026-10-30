# Modèle de politique

La politique d'agents-firewall se gère comme celle d'un pare-feu d'entreprise : des **objets** réutilisables, des **zones** d'agents, une **base de règles** ordonnée en deux couches, et un cycle **session → publication → installation** avec des **révisions** et un retour arrière.

Ce document décrit le modèle tel qu'il est figé par les contrats de la V1 (plan d'implémentation §3.1, [ADR 0005](adr/0005-ordre-d-evaluation.md)). Les écrans, la CLI et le MCP manipulent tous ce même modèle par l'API.

## Principes

- **Refus par défaut.** Ce qui n'est pas explicitement autorisé est refusé, immédiatement et de façon explicite.
- **Pas d'exception par agent.** Une règle a pour source une **zone**, jamais un agent. Un agent aux besoins particuliers reçoit sa propre zone.
- **Un socle commun** s'applique avant tout le reste, à tous les agents, et ne peut pas être contourné par une règle de zone.
- **Le détail maximal par défaut** : les flux sont journalisés avec leur contenu HTTP, secrets masqués.
- **Rien n'est appliqué tant que ce n'est pas publié puis installé.**

## Objets

Les objets sont nommés, commentés et réutilisables. La fonction **« Où est-il utilisé ? »** (`GET /api/v1/objects/{id}/where-used`) liste les règles et groupes qui y font référence.

### Destinations

| Type | Exemple | Remarques |
|---|---|---|
| Domaine | `api.exemple.com`, `*.exemple.com` | voir les règles du joker ci-dessous |
| Hôte | `203.0.113.10` | IPv4 ou IPv6 |
| Réseau | `10.20.0.0/16` | notation CIDR |
| Plage | `192.0.2.10` → `192.0.2.50` | |
| Groupe | « Microsoft 365 » = `graph.microsoft.com` + `login.microsoftonline.com` | regroupe d'autres objets |
| Toute destination | — | équivalent d'une destination vide dans une règle |

**Joker.** `*.exemple.com` correspond à `api.exemple.com` et à `a.b.exemple.com`, mais **ni à `exemple.com` lui-même, ni à `faux-exemple.com`**. La comparaison ignore la casse et le point final (`API.Exemple.com.` est traité comme `api.exemple.com`). Pour couvrir le domaine et ses sous-domaines, mettez les deux objets dans un groupe.

**Catégories.** Un objet destination peut porter une catégorie qui change son traitement :

| Catégorie | Effet |
|---|---|
| `llm_provider` (fournisseur LLM) | trafic journalisé en détail, mais **exempté du blocage par classe de données** (voir plus bas) |
| `cloud_metadata` (métadonnées cloud) | sert au socle : `169.254.169.254`, `metadata.google.internal`… ; déclenche une alerte en cas de tentative |
| `internal` (interne) | marque une destination comme interne pour l'affichage et la carte des flux |

### Services

Un service décrit **comment** on parle à la destination :

- protocole L4 : TCP, UDP ou les deux ;
- ports ou plages de ports (`443`, `8000-8099`) ;
- critère applicatif optionnel : protocole (HTTP, HTTPS, DNS, SSH, TLS, autre), **méthodes** HTTP (`GET`, `POST`…) et **préfixes de chemin** (`/v1/messages`).

Exemple : un service « GitHub lecture seule » = HTTPS, port 443, méthodes `GET` et `HEAD`. Associé à l'objet `api.github.com`, il autorise la lecture mais refuse un `POST` de création de dépôt.

Les critères de méthode et de chemin ne peuvent être vérifiés que sur du trafic **inspecté** (déchiffré) ou en HTTP clair.

### Classes de données

Une classe de données regroupe des **détecteurs** de contenu. Elle a une catégorie : `secret`, `infra`, `commercial`, `personal` ou `custom`.

Détecteurs intégrés : clés AWS, jetons GitHub et GitLab, clés Anthropic et OpenAI, JWT, clés privées PEM, mots de passe dans une URL, chaînes à forte entropie dans `password=` / `token=`, IBAN, adresses e-mail, inventaire d'infrastructure (IP privées, noms d'hôtes internes configurables). Vous pouvez ajouter vos propres détecteurs par expression régulière.

La détection résiste aux contournements simples : secret coupé entre deux paquets, encodé en base64 ou en URL, passé en majuscules. Une URL présignée S3 (`X-Amz-Signature=…`) n'est **pas** considérée comme un secret, ce qui évite un faux positif fréquent.

Dans les journaux, chaque valeur détectée est remplacée par son type et une empreinte courte, par exemple `[SECRET:aws_access_key:3f9a1c2b7d10]` : on sait qu'un même secret est sorti plusieurs fois sans jamais le stocker.

## Zones et agents

Une **zone** regroupe des agents qui ont les mêmes autorisations, à la manière d'un VLAN. Exemples : `internes`, `clients`, `ops`.

| Propriété | Rôle |
|---|---|
| `mode` | `enforce` (application) ou `observe` (observation, voir plus bas) |
| `delegated_to_mcp` | la zone peut être administrée par l'agent MCP agréé ([mcp.md](mcp.md)) |

Un **agent** est créé par l'enrôlement. Il appartient à **une seule** zone et porte : son type (Docker Compose, Coolify, Kubernetes, conteneur), sa passerelle, ses adresses sur le réseau interne (son identité), des étiquettes, et deux indicateurs : `hermes` (plugin installé) et `mcp_admin` (agent agréé pour le MCP).

Changer un agent de zone est une modification de politique comme une autre : elle passe par une session et une publication.

## Base de règles

### Deux couches

1. **Socle commun** (`baseline`) : évalué en premier pour tous les agents. C'est là que vivent les interdits absolus : métadonnées cloud, liste de refus globale, « un secret ne sort jamais ». Une règle du socle peut avoir une source vide (= toutes les zones) ; c'est la seule couche où c'est permis.
2. **Règles de zone** : une base ordonnée par zone, évaluée de haut en bas.

Les règles peuvent être regroupées en **sections** nommées pour la lisibilité.

### Champs d'une règle

| Champ | Contenu | Valeur vide |
|---|---|---|
| Numéro | rang global (socle puis zone), recalculé à chaque publication | — |
| Nom, commentaire | texte libre | — |
| Source | une ou plusieurs zones | toutes les zones (socle seulement) |
| Destination | objets | toute destination |
| Service | services | tout service |
| Classes de données | condition sur le contenu | pas de condition de contenu |
| Action | `accept` ou `deny` | — |
| Trace | `none`, `log`, `detailed` (contenu HTTP, **défaut**), `capture` | — |
| Expiration | date après laquelle la règle est ignorée | jamais |
| Activée | une règle désactivée est ignorée | — |

La console affiche aussi, pour chaque règle, un **compteur d'utilisations** et la **date de dernière utilisation**.

### Ordre d'évaluation

Pour chaque connexion, la passerelle applique **la première règle qui correspond**, dans cet ordre :

1. **Socle commun**, par position.
2. **Règles de la zone de l'agent**, par position.
3. **Interne surveillé** : si la destination est dans les réseaux internes (par défaut RFC 1918 et `fc00::/7`) ou est un autre agent, et qu'aucune règle n'a tranché, le flux est **accepté et journalisé en détail**.
4. **Nettoyage** : tout le reste est **refusé**.

Cas particuliers :

- Une règle expirée ou désactivée est ignorée.
- Une règle **avec classes de données** ne correspond que si l'une de ces classes est détectée dans le contenu.
- Si la destination est un **fournisseur LLM**, les règles avec classes de données sont **sautées**.
- Un **agent inconnu** (adresse non enrôlée) est toujours refusé.
- Toute erreur interne (politique absente, corrompue, analyse impossible) aboutit à un **refus**. La passerelle ne laisse jamais tout passer.

### Ce que voit l'agent quand il est refusé

En HTTP(S), la réponse est immédiate et explicite :

```
HTTP/1.1 403 Forbidden
X-Agents-Firewall: denied

blocked by agents-firewall: exfil.exemple.com not allowed for mon-agent (rule default-deny)
```

Le texte est en anglais car il s'adresse aux programmes et aux modèles ; la console le traduit. Quand c'est une règle explicite qui refuse, son numéro est indiqué (`rule 7`) ; quand c'est le nettoyage implicite, la réponse indique `rule default-deny`. En TCP brut, la connexion est réinitialisée (RST) ; en DNS, la requête reçoit une réponse `REFUSED`. Dans tous les cas, le refus est journalisé avec la règle appliquée.

## Contenu et classes de données

Une règle peut refuser selon ce qui **sort**, pas seulement selon la destination. Exemple dans le socle :

| N° | Nom | Source | Destination | Classes | Action |
|---|---|---|---|---|---|
| 3 | Aucun secret ne sort | (toutes) | (toute) | Secrets | deny |

Fonctionnement :

- les corps de requête sont mis en mémoire tampon et analysés **avant envoi**, jusqu'à 1 Mio par défaut (`max_buffered_body`) ;
- au-delà (gros envois) et pour les flux continus (WebSocket, streaming), l'analyse se fait **au fil de l'eau**, avec coupure dès la détection quand c'est possible, sinon alerte ;
- les contenus stockés sont limités à 256 Kio par défaut (`max_stored_body`) ; au-delà, ils sont tronqués, la troncature est signalée et l'empreinte du contenu complet est conservée.

## Fournisseurs LLM

Le contexte envoyé à un fournisseur de modèle contient par nature ce que l'agent a lu, secrets compris. Bloquer ces requêtes sur la présence d'un secret rendrait l'agent inutilisable. D'où la catégorie `llm_provider` :

- le trafic vers ces destinations est **journalisé en détail** ;
- les règles à classes de données **ne s'y appliquent pas** ;
- les secrets restent **masqués dans les journaux**.

La destination elle-même reste soumise aux règles : un fournisseur LLM non autorisé dans la zone est refusé comme n'importe quelle destination. Ne classez en `llm_provider` que les points d'accès d'API des fournisseurs que vous utilisez (par exemple `api.anthropic.com`, `api.openai.com`), pas des domaines larges.

## Flux internes

Par défaut, les flux d'un agent vers un autre agent, le LAN, une base de données ou une API d'administration sont **autorisés et surveillés** : ils passent par la passerelle, sont journalisés avec le même détail que les flux vers Internet, et alimentent la carte des flux internes et la détection de mouvement latéral.

- Les appels aux API d'administration (Kubernetes, Coolify, Docker, Proxmox) sont reconnus et journalisés avec l'action et la ressource visée (création de pod, `exec`, redéploiement…).
- Les sessions SSH sont journalisées au niveau du flux (hôte, durée, volumes).
- Pour **bloquer** un flux interne, écrivez une règle de zone explicite, par exemple « `clients` → `Réseau LAN` : deny ». Elle s'applique avant l'acceptation implicite « interne surveillé ».

Les réseaux considérés comme internes se règlent dans `internal_networks` (réglages de la politique).

## Mode observation

Une zone en mode `observe` laisse tout passer et journalise ce qui **aurait été refusé** (verdict accepté, marqué `observed`). C'est l'outil pour démarrer : on observe le trafic réel quelques jours, on construit les règles à partir du journal (« Autoriser »), puis on passe la zone en `enforce`.

Exception volontaire : le **socle « métadonnées cloud »** reste appliqué même en observation, car une tentative vers ces adresses n'est jamais légitime.

## Politique d'inspection HTTPS

L'inspection est une politique à part, avec ses propres règles ordonnées (zones, destinations, action `inspect` ou `bypass`). **Par défaut, tout est inspecté.**

Mettez en contournement (`bypass`) les destinations qui refusent un certificat autre que le leur (épinglage de certificat), par exemple certains clients de mise à jour ou d'applications mobiles. Pour ces destinations, seules les métadonnées sont visibles (nom SNI, adresses, volumes) : ni le contenu, ni la méthode, ni le chemin, et donc ni les classes de données ni les critères applicatifs des services.

## Réglages de la politique

| Réglage | Défaut | Rôle |
|---|---|---|
| `internal_networks` | RFC 1918 + `fc00::/7` | réseaux traités comme internes |
| `max_buffered_body` | 1 Mio | taille analysée avant envoi |
| `max_stored_body` | 256 Kio | taille de corps conservée |
| rétention des flux | 30 jours | |
| rétention HTTP | 14 jours | |
| rétention des captures | 7 jours | |

## Sessions, publication, installation, révisions

Les modifications ne s'appliquent jamais directement. Le cycle est le suivant :

```
 session ──▶ publier ──▶ révision n ──▶ vérifier ──▶ installer sur passerelle(s)
 (brouillon,             (numérotée,                  (résultat par passerelle)
  verrous)               auteur, date,
                         commentaire, diff)
```

1. **Session.** Un administrateur (humain ou agent agréé) ouvre une session. Ses modifications ne sont visibles que de lui. Chaque objet modifié est **verrouillé** pour les autres sessions jusqu'à publication ou abandon.
2. **Publication.** Publier crée une **révision numérotée** avec l'auteur, la date, un commentaire et une **différence lisible** avec la révision précédente. On peut aussi abandonner la session.
3. **Vérification.** Avant installation, la vérification signale les **règles masquées** par une règle plus haute (elles ne seront jamais atteintes), les **objets inutilisés** et les **règles expirées**.
4. **Installation.** Installer, c'est fixer la révision voulue pour une ou plusieurs passerelles. Chaque passerelle télécharge la révision, la vérifie (format, empreinte SHA-256), la compile et accuse réception. Le résultat est visible **par passerelle** : révision désirée, révision active, succès ou erreur. Une révision rejetée par une passerelle n'est pas appliquée : la précédente reste en place.
5. **Retour arrière.** Installer une révision antérieure. Rien n'est effacé : l'historique des révisions est conservé.

Les **approbations** s'insèrent avant la publication : certaines modifications demandées par l'agent MCP agréé exigent la validation d'un humain ([mcp.md](mcp.md#élargissements-soumis-à-validation)).

Chaque étape (ouverture de session, modification, publication, installation, retour arrière) est inscrite dans l'**audit chaîné**.

## Exemple : une politique pour deux zones

Objets :

| Objet | Type | Catégorie |
|---|---|---|
| `Métadonnées cloud` | groupe : `169.254.169.254`, `metadata.google.internal` | `cloud_metadata` |
| `API Anthropic` | domaine `api.anthropic.com` | `llm_provider` |
| `GitHub API` | domaine `api.github.com` | |
| `Stockage S3` | domaine `*.s3.amazonaws.com` | |
| `API partenaire` | domaine `api.partenaire.exemple` | |
| `LAN` | réseau `192.168.0.0/16` | `internal` |

Services : `HTTPS` (TCP 443, HTTPS), `HTTPS lecture` (TCP 443, HTTPS, méthodes `GET`/`HEAD`).

Classes de données : `Secrets` (catégorie `secret`, détecteurs intégrés), `Inventaire infra` (catégorie `infra`).

Zones : `internes` (enforce), `clients` (observe pendant la mise en place, puis enforce).

Base de règles :

| N° | Couche | Nom | Source | Destination | Service | Classes | Action |
|---|---|---|---|---|---|---|---|
| 1 | socle | Métadonnées cloud interdites | (toutes) | Métadonnées cloud | (tout) | | deny |
| 2 | socle | Aucun secret ne sort | (toutes) | (toute) | (tout) | Secrets | deny |
| 3 | socle | Pas d'inventaire d'infrastructure | (toutes) | (toute) | (tout) | Inventaire infra | deny |
| 4 | internes | Modèle de langage | internes | API Anthropic | HTTPS | | accept |
| 5 | internes | Lecture GitHub | internes | GitHub API | HTTPS lecture | | accept |
| 6 | internes | Dépôt de fichiers | internes | Stockage S3 | HTTPS | | accept |
| 7 | clients | Modèle de langage | clients | API Anthropic | HTTPS | | accept |
| 8 | clients | API du partenaire | clients | API partenaire | HTTPS | | accept |
| 9 | clients | Pas de LAN | clients | LAN | (tout) | | deny |

Ce que cela donne :

- `internes` envoie un prompt contenant une clé AWS à `api.anthropic.com` : règle 2 sautée (fournisseur LLM), règle 4 → **accepté**, clé masquée dans le journal.
- `internes` envoie la même clé à un dépôt S3 : règle 2 → **refusé**.
- `internes` fait un `POST` sur `api.github.com` : règle 5 ne correspond pas (méthode), nettoyage → **refusé**.
- `internes` interroge une base sur `192.168.10.5:5432` : aucune règle → **interne surveillé**, accepté et journalisé.
- `clients`, encore en observation, appelle `exfil.exemple.com` : le nettoyage aurait refusé, le flux **passe** et apparaît `observed` dans le journal.
- Une fois `clients` passée en `enforce`, la même tentative est **refusée** (nettoyage), et l'accès à la base `192.168.10.5` aussi (règle 9).
- Quel que soit le mode, une tentative vers `169.254.169.254` est **refusée** (règle 1) et lève une alerte.

Une politique d'exemple complète, générique, est fournie avec la démo (`demo/policy/demo-policy.json`, à venir).
