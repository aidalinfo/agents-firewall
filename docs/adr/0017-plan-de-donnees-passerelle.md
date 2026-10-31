# ADR 0017 — Plan de données de la passerelle : écoutes, aiguillage et pipeline

- Statut : accepté — 2026-10-31
- Lot : L6

## Contexte
La passerelle (`crates/afw-gateway`) applique la politique compilée par `afw-engine` à tout le trafic d'un hôte
d'agents (ADR 0003, 0004, 0005, 0016). Elle ne doit jamais tomber en mode ouvert (ENF-02) et doit rester
imperceptible en latence (ENF-01).

## Décisions
1. **Écoutes.** Transparent `:15001` (nftables `redirect`, destination d'origine par `getsockopt(SO_ORIGINAL_DST)`),
   proxy explicite `:3128` (`CONNECT` et requêtes en forme absolue), DNS `:53` UDP+TCP, santé `:9090`
   (`/healthz`, `/metrics` Prometheus, `/ca.crt`). `AFW_INTERCEPT=proxy-dns` (Kubernetes) n'ouvre pas l'écoute
   transparente. Une connexion transparente dont la destination d'origine est inconnue, ou vise la passerelle
   elle-même, est réinitialisée.
2. **Aiguillage commun** (transparent et tunnels `CONNECT`) : lecture des premiers octets (délai borné, 800 ms).
   ClientHello → SNI ; requête HTTP reconnue de façon générique (`token SP cible SP HTTP/1.x`, lignes vides de tête
   ignorées, `PRI * HTTP/2.0`) → `Host` ; bannière `SSH-`. **Des octets incomplets ou mal formés qui ressemblent à
   TLS (`0x16`) ou à HTTP sont refusés (RST), jamais relayés en L4** — y compris un ClientHello lent au-delà du
   délai. Seule une connexion sans aucun octet dans le délai (protocole « serveur d'abord ») ou au début clairement
   non TLS/HTTP part en L4. Un `CONNECT` dont le SNI diffère de la cible est refusé.
3. **Agent = adresse source** ; agent inconnu, politique absente/corrompue, erreur interne : refus.
4. **TLS.** Décision de connexion avec l'adresse résolue par la passerelle (`dst_ip_trusted = true`). Tunnel opaque
   seulement si la décision accepte, que l'inspection est contournée (`inspect_tls = false`) **et** que
   `needs_l7` est faux ; sinon terminaison TLS avec une feuille de `GatewayCa` (nom = SNI, ou IP d'origine sans
   SNI), y compris pour un refus, afin de rendre le message EF-21. L'amont est vérifié sur le même nom.
   Agent inconnu ou absence de politique : refus (RST) **avant** toute génération de certificat. Génération de
   feuilles limitée à 20 noms nouveaux par agent et par minute ; une tentative refusée par cette limite n'est pas
   comptée (refus + alerte).
5. **HTTP (par requête).** L'autorité d'une URI absolue (ou `:authority` en h2) et l'en-tête `Host` doivent être
   égaux ; plusieurs `Host` : refus. `Host` (ou l'autorité) doit être égal au nom du flux (SNI, `CONNECT`
   ou premier `Host` en clair ; IP pour un flux sans nom), sinon 403 `rule host-mismatch` ; décision avec
   méthode et chemin ; analyse URL + en-têtes + corps ; re-décision avec les classes détectées ; refus EF-21
   exact (`403`, `X-Agents-Firewall: denied`, `blocked by agents-firewall: <destination> not allowed for <agent>
   (rule <n>)`). Chaque requête d'une connexion est jugée (une connexion acceptée ne vaut pas pour la suivante).
6. **Amont HTTP.** Client hyper par flux, épinglé à l'adresse résolue ; ALPN amont aligné sur celui de l'agent
   (HTTP/1.1 si l'agent parle HTTP/1.1, h2 sinon) : pas de traduction de protocole inutile ni de coût
   d'établissement h2 par connexion. En-têtes « hop-by-hop » retirés.
7. **L4.** Décision sur adresse/port (+ nom attribué par le cache DNS), puis copie bidirectionnelle comptée ;
   refus = RST (`SO_LINGER 0`) + événement. **Relais brut seulement si la décision accepte ET
   `Decision::content_rules_apply` est faux** (aucune règle Deny à classes de données, plus haute que la règle
   décisive, ne pourrait viser ce flux ; les Deny par chemin s'appliquent déjà à toute la connexion quand les
   requêtes ne seront jamais vues, ADR 0016 §17) ; sinon refus `content-not-inspectable` : un contenu non
   inspectable n'est pas autorisé là où une règle de contenu s'applique. Conséquence pour les politiques : une
   règle de socle « secrets sortants » vers « any » interdit tout TCP brut ; la cibler sur les destinations
   externes pour laisser passer les flux internes non HTTP (SSH, bases). UDP autre que 53 : rejeté par nftables.
8. **Événements.** Un `FlowEvent` par connexion acceptée (émis à la fin, compteurs d'octets), un par refus (au
   moment du refus), un `HttpEvent` par requête (corps masqués par `afw_dlp::mask_bytes`, tronqués à
   `max_stored_body` sans couper une valeur détectée, SHA-256 du contenu complet ; valeurs d'en-têtes
   d'authentification toujours remplacées par `[REDACTED:<empreinte>]`), `DnsEvent` par requête DNS,
   `RuleHits` agrégés. File bornée en mémoire (10 000) + débordement disque (64 Mio, puis comptage des pertes),
   envoi `POST /gw/v1/events` par lots de 500 ou chaque seconde ; sans console : `events.jsonl` local. Le
   débordement disque est asynchrone et en ajout. **Si des événements doivent être perdus (file pleine et spool
   plein ou non inscriptible), la passerelle refuse les NOUVEAUX flux (`event-backlog`) jusqu'à ce que l'arriéré
   redescende sous la moitié des bornes**, avec une alerte au début et à la fin : la traçabilité prime sur la
   disponibilité.
9. **Console.** Enregistrement (`afw-gateway register`, ou au démarrage avec `AFW_REGISTRATION_TOKEN`), long-poll
   politique + accusé, battement de cœur (15 s) et commandes (`StartCapture`, `Reinstall`, `SelfTest`), mTLS par
   `GatewayIdentity`. Console injoignable : la dernière politique valide reste appliquée (EF-23).
10. **Politique.** `policy.json` écrit atomiquement (temporaire + `fsync` + renommage) ; vérification d'empreinte,
    règle anti-retour arrière, compilation et construction du scanner avant échange atomique ; échec = politique
    précédente conservée, ou tout refuser au démarrage. `afw-gateway seal-policy` scelle un `PolicyDocument`
    pour `--standalone-policy` (recette, tests).
11. **Captures** (EF-33) : pcap écrit à la main (`LINKTYPE_RAW`, en-têtes IPv4/IPv6 + TCP reconstitués), bornées à
    64 Mio et 1 h, envoyées à `/gw/v1/captures/{id}`. **Elles enregistrent les octets tels qu'ils passent sur le
    fil côté agent : pour un flux inspecté, le TLS chiffré, jamais le clair déchiffré.** Le contenu déchiffré
    n'existe que dans les `HttpEvent`, masqués (EF-35).
12. **Alertes locales** : métadonnées cloud, rafale de refus (≥ 10/60 s), balayage (≥ 10 ports d'un hôte ou
    ≥ 10 hôtes en 60 s), port sensible, nouvel hôte interne, rafale interne (≥ 100/60 s), secret détecté
    (y compris vers un fournisseur LLM, non bloqué), action d'administration `exec`/`delete`/`attach`, débit de
    SNI ; anti-répétition 60 s par (type, agent, clé).
13. **Santé.** `/healthz` et `/metrics` (`:9090`, adresse `AFW_HEALTH_IP`) ne sont pas joignables depuis
    l'interface interne (nftables : pas d'exception pour 9090, rejet en entrée) ; la CA publique est servie aux
    agents sur `http://<passerelle>:3128/ca.crt`. En mode `proxy-dns` (Kubernetes), la NetworkPolicy ne doit pas
    ouvrir 9090 aux agents.
14. **Déploiement.** `deploy/docker/Dockerfile.gateway` (multi-étapes, binaire seul, nftables + iproute2, racine
    pour `nft` et `:53`), `gateway-entrypoint.sh` : `ip_forward=1` vérifié, `send_redirects=0` (tenté) et
    redirections ICMP sortantes supprimées par nftables, table `inet afw` (prerouting : ports de service de la
    passerelle acceptés, TCP → `:15001`, UDP 53 → DNS ; forward `policy drop` ; input : UDP ≠ 53 rejeté). Toute
    erreur arrête le conteneur. Interfaces internes : `AFW_INTERNAL_IFACE` ou déduites de `AFW_INTERNAL_SUBNETS`.

## Conséquences
- Dépendances ajoutées à la crate (toutes déjà au workspace) : hyper, hyper-util, http, http-body-util,
  tokio-rustls, rustls, hickory-proto, clap, tower, libc, bytes, base64, sha2, regex.
- Le test d'isolement réel (`deploy/docker/isolation-test/run.sh`) remplace le test `#[ignore]` nftables
  envisagé : il exerce le vrai script d'entrée, `SO_ORIGINAL_DST` et `afw-netinit`.
