# ADR 0018 — Nom contrôlé par la politique, DNS filtrant et attribution des flux

- Statut : accepté — 2026-10-31
- Lot : L6

## Contexte
Un agent peut ignorer le proxy, choisir lui-même l'adresse de connexion (SNI d'un domaine autorisé vers une IP
de son choix), réécrire `Host` (domain fronting) ou interroger un résolveur externe.

## Décisions
1. **Le nom gouverne la destination.** Dès qu'un nom est présent (SNI, `Host`, cible `CONNECT`), la passerelle
   décide d'abord sur le nom seul : **un nom refusé n'est jamais résolu en amont** (pas d'exfiltration par la
   résolution). Sinon elle le résout avec son propre résolveur (`AFW_UPSTREAM_DNS`, sinon `/etc/resolv.conf`, sinon `getaddrinfo`), se
   connecte à **cette** adresse et la passe au moteur avec `dst_ip_trusted = true` ; l'adresse choisie par
   l'agent n'est jamais utilisée. Sans nom, l'adresse d'origine est la vraie destination (`dst_ip_trusted = true`).
2. **Métadonnées cloud.** Liste alignée sur le moteur (`169.254.0.0/16`, `100.100.100.200`, `fd00:ec2::254`,
   `metadata.google.internal`, `metadata.goog`, `metadata`) : refusées, même en zone observée, sauf règle Accept
   explicite du **socle** ; le DNS ne renvoie jamais une telle adresse derrière un nom (REFUSED + alerte).
3. **DNS filtrant.** Décision « service DNS » (`udp/53`, `app = dns`) sur le nom. Si seul le nettoyage refuse, le
   nom est résolu quand la politique permettrait de le joindre : essai des services de la politique puis de
   HTTPS/HTTP pour ce nom (y compris `needs_l7`), **sans résolution**. L'acceptation « interne surveillé » d'un nom
   n'est possible que s'il correspond à un objet de catégorie `internal` (décidé par le moteur) ou au nom d'un
   agent enrôlé (`<agent>` ou `<agent>.<domaine>`, accepté si toutes ses adresses sont internes). Tout autre nom :
   `REFUSED` sans aucune requête amont (ex. `<données>.exfil.attacker.test`). Agent inconnu : `REFUSED`. Les réponses A/AAAA sont
   synthétisées (TTL 60 s) à partir du résolveur de la passerelle ; les autres types sont relayés tels quels.
   Le trafic UDP 53 vers n'importe quel résolveur (`dig @8.8.8.8`) est redirigé vers ce DNS par nftables.
4. **Attribution par cache DNS.** Chaque adresse rendue à un agent est mémorisée (agent, adresse) → nom pendant
   10 min ; une connexion L4 sans SNI ni `Host` vers cette adresse est jugée avec ce nom (ex. SSH vers
   `git.example.com`). Les règles doivent donc restreindre les services : un nom accepté « tous services »
   autorise tout port vers les adresses que le DNS a rendues pour lui.

## Alternatives écartées
- DNS ouvert pour tout nom : fuite d'information et résolution de noms d'exfiltration.
- Exiger une règle DNS par destination : double saisie systématique pour l'administrateur.
