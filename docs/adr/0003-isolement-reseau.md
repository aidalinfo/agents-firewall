# ADR 0003 — Isolement réseau et interception transparente

- Statut : accepté — 2026-10-30

## Contexte
EF-22 / ENF-07 : un agent ne doit pas sortir sans la passerelle, même s'il ignore la configuration de proxy ; le trafic non HTTP est filtré par la même politique ; si la passerelle tombe, l'agent n'a plus de réseau.

## Décision (Docker)
- Réseau Docker `afw-<passerelle>` créé avec `internal: true` : aucun accès extérieur, aucune route par défaut.
- La passerelle est attachée à ce réseau (IP fixe) et à un réseau de sortie. Elle active `ip_forward`, redirige par nftables tout TCP entrant de l'interface interne vers son écoute transparente (`SO_ORIGINAL_DST`), l'UDP 53 vers son DNS, et `drop` tout autre transfert.
- Chaque agent partage l'espace réseau d'un petit conteneur `afw-net-<agent>` (motif « pause » de Kubernetes) qui seul possède `NET_ADMIN` et pose la route par défaut vers la passerelle et le DNS. L'agent n'a pas `NET_ADMIN` : il ne peut pas changer sa route. S'il redémarre, il retrouve le même espace réseau.
- Variables `HTTP(S)_PROXY` et CA d'inspection posées en plus, pour les clients qui les respectent (meilleure attribution du nom).
- Passerelle arrêtée ⇒ la route pointe vers une IP muette ⇒ aucun réseau (fermeture par défaut).
- Identité d'un agent = adresse IP de son espace réseau sur le réseau interne (unique, fixée à l'enrôlement).

## Décision (Kubernetes)
Passerelle par namespace ; `NetworkPolicy` d'egress n'autorisant que la passerelle ; DNS du pod pointé sur la passerelle, variables de proxy et CA montée ; le trafic qui ignore le proxy suit la résolution DNS de la passerelle et passe donc par elle ; tout le reste est bloqué par la NetworkPolicy.

## Alternatives écartées
eBPF (complexité, privilèges), proxy explicite seul (contournable), `iptables` sur l'hôte (mélange avec les règles Docker et dépendance à l'hôte).
