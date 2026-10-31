# ADR 0027 — Recette de bout en bout : sémantique vérifiée, mesures et captures

- Statut : accepté
- Date : 2026-10-31
- Lot : L13

## Contexte

L'environnement `demo/` (ADR 0024) a été écrit avant que la passerelle, l'API, la console et le plugin soient
fusionnés. Joué pour la première fois sur `dev`, il a révélé des écarts d'intégration (configuration) et des
scénarios dont l'attente ne correspondait pas à la sémantique réelle du plan de données (ADR 0017). Il fallait
trancher, pour chaque écart, entre corriger le produit et corriger le scénario, sans affaiblir la preuve.

## Décisions

1. **Corrections produit (petites, testées).**
   - `afw-api` : `AFW_PKI_DIR` vaut par défaut `$AFW_STATE_DIR/pki` (l'ancien défaut `/var/lib/afw/pki` n'est pas
     inscriptible par l'utilisateur 10001 de l'image : l'API refusait de démarrer) ; `AFW_CONSOLE_CA_EXPORT` copie
     le seul certificat public de la CA console (0644, écriture atomique) pour le premier contact des passerelles
     (`AFW_CONSOLE_CA_FILE`). Les fichiers compose et Helm supposaient déjà cette variable.
   - Compose, Helm, démo : `AFW_GW_SERVER_NAMES` (nom réellement lu) au lieu de `AFW_PUBLIC_HOSTNAMES`.
   - Démo : console en même origine (`NUXT_PUBLIC_API_BASE` vide, `NUXT_API_PROXY_TARGET=http://afw-api:8080`,
     ADR 0014 §9) ; jeton du plugin de daniel-bot rechargé avant le démarrage des agents ; agents rattachés à la
     passerelle de démo ; générateurs aléatoires insensibles à `SIGPIPE` sous `set -o pipefail`.
2. **Sémantique retenue dans les scénarios (le produit est conforme, l'attente était fausse).**
   - **HTTPS par le proxy explicite** : le refus a lieu sur le `CONNECT` (403 + `X-Agents-Firewall: denied` + message
     EF-21 dans le corps). curl affiche alors `http_code=000` et `http_connect=403`, et n'affiche jamais le corps
     d'un `CONNECT` refusé : les scénarios lisent le statut du `CONNECT` (`http_code_cmd`) et le message EF-21 sur le
     fil (`nc`). La règle implicite finale est nommée `default-deny` dans le message (`afw-engine`).
   - **`Host` usurpé en HTTP clair vers une IP interdite** : le flux porte le nom de `Host` et la passerelle se
     connecte à l'adresse résolue de CE nom (ADR 0017 §5-6), jamais à l'IP visée. Rien n'atteint la cible ; la
     requête peut atteindre `allowed.example`, destination autorisée : ce n'est pas un contournement.
   - **Écoute transparente** : toute connexion TCP est acceptée localement par la passerelle avant la décision, donc
     `nc -z` « réussit » toujours. Une sonde d'accessibilité doit obtenir une réponse du service : requête
     `SSLRequest` PostgreSQL (un serveur joignable répond `S`/`N`), avec un témoin positif sur la base du LAN.
   - **Agent agréé (scénario 10)** : tant que `afw-mcp` n'est pas fusionné, les mêmes appels sont faits en REST avec
     le MÊME jeton `mcp_agent` ; l'API applique EF-51 et trace l'interface `mcp` d'après le rôle du jeton, quel que
     soit le transport. Le résultat l'indique (« repli REST ») ; à rejouer avec `afw-mcp`.
3. **Scénarios ajoutés** : 18 (passerelle arrêtée : plus de réseau, reprise avec la révision installée), 19 (API
   arrêtée : la passerelle applique toujours refus, autorisations et DLP, et livre ses événements au retour),
   20 (mesures du journal par l'API).
4. **Latence (ENF-01)** : HTTPS inspecté (TLS terminé, analysé, re-chiffré) par le proxy explicite contre un client
   direct sur le réseau `wan`, connexion nouvelle (une poignée de main par requête) et réutilisée (keep-alive, premier
   transfert exclu) ; 5 passes de 50 requêtes, passerelle et direct alternés, après un tour de chauffe ; on publie la
   médiane des p50/p95 des passes. Le seuil reste p95 du surcoût < 100 ms en connexion nouvelle.
5. **Captures** : spec Playwright dédiée (`console/e2e/recette.spec.ts`, ignorée sans `AFW_RECETTE`), lancée par
   `demo/screenshots.sh` dans `mcr.microsoft.com/playwright:v1.64.1-noble` (version de `@playwright/test`) sur le
   réseau `publish`, après `run-all.sh` : les écrans montrent les données des scénarios. Le parcours « Autoriser »
   dans la console est chronométré du clic sur le refus jusqu'au premier passage effectif de l'agent (sonde toutes
   les 500 ms).

## Conséquences

- Les preuves sont versionnées dans `docs/rapport/recette/` et `docs/rapport/captures/`.
- Constats laissés aux lots concernés (pas de correction ici, hors périmètre ou changement de comportement) :
  un `CONNECT` refusé est journalisé comme flux TCP vers `0.0.0.0:443` affiché « connexion refusée (RST) » alors que
  l'agent a reçu un 403 explicite ; la console affiche « connexion refusée (RST) » pour une requête HTTP refusée
  par 403 ; le journal d'audit est listé du plus ancien au plus récent (les dernières modifications sont derrière
  « Charger plus ») ; la plupart des clients HTTPS n'affichent pas le message EF-21 d'un `CONNECT` refusé (seul le
  statut 403 est visible de l'agent, le message reste lisible dans le journal).
- Scénarios 10 et 11 à rejouer avec la CLI (`afw-mcp`, `afw enroll compose`) après fusion des lots L8/L9.
