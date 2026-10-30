# Environnement de recette

Démo locale et hermétique d'agents-firewall (aucun service Internet) : une passerelle, deux zones (`internes`
en application, `clients` en observation puis application), trois agents (`daniel-bot` Hermes, `laurent-bot`,
`acme-bot`), un LAN simulé (`internal-db`) et un « Internet » simulé (faux fournisseur LLM, cible
d'exfiltration, API autorisée, faux S3, DNS de démo). Conception : `docs/adr/0024-deploiement-et-demo.md`.

```sh
demo/up.sh                    # construit les images en local, démarre, enregistre la passerelle, installe la politique
demo/scenarios/run-all.sh     # joue les scénarios -> demo/.state/results.json et results.md
demo/scenarios/run-all.sh 01 05   # un sous-ensemble
demo/down.sh [--purge]        # arrête (et efface volumes et état avec --purge)
```

Console : http://localhost:3000 (jeton `afw-demo-admin-token`, démo uniquement). API : http://127.0.0.1:8080/api/v1.

| Scénario | Vérifie |
|---|---|
| 01-refus-immediat | 403 explicite, en-tête et message EF-21, journal, rien reçu par la cible |
| 02-autoriser-depuis-le-journal | « Autoriser » → publier → installer → nouvel essai OK en < 2 min |
| 03-contournement-variable | URL cachée dans une variable, base64, wget, Python |
| 04-contournement-script | script Python qui ignore le proxy (urllib, socket TLS, http.client) |
| 05-contournement-proxy-ignore | `--noproxy`, IP directe, Host/SNI, nc, DNS externe, métadonnées, route |
| 06-secret-bloque | secret vers une destination autorisée : coupé et masqué |
| 07-llm-exempte | secret vers le fournisseur LLM : passe, masqué dans le journal |
| 08-mouvement-lateral | balayage de ports interne : alerte `port_scan` |
| 09-publier-installer-rollback | révision installée puis retour arrière, vérifiés par le trafic |
| 10-mcp-agree-audit | agent agréé via `afw-mcp` : zone déléguée tracée, sa propre zone refusée |
| 11-hermes-une-commande | nouveau bot Hermes enrôlé en une commande et visible |
| 12-latence | p50/p95 avec et sans passerelle |
| 13-agent-vers-agent | aucun chemin direct entre agents |

Un scénario rend `SKIP` quand une brique n'est pas encore disponible (image non construite, commande absente).
Tous les appels à l'API et à la CLI sont dans `demo/lib.sh`. Tests des fichiers de déploiement :
`deploy/tests/run.sh [static|netinit|world|images]`.
