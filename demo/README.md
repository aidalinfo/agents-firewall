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

Console : http://localhost:3000, API : http://127.0.0.1:8080/api/v1. Le jeton d'administration et la clé de
contenu sont générés au premier `up.sh` dans `demo/.state/secrets.env` (0600, jamais commités).

Les agents enrôlés (`docker-compose.agents.yml`) sont **générés par afw-enroll** depuis `agents.base.yml` :
`deploy/tests/enroll-sync.sh --write` après toute modification.

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
| 11-hermes-une-commande | nouveau bot Hermes enrôlé, publié et démarré en une commande (`afw enroll … --apply`), visible et protégé |
| 12-latence | p50/p95 avec et sans passerelle, HTTPS inspecté, connexion nouvelle et réutilisée, médiane de 5 passes |
| 13-agent-vers-agent | aucun chemin direct entre agents (flux interne journalisé ou refus journalisé) |
| 14-tracabilite | flux → agent, conversation, outil, contenu, règle en < 60 s (appel d'outil de daniel-bot) |
| 15-outil-mcp-sortant | un outil MCP stdio qui fait sa propre sortie réseau est bloqué |
| 16-agent-reecrit-politique | un agent ne peut pas écrire la politique par l'API (refus de la passerelle) |
| 17-passerelle-sans-internet | la passerelle ne joint pas example.com, ne résout que par le DNS amont |
| 18-passerelle-arretee | passerelle arrêtée : plus aucun accès (proxy, IP directe, LAN, DNS) ; reprise avec sa révision |
| 19-console-injoignable | API arrêtée : la passerelle applique toujours la révision installée (autorisé, refusé, DLP), journal rattrapé |
| 20-mesures-journal | mesures : refus → flux ouvert par l'API ; appel d'outil → agent, conversation, action, contenu, règle |

Hors démo (production) : migration de Daniel, Laurent et Vulcain et retrait de l'egress-guard actuel (cahier §8).

Un scénario rend `SKIP` quand une brique n'est pas encore disponible (image non construite, commande absente).
Tous les appels à l'API et à la CLI sont dans `demo/lib.sh`. Captures d'écran de la console sur la démo en cours :
`demo/screenshots.sh` (après `run-all.sh`). Tests des fichiers de déploiement :
`deploy/tests/run.sh [static|enroll|netinit|world|images]`.
