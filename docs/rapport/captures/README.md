# Captures d'écran de la recette

Prises le 2026-10-31 sur l'environnement de démo local (`demo/up.sh`), **après** `demo/scenarios/run-all.sh` : les
données affichées sont celles produites par les scénarios (refus, contournements, secret, mouvement latéral, agent
agréé…). Console réelle sur l'API réelle, 1440×900, Playwright `v1.64.1` (`demo/screenshots.sh`,
`console/e2e/recette.spec.ts`). Thème sombre et clair pour les écrans principaux.

| Fichier | Écran |
|---|---|
| `01-connexion.png` | Connexion (jeton d'API ou OIDC). |
| `02-journal-sombre.png` | Journal en direct : refus et acceptations, histogramme, détail du refus sélectionné (daniel-bot → exfil.example). |
| `03-journal-clair.png` | Le même journal en thème clair (refus d'acme-bot puis acceptation après « Autoriser »). |
| `04-flux-refuse-sombre.png` | Détail d'un flux refusé : trace d'évaluation, message reçu par l'agent (EF-21), requête HTTP, bouton « Autoriser ce flux ». |
| `05-flux-refuse-clair.png` | Le même détail en thème clair. |
| `06-flux-refuse-conversation-sombre.png` | Onglet « Agent et conversation » : appel d'outil `fetch` de daniel-bot, conversation, rattachement certain. |
| `07-flux-refuse-conversation-clair.png` | Le même onglet en thème clair. |
| `08-autoriser-formulaire.png` | Formulaire « Autoriser » ouvert depuis un refus d'acme-bot (zone, destination, service, expiration, équivalent CLI). |
| `09-regles-barre-de-session.png` | Base de règles avec la barre de session (règle ajoutée, étapes Modifier → Publier → Installer). |
| `10-publication.png` | Panneau de publication (commentaire, numéro de révision). |
| `11-installation.png` | Résultat de l'installation sur `demo-gw`. |
| `12-regles-sombre.png` | Base de règles (socle + zone clients), compteurs d'utilisation réels. |
| `13-regles-clair.png` | Base de règles en thème clair. |
| `14-agent-daniel-bot-sombre.png` | Vue agent daniel-bot : zone, plugin Hermes (corrélation active), agent agréé MCP, destinations, derniers refus et appels d'outil. |
| `15-agent-daniel-bot-clair.png` | Vue agent en thème clair. |
| `16-flux-internes-sombre.png` | Carte des flux internes et alertes (balayage de ports de laurent-bot, ports sensibles, nouveaux hôtes). |
| `17-flux-internes-clair.png` | Carte des flux internes en thème clair. |
| `18-alertes-mouvement-lateral.png` | Alertes, dont `port_scan` levée par le scénario 08. |
| `19-objets-ou-utilise.png` | Objet `allowed.example` et « où utilisé ». |
| `20-zones.png` | Zones `internes` et `clients` (toutes deux en application, `clients` déléguée à l'agent agréé) avec leurs agents ; liste des objets. |
| `21-audit-sombre.png` | Journal d'audit, dernières entrées : interfaces Console (« Autoriser »), CLI `afw`, MCP (agent agréé) et API, chaîne intègre. |
| `22-audit-clair.png` | Le même audit en thème clair. |
| `23-passerelles-sombre.png` | Passerelle `demo-gw` : en ligne, révision installée, latence ajoutée, installations. |
| `24-passerelles-clair.png` | Passerelles en thème clair. |
| `25-revisions-diff.png` | Révisions et diff (révision 2 : zone clients passée en application), retour arrière. |
| `26-inspection-tls.png` | Inspection TLS (règles d'inspection, CA de la passerelle). |
| `27-parametres.png` | Paramètres. |

Juste avant la prise, `demo/screenshots.sh` fait agir les trois interfaces sur le même refus : la CLI renouvelle le
jeton de l'agent agréé et ouvre le flux, l'agent agréé le lit par `afw-mcp` et prépare une règle dans sa zone déléguée
(non publiée), puis le parcours « Autoriser » de la console est chronométré.
