# ADR 0015 — Plugin Hermes : intégration, protocole d'événements et étage intention

- Statut : accepté — 2026-10-30
- Lot : L4 (`integrations/hermes/`)

## Contexte
EF-34, EF-61, EF-62, conception §7.3, §9 et §15, ADR 0007. Le plugin doit fournir la corrélation
(événements d'appel d'outil) et reprendre les classes d'actions de l'egress-guard avec leur « gate »,
sans dupliquer ce que porte la passerelle (destinations, classes de données).

## Décisions

### Mécanisme Hermes
Vérifié dans la documentation publique de Hermes Agent et dans un plugin réel en service
(`pulse-chat`, Hermes v2026.9.24) :
- plugin = dossier `~/.hermes/plugins/<nom>/` (`plugin.yaml` + `__init__.py` exposant `register(ctx)`)
  ou paquet pip avec le point d'entrée `hermes_agent.plugins` ; activation par `plugins.enabled` ;
- `ctx.register_hook("pre_tool_call"|"post_tool_call", fn)`, testé avec `getattr` (un Hermes ancien
  sans `register_hook` ⇒ avertissement, aucun plantage) ; rappels appelés en arguments nommés
  (`tool_name`, `args`, `task_id`, `session_id`, `tool_call_id`, `result`, `status`, `duration_ms`…) ;
- `pre_tool_call` bloque par le retour `{"action": "block", "message": …}` (le message revient au
  modèle comme résultat d'outil) ; `None` laisse passer ; Hermes émet `post_tool_call` même pour un
  appel bloqué ;
- le contexte de session se lit par `gateway.session_context.get_session_env` (importé
  paresseusement, absent hors Hermes).
Le `plugin.yaml` suit les champs du plugin réel (`name`, `label`, `kind`, `version`, `description`,
`author`, `requires_env`, `optional_env`).

### Mode hook en ligne de commande
`python -m afw_hermes.hook` (alias `afw-hermes-hook`) remplace `hook_entry.py` de l'egress-guard sans
modifier Hermes. Il accepte la charge des hooks shell Hermes et celle de l'egress-guard
(`tool`/`args`), répond `afw_decision` + les deux formes de blocage reconnues par Hermes
(`action/message`, `decision/reason`) et sort en code 2 sur blocage (Hermes bloque sur code 2 même
sans JSON). Il n'appelle jamais le réseau : politique lue en cache disque, événements écrits dans la
file disque, et un processus détaché `python -m afw_hermes.flush` (verrou fichier, un seul à la fois,
au plus un lancement par seconde) envoie la file et rafraîchit la politique. Erreur interne ⇒ code 1,
ce qui laisse l'exploitant choisir via `fail_closed`.

### Protocole d'événements (à l'attention du lot API)
- Chaque appel produit deux envois du même `id` (uuid4) : début (`ended_at`, `status` nuls) puis fin
  (`ended_at`, `status` = `ok` | `error` | statut fourni par Hermes). **L'ingestion doit donc être un
  « upsert » par `id`**, la fin complétant le début. Un appel bloqué n'est envoyé qu'une fois, déjà
  terminé, `status` = `gated` ou `denied`.
- Corrélation début/fin : `tool_call_id` de Hermes s'il existe, sinon (conversation, outil, résumé
  des arguments) en FIFO ; en mode CLI, un fichier par appel en attente (`state_dir/pending/`, purgé
  après 24 h).
- `conversation_id` : `session_id`, puis `HERMES_SESSION_ID`/`HERMES_SESSION_CHAT_ID`, puis `task_id`,
  sinon `unknown`.
- `args_summary` : `clé: valeur; …`, secrets masqués (`***`) par nom de clé et par forme (Bearer/Basic,
  `sk-`, `ghp_`, `AKIA`, `xox?-`, JWT, clé privée PEM, identifiants dans une URL, `password=`…),
  tronqué à 500 caractères. Masquage simple sans empreinte : l'empreinte des secrets (§7.2) reste
  du ressort de la passerelle, qui voit le contenu réel.
- Envoi : file mémoire bornée (10 000, le plus ancien est perdu), lots de 100 au plus toutes les 1 s,
  backoff exponentiel 0,5 s → 30 s, file disque JSONL bornée (5 Mo) rejouée en premier. 401/403/408/
  409/425/429 et 5xx ⇒ réessai ; autres 4xx ⇒ lot abandonné (journalisé). `enqueue` est O(1) : le
  hook ne dépend jamais de la console (mesuré < 50 ms même console endormie).
- Client HTTP : seulement http/https, **aucune redirection suivie** (urllib recopierait
  `Authorization` vers le nouvel hôte), CA privée via `AFW_CA_FILE`. Le jeton d'agent n'est
  **jamais envoyé en `http://`** sauf vers une adresse de bouclage (`localhost`, `127.0.0.0/8`, `::1`),
  une IP privée ou de lien local, ou un nom de service Docker sans point ; sinon la requête est
  refusée localement (avertissement journalisé une fois par hôte) et traitée comme une panne réseau.
- Masquage : toute valeur, de n'importe quel type, placée sous une clé sensible devient `***` ;
  formes de ligne de commande couvertes : `--password X`, `--token=X`, `--secret X`, `-pX`,
  `-u user:pass`, `export VAR_SECRET valeur`. Profondeur limitée à 8 niveaux (au-delà : `[…]`).

### Étage intention
- Format servi par `GET /api/v1/intent-policy` :
  `{"version": int, "action_classes": [{"id","name","tools":[glob…],"patterns":[regex…],"decision"}]}`.
- Sémantique : la classe s'applique si (`tools` vide ou un glob, insensible à la casse, correspond au
  nom de l'outil) ET (`patterns` vide ou une regex trouve une correspondance dans le *sujet* : nom
  de l'outil en 1re ligne, puis une ligne par argument `clé: valeur`, structures imbriquées aplaties,
  normalisation NFKC contre les homoglyphes pleine chasse). `\A` ancre donc sur le nom d'outil, ce
  qui permet d'exprimer « outil `delete_*` » et « commande `rm -rf` » dans une même classe.
- `tools` et `patterns` doivent être des listes (sinon document rejeté). Un même `id` peut figurer
  dans plusieurs entrées, chacune avec sa portée d'outils : c'est ainsi que la politique intégrée
  limite les motifs « commande » aux outils d'exécution.
- Portée des motifs (politique intégrée) : les motifs « commande » (`rm -r`, `rmdir`, `shred`,
  `shutil.rmtree`, `git push --force`/`-f`, `find -delete`, SQL `DROP`/`DELETE FROM`, `-X DELETE` /
  `--request DELETE`, `kubectl`/`docker`/`helm`/`terraform`, `chmod`/`chown`/`GRANT`) ne s'appliquent
  qu'aux outils d'exécution (`terminal`, `shell`, `bash`, `execute_code`, `*exec*`, `*command*`…) ;
  `method: delete` qu'aux outils HTTP (`fetch`, `*request*`, `http*`…) ; les motifs sur le **nom**
  d'outil (`delete_*`, `*_share_*`, `coolify_*`, `freepik_*`) à tous les outils. Pour les outils
  d'écriture de fichiers (`write_file`, `*edit*`, `*patch*`, `create_file`…), les clés de contenu
  (`content`, `patch`, `text`, `body`, `new_string`, `diff`…) ne sont pas inspectées : ce sont des
  données, pas des commandes (évite de bloquer un README qui cite `rm -rf` ou un modèle Django
  `on_delete`). Cette exclusion est faite par le plugin, quelle que soit la politique servie.
- Plusieurs classes ⇒ décision la plus stricte (deny > gate > log > allow), à égalité la première
  dans l'ordre de la politique.
- Validation stricte : un document invalide (version non entière, décision inconnue, regex invalide,
  id manquant) est rejeté **en entier**, la politique précédente est conservée — on ne laisse jamais
  une politique partiellement lue affaiblir le contrôle.
- Repli : politique console (rafraîchie toutes les 60 s en tâche de fond, jamais bloquant) → dernière
  connue en mémoire → cache disque `state_dir/intent-policy.json` (écriture atomique) → politique
  intégrée.
- Politique intégrée prudente : `infra_destructive`, `access`, `irreversible` en **gate** ;
  `paid_generation` en **log** (enjeu de coût, pas de sécurité : on évite la friction, la console
  peut la passer en gate). `access` est en gate car un partage ou un droit élargi est une sortie de
  données différée.
- « gate » = blocage + message « action soumise à validation humaine : <classe> (outil « … ») … »
  (§15). « deny » = blocage + message de refus. Le retour `approve` de Hermes (validation intégrée)
  n'est pas utilisé en V1 : la vraie file de validation est une évolution ultérieure (EF-52).
- La décision est calculée et renvoyée **avant** toute écriture d'événement, dans un bloc séparé :
  un échec de l'enregistrement (file pleine, disque en lecture seule, arguments pathologiques) ne
  rouvre jamais un « gate ». En mode CLI, la réponse et le code 2 sont produits même si la file
  disque est inaccessible. Échec interne de l'évaluation ⇒ évaluation avec la politique intégrée ;
  un hook en processus ne lève jamais d'exception (Hermes bloquerait alors tous les outils).
- Le mode CLI n'effectue aucun appel réseau (pas de rafraîchissement en tâche de fond dans le
  processus du hook) ; seul le processus détaché `afw_hermes.flush` contacte la console.

### Emplacement de l'état
Le répertoire d'état (cache de politique, file disque, appels en attente) est par défaut
`$XDG_STATE_HOME/afw-hermes` (à défaut `~/.local/state/afw-hermes`), **hors** de `$HERMES_HOME` et du
répertoire de travail de l'agent, pour qu'un outil d'écriture de fichiers de l'agent ne le vise pas
par accident. `AFW_STATE_DIR` le remplace (ex. `/var/lib/afw-hermes` dans l'image de démo).

## Conséquences et limites
- **Le cache de politique est modifiable par l'agent** : il tourne sous le même utilisateur que le
  plugin, et un agent qui a un terminal peut réécrire `intent-policy.json` (ou la file disque). C'est
  une limite assumée : l'étage intention est un garde-fou métier contre les erreurs et les
  injections ordinaires, pas une frontière de sécurité. La barrière reste la passerelle, hors de
  portée de l'agent ; un cache altéré est d'ailleurs remplacé au rafraîchissement suivant.
- L'étage intention inspecte du texte : il est contournable (variable, script, MCP qui fait ses
  propres appels). C'est assumé (§2.2) : la barrière est la passerelle ; le plugin apporte le
  « gate » métier et la corrélation.
- La décision `log` n'est pas transmise dans l'événement (le contrat `ToolCallEvent` n'a pas de
  champ dédié) ; elle est journalisée localement. Un champ `action_class` pourra être ajouté au
  contrat plus tard sans casser le format.
- Sans `AFW_CONSOLE_URL`, rien n'est envoyé et la politique intégrée s'applique.
- Le client respecte les variables de proxy de l'environnement : sur un agent enrôlé, l'accès à la
  console passe par la passerelle, qui doit l'autoriser (règle de socle à prévoir par le lot
  politique/enrôlement), ou être exclu via `NO_PROXY`.
