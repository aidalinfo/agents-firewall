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
  `Authorization` vers le nouvel hôte), CA privée via `AFW_CA_FILE`.

### Étage intention
- Format servi par `GET /api/v1/intent-policy` :
  `{"version": int, "action_classes": [{"id","name","tools":[glob…],"patterns":[regex…],"decision"}]}`.
- Sémantique : la classe s'applique si (`tools` vide ou un glob, insensible à la casse, correspond au
  nom de l'outil) ET (`patterns` vide ou une regex trouve une correspondance dans le *sujet* : nom
  de l'outil en 1re ligne, puis une ligne par argument `clé: valeur`, structures imbriquées aplaties,
  normalisation NFKC contre les homoglyphes pleine chasse). `\A` ancre donc sur le nom d'outil, ce
  qui permet d'exprimer « outil `delete_*` » et « commande `rm -rf` » dans une même classe.
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
- Échec interne de l'évaluation ⇒ évaluation avec la politique intégrée ; un hook en processus ne
  lève jamais d'exception (Hermes bloquerait alors tous les outils).

## Conséquences et limites
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
