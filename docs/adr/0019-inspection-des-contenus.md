# ADR 0019 — Inspection des contenus : tampon, flux, WebSocket et décompression

- Statut : accepté — 2026-10-31
- Lot : L6

## Contexte
EF-24/EF-25/EF-35 : analyser avant envoi jusqu'à une taille configurable, puis au fil de l'eau avec coupure ;
ne jamais relayer un secret complet ; masquer avant stockage ; exempter les fournisseurs LLM du blocage.

## Décisions
1. **Corps de requête ≤ `max_buffered_body`** : mis en tampon, décodé (`afw_dlp::decode_content`, gzip/deflate/br,
   sortie bornée à 8 × le tampon) puis analysé avec l'URL et les en-têtes ; re-décision avec les classes ; refus
   = 403 EF-21 sans contacter l'amont. Décodage impossible ou trop volumineux : refus
   (`rule content-inspection`).
2. **Au-delà du tampon** : analyse sans état de la partie déjà lue, puis `afw_dlp::StreamScanner` dans une tâche
   dédiée qui alimente le corps amont : seuls les octets jusqu'à `safe_len()` sont relayés ; le reste n'est
   relayé qu'après un `finish()` sans détection refusée. Détection refusée : le corps amont se termine en erreur
   (requête amont avortée), l'agent reçoit le 403 EF-21, alerte. Un corps compressé trop gros pour le tampon
   est refusé (pas d'analyse incrémentale d'un flux compressé).
3. **WebSocket** : mise à niveau relayée sur une connexion amont HTTP/1.1 dédiée ; côté agent → amont, chaque
   message est reconstitué (trames démasquées, borne `max_buffered_body`, au-delà : coupure) et analysé avec
   les 8 Kio précédents avant que la moindre de ses trames soit relayée : une valeur coupée entre deux messages
   est trouvée avant que le message qui la complète parte. Détection refusée : trame de fermeture 1008 vers
   l'agent, fermeture des deux côtés, alerte. Les trames de contrôle sont analysées seules. Sens amont → agent
   relayé tel quel. (On n'utilise pas `safe_len` ici : retenir la fin d'un petit message bloquerait les
   échanges interactifs.)
4. **Réponses** : relayées sans attente (SSE compris) ; les `max_buffered_body` premiers octets sont analysés
   pour le journal (masquage, constats) ; jamais de blocage sur une réponse.
5. **Fournisseurs LLM** : l'exemption vient du moteur (les règles à classes de données sont sautées) ; les
   constats restent journalisés, masqués, et l'alerte « secret détecté » est levée sans blocage.
6. **Stockage** : contenu masqué avant de quitter la passerelle, tronqué à `max_stored_body` sans couper une
   valeur détectée (coupe avant elle), empreinte SHA-256 du contenu complet non masqué ; en-têtes
   d'authentification et cookies toujours remplacés par une empreinte ; suivi `none` : pas d'événement HTTP,
   `log` : sans corps.

## Limites
- Un flux compressé (`Content-Encoding`) plus gros que le tampon est refusé plutôt qu'analysé.
- Un message WebSocket plus gros que `max_buffered_body` coupe la connexion.
- L'analyse des réponses est limitée aux `max_buffered_body` premiers octets.
