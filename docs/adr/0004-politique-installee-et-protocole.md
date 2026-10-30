# ADR 0004 — Politique installée et protocole passerelle ↔ console

- Statut : accepté — 2026-10-30

## Décision
- La politique installée est un document JSON `InstalledPolicy` (format 1) : la révision publiée complète (objets résolus, zones, agents, règles, inspection, réglages) + empreinte SHA-256 du JSON canonique. La passerelle compile ce document localement ; empreinte fausse ou format inconnu ⇒ document rejeté, dernière politique valide conservée, ou tout refuser s'il n'y en a aucune.
- Modèle « pull » : la passerelle interroge la console (`GET /gw/v1/policy?have=<rev>`, long-poll 25 s), accuse réception (`POST /gw/v1/policy/ack`), envoie ses événements par lots et un battement de cœur qui rapporte des commandes (capture, réinstallation, auto-test). Installer = fixer la révision désirée d'une passerelle ; le résultat par passerelle vient de l'accusé.
- Transport HTTPS avec authentification mutuelle : la console a sa propre autorité ; une passerelle s'enregistre avec un jeton à usage unique (15 min) et une CSR, reçoit son certificat client. La clé privée de la passerelle et celle de sa CA d'inspection ne quittent jamais son hôte (ENF-02, ENF-03).
- La politique est persistée sur disque par la passerelle : console injoignable ⇒ dernière politique appliquée (EF-23).
