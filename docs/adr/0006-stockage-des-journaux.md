# ADR 0006 — Stockage des journaux et des contenus

- Statut : accepté — 2026-10-30

## Décision
Trait `LogStore` côté API avec deux implémentations : PostgreSQL (défaut, petits déploiements, tests) et ClickHouse (interface HTTP, recommandé pour la flotte, ENF-04). Les corps HTTP sont masqués par la passerelle puis chiffrés AES-256-GCM par l'API avant stockage ; clé fournie par `AFW_DATA_KEY`. Les captures pcap sont stockées chiffrées sur un stockage objet (système de fichiers ou S3 compatible). Rétention configurable par niveau (flux, HTTP, captures) avec purge périodique.

## Conséquences
La démo utilise PostgreSQL pour limiter la mémoire ; le compose de production propose ClickHouse.
