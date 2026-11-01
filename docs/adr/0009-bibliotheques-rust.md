# ADR 0009 — Bibliothèques Rust

- Statut : accepté — 2026-10-30

## Décision
tokio, hyper 1 / hyper-util (proxy, HTTP/1.1 et HTTP/2), rustls 0.23 avec le fournisseur `ring` (pas de dépendance cmake), tokio-rustls, rcgen (CA et feuilles), hickory-proto (DNS), axum 0.8 (API), sqlx 0.8 (PostgreSQL), reqwest (clients), clap 4 (CLI), rmcp (MCP), aes-gcm, openidconnect, schemars. Toutes sous MIT et/ou Apache-2.0 (ISC pour ring). Pas de framework de proxy tiers (pingora, rama) : la surface utile est petite et le contrôle de la fermeture par défaut doit être total.
