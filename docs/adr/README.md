# Décisions d'architecture (ADR)

Choix faits par le constructeur pendant la V1 (sections 14 et [proposition] de la conception).
Les décisions **[Killian]** ne sont pas rediscutées ici.

| N° | Titre | Statut |
|---|---|---|
| [0001](0001-organisation-du-depot.md) | Organisation du dépôt | accepté |
| [0002](0002-environnement-de-build.md) | Builds Rust dans un conteneur Linux | accepté |
| [0003](0003-isolement-reseau.md) | Isolement réseau et interception transparente | accepté |
| [0004](0004-politique-installee-et-protocole.md) | Politique installée et protocole passerelle ↔ console | accepté |
| [0005](0005-ordre-d-evaluation.md) | Ordre d'évaluation, flux internes et exemption LLM | accepté |
| [0006](0006-stockage-des-journaux.md) | Stockage des journaux et des contenus | accepté |
| [0007](0007-correlation.md) | Corrélation intention ↔ flux | accepté |
| [0008](0008-api-contract-first.md) | API contract-first | accepté |
| [0009](0009-bibliotheques-rust.md) | Bibliothèques Rust | accepté |
| [0010](0010-integration-git.md) | Intégration : branches de lot et PR vers dev | accepté |
| [0011](0011-contrats-partages.md) | Contrats partagés (lot L0) | accepté |
| [0012](0012-detection-dlp.md) | Détection des classes de données (`afw-dlp`) | accepté |
| [0013](0013-pki-et-inspection-tls.md) | PKI de la console et autorité d'inspection TLS (crate `afw-tls`) | accepté |
| [0014](0014-console-spa-et-couche-api.md) | Console : SPA Nuxt, couche `AfwApi` et données de démonstration | accepté |
| [0015](0015-plugin-hermes.md) | Plugin Hermes : intégration, protocole d'événements et étage intention | accepté |
| [0016](0016-moteur-de-regles.md) | Moteur de règles (`afw-engine`) : sémantique de correspondance et refus en cas de doute | accepté |
| [0017](0017-plan-de-donnees-passerelle.md) | Plan de données de la passerelle : écoutes, aiguillage et pipeline | accepté |
| [0018](0018-nom-controle-dns-filtrant.md) | Nom contrôlé par la politique, DNS filtrant et attribution des flux | accepté |
| [0019](0019-inspection-des-contenus.md) | Inspection des contenus : tampon, flux, WebSocket et décompression | accepté |
| [0020](0020-api-politique-sessions-et-revisions.md) | API politique : stockage, sessions, droits de l'agent MCP | accepté |
| [0021](0021-api-journaux.md) | API journaux : stockage, chiffrement, corrélation, alertes | accepté |
| [0022](0022-api-auth-passerelles-audit.md) | API : authentification, passerelles et ancrage de l'audit (lot L7c) | accepté |
| [0023](0023-enrolement-des-agents.md) | Enrôlement des agents (crate `afw-enroll`) | accepté |
| [0024](0024-deploiement-et-demo.md) | Déploiement (images, Compose, Helm) et environnement de démo | accepté |
| [0025](0025-cli-client-et-serveur-mcp.md) | Client Rust, CLI `afw` et serveur MCP `afw-mcp` | accepté |
| [0026](0026-import-egress-guard.md) | Import de la politique egress-guard (`afw-import`) | accepté |
| [0027](0027-recette-de-bout-en-bout.md) | Recette de bout en bout : sémantique vérifiée, mesures et captures | accepté |
| [0028](0028-mode-de-refus-et-ordre-de-l-audit.md) | Mode de refus des flux, ordre de l'audit et session MCP abandonnée | accepté |
