# Brief de construction (agent « goal »)

Objectif : construire la V1 complète d'agents-firewall, un pare-feu open source pour agents IA,
dans le dépôt https://github.com/aidalinfo/agents-firewall (Apache 2.0).

## Sources de vérité, à lire en entier avant toute chose

- `AGENTS.md` (règles de travail et décisions non négociables)
- `docs/cahier-des-charges.md` (exigences EF-xx / ENF-xx, critères de réussite, livrables)
- `docs/superpowers/specs/2026-10-30-agents-firewall-design.md` (conception, décisions [Killian]
  et [proposition], section 14 « laissé au constructeur », section 15 précisions)
- `CONTRIBUTING.md`, `SECURITY.md`, `NOTICE`

## Méthode

1. Écris d'abord un plan d'implémentation détaillé dans `docs/superpowers/plans/`, découpé en
   jalons livrables et testables, par exemple :
   moteur de règles → passerelle HTTP(S) + DNS + L4 → isolement réseau et enrôlement Docker →
   API du plan de contrôle → journaux et corrélation → console Nuxt → CLI `afw` → serveur MCP →
   plugin Hermes → Coolify et Kubernetes → Helm → import de politique egress-guard.
   Fais valider ce plan avant de coder.
2. Développe jalon par jalon, en TDD, sur des branches, une PR par jalon vers `dev`.
   Ne pousse jamais directement sur `main`.
3. Avant chaque jalon touchant la sécurité (moteur de règles, TLS, isolement, auth, audit),
   écris d'abord les tests de contournement qui doivent échouer.

## Contraintes non négociables

- Passerelle, API, CLI et MCP en Rust (workspace cargo dans `crates/`). Console en Nuxt 4 +
  Nuxt UI (`console/`), client généré depuis l'OpenAPI. Plugin Hermes en Python
  (`integrations/hermes/`).
- API d'abord : aucune fonction disponible uniquement dans l'UI.
- Refus par défaut, refus immédiat et explicite ; la passerelle ne tombe jamais en mode ouvert.
- Pas d'exceptions par agent : socle commun + zones ; source d'une règle = une zone.
- Flux internes : surveillance et alertes seulement par défaut (pas de relais SSH, pas de
  blocage par action des API d'administration).
- Catégorie « fournisseur LLM » : journalisée, exemptée du blocage par classe de données.
- Un seul agent agréé sur le MCP ; il ne peut jamais modifier ce qui s'applique à lui-même.
- Audit de chaque modification, chaîné par empreinte.
- Rien de spécifique à Pulse myIT dans le cœur.
- Code tiers réutilisé (ex. Pipelock, Apache 2.0) : en-tête conservé et entrée dans `NOTICE`.
- Conventional Commits signés (`git commit -s`). `cargo fmt`, `clippy` et tests verts avant chaque push.

## Définition de terminé

Tous les critères de la section 8 du cahier des charges sont démontrés par des tests
automatisés ou une procédure de recette documentée, et les livrables de la section 9 sont
dans le dépôt.

## Arrête-toi et demande avant

- tout choix qui contredit une décision [Killian] ;
- tout ajout de dépendance à licence non compatible Apache 2.0 ;
- toute publication (release, image, package).

Points encore ouverts, à ne pas trancher seul : nom définitif du projet, emplacement du
premier déploiement.
