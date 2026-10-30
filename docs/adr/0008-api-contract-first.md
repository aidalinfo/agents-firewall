# ADR 0008 — API contract-first

- Statut : accepté — 2026-10-30

## Décision
`docs/api/openapi.yaml` est écrit à la main avant l'implémentation et sert de contrat aux lots parallèles. L'API vérifie par un test que chaque route implémentée existe dans le contrat. La console génère ses types avec `openapi-typescript` ; la CLI et le MCP utilisent `afw-client` qui reprend les DTO d'`afw-core`.
