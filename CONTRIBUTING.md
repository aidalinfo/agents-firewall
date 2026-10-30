# Contributing to agents-firewall

Thanks for your interest! The project is in its **design phase**: feedback on the specification and the design is the most valuable contribution right now.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Discuss the design** — open a [discussion](https://github.com/aidalinfo/agents-firewall/discussions) or comment on the documents in [`docs/`](docs/).
- **Report a bug or request a feature** — use the [issue templates](https://github.com/aidalinfo/agents-firewall/issues/new/choose).
- **Report a vulnerability** — never in a public issue; follow [SECURITY.md](SECURITY.md).
- **Send a pull request** — see below.

Documentation is currently written in French; English contributions are welcome and will be translated as needed.

## Repository layout (planned)

| Path | Content |
|---|---|
| `docs/` | Specification, design documents, ADRs |
| `crates/` | Rust workspace: gateway, control-plane API, `afw` CLI, MCP server |
| `console/` | Nuxt 4 web console |
| `integrations/hermes/` | Hermes agent plugin (Python) |
| `deploy/` | Docker Compose files and Helm chart |

## Pull requests

1. Open an issue or discussion first for anything non-trivial, so we agree on the approach.
2. Fork the repository and create a branch from `main`.
3. Keep pull requests focused: one change per PR.
4. Add or update tests and documentation with your change.
5. Run the checks locally before pushing (formatting, linting, tests — commands will be documented here as the code lands: `cargo fmt`, `cargo clippy`, `cargo test`, and `pnpm lint` / `pnpm test` for the console).
6. Fill in the pull request template.

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(gateway): add SNI-based destination matching
fix(console): keep log filters when switching agents
docs: clarify the zone model
```

Common types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.

### Developer Certificate of Origin

By contributing, you certify that you wrote the contribution or otherwise have the right to submit it under the [Apache License 2.0](LICENSE), as described by the [Developer Certificate of Origin](https://developercertificate.org/). Please sign off your commits:

```
git commit -s -m "feat: ..."
```

### Reusing third-party code

Code copied or adapted from another project must be under a license compatible with Apache 2.0, keep its original copyright header, and be listed in [NOTICE](NOTICE).

## Security-sensitive changes

This project is a security product. Changes to the rule engine, TLS inspection, isolation, authentication or audit log require a review by a maintainer and tests that demonstrate both the intended behavior and the absence of a bypass.
