# Contributing to agents-firewall

Thanks for your interest! The V1 is **under construction**: the specification, design and implementation plan are written, and the components are being built and merged into the `dev` branch. Feedback on the design and on the user documentation is very welcome.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Discuss the design** — open a [discussion](https://github.com/aidalinfo/agents-firewall/discussions) or comment on the documents in [`docs/`](docs/).
- **Report a bug or request a feature** — use the [issue templates](https://github.com/aidalinfo/agents-firewall/issues/new/choose).
- **Report a vulnerability** — never in a public issue; follow [SECURITY.md](SECURITY.md).
- **Send a pull request** — see below.

Documentation is written in French (user guides in [`docs/`](docs/)); code, identifiers, comments and commit messages are in English. English documentation contributions are welcome and will be translated as needed.

## Repository layout

| Path | Content |
|---|---|
| `Cargo.toml`, `crates/` | Rust workspace ([ADR 0001](docs/adr/0001-organisation-du-depot.md)) |
| `crates/afw-core` | shared contracts: policy model, installed policy, events, gateway protocol |
| `crates/afw-engine` | rule engine (compile, evaluate, verify) |
| `crates/afw-dlp` | data classes, secret detection and masking |
| `crates/afw-tls` | per-gateway inspection CA, console PKI (mTLS) |
| `crates/afw-gateway` | gateway binary (data plane) |
| `crates/afw-api` | control-plane API binary |
| `crates/afw-client`, `crates/afw-cli`, `crates/afw-mcp` | API client, `afw` CLI, admin MCP server |
| `crates/afw-enroll`, `crates/afw-import` | enrollment (Compose, Coolify, Kubernetes), egress-guard import |
| `console/` | Nuxt 4 + Nuxt UI web console (pnpm) |
| `integrations/hermes/` | Hermes agent plugin (Python) |
| `deploy/` | Dockerfiles, Docker Compose files, Helm chart |
| `demo/` | local acceptance environment and scenarios |
| `docs/` | specification, design, plans, ADRs, user guides (French) |
| `docs/api/openapi.yaml` | REST contract, source of truth ([ADR 0008](docs/adr/0008-api-contract-first.md)) |
| `scripts/` | developer scripts (`scripts/cargo.sh`) |

Some of these directories land with the V1 work packages and may not exist yet on `dev`.

## Development environment

Nothing needs to be installed on your machine except **Docker**: every toolchain runs in a container ([ADR 0002](docs/adr/0002-environnement-de-build.md)).

### Rust

`scripts/cargo.sh` runs cargo inside `rust:1.91-bookworm`, with shared registry caches and a `target` volume per checkout:

```sh
scripts/cargo.sh fmt --all --check
scripts/cargo.sh clippy --workspace --all-targets -- -D warnings
scripts/cargo.sh test --workspace            # or: scripts/cargo.sh test -p afw-engine
```

Useful variables: `CARGO_BUILD_JOBS` (default 3), `AFW_DOCKER_MEMORY` (default `3g`), `AFW_DOCKER_ARGS` (extra `docker run` options, e.g. `--cap-add NET_ADMIN` for gateway tests), `AFW_TARGET_VOLUME`.

### Console (Nuxt)

```sh
docker run --rm -v "$PWD":/w -w /w/console \
  -v afw-pnpm-store:/pnpm-store -e npm_config_store_dir=/pnpm-store \
  node:24-bookworm-slim bash -c "corepack enable && pnpm install && pnpm lint && pnpm test"
```

### Hermes plugin (Python)

```sh
docker run --rm -v "$PWD":/w -w /w/integrations/hermes python:3.12-slim \
  bash -c "pip install -q -e '.[dev]' && pytest -q"
```

### Deployment files

```sh
docker run --rm -v "$PWD":/w -w /w alpine/helm:3.16.2 lint deploy/helm/agents-firewall
docker run --rm -v "$PWD":/mnt koalaman/shellcheck:stable demo/*.sh
```

## Pull requests

1. Open an issue or discussion first for anything non-trivial, so we agree on the approach.
2. Fork the repository and create a branch from `dev` (the integration branch). Never push to `main`.
3. Keep pull requests focused: one change per PR.
4. Add or update tests and documentation with your change.
5. Run the checks locally before pushing: `scripts/cargo.sh fmt --all --check`, `scripts/cargo.sh clippy --workspace --all-targets -- -D warnings`, `scripts/cargo.sh test` for the crates you touched, and the console lint, typecheck and tests if you changed `console/` (see [Development environment](#development-environment)).
6. Open the pull request against `dev`.
7. Fill in the pull request template.

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

This project is a security product. Changes to the rule engine, TLS inspection, isolation, authentication or audit log require a review by a maintainer and tests that demonstrate both the intended behavior and the absence of a bypass. Write the bypass tests first: they must fail before the change and pass after it.
