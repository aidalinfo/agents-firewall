# AGENTS.md — instructions for coding agents

This file briefs any coding agent (Claude Code, Codex, Hermes…) working on this repository.
`CLAUDE.md` points here.

## Project

**agents-firewall** is an open-source (Apache 2.0) firewall for AI agents: centrally managed
egress control, full traffic visibility (TLS inspection) and audit for fleets of LLM agents.
Status: **design done, build starting.**

## Read first (sources of truth)

1. `docs/cahier-des-charges.md` — specification: requirements `EF-xx` / `ENF-xx`, success
   criteria (section 8), deliverables (section 9), open points (section 10).
2. `docs/superpowers/specs/2026-10-30-agents-firewall-design.md` — design. Decisions tagged
   **[Killian]** are the product owner's and must not be changed without asking. Decisions
   tagged **[proposition]** are design choices you may refine with justification. Section 14
   lists what is left to the builder; section 15 holds clarifications from review.
3. `CONTRIBUTING.md`, `SECURITY.md`, `NOTICE`.
4. `docs/prompts/build-goal.md` — the full build brief (goal, method, constraints, definition of done).

The documentation is written in French. Code, identifiers, commit messages and code comments
are in English.

## Non-negotiable decisions

- Gateway, control-plane API, `afw` CLI and MCP server in **Rust** (cargo workspace in `crates/`).
  Web console in **Nuxt 4 + Nuxt UI** (`console/`), client generated from the OpenAPI spec.
  Hermes plugin in Python (`integrations/hermes/`). Deployment files in `deploy/`.
- **API first**: nothing exists only in the UI; CLI and MCP have the same reach.
- **Default deny**, immediate and explicit denial; the gateway never fails open.
- Policy = shared **baseline** + **zones** (VLAN-like). No per-agent exceptions; a rule's source is a zone.
- Check Point–style management: objects, ordered rulebase, sessions, publish, install, revisions.
- Maximum traffic detail by default (TLS inspection), secrets masked before storage.
- **Internal flows**: monitoring and alerts only by default (no SSH relay, no per-action blocking
  of admin APIs). Blocking stays possible through explicit rules.
- **LLM provider** destinations: logged in detail, exempt from data-class blocking.
- A single approved agent may use the admin MCP; it can never change rules that apply to itself.
- Every change audited in a hash-chained, append-only log.
- Enrollment for Docker Compose, Coolify-managed containers and Kubernetes pods.
- Nothing specific to Pulse myIT in the core.

## Working rules

- Never push to `main` directly. Work on branches, open a PR per milestone. `dev` is the
  integration branch.
- Conventional Commits, signed off (`git commit -s`).
- TDD. For anything security-sensitive (rule engine, TLS, isolation, auth, audit), write the
  bypass tests first.
- Before pushing: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and the
  console's lint and tests.
- Third-party code: Apache-2.0-compatible only, original header kept, entry added to `NOTICE`.
- Ask before: contradicting a **[Killian]** decision, adding a dependency with an incompatible
  license, publishing anything (release, image, package). Open points not to decide alone:
  final project name, first deployment location.
