<div align="center">

# agents-firewall

**An open-source firewall for AI agents: centrally managed egress control, full traffic visibility and audit for fleets of LLM agents.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: V1 in progress](https://img.shields.io/badge/status-V1%20in%20progress-orange.svg)](#status)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Français](README.fr.md) · [Documentation (FR)](#documentation) · [Specification (FR)](docs/cahier-des-charges.md) · [Design (FR)](docs/superpowers/specs/2026-10-30-agents-firewall-design.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## Why

AI agents read untrusted content (emails, web pages, documents) and hold tools that reach the network (shell, HTTP fetch, email, MCP servers, scripts they write themselves). A single **prompt injection** is enough to make an agent exfiltrate private data. When an agent combines *access to private data*, *exposure to untrusted content* and *the ability to communicate externally* — the so-called **lethal trifecta** — a leak is only a matter of time.

The most reliable way to break the trifecta is to **control what leaves**. Guardrails that live *inside* the agent (prompt rules, SDK hooks that inspect tool arguments) can be bypassed by the very agent they are meant to watch: a URL hidden in a variable, a script, or an MCP server making its own calls goes straight through.

**agents-firewall** enforces policy **on the network**, outside the agent, and manages it like an enterprise firewall.

## What it does

- **Unbypassable egress control** — every enrolled agent container reaches the outside world *only* through a gateway. Default deny. Denials are immediate and explicit, so the agent can explain what happened.
- **Enterprise-grade policy model** — inspired by Check Point: reusable objects, zones (VLAN-like groups of agents), an ordered rulebase with a shared baseline layer, sessions, publish & install, revisions, rollback, hit counts, "where used".
- **Maximum visibility** — every flow, DNS query and HTTP request/response (TLS inspection), with on-demand packet captures, all **correlated with the agent tool call and conversation** that triggered them.
- **Data-aware rules** — block requests by data class (secrets, infrastructure inventory, commercial data), not only by destination. Secrets are masked before logs are stored.
- **Internal traffic monitoring** — agent-to-agent, LAN, databases, Kubernetes/Coolify/Docker admin APIs, with lateral-movement detection and an internal flow map.
- **API-first** — everything the web console does is available through the API, the `afw` CLI and an **MCP server**, so a single approved admin agent can operate the firewall. Every change is audited in a tamper-evident log.
- **One-command enrollment** — `afw enroll <container>` for Docker Compose, Coolify-managed containers and Kubernetes pods. First-class integration with [Hermes](https://github.com/NousResearch) agents.

## Architecture

```
          ┌──────────── Management console (control plane) ────────────┐
          │  afw-api: REST /api/v1 (OpenAPI) · gateway routes /gw/v1   │
          │  Nuxt web console · `afw` CLI · admin MCP server           │
          │  PostgreSQL (config, audit) · logs: PostgreSQL/ClickHouse  │
          └──────────────▲─────────────────────────▲───────────────────┘
       policy (pull,     │ mTLS                    │ events, heartbeat
       signed revision)  │                         │
   ┌──────── Agent host ─┴─────────────────────────┴───────────────────┐
   │  afw-gateway (one per host, Rust)                                 │
   │   explicit proxy :3128 · transparent TCP :15001 · DNS :53         │
   │   TLS inspection · rule engine · secret masking · pcap capture    │
   │        ▲ the only route out (internal Docker network or           │
   │        │ Kubernetes NetworkPolicy); no gateway = no network       │
   │   [agent A]   [agent B]   [agent C]   + Hermes plugin (intent)    │
   └───────────────────────────────────────────────────────────────────┘
```

| Component | Technology | Location |
|---|---|---|
| Gateway (data plane) | Rust | `crates/afw-gateway` |
| Control plane API | Rust (axum, sqlx) | `crates/afw-api` |
| `afw` CLI, MCP server | Rust | `crates/afw-cli`, `crates/afw-mcp` |
| Rule engine, DLP, TLS, enrollment | Rust libraries | `crates/afw-engine`, `afw-dlp`, `afw-tls`, `afw-enroll` |
| Web console | Nuxt 4 + Nuxt UI | `console/` |
| Agent integration | Hermes plugin (Python); network-only mode for any container | `integrations/hermes/` |
| Deployment | Docker Compose, Helm chart | `deploy/` |
| Storage | PostgreSQL; ClickHouse for large fleets; filesystem or S3-compatible storage for captures | |

Key design decisions are recorded as [ADRs](docs/adr/README.md).

## Status

🚧 **V1 under construction.** The specification, design, implementation plan and architecture decisions are done; the components are being built in parallel and merged into the `dev` branch. Nothing is ready for production yet, and no release or image has been published.

- [Specification — *cahier des charges*](docs/cahier-des-charges.md)
- [Design document](docs/superpowers/specs/2026-10-30-agents-firewall-design.md)
- [V1 implementation plan](docs/superpowers/plans/2026-10-30-agents-firewall-v1.md)
- [Instructions for coding agents](AGENTS.md)

## Quick start (local demo, coming soon)

Once the V1 lands, a self-contained demo environment will run everything on one machine, with no Internet access needed: console, API, one gateway with two zones, three fake agents (one of them a Hermes agent), a fake LLM provider and an exfiltration target.

```sh
demo/up.sh                 # build images, start, create and install the demo policy
# console: http://localhost:3000
demo/scenarios/run-all.sh  # run the acceptance scenarios (bypass attempts, "Allow" in < 2 min…)
demo/down.sh
```

## Documentation

The documentation is written in French.

| Guide | Content |
|---|---|
| [Installation](docs/installation.md) | console (Compose, Helm), gateway, registration token |
| [Enrollment](docs/enrolement.md) | Docker Compose, Coolify, Kubernetes, Hermes, unenroll |
| [Policy model](docs/modele-de-politique.md) | objects, zones, baseline, evaluation order, inspection, data classes, publish & install |
| [Operations](docs/exploitation.md) | logs, "Allow", alerts, captures, retention, backup, upgrades, outages |
| [Security](docs/securite.md) | threat model, fail-closed, isolation, audit, known limitations |
| [API](docs/api.md) · [CLI](docs/cli.md) · [MCP](docs/mcp.md) | automation interfaces |
| [Migrating from egress-guard](docs/migration-egress-guard.md) | from an in-agent hook to network enforcement |

## How it compares

| | Scope | Central fleet console | Firewall-style policy (objects, zones, publish/install) | Admin MCP |
|---|---|---|---|---|
| [StrongDM Leash](https://github.com/strongdm/leash) | One developer's coding agent, local | — | Cedar policies | — |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | Agent egress proxy with deep content scanning | — | Built-in detection | — |
| **agents-firewall** | Fleets of always-on agents across hosts | ✅ | ✅ | ✅ |

We learn from both projects and gratefully acknowledge them (see [NOTICE](NOTICE)).

## Contributing

Contributions, ideas and feedback are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

Found a security issue? Please **do not open a public issue**: see [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 Aidalinfo / Pulse myIT and contributors.

<sub>Keywords: AI agent firewall, LLM agent security, egress filtering, egress proxy, prompt injection, data exfiltration prevention, DLP, MCP security, Model Context Protocol, TLS inspection, zero trust for AI agents, agent observability, audit log, Rust, Nuxt.</sub>
