# Security Policy

agents-firewall is a security product: we take vulnerabilities seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not report security issues through public GitHub issues, discussions or pull requests.**

Use GitHub's private vulnerability reporting instead:

👉 [Report a vulnerability](https://github.com/aidalinfo/agents-firewall/security/advisories/new)

Please include:

- the affected component (gateway, control plane, CLI, MCP server, console, agent plugin) and version or commit;
- a description of the issue and its impact (e.g. policy bypass, unauthorized rule change, log tampering, secret exposure);
- steps to reproduce or a proof of concept;
- any suggested fix.

## What to expect

- Acknowledgement within **3 business days**.
- An initial assessment within **10 business days**.
- Coordinated disclosure: we will agree on a timeline with you, publish a GitHub Security Advisory with the fix, and credit you unless you prefer to remain anonymous.

## Scope

Particularly relevant:

- any way for an enrolled agent to reach a destination without going through the gateway or without the policy being applied;
- any way for an agent to modify rules that apply to itself;
- tampering with or deleting audit records undetected;
- exposure of captured content or secrets to unauthorized users;
- weaknesses in TLS inspection certificate handling.

## Supported versions

The project is pre-release. Until the first stable release, only the `main` branch receives security fixes.
