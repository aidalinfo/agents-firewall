# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `afw enroll` (Docker Compose, Coolify): the published ports of an enrolled service stay reachable. They used to be
  moved to the `afw-net-<agent>` holder, on an `internal` network where Docker creates no host listener. They are now
  served, verbatim, by an `afw-in-<agent>` relay routed through the gateway's new `afw-ingress` network (inbound TCP
  only, masqueraded; the agent keeps a single interface and route). UDP or non-literal container ports are refused.
  `afw unenroll --apply` removes the orphaned enrollment containers (#22).

### Added

- Specification (*cahier des charges*) and design document.
- Project governance files: license, notice, contributing guide, code of conduct, security policy.
