# Contributing to cargo-barbican

Guide for anyone working on cargo-barbican.

**Agent contributors:** read [contributor/agents.md](contributor/agents.md)
first for the repo-specific route-map.

## Documentation Layers

This repo follows the
[Agent-Ready Documentation Standard v1.0.0](standards/agent-ready-documentation.md).
Start with [README.md](README.md), which routes to the documentation layers:

- [User](user/README.md) — consumer adoption and integration guidance
- [Functional](functional/README.md) — planned CLI and behaviour contracts
- [Architecture](architecture/README.md) — goals, boundaries, and decision routing
- [Contributor](contributor/README.md) — implementation plan and contributor workflow
- [Standards](standards/README.md) — shared standards adopted by this repo

When you add, move, remove, or rename docs, update the relevant `README.md`
indexes so the routing chain stays explicit.

## When To Update Which Layer

| Change type | Update |
|---|---|
| Consumer adoption or re-sync flow changes | `user/integration.md` |
| Planned subcommand surface, exit codes, or behavioural contract changes | `functional/cli.md` |
| System goals, boundaries, library/binary split, or architectural rationale changes | `architecture/overview.md` |
| Non-obvious architectural decisions that should be preserved historically | add a DD under `architecture/decisions/` and update its index |
| Implementation plan, dependency discipline, or shipped-template boundary changes | `contributor/specification.md` |
| Repo-specific agent workflow or hard stops | `contributor/agents.md` |
| Dependency review policy or record format changes | `dependency-reviews/README.md` |

## Dependency Review Discipline

Every direct dependency change, dependency-tool install, and `deny.toml`
policy change needs a checked-in record under `docs/dependency-reviews/`
before the change lands.

Records may inherit from
[undertask](https://github.com/rob-morris/undertask)'s review records when the
source, version, and trust model match. First-principles reviews are required
for anything outside that inherited set.

## Before Committing

1. `cargo build --locked` passes.
2. `cargo test --locked` passes.
3. `cargo audit` and `cargo deny check` pass once the repo has the required tooling and policy files.
4. Any new dependency has a checked-in review record.
