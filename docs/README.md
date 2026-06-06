# Documentation

Root index for cargo-barbican's repo-facing documentation. Start with the
index that matches your task; each layer `README.md` or shared standards index
routes to its artefacts.

## Layer Indexes

- [User](user/README.md) — how to adopt and use cargo-barbican in a consumer repo
- [Functional](functional/README.md) — CLI and behaviour contracts
- [Architecture](architecture/README.md) — goals, boundaries, and design-decision routing
- [Contributor](contributor/README.md) — how to contribute to this repo
- [Standards](standards/README.md) — shared standards adopted by this repo

## Convention-Based Exceptions

- [Contributing](CONTRIBUTING.md) — contributor entry point at the chosen location
- [Changelog](CHANGELOG.md) — shipped version-history index with per-version files under `changelog/`
- [Design Brief](design.md) — compatibility pointer to the canonical design docs
- [Integration Pointer](integration.md) — compatibility pointer to the canonical user integration guide

## Shared Standards

- [Standards](standards/README.md) — index of shared standards
- [Agent-Ready Documentation](standards/agent-ready-documentation.md) — documentation structure standard for agent-effective projects
- [Changelog](standards/changelog.md) — shipped version-history standard for this repo
- [Commit Messages](standards/commit-messages.md) — commit-subject and commit-body standard for this repo

The `templates/` directory at the repo root is shipped content copied into
consumer repos. It is not part of the repo-facing documentation layers.
