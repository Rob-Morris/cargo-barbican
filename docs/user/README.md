# User Documentation

How to adopt and use cargo-barbican from a consumer repo: installation, command
workflows, policy configuration, CI and re-sync, day-2 operations, and
hardening.

- [Adoption](adoption.md) — start here: new/existing projects, review, activation and recovery
- [Command Guide](commands.md) — workflows and per-command usage reference
- [Configuration](configuration.md) — `barbican.toml`, verification runner and `reviewed-targets.toml` reference
- [Reviewed Families](families.md) — discover, inspect and extend exact family scope without completing review
- [Reviewed Git Sources](git-sources.md) — exact source review, offline admission and scanner limits
- [Rust Toolchains](toolchains.md) — pre-execution review, local acceptance, checked installation/component additions and separate activation
- [Integration](integration.md) — install, template, and re-sync model
- [CI](ci.md) — legacy CI, protected-controller admission bootstrap and pre-commit hooks
- [Operations](operations.md) — failing audits, lockfile recovery, routine updates and family lifecycle
- [Hardening](hardening.md) — making the barbican gate hard to bypass
