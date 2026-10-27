# User Documentation

How to adopt and use cargo-barbican from a consumer repo: installation, command
workflows, policy configuration, CI and re-sync, day-2 operations, and
hardening.

- [Adoption](adoption.md) — start here: new/existing projects, review, activation and recovery
- [Command Guide](commands.md) — workflows and per-command usage reference
- [Configuration](configuration.md) — `barbican.toml`, verification runner and `reviewed-targets.toml` reference
- [Reviewed Families](families.md) — discover, inspect and extend exact family scope without completing review
- [Reviewed Git Sources](git-sources.md) — exact source review, offline admission and scanner limits
- [Integration](integration.md) — install, template, and re-sync model
- [CI](ci.md) — GitHub Actions workflow example and pre-commit-hook guidance
- [Operations](operations.md) — failing audits, lockfile recovery, routine updates and family lifecycle
- [Hardening](hardening.md) — making the barbican gate hard to bypass
