# Pre-Commit Canary

Local receipt for subjective contributor checks that the hooks cannot infer
from the diff alone.

## Tasks

[1] Verification: `cargo build --locked` and `cargo test --locked` were run, or the skip reason is recorded below.
[2] Delegated inspectors: `cargo audit` and `cargo deny check advisories bans sources` were run when the repo state and local tooling make them applicable, or the skip reason is recorded below.
[3] Dependency provenance: any direct dependency change, dependency-tool install, or `deny.toml` policy change has a checked-in record under `docs/dependency-reviews/`.
[4] Docs routing: if docs were added, moved, removed, or materially changed, the relevant `README.md` indexes and cited standards/contributor docs were updated.
[5] Version bundle: if the shared repo version changed, both crate manifests, `docs/CHANGELOG.md`, and the matching `docs/changelog/vX.Y.Z.md` entry were updated together.
[6] Commit subject: the subject was drafted against `docs/standards/commit-messages.md`, and any versioned subject reuses the canonical changelog `Summary` verbatim.

## Log

Write one line per task before committing. Leave `.canary--pre-commit`
unstaged and untracked.

Example:

```text
[1] Verification: done
[2] Delegated inspectors: skip, cargo-audit not yet installed on this machine
[3] Dependency provenance: done
[4] Docs routing: done
[5] Version bundle: skip, no version change in this commit
[6] Commit subject: done
```
