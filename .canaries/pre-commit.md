# Pre-Commit Canary

Local receipt for contributor checks that are subjective or policy-driven. The
pre-commit hook also runs objective checks before validating this receipt.

## Tasks

[1] Verification: `sh scripts/verify.sh` was run with no flags. Do not
substitute the raw cargo/audit/deny command sequence for this dogfooded gate.
Off `main` only, `sh scripts/verify.sh --vanilla` or
`sh scripts/verify.sh --skip REASON` may be used when the repo is in a known
intermediate state; record the command and reason below.
`VERIFY_BRANCH_OVERRIDE` exists only for tests and controlled local validation
of the branch guard; do not use it for normal commit verification.
[2] Dependency provenance: any direct dependency change, dependency-tool install, or `deny.toml` policy change has a checked-in record under `docs/dependency-reviews/`.
[3] Docs routing: if docs were added, moved, removed, or materially changed, the relevant `README.md` indexes and cited standards/contributor docs were updated.
[4] Doc version consistency: `scripts/check_doc_versions.sh --staged` passes for the staged commit, including README badges, install tags, Rust toolchain badge, and shipped template sync headers.
[5] Version bundle: if the shared repo version changed, both crate manifests, `docs/CHANGELOG.md`, and the matching `docs/changelog/vX.Y.Z.md` entry were updated together.
[6] Commit subject: the subject was drafted against `docs/standards/commit-messages.md`, and any versioned subject reuses the canonical changelog `Summary` verbatim.

## Log

Write one line per task before committing. Leave `.canary--pre-commit`
unstaged and untracked.

Example:

```text
[1] Verification: done, sh scripts/verify.sh passed
[2] Dependency provenance: done
[3] Docs routing: done
[4] Doc version consistency: done
[5] Version bundle: skip, no version change in this commit
[6] Commit subject: done
```
