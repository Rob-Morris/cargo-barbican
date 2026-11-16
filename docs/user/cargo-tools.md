# Reviewed Cargo Tools

Use an **already trusted** direct `cargo-barbican` executable to review a Rust
binary before allowing its build scripts, proc macros or installed program to
run. `tool` owns review, explicit acceptance, native installation and independent
checks. `toolchain` separately governs the compiler distribution; Gatehouse
continues to compose repository checks and never installs tools automatically.

## Prerequisites and scope

The qualified evaluator is native Cargo/rustc 1.95.0 at their exact upstream
commits, with trusted cargo-deny 0.19.6 and, when selected by policy,
cargo-audit 0.22.1. These tools must already be trusted and installed. Barbican
does not install a scanner or compiler to review its own replacement. Explicit
`--cargo` and `--rustc` paths select already installed regular executables;
Rustup proxies, wrappers and unqualified evaluator tuples are refused.

The native routes target macOS ARM64 and Linux x86-64, resolver 2 or 3, native
host builds, explicit binary targets, and the `release` or `dev` profile.
Unsupported hosts, cross compilation, custom profiles, alternate registries,
unbound external paths, ambiguous graph output and unsupported source layouts
fail closed. Exact Git source materialisation preserves the repository workspace
and auxiliary files. Dependencies requiring several different directory parents
inside one Git repository are currently refused rather than rewritten.

Use direct invocation from a trusted launch context. Starting with ordinary
`cargo barbican` can run a repository-selected compiler before Barbican starts.
The compiler and scanners are trusted evaluators, not candidate tools.

## Review before installation

Run inside the repository whose policy should apply, use global `--repo ROOT`
for an explicit repository, or choose `--standalone` for personal policy:

```bash
cargo-barbican tool review cargo-audit@0.22.1 --standalone
cargo-barbican --repo /absolute/consumer tool review \
  --git https://github.com/Rob-Morris/cargo-barbican \
  --rev FULL_40_HEX_COMMIT --package cargo-barbican
```

Replace `FULL_40_HEX_COMMIT` with the exact immutable commit to review. A source
tree containing unsupported symlinks refuses even if its build would ignore
them. Earlier Barbican source such as v0.41.2 contains a tracked instructions
symlink and does not qualify for this all-entry route; use a conforming source
revision rather than changing the immutable old release.

Review collects and verifies sources, the effective lockfile, selected binary
targets/features and the actual native normal/build dependency graph. It does
not build, install or execute the candidate. `--bin NAME` can be repeated;
`--features a,b`, `--no-default-features`, `--all-features`, `--profile dev` and
the explicit native `--target` become part of the reviewed subject. An omitted
or unusable upstream lockfile requires a separately recorded derived resolution;
the effective lock must be fully reviewed before installation. Install cannot
silently select a new graph.

The result includes a stable review ID, source and detailed dossier directories,
findings, baseline status and a **PENDING** assessment path. Read the actual
sources and dossier; scanner success alone does not establish safety. Registry
packages use the canonical checksum, yank, age, indicator and execution-surface
rules. Git provenance and advisory coverage limits remain explicit; registry
publication age is not invented for Git commits. Licence, ban and source policy
comes from the originating policy, never candidate-controlled configuration.
Unqualified cargo-deny local exception files in candidate/manifest ancestry
refuse: an explicit deny config alone does not suppress that native discovery.

Use `--from INSTALLATION-ID` when updating a tool with a prior Barbican binding.
A missing or invalid baseline reports `baseline-unavailable`; it does not claim
that the old bytes have been reviewed or suppress full new-subject review.

## Review an age or assigned-advisory finding

A blocked dossier can supply the exact bindings for a narrowly reviewed
exception. Select one finding and a finite deadline, for example:

```sh
cargo-barbican --repo /path/to/repo tool exception REVIEW_ID --age \
  --package example-tool@1.2.3 --review-by 2026-12-01 \
  --review-record docs/tool-reviews/example-age.json
```

Use `--advisory RUSTSEC-YYYY-NNNN` in place of `--age` for an assigned advisory.
The command reports candidates if the package/source is ambiguous and prints
a publication command. Paths are relative to the originating repository, or
the private data root with `--standalone`. The deadline covers the whole UTC
date; there is no default. Git, provisional advisories and yanks cannot receive
these exceptions. `--path` and `--rule` are reserved for IOC review.

Edit the generated JSON's `reviewer` and embedded `review_record` prose with
the evidence, exact risk, mitigations and reason for the deadline. Remove all
pending content. Leave `reviewed_at_utc=0` and the derived digest alone; explicit
publication computes them. Then run the printed command, or use:

```sh
cargo-barbican --repo /path/to/repo tool exception REVIEW_ID --age \
  --package example-tool@1.2.3 --record docs/tool-reviews/example-age.json
```

The scaffold grants nothing. Publication finalises that JSON and references it
in `[tools].exception_records`. The file remains live authority: edits/removal
invalidate its previous binding. Publication never rewrites or renews an active
record; remove its reference and deliberately review/re-add if changes are
needed. A failed policy write may leave a completed unreferenced record; retry
preserves valid completion metadata. Commit the policy and record together.

Recollect tool review under the new policy before completing assessment and
acceptance. This authoring step runs no evaluators or scanners and does not
install or grant repository admission. Subsequent review and installation
still check current evidence, source integrity, yanks, coverage, expiry and
all independent findings.

## Review individual IOC findings

Use `tool exception REVIEW_ID --ioc --review-record PATH` to scaffold exact
source/finding rationale from a stored review, including a blocked review.
After deliberate completion, `--record PATH` revalidates the source and attaches
an exact Subject/base-policy grant. It does not accept or install the tool.
Paths are repository-relative, or private-data-root-relative with `--standalone`.
There is no default IOC expiry; an explicit deadline is enforced. Recollect
review after changing policy, and retain independent advisory, age, yank,
checksum, coverage, licence and source blockers. See [exact IOC review](ioc.md)
for selectors, record completion and revocation.

## Complete and explicitly accept the assessment

The generated template names the exact review. Complete every `Response:` field,
the reviewer, risk acknowledgement and decision. The required format includes:

```text
Cargo-Tool-Review: <exact-review-id>
Reviewer: <reviewer identity>
Decision: ACCEPT
Response: source-review=<actual source/provenance assessment>
Response: execution-surfaces=<build scripts, proc macros and native-code assessment>
Response: runtime-use=<intended runtime and capability assessment>
Response: coverage-limitations=<remaining uncertainty and scanner limitations>
Risk-Acknowledgement: <explicit residual-risk acknowledgement>
```

Placeholder text is not completion. Keep the completed record intact: its exact
bytes bind the assessment and local acceptance.

```bash
cargo-barbican tool accept <review-id> --record /absolute/completed.md --standalone
```

Acceptance refreshes online evidence by default. An unchanged successful refresh
preserves the review and prior reviewer assessment; material evidence, policy,
source or evaluator changes require a new review. Blocking findings cannot be
waived by ordinary acceptance prose.

Local acceptance is personal authority. To additionally approve use for a
repository, configure an explicit `[tools].admission_scope` and pass
`--approve-repo --repo-record PATH` with a completed record inside that actual
repository. Supporting immutable evidence is published before `[[rust.tools]]`.
Explicit reapproval of the same subject retains its old bundle and changes only
that subject's declaration. Portable evidence never grants another user local
acceptance. Tool rows do not count as dependency families or satisfy the existing
direct-dependency coverage floor.

## Install the accepted inputs

```bash
cargo-barbican tool install <review-id> --standalone
# Optional explicit ordinary Cargo install root:
cargo-barbican tool install <review-id> --standalone --root /absolute/tools
```

Installation refreshes eligibility, rematerialises exactly accepted sources and
the effective lock, then invokes trusted Cargo with a verified public `--path`
stage and frozen/offline inputs. Normal Cargo roots are retained. Cargo records
the stage as a **path source**; Barbican independently binds original registry
or Git provenance. Native `cargo install --list` therefore cannot reconstruct
that upstream identity, and ordinary update tools may not infer its source.
Use Barbican's stored review and installation IDs for future updates.
Relative `--root` paths resolve from the original invocation directory, before
private Cargo-home staging; the absolute destination is then fixed explicitly.

The accepted build may execute reviewed build scripts/proc macros. It uses
ordinary native compiler/linker semantics, not a sandbox or a reproducible-build
guarantee. All selected published outputs must match reported compiler artifacts
before a complete installation ID is issued. Unselected old outputs are reported
separately and gain no new authority.

For a native-tracked pre-Barbican installation, `--replace-existing` explicitly
allows replacement only after matching the original source/package family and
checking every affected name. Unmanaged collisions and unsupported prior
tracking refuse. A previously Barbican-bound installation must still pass its
own drift checks. Replacing Barbican itself requires an independent already
trusted checker that will survive replacement; the running evaluator must not
be overwritten during its own check.

Native publication can be partial. A failed command reports retained effects
and diagnostic records; it does not invent rollback or publish a complete
binding for incomplete outputs. Keep those diagnostics and reconcile the
reported native state before retrying. Do not clear private records merely to
turn a refusal into success.

After a partial update, the old binding may correctly refuse correspondence.
To continue with the accepted subject, choose a new empty ordinary root with
`tool install <review-id> --root /absolute/new-root`, repeating current
eligibility checks, then check that exact consumer selection. This leaves the
affected root and its history available for deliberate recovery. Restoring a
trusted backup of the prior outputs and native records can re-establish its
old correspondence; a native uninstall or rebuild alone does not prove those
previous byte identities. Automatic repair of an unexplained or partial root
is outside this command's contract.

## Check installation and actual consumer selection

```bash
cargo-barbican tool installation-check <installation-id>
cargo-barbican tool admission-check <installation-id> --standalone \
  --bin cargo-audit --executable /absolute/tools/bin/cargo-audit
cargo-barbican tool admission-check <installation-id> --standalone \
  --bin cargo-audit --lookup-path
cargo-barbican tool admission-check <installation-id> --standalone \
  --bin cargo-audit --cargo-subcommand audit
```

`installation-check` is static and network-independent. It checks every recorded
output and that package's native tracking at the recorded root. It can pass for
an off-PATH installation and says nothing about which program a consumer selects.

`admission-check` requires exactly one selector and `--bin NAME`. It checks the
actual first selected executable, all installed outputs, local acceptance,
current policy, known adverse facts and any separate repository authority.
Cargo selection includes applicable configuration and native Cargo-home
precedence: Cargo prepends its home `bin` only when that directory is absent
from PATH; if present, it keeps its existing position and earlier matches win.
Aliases and builtins are refused. An unsupported first symlink or shim is not
skipped to approve a later file. Interactive shell aliases/functions/hash tables
and future filesystem changes are outside this static process-context check.
Cargo-subcommand admission also resolves the actual first `cargo` on process
PATH and requires its exact protected trusted identity. A Rustup proxy or other
shim is not substituted with the intake evaluator; put the qualified direct
Cargo binary first when using this selector. Admission independently establishes
actual cwd governance: an unrelated `--repo` cannot lend authority, and
`--standalone` cannot bypass the actual opted-in repository. Ambiguous nested
membership refuses with guidance to use the actual root.

## Freshness, storage and automation

Review, acceptance, install and new consumer admission require successful online
evidence by default. Only acceptance/install/admission support an explicit
per-operation `--cached-admission --cache-reason REASON`, bounded by 24 hours
and any earlier source or exception expiry. It is never automatic fallback or
a saved default. Unchanged continuing use still checks policy, correspondence,
deadlines and retained adverse facts without a new-operation age limit.
Cached operations persist their requested reason and exact evidence IDs before
granting authority or installing; the result names that private intent receipt.
It records a request, not proof of success, and never selects cached mode for a
later invocation.
Changing the canonical consumer cwd or governance context requires new admission,
including for direct-path and PATH selectors.
Failed or unfinished source refreshes block relevant old cache until reconciled;
an unrelated package or Git revision cannot clear them.

Global `--data-dir` and `--cache-dir` select private owned storage. Authority and
durable adverse knowledge live under `cargo-tools/v1` in data; disposable
materialisations are separate. Standalone policy may be supplied in
`cargo-tools/v1/policy.toml` and `deny.toml` under that data root. Repository
policy comes from the explicitly discovered filesystem governance root;
candidate Cargo configuration is not adopted as evaluator policy.

Use `--format json` for schema-1 machine results. Exit 0 means the named scoped
operation passed; exit 1 means blocked, unavailable or failed correspondence;
exit 2 means invalid command input. A successful review still requires an
explicit assessment by a human or authorised agent. Existing workspace command
exit contracts are unchanged.

Collection has bounded archives, inventories, process output, records and a
30-minute deadline. Native Git has a per-file pack bound, not an aggregate
quota on opaque Git storage. Build execution is not covered by that collection
deadline or a general disk/process sandbox. Cooperating Barbican writers are
serialised, but hostile concurrent writers and other Cargo processes remain
outside the static one-writer guarantee.
