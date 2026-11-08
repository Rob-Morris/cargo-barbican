# Reviewing And Updating Rust Toolchains

Use the direct, already trusted `cargo-barbican` executable when reviewing a
new Rust compiler. Launching it through `cargo` can select or install the
repository's compiler before Barbican starts. Existing trusted tools may run;
the new toolchain needs review and explicit local acceptance first.

Toolchain admission covers official, exact stable Rust distributions. It is
separate from reviewing Cargo-installed applications such as `cargo-audit`.
It does not prove that a compiler is harmless, reproduce its binaries from
source, or establish application compatibility.

## The Workflow

The steps have different jobs:

| Step | Establishes |
| --- | --- |
| `toolchain review` | Authenticated distribution inputs, selected components, expected installed contents and scoped source/security evidence. No candidate execution. |
| `toolchain accept` | Your explicit local acceptance of a completed human review; with repository context, its current policy admission as well. |
| `toolchain install` | A checked handoff of accepted inputs to a qualified, already trusted Rustup, followed by independent installed-content verification. |
| `toolchain adopt` | Current static correspondence for an existing installation. It cannot undo or approve historical execution. |
| `toolchain installation-check` | Current correspondence of the installed files to the accepted distribution. |
| `toolchain admission-check` | Applicable repository admission and local installed correspondence. |
| `toolchain activate` | A separate, explicit edit of the repository's canonical toolchain pin. |
| `toolchain check` | Existing runtime conformance to the pin. It executes trusted tools and is not a substitute for admission. |

Use `cargo-barbican toolchain --help` and each subcommand's `--help` for exact
arguments. Choose an exact stable release; floating `stable`, beta, nightly,
custom toolchains and source builds are outside the admission feature.

Use `--repo <governance-root>` when the current directory is not the actual
repository root. Use `--standalone` deliberately for personal review and
acceptance without repository admission; activation always needs a repository.

Before the first repository review, set a stable admission scope in
`barbican.toml`:

```toml
[toolchain]
admission_scope = "your-organisation/your-repository"
```

Defaults do not set a scope. Repository acceptance requires it to publish
admission; without it, acceptance retains the personal decision but refuses
repository publication. This does not enable admission enforcement for the
existing pin: `require_admission` is a separate opt-in described below.

From the governance root, start a review without changing the current pin:

```sh
cargo-barbican toolchain review <exact-stable-release>
```

Repository declarations determine supported components and targets. An absent
profile means `minimal`; `default` and explicitly supported additions are also
available. The review reports the complete effective selection. It cannot
silently discard requested components or accept extra installed files.

Read the collected sources and findings and complete the generated review
record. Its exact identity lines and assessed findings/unknowns bind your
decision to this investigation and policy. Removing `PENDING` markers alone
is not a review. Explain applicability and accepted uncertainty in the
rationale, then accept that exact review:

```sh
cargo-barbican toolchain accept <review-id> --record <completed-review.md>
```

An investigation is reusable evidence. Personal acceptance, repository
admission and an installation are distinct. Another repository must apply
its own current policy; another user or CI runner must explicitly establish
its own local acceptance. A checked-in record or restored cache cannot grant
that local acceptance by itself.

After acceptance, use a qualified Rustup executable for installation, or
statically adopt an existing matching installation:

```sh
cargo-barbican toolchain install <review-id> --rustup-executable <absolute-trusted-rustup-path>
cargo-barbican toolchain adopt <review-id>
```

These are alternatives, not a required sequence. Native installation may
internally probe `rustc`, so acceptance and exact input checks happen before
Rustup is invoked. Verification after installation does not retrospectively
authorise a first execution.

Finally, activate the admitted, verified toolchain deliberately:

```sh
cargo-barbican toolchain activate <review-id>
```

Activation preserves unrelated supported TOML declarations and changes the
repository pin. It does not build or test the project, install missing tools
implicitly, or change an existing global default. Run the existing explicit
verification or release gate afterwards to assess compatibility.

## Repository Governance And Gates

After accepting and installing or adopting the toolchain, deliberately opt
in to admission enforcement. Keep the scope established before review:

```toml
[toolchain]
require_admission = true
admission_scope = "your-organisation/your-repository"
```

The scope belongs to current repository governance. It is not taken from a
copied admission record. Release age uses the existing
`[release_age].minimum_days` setting, which defaults to seven days. A
toolchain's evidence or exception cannot grant permission to a crate family.

Standalone operations may explicitly choose `--min-age-days`. Repeat that
choice on each operation that uses the review: it is an invocation override,
not a saved default or permanent waiver. Omitting it applies the ordinary
seven-day policy and can cause a policy mismatch with an overridden review.
Repository-context operations use checked-in `release_age.minimum_days` and
exact scoped exceptions; they refuse an invocation override before collecting
an unusable review.

For opted-in execution gates, static admission and installed correspondence
must pass before Cargo workspace discovery or candidate probes. Ambiguous
nested workspaces require the actual governance root, supplied with
`--repo <root>` or by changing to that root. A legacy configuration without
admission opt-in retains its existing conformance checks.

## Fresh Evidence And Continuing Use

New acceptance, repository admission, installation and first adoption require
online evidence by default. Disconnected admission is an explicit exception
for one operation:

```text
--cached-admission --cache-reason <reason>
```

Every required mutable source must have a successful matching observation no
more than 24 hours old, or younger when its own expiry requires it. The oldest
required observation controls the deadline. There is no automatic fallback
or saved cached mode. Copying, rereading or accepting evidence does not renew
its collection time; incomplete, changed or security-invalid evidence blocks.

Ordinary continuing use of an unchanged local admission does not expire
merely because 24 hours pass. It still checks current policy, any explicit
review deadline, known adverse information, source expiry and actual
installed contents. That continuing-use status cannot authorise a new
repository, installation or consumer context.

## Trust And Storage

`toolchain trust show` displays the per-user approved public distribution
baseline. `toolchain trust refresh` retrieves a proposal; material changes
need explicit `toolchain trust approve <proposal-id>`. An unchanged refresh
does not require a new approval or change the original approval time. A
bundled Barbican baseline update is also a proposal when it changes existing
local material. Conflicts and authenticated adverse observations are
preserved. No private signing keys or personal GPG configuration are needed.

On macOS, durable toolchain records live under
`~/Library/Application Support/cargo-barbican` and disposable downloads under
`~/Library/Caches/cargo-barbican`. Linux uses the corresponding XDG data and
cache roots. Explicit `--data-dir` and `--cache-dir` are available for
operators and CI. These must be separate private roots outside repository
governance; a repository cannot silently redirect global approval through
Cargo configuration. Cache deletion loses downloads, not approval. Cache
restoration supplies bytes, not approval.

Completed portable evidence and review prose are published under
`docs/dependency-reviews/toolchains/` and referenced by exact digests in
`[[rust.toolchains]]` entries of `reviewed-targets.toml`. Review those files
and policy changes together. They contain portable evidence, not a private
installation path or another machine's installed-content receipt.

## Installation Edges And Recovery

Existing defaults, unrelated toolchains and repository edits are preserved.
When Rustup has no default, installation refuses unless you explicitly choose
`--allow-initial-default`. If that owned first assignment is followed by a
supported failure, Barbican attempts native default unsetting only while the
assignment still matches its captured state. A conflicting external edit is
preserved and reported. Installed files remain for inspection; this is not a
transactional rollback of installation or prior execution.

Use one writer. Changed inputs, symlinks, unknown extra files, modified
payloads, unsupported metadata or an unqualified evaluator cause refusal.
Inspect the reported retained state and correct the cause before retrying;
do not delete files merely to make a check pass. Existing installations with
recognised extra components need an explicitly expanded review.

Native handoff and installed mapping are enabled only for qualified
host/evaluator/encoding combinations. Other combinations fail explicitly.
Reviewing metadata for a host does not qualify its installer. See the
subcommand diagnostics for the required evaluator; do not work around a
refusal by running the candidate to identify it.

The current qualified evaluator is native macOS ARM64 Rustup 1.29.0, exact
executable SHA256
`16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496`
(the reviewed Homebrew 1.29.0_1 libexec build). The current CLI review route
selects XZ inputs; it does not offer a Gzip selection or fallback.
Barbican does not install that evaluator automatically. A version banner alone
does not qualify a different binary. Authentic installed-output proof covers
native minimal Rust with supported Clippy/rustfmt additions; broader
default/docs and cross-target native scope remain unavailable pending their
own qualification.

## CI Bootstrap

Provision an already trusted Barbican binary and qualified Rustup before
installing or launching the target compiler. Establish explicit local
acceptance from the reviewed portable inputs, install or adopt under current
repository policy, verify local correspondence, then run the existing gate.
Start with empty per-user approval state when testing this sequence. A
cached approval directory is not a substitute for local acceptance.

The existing generated CI template installs Rust before its normal gate; it
does not by itself provide pre-execution admission. Opting into admission
requires the explicit bootstrap above before that install or any Cargo
launcher. See [CI](ci.md) and [hardening](hardening.md) for the existing gate
boundaries.
