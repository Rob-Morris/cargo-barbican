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

Each selected archive has a component evidence row: authenticated archive identity,
source revision and package relationship, represented advisory corpus, and explicit
coverage limits. Rustc/rustdoc, Cargo, std, docs, Clippy and rustfmt do not acquire
coverage merely by sharing a Rust release. Target-independent `rust-src` uses
the StandardLibrary source relationship and attributes applicable std findings
to both source and binary selections. Its represented lockfile does not cover
every libunwind/vendor/path source; those omissions remain explicit. Docs include a static inventory of
files and embedded JavaScript/CSS; these assets are not executed, and their full
dependency graph and browser behaviour remain for explicit assessment. Missing
required provenance blocks acceptance; a stated residual uncertainty can be
assessed but cannot replace missing evidence.

RustSec records awaiting an assigned advisory number appear as
`rustsec-provisional:<digest>/…` findings. Each digest binds the exact crates
corpus path and original record bytes, so separate issues remain separate even
when they share `RUSTSEC-0000-0000`, a package or aliases. The generated review
shows the original placeholder, source path, exact source commit and affected
status beside each required `Assessed-Finding` line. Read and assess every
issue individually. Provisional status gives no exemption: known applicable
adverse findings still block admission, while unknown reachability uses the
ordinary explicit assessment rules.

A fresh collection after assignment, a path change or a body change requires
new exact-evidence review and acceptance; aliases do not transfer approval.
Retained historical evidence, including an old bare-placeholder finding, keeps
its original identity when loaded. Continuing use checks the existing exact
consumer/admission/installation binding and retained source knowledge and
expiry; it does not poll upstream for assignment. Fresh operations still require
online collection or the existing explicitly bounded cached-admission route.

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

To add supported components to an existing exact-release slot, expand the
repository selection (or the standalone review options), review and accept the
**complete final selection**, then run:

```sh
cargo-barbican toolchain install <final-review-id> --add-components \
  --rustup-executable <absolute-trusted-rustup-path>
```

This mode verifies the whole existing base against the final authenticated
inputs before adding only the missing components. It needs no separate baseline
review ID and grants no historical execution approval. It refuses an absent
slot, removals, unknown extras or changed contents; `--allow-initial-default`
cannot be combined with it. An already complete matching slot is a static
verified no-op, without probing Rustup or requiring fresh creation modes.
The earlier narrower review no longer describes the expanded installed tree;
other repositories must deliberately admit the complete selection themselves.
Failure or cancellation can retain partial additions for inspection, without
a rollback promise. A binding requires complete final verification; cancellation
observed after publication reports and retains the completed binding. Retry only after reconciling
the retained state with the accepted final inputs.

After install or adoption, diagnose installed correspondence or continuing
repository admission with the same review ID:

```sh
cargo-barbican toolchain installation-check <review-id>
cargo-barbican toolchain admission-check <review-id>
```

`installation-check` is static inspection and takes no cached-admission mode;
omit `--cached-admission` and `--cache-reason` on that command.

`admission-check` requires a matching installation; it is not a pre-install
eligibility check. Acceptance and installation apply that earlier decision.

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

Earlier generic default/docs evidence cannot authorise the newly qualified scope,
even when its cached observations are less than 24 hours old. Run a new review and
complete its component-specific assessment. Existing schema-1 evidence for the
previously supported macOS ARM64 minimal selection, including its optional host
Clippy/rustfmt additions, keeps its identity and continuing-use semantics.

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

Fresh native installation requires effective creation modes `0644` for files
and `0755` for directories. Barbican checks these in private scratch space
before starting Rustup. If the check refuses a restrictive shell umask, retry
only the install command with a command-local setting, for example
`(umask 022; cargo-barbican toolchain install <review-id>)`. Barbican does not
change the process umask or repair an installed payload. Checking an existing
slot does not require this creation-mode preflight.

Existing defaults, unrelated toolchains and repository edits are preserved.
When Rustup has no default, installation refuses unless you explicitly choose
`--allow-initial-default`. If that owned first assignment is followed by a
supported failure, Barbican attempts native default unsetting only while the
assignment still matches its captured state. A conflicting external edit is
preserved and reported. Installed files remain for inspection; this is not a
transactional rollback of installation or prior execution.

SIGINT and SIGTERM are checked during installed-file verification, including
bounded hash reads, and before an installed-success result or new continuing-use
binding. Cancellation retains installed data and prior bindings; it does not
erase operation intent/history. An owned initial-default assignment follows the
same recovery rules above. If publication completed before cancellation was
observed, the diagnostic reports that retained outcome instead of claiming rollback.

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

The qualified native host is macOS ARM64. Evaluators are a closed set of exact
protected regular executable files (symlinks and multiple hardlinks refuse):

| Rustup build | Executable SHA256 |
| --- | --- |
| Official prebuilt 1.29.3 ARM64 | `63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f` |
| Existing reviewed Homebrew 1.29.0_1 libexec | `16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496` |

Use an already trusted exact build; Barbican does not download, install or
update it. The official build's [provenance and qualification record](../dependency-reviews/2026-11-12-official-rustup-evaluator.md)
retains supplier-build uncertainty. A version banner alone cannot qualify a
different binary. Identity is checked before isolated help or effects, and the
multicall executable is deliberately invoked as `rustup`.

The CLI review route selects XZ inputs; it offers no Gzip selection or fallback.
Supported selections cover minimal/default profiles, host docs/Clippy/rustfmt
and target-independent `rust-src`, through fresh install, static adoption and
explicit reviewed component additions. Other hosts, cross targets and components
outside that set remain unavailable.
The [authentic default/docs qualification](../dependency-reviews/2026-11-10-native-default-docs-qualification.md)
exercises already-trusted Rust 1.95.0 through the production mapping and public
admission workflow. It qualifies the machinery; each selected release still
requires its own authenticated evidence, assessment and local acceptance.
Documentation is inventoried and checked as installed data; this proof does not
render it, execute its scripts or establish repository compatibility.

## CI Bootstrap

With admission enabled, use the already trusted direct Barbican executable
to generate the [maintainer-dispatched admission workflow](ci.md#maintainer-dispatched-admission):

```sh
cargo-barbican policy init --ci github --ci-bootstrap ci-bootstrap.json
```

The linked guide defines the strict bootstrap JSON, provider layout and
protected controller setup. A trusted maintainer dispatches from the reviewed
immutable protected tag, with exact candidate and comparison-base commits.
Optional actor/event execution policies add defence in depth; they are not a
product availability prerequisite. The resulting run is not an automatic
required check on the candidate SHA and does not govern other workflows.

The immutable reviewed provider supplies trusted Barbican, the qualified
Rustup evaluator and reviewed scanner delegates before candidate checkout.
Its `cargo`, `rustc` and `rustdoc` must be trusted Rustup proxies selecting the
newly admitted private toolchain, not fixed binaries from the provider's
bootstrap compiler. Candidate stages unset `RUSTUP_TOOLCHAIN` and use fresh
private Cargo/Rustup and data/cache roots.

Before installing or probing the target, `toolchain accept --approved-repo`
compares candidate governance and the complete selected review bundle against
the independently trusted immutable approved checkout, then establishes fresh
local acceptance in the candidate's actual root. The applying controller
authenticates approval origin; the comparison option only checks inputs.
Normal fresh-evidence requirements remain active. Installation, installed
correspondence, admission and conformance checks precede Cargo fetch and the
existing gate. Cached approval directories are not reused.

The separate generated admission workflow preserves existing files. Review
and disable or migrate legacy install-first workflows when adopting this
boundary. See [CI](ci.md) and [hardening](hardening.md) for its scope and the
existing gate boundaries.
