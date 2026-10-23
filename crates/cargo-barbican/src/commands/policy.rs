use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{BarbicanConfig, ExactRustToolchainChannel, parse_reviewed_targets_toml};

use crate::cli::{CiSystem, PolicyCommand, REVIEWED_TARGETS_CONFIG_FILE};

use super::scaffold_fs::{ScaffoldState, confined_scaffold_state, create_dir_all, write_new_file};
use super::toolchain::{
    GENERATED_RUSTUP_PROFILE, RUST_TOOLCHAIN_TOML, ToolchainPinState, inspect_toolchain_pin,
    render_toolchain_toml,
};
use super::{
    CommandError, REVIEW_RECORDS_DIR, escape_diagnostic_for_terminal,
    exit_code_from_policy_failures,
};

pub(crate) const DEFAULT_BARBICAN_CONFIG: &str =
    include_str!("../../../../templates/barbican.toml");
pub(crate) const DEFAULT_DENY_TOML: &str = include_str!("../../../../templates/deny.toml");
const DEFAULT_REVIEWED_TARGETS: &str = include_str!("../../../../templates/reviewed-targets.toml");
const DEFAULT_DEPENDENCY_REVIEWS_README: &str =
    include_str!("../../../../templates/dependency-reviews/README.md");

const ADOPTION_GUIDE_PATH: &str =
    "https://github.com/Rob-Morris/cargo-barbican/blob/main/docs/user/adoption.md";

const PRE_COMMIT_HOOK_TEMPLATE_PATH: &str =
    "https://github.com/Rob-Morris/cargo-barbican/blob/main/templates/hooks/pre-commit";

const GITHUB_WORKFLOW_PATH: &str = ".github/workflows/barbican.yml";

/// The ready-to-run GitHub Actions enforcement gate emitted by
/// `policy init --ci github`. Kept as a plain string literal (not `format!`)
/// so the workflow's own `${{ ... }}` expressions pass through verbatim rather
/// than colliding with Rust's format braces. Third-party actions are pinned by
/// full commit SHA to match the repo's own dogfooded `ci.yml`.
const GITHUB_CI_WORKFLOW: &str = r#"# Synced from cargo-barbican v0.34.0
#
# cargo-barbican enforcement gate (server-side, authoritative).
#
# This workflow is the real gate for what enters the dependency graph. The
# shipped client-side pre-commit hook (templates/hooks/pre-commit) runs a cheap
# subset and is advisory and skippable (git commit --no-verify); this workflow
# is not.
#
# Third-party actions are pinned by full commit SHA with a version comment.
# `--locked` installs from committed lockfiles but does not pin the installed
# tool versions. These installs select the exact reviewed release candidates.
name: barbican

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always

jobs:
  gate:
    name: cargo-barbican gate
    runs-on: ubuntu-latest
    steps:
      - id: checkout
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Full history so age-lock and assess can diff against the PR base commit.
          fetch-depth: 0
      - id: toolchain
        name: Install the pinned Rust toolchain
        # Reads rust-toolchain.toml; pin your toolchain there for reproducible gates.
        run: rustup toolchain install
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - id: tools
        name: Install cargo-barbican, cargo-deny, and cargo-audit
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.34.0 cargo-barbican
          cargo install --locked cargo-deny@0.19.6
          cargo install --locked cargo-audit@0.22.1
      - id: fetch
        name: Fetch dependencies for every target platform
        # The gate resolves frozen cross-platform cargo metadata, which needs
        # every platform's crates in the local cache — including ones a build
        # on this runner never downloads (e.g. Windows-only crates). Plain
        # `cargo fetch` with no --target populates them all.
        run: cargo fetch --locked
      - id: pre_release
        name: Pre-release supply-chain gate
        run: cargo barbican gatehouse pre-release
      - id: evidence_toolchain
        name: Check toolchain before PR evidence
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' }}
        run: cargo barbican toolchain check
      - id: pr_base
        name: Check explicit PR base availability
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' }}
        shell: bash
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          if [[ ! "$BASE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
            printf '%s\n' 'FAIL PR evidence unavailable: invalid or missing PR base SHA' >&2
            exit 1
          fi
          if ! git cat-file -e "$BASE_SHA^{commit}"; then
            printf '%s\n' 'FAIL PR evidence unavailable: PR base commit is not available locally' >&2
            exit 1
          fi
      - id: age_lock
        name: Check release age against the PR base
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' &&
              steps.evidence_toolchain.outcome == 'success' && steps.pr_base.outcome == 'success' }}
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: cargo barbican age-lock --base-ref "$BASE_SHA"
      - id: assess
        name: Assess against the PR base
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' &&
              steps.evidence_toolchain.outcome == 'success' && steps.pr_base.outcome == 'success' }}
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: cargo barbican assess --base-ref "$BASE_SHA"
      - name: Summarise PR evidence
        if: ${{ !cancelled() && github.event_name == 'pull_request' }}
        shell: bash
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          CHECKOUT_OUTCOME: ${{ steps.checkout.outcome }}
          TOOLCHAIN_OUTCOME: ${{ steps.toolchain.outcome }}
          TOOLS_OUTCOME: ${{ steps.tools.outcome }}
          FETCH_OUTCOME: ${{ steps.fetch.outcome }}
          GATE_OUTCOME: ${{ steps.pre_release.outcome }}
          ELIGIBILITY_OUTCOME: ${{ steps.evidence_toolchain.outcome }}
          BASE_OUTCOME: ${{ steps.pr_base.outcome }}
          AGE_OUTCOME: ${{ steps.age_lock.outcome }}
          ASSESS_OUTCOME: ${{ steps.assess.outcome }}
        run: |
          native_outcome() {
            case "$1" in
              success|failure|skipped|cancelled) printf '%s' "$1" ;;
              *) printf '%s' 'unavailable' ;;
            esac
          }
          setup_missing=
          for prerequisite in "checkout:$CHECKOUT_OUTCOME" "toolchain:$TOOLCHAIN_OUTCOME" "tools:$TOOLS_OUTCOME" "fetch:$FETCH_OUTCOME"; do
            if [[ "$prerequisite" != *:success ]]; then
              setup_missing="${setup_missing}${setup_missing:+, }${prerequisite%%:*}"
            fi
          done
          unavailable=
          if [[ -n "$setup_missing" ]]; then
            unavailable="setup incomplete: $setup_missing"
          fi
          if [[ "$ELIGIBILITY_OUTCOME" != success ]]; then
            unavailable="${unavailable}${unavailable:+; }toolchain conformance $(native_outcome "$ELIGIBILITY_OUTCOME")"
          fi
          if [[ "$BASE_OUTCOME" != success ]]; then
            unavailable="${unavailable}${unavailable:+; }PR base $(native_outcome "$BASE_OUTCOME")"
          fi
          evidence_outcome() {
            case "$1" in
              success|failure) native_outcome "$1" ;;
              *) printf 'unavailable — %s' "${unavailable:-did not run}" ;;
            esac
          }
          if [[ "$BASE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
            base_label=$BASE_SHA
          else
            base_label='unavailable (invalid event SHA)'
          fi
          if current_revision=$(git rev-parse --verify HEAD 2>/dev/null) && [[ "$current_revision" =~ ^[0-9a-fA-F]{40}$ ]]; then
            current_label=$current_revision
          else
            current_label=unavailable
          fi
          {
            printf '%s\n' '## PR dependency evidence' '' '| Check | Native outcome / availability |' '| --- | --- |'
            printf '| Requested PR base | %s |\n' "$base_label"
            printf '| Checked-out revision | %s |\n' "$current_label"
            printf '| Checkout | %s |\n' "$(native_outcome "$CHECKOUT_OUTCOME")"
            printf '| Toolchain installation | %s |\n' "$(native_outcome "$TOOLCHAIN_OUTCOME")"
            printf '| Tool installation | %s |\n' "$(native_outcome "$TOOLS_OUTCOME")"
            printf '| Dependency fetch | %s |\n' "$(native_outcome "$FETCH_OUTCOME")"
            printf '| Pre-release gate | %s |\n' "$(native_outcome "$GATE_OUTCOME")"
            printf '| Evidence toolchain conformance | %s |\n' "$(native_outcome "$ELIGIBILITY_OUTCOME")"
            printf '| PR base availability | %s |\n' "$(native_outcome "$BASE_OUTCOME")"
            printf '| age-lock | %s |\n' "$(evidence_outcome "$AGE_OUTCOME")"
            printf '| assess | %s |\n' "$(evidence_outcome "$ASSESS_OUTCOME")"
            printf '\n%s\n' 'Failures retain their command logs and keep the job red. Unavailable evidence is not a passing policy verdict.'
          } | tee -a "$GITHUB_STEP_SUMMARY"
"#;

pub(super) fn run_policy(
    command: PolicyCommand,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    match command {
        PolicyCommand::Init { toolchain, ci } => {
            run_policy_init(toolchain.as_ref(), ci, current_dir, stdout)
        }
    }
}

fn run_policy_init(
    requested_toolchain: Option<&ExactRustToolchainChannel>,
    ci: Option<CiSystem>,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let mut report = InitReport::default();

    let config_path = Path::new("barbican.toml");
    let config_ok = ensure_config(current_dir, config_path, &mut report)?;
    let toolchain_ok = ensure_toolchain_pin(current_dir, requested_toolchain, &mut report)?;

    if config_ok {
        ensure_file(
            current_dir,
            Path::new("deny.toml"),
            DEFAULT_DENY_TOML,
            &mut report,
        )?;
        ensure_reviewed_targets(
            current_dir,
            Path::new(REVIEWED_TARGETS_CONFIG_FILE),
            &mut report,
        )?;
        let review_directory_ok =
            ensure_directory(current_dir, Path::new(REVIEW_RECORDS_DIR), &mut report)?;
        if review_directory_ok {
            ensure_file(
                current_dir,
                &Path::new(REVIEW_RECORDS_DIR).join("README.md"),
                DEFAULT_DEPENDENCY_REVIEWS_README,
                &mut report,
            )?;
        }
    }

    // The CI workflow is a self-contained artefact that does not depend on
    // barbican.toml parsing, so it is emitted independently of `config_ok`.
    let workflow_blocked_by_existing = match ci {
        Some(CiSystem::Github) if toolchain_ok => {
            ensure_ci_workflow(current_dir, Path::new(GITHUB_WORKFLOW_PATH), &mut report)?
        }
        Some(CiSystem::Github) => {
            report.blocked(
                Path::new(GITHUB_WORKFLOW_PATH),
                format!("requires a valid exact {RUST_TOOLCHAIN_TOML} pin"),
            );
            false
        }
        None => false,
    };

    report.render(ci, stdout)?;

    if workflow_blocked_by_existing {
        writeln!(
            stdout,
            "\nThe {GITHUB_WORKFLOW_PATH} workflow was not written because a file already exists there. Its intended contents are:\n\n{GITHUB_CI_WORKFLOW}"
        )
        .map_err(CommandError::Io)?;
    }

    Ok(exit_code_from_policy_failures(report.has_blocked()))
}

fn ensure_toolchain_pin(
    current_dir: &Path,
    requested: Option<&ExactRustToolchainChannel>,
    report: &mut InitReport,
) -> Result<bool, CommandError> {
    let path = Path::new(RUST_TOOLCHAIN_TOML);
    match inspect_toolchain_pin(current_dir) {
        ToolchainPinState::Missing => match requested {
            Some(pin) => {
                write_new_file(current_dir, path, &render_toolchain_toml(pin))?;
                report.created_with_detail(
                    path,
                    format!(
                        "exact channel {}; rustup profile {GENERATED_RUSTUP_PROFILE}",
                        pin.as_str()
                    ),
                );
                Ok(true)
            }
            None => {
                report.blocked(
                    path,
                    "missing; rerun with --toolchain <exact-channel> to make the compiler pin an explicit operator decision",
                );
                Ok(false)
            }
        },
        ToolchainPinState::Valid(existing) => {
            if let Some(requested) = requested
                && requested != &existing
            {
                report.blocked(
                    path,
                    format!("pins {existing}; refusing requested conflicting pin {requested}"),
                );
                return Ok(false);
            }
            report.already_present(path);
            Ok(true)
        }
        ToolchainPinState::Invalid(detail) => {
            report.blocked(path, detail);
            Ok(false)
        }
    }
}

/// Emits the CI enforcement workflow, failing closed rather than overwriting.
/// Unlike the idempotent base scaffold, an existing regular workflow file is a
/// blocking condition: the caller re-prints the intended contents so the
/// difference can be reconciled by hand. Returns `true` when the workflow was
/// blocked specifically by an existing regular file.
fn ensure_ci_workflow(
    current_dir: &Path,
    relative_path: &Path,
    report: &mut InitReport,
) -> Result<bool, CommandError> {
    match confined_scaffold_state(current_dir, relative_path)? {
        ScaffoldState::Missing => {
            write_new_file(current_dir, relative_path, GITHUB_CI_WORKFLOW)?;
            report.created(relative_path);
            Ok(false)
        }
        ScaffoldState::RegularFile => {
            report.blocked(
                relative_path,
                "already exists; refusing to overwrite the CI workflow",
            );
            Ok(true)
        }
        state => {
            report.blocked(relative_path, block_reason(state, ExpectedScaffold::File));
            Ok(false)
        }
    }
}

fn ensure_config(
    current_dir: &Path,
    relative_path: &Path,
    report: &mut InitReport,
) -> Result<bool, CommandError> {
    match confined_scaffold_state(current_dir, relative_path)? {
        ScaffoldState::Missing => {
            write_new_file(current_dir, relative_path, DEFAULT_BARBICAN_CONFIG)?;
            report.created(relative_path);
            Ok(true)
        }
        ScaffoldState::RegularFile => {
            let text = fs::read_to_string(current_dir.join(relative_path)).map_err(|source| {
                CommandError::ConfigRead {
                    path: relative_path.display().to_string(),
                    source,
                }
            })?;
            match BarbicanConfig::from_toml_str(&text) {
                Ok(_) => {
                    report.already_present(relative_path);
                    Ok(true)
                }
                Err(error) => {
                    report.blocked(relative_path, format!("invalid config: {error}"));
                    Ok(false)
                }
            }
        }
        state => {
            report.blocked(relative_path, block_reason(state, ExpectedScaffold::File));
            Ok(false)
        }
    }
}

fn ensure_file(
    current_dir: &Path,
    relative_path: &Path,
    contents: &str,
    report: &mut InitReport,
) -> Result<(), CommandError> {
    match confined_scaffold_state(current_dir, relative_path)? {
        ScaffoldState::Missing => {
            write_new_file(current_dir, relative_path, contents)?;
            report.created(relative_path);
        }
        ScaffoldState::RegularFile => report.already_present(relative_path),
        state => report.blocked(relative_path, block_reason(state, ExpectedScaffold::File)),
    }

    Ok(())
}

fn ensure_reviewed_targets(
    current_dir: &Path,
    relative_path: &Path,
    report: &mut InitReport,
) -> Result<(), CommandError> {
    match confined_scaffold_state(current_dir, relative_path)? {
        ScaffoldState::Missing => {
            write_new_file(current_dir, relative_path, DEFAULT_REVIEWED_TARGETS)?;
            report.created(relative_path);
        }
        ScaffoldState::RegularFile => {
            let text = fs::read_to_string(current_dir.join(relative_path)).map_err(|source| {
                CommandError::ReviewedTargetsRead {
                    path: relative_path.display().to_string(),
                    source,
                }
            })?;
            match parse_reviewed_targets_toml(&text) {
                Ok(_) => report.already_present(relative_path),
                Err(error) => report.blocked(relative_path, format!("invalid policy: {error}")),
            }
        }
        state => report.blocked(relative_path, block_reason(state, ExpectedScaffold::File)),
    }

    Ok(())
}

fn ensure_directory(
    current_dir: &Path,
    relative_path: &Path,
    report: &mut InitReport,
) -> Result<bool, CommandError> {
    match confined_scaffold_state(current_dir, relative_path)? {
        ScaffoldState::Missing => {
            create_dir_all(current_dir, relative_path)?;
            report.created(relative_path);
            Ok(true)
        }
        ScaffoldState::RegularDirectory => {
            report.already_present(relative_path);
            Ok(true)
        }
        state => {
            report.blocked(
                relative_path,
                block_reason(state, ExpectedScaffold::Directory),
            );
            Ok(false)
        }
    }
}

fn block_reason(state: ScaffoldState, expected: ExpectedScaffold) -> String {
    match state {
        ScaffoldState::RegularDirectory => format!("expected {}, found directory", expected.name()),
        ScaffoldState::RegularFile => format!("expected {}, found regular file", expected.name()),
        ScaffoldState::WrongType(kind) => format!("expected {}, found {kind}", expected.name()),
        ScaffoldState::BlockedAncestor { path } => {
            format!("ancestor {} is not a regular directory", path.display())
        }
        ScaffoldState::Missing => {
            unreachable!("missing scaffold paths are handled before blocking")
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedScaffold {
    File,
    Directory,
}

impl ExpectedScaffold {
    fn name(self) -> &'static str {
        match self {
            Self::File => "regular file",
            Self::Directory => "directory",
        }
    }
}

#[derive(Default)]
struct InitReport {
    items: Vec<InitReportItem>,
}

impl InitReport {
    fn created(&mut self, path: &Path) {
        self.items.push(InitReportItem {
            path: path.to_path_buf(),
            status: InitStatus::Created,
        });
    }

    fn created_with_detail(&mut self, path: &Path, detail: impl Into<String>) {
        self.items.push(InitReportItem {
            path: path.to_path_buf(),
            status: InitStatus::CreatedWithDetail(detail.into()),
        });
    }

    fn already_present(&mut self, path: &Path) {
        self.items.push(InitReportItem {
            path: path.to_path_buf(),
            status: InitStatus::AlreadyPresent,
        });
    }

    fn blocked(&mut self, path: &Path, detail: impl Into<String>) {
        self.items.push(InitReportItem {
            path: path.to_path_buf(),
            status: InitStatus::Blocked(detail.into()),
        });
    }

    fn has_blocked(&self) -> bool {
        self.items
            .iter()
            .any(|item| matches!(item.status, InitStatus::Blocked(_)))
    }

    fn render(&self, ci: Option<CiSystem>, stdout: &mut dyn Write) -> Result<(), CommandError> {
        writeln!(stdout, "Policy init:").map_err(CommandError::Io)?;
        for item in &self.items {
            match &item.status {
                InitStatus::Blocked(detail) | InitStatus::CreatedWithDetail(detail) => writeln!(
                    stdout,
                    "- {}: {} ({})",
                    item.path.display(),
                    item.status.as_str(),
                    escape_diagnostic_for_terminal(detail),
                )
                .map_err(CommandError::Io)?,
                InitStatus::Created | InitStatus::AlreadyPresent => writeln!(
                    stdout,
                    "- {}: {}",
                    item.path.display(),
                    item.status.as_str()
                )
                .map_err(CommandError::Io)?,
            }
        }

        if self.has_blocked() {
            writeln!(
                stdout,
                "\nResolve the blocked scaffold item(s), then rerun `cargo barbican policy init`."
            )
            .map_err(CommandError::Io)?;
        } else {
            let ci_step = match ci {
                Some(CiSystem::Github) => format!(
                    "- A CI enforcement workflow was written to {GITHUB_WORKFLOW_PATH}; it is the authoritative server-side gate. Review it and commit it."
                ),
                None => {
                    "- Add a CI enforcement gate: rerun with `cargo barbican policy init --ci github` to emit .github/workflows/barbican.yml.".to_owned()
                }
            };
            writeln!(
                stdout,
                "\nNext steps:\n- Review the manual adoption guide: {ADOPTION_GUIDE_PATH}\n- Review current dependencies and write dependency review records.\n- Populate reviewed-targets.toml only for deliberately reviewed families.\n- Run `cargo barbican gatehouse pre-release`.\n{ci_step}\n- Install the advisory client-side pre-commit hook shipped at {PRE_COMMIT_HOOK_TEMPLATE_PATH}: point `git config core.hooksPath` at its directory, or copy it into .git/hooks/pre-commit and make it executable. It runs the cheap subset (pin check, inventory --enforce) and is skippable with `git commit --no-verify`; CI is the real gate."
            )
            .map_err(CommandError::Io)?;
        }

        Ok(())
    }
}

struct InitReportItem {
    path: PathBuf,
    status: InitStatus,
}

enum InitStatus {
    Created,
    CreatedWithDetail(String),
    AlreadyPresent,
    Blocked(String),
}

impl InitStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::CreatedWithDetail(_) => "created",
            Self::AlreadyPresent => "already present",
            Self::Blocked(_) => "blocked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_BARBICAN_CONFIG, DEFAULT_DENY_TOML, GITHUB_CI_WORKFLOW};

    #[test]
    fn github_ci_workflow_runs_the_enforcement_gate_with_pinned_actions() {
        for gate_command in [
            // Fetching without --target pre-populates every platform's crates,
            // so the gate's frozen cross-platform metadata resolves offline
            // even on a cold runner cache.
            "cargo fetch --locked",
            "cargo barbican gatehouse pre-release",
            "cargo barbican toolchain check",
            "cargo barbican age-lock --base-ref",
            "cargo barbican assess --base-ref",
        ] {
            assert!(
                GITHUB_CI_WORKFLOW.contains(gate_command),
                "emitted workflow should run `{gate_command}`"
            );
        }
        assert_eq!(
            GITHUB_CI_WORKFLOW
                .matches("cargo barbican gatehouse pre-release")
                .count(),
            1
        );
        assert!(!GITHUB_CI_WORKFLOW.contains("cargo barbican inventory --enforce"));
        assert!(GITHUB_CI_WORKFLOW.contains("cargo install --locked"));
        assert!(GITHUB_CI_WORKFLOW.contains("--tag v0.34.0"));
        assert!(GITHUB_CI_WORKFLOW.contains("cargo-deny@0.19.6"));
        assert!(GITHUB_CI_WORKFLOW.contains("cargo-audit@0.22.1"));
        // Third-party actions must stay pinned by full commit SHA with a
        // version comment rather than a mutable tag.
        assert!(
            GITHUB_CI_WORKFLOW
                .contains("actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3")
        );
        assert!(
            GITHUB_CI_WORKFLOW
                .contains("Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1")
        );
    }

    #[test]
    fn embedded_default_config_matches_template() {
        let template_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/barbican.toml");
        let template =
            std::fs::read_to_string(template_path).expect("template config should be readable");

        assert_eq!(DEFAULT_BARBICAN_CONFIG, template);
    }

    #[test]
    fn embedded_default_deny_toml_matches_template() {
        let template_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/deny.toml");
        let template =
            std::fs::read_to_string(template_path).expect("deny template should be readable");

        assert_eq!(DEFAULT_DENY_TOML, template);
    }

    #[test]
    fn embedded_default_deny_toml_preserves_advisory_coexistence_boundary() {
        assert!(DEFAULT_DENY_TOML.contains("never authorise a Barbican pass"));
        assert!(DEFAULT_DENY_TOML.contains("GOVERNED"));
        assert!(DEFAULT_DENY_TOML.contains("ignore = []"));
    }

    #[test]
    fn embedded_default_config_parses() {
        barbican::BarbicanConfig::from_toml_str(DEFAULT_BARBICAN_CONFIG)
            .expect("embedded default config should parse");
    }
    fn workflow_step(id: &str) -> &str {
        GITHUB_CI_WORKFLOW
            .split_once(&format!("      - id: {id}\n"))
            .unwrap()
            .1
            .split("      - ")
            .next()
            .unwrap()
    }

    #[test]
    fn pr_evidence_steps_are_independent_and_require_complete_eligibility() {
        for id in ["evidence_toolchain", "pr_base", "age_lock", "assess"] {
            let step = workflow_step(id);
            assert!(step.contains("!cancelled()"), "{id}");
            assert!(step.contains("github.event_name == 'pull_request'"), "{id}");
            for prerequisite in ["checkout", "toolchain", "tools", "fetch"] {
                assert!(
                    step.contains(&format!("steps.{prerequisite}.outcome == 'success'")),
                    "{id}/{prerequisite}"
                );
            }
            assert!(!step.contains("steps.pre_release.outcome"), "{id}");
            assert!(!step.contains("steps.age_lock.outcome"), "{id}");
            assert!(!step.contains("steps.assess.outcome"), "{id}");
        }
        for id in ["age_lock", "assess"] {
            let step = workflow_step(id);
            for prerequisite in ["evidence_toolchain", "pr_base"] {
                assert!(step.contains(&format!("steps.{prerequisite}.outcome == 'success'")));
            }
            assert!(step.contains("BASE_SHA: ${{ github.event.pull_request.base.sha }}"));
            assert!(step.contains("--base-ref \"$BASE_SHA\""));
        }
        assert_eq!(
            GITHUB_CI_WORKFLOW
                .matches("run: cargo barbican toolchain check")
                .count(),
            1
        );
        for forbidden in [
            "continue-on-error",
            "always()",
            "|| true",
            "--policy-mode",
            "pull_request_target",
        ] {
            assert!(!GITHUB_CI_WORKFLOW.contains(forbidden), "{forbidden}");
        }
        assert!(workflow_step("pr_base").contains("git cat-file -e \"$BASE_SHA^{commit}\""));
    }

    #[test]
    fn generated_pr_summary_reports_native_failures_and_unavailable_evidence() {
        use std::fs;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let summary = GITHUB_CI_WORKFLOW
            .split_once("      - name: Summarise PR evidence\n")
            .unwrap()
            .1;
        let script = summary
            .split_once("        run: |\n")
            .unwrap()
            .1
            .lines()
            .map(|line| line.strip_prefix("          ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[], "| assess | success |"),
            (
                &[("GATE_OUTCOME", "failure"), ("AGE_OUTCOME", "failure")],
                "| assess | success |",
            ),
            (
                &[
                    ("CHECKOUT_OUTCOME", "failure"),
                    ("TOOLS_OUTCOME", "skipped"),
                    ("AGE_OUTCOME", "skipped"),
                    ("ASSESS_OUTCOME", "skipped"),
                ],
                "setup incomplete: checkout, tools",
            ),
            (
                &[
                    ("ELIGIBILITY_OUTCOME", "failure"),
                    ("BASE_OUTCOME", "failure"),
                    ("AGE_OUTCOME", "skipped"),
                ],
                "toolchain conformance failure; PR base failure",
            ),
            (
                &[("BASE_OUTCOME", "failure"), ("ASSESS_OUTCOME", "skipped")],
                "unavailable — PR base failure",
            ),
            (&[("AGE_OUTCOME", "skipped")], "unavailable — did not run"),
            (
                &[
                    ("BASE_SHA", "unsafe|\n\u{1b}[31mINJECTED"),
                    ("GATE_OUTCOME", "INJECTED"),
                ],
                "unavailable (invalid event SHA)",
            ),
        ];
        for (overrides, expected) in cases {
            let root = std::env::temp_dir().join(format!(
                "barbican-pr-summary-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let path = root.join("summary.md");
            let mut command = Command::new("bash");
            command
                .args(["-e", "-o", "pipefail", "-c", &script])
                .current_dir(&root)
                .env("GITHUB_STEP_SUMMARY", &path)
                .env("BASE_SHA", "1".repeat(40));
            for name in [
                "CHECKOUT_OUTCOME",
                "TOOLCHAIN_OUTCOME",
                "TOOLS_OUTCOME",
                "FETCH_OUTCOME",
                "GATE_OUTCOME",
                "ELIGIBILITY_OUTCOME",
                "BASE_OUTCOME",
                "AGE_OUTCOME",
                "ASSESS_OUTCOME",
            ] {
                command.env(name, "success");
            }
            for (name, value) in *overrides {
                command.env(name, value);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{output:?}");
            let text = fs::read_to_string(&path).unwrap();
            assert_eq!(output.stdout, text.as_bytes());
            assert!(text.contains(expected), "{expected}: {text}");
            assert!(!text.contains("INJECTED"));
            if overrides.contains(&("GATE_OUTCOME", "failure")) {
                assert!(text.contains("| Pre-release gate | failure |"));
                assert!(text.contains("| age-lock | failure |"));
            }
            let failed = command.env("GITHUB_STEP_SUMMARY", &root).output().unwrap();
            assert!(
                !failed.status.success(),
                "summary write errors must stay visible"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}
