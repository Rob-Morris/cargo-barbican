use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{BarbicanConfig, parse_reviewed_targets_toml};

use crate::cli::{CiSystem, PolicyCommand, REVIEWED_TARGETS_CONFIG_FILE};

use super::scaffold_fs::{ScaffoldState, confined_scaffold_state, create_dir_all, write_new_file};
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
const GITHUB_CI_WORKFLOW: &str = r#"# Synced from cargo-barbican v0.27.0
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
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Full history so age-lock and assess can diff against the PR base commit.
          fetch-depth: 0
      - name: Install the pinned Rust toolchain
        # Reads rust-toolchain.toml; pin your toolchain there for reproducible gates.
        run: rustup toolchain install
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - name: Install cargo-barbican, cargo-deny, and cargo-audit
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.27.0 cargo-barbican
          cargo install --locked cargo-deny@0.19.6
          cargo install --locked cargo-audit@0.22.1
      - name: Fetch dependencies for every target platform
        # The gate resolves frozen cross-platform cargo metadata, which needs
        # every platform's crates in the local cache — including ones a build
        # on this runner never downloads (e.g. Windows-only crates). Plain
        # `cargo fetch` with no --target populates them all.
        run: cargo fetch --locked
      - name: Pre-release supply-chain gate
        run: cargo barbican gatehouse pre-release
      - name: Age-lock and assess against the PR base
        if: github.event_name == 'pull_request'
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          cargo barbican age-lock --base-ref "$BASE_SHA"
          cargo barbican assess --base-ref "$BASE_SHA"
"#;

pub(super) fn run_policy(
    command: PolicyCommand,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    match command {
        PolicyCommand::Init { ci } => run_policy_init(ci, current_dir, stdout),
    }
}

fn run_policy_init(
    ci: Option<CiSystem>,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let mut report = InitReport::default();

    let config_path = Path::new("barbican.toml");
    let config_ok = ensure_config(current_dir, config_path, &mut report)?;

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
        Some(CiSystem::Github) => {
            ensure_ci_workflow(current_dir, Path::new(GITHUB_WORKFLOW_PATH), &mut report)?
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
                InitStatus::Blocked(detail) => writeln!(
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
    AlreadyPresent,
    Blocked(String),
}

impl InitStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
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
        assert!(GITHUB_CI_WORKFLOW.contains("--tag v0.27.0"));
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
}
