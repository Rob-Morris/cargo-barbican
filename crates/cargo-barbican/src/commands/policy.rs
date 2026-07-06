use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{BarbicanConfig, parse_reviewed_targets_toml};

use crate::cli::{PolicyCommand, REVIEWED_TARGETS_CONFIG_FILE};

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
    "https://github.com/rob-morris/cargo-barbican/blob/main/docs/user/adoption.md";

pub(super) fn run_policy(
    command: PolicyCommand,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    match command {
        PolicyCommand::Init => run_policy_init(current_dir, stdout),
    }
}

fn run_policy_init(current_dir: &Path, stdout: &mut dyn Write) -> Result<ExitCode, CommandError> {
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

    report.render(stdout)?;

    Ok(exit_code_from_policy_failures(report.has_blocked()))
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

    fn render(&self, stdout: &mut dyn Write) -> Result<(), CommandError> {
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
            writeln!(
                stdout,
                "\nNext steps:\n- Review the manual adoption guide: {ADOPTION_GUIDE_PATH}\n- Review current dependencies and write dependency review records.\n- Populate reviewed-targets.toml only for deliberately reviewed families.\n- Run `cargo barbican pin check`, then `cargo barbican audit`, then `cargo barbican verify`."
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
    use super::{DEFAULT_BARBICAN_CONFIG, DEFAULT_DENY_TOML};

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
    fn embedded_default_config_parses() {
        barbican::BarbicanConfig::from_toml_str(DEFAULT_BARBICAN_CONFIG)
            .expect("embedded default config should parse");
    }
}
