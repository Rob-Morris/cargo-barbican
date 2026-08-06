use std::fmt;
use std::fmt::Write as _;
use std::io;
use std::process::ExitCode;

use barbican::{ConfigLoadError, ReviewedTargetsError};

use crate::command_runner::RunnerError;
use crate::crates_io_http::CRATES_IO_BASE_URL_ENV;

#[derive(Debug)]
pub enum CommandError {
    CargoHomeUnresolved,
    CargoConfigRead {
        path: String,
        source: io::Error,
    },
    Config(ConfigLoadError),
    ConfigRead {
        path: String,
        source: io::Error,
    },
    GitRead {
        object: String,
        source: RunnerError,
    },
    InvalidEnvironment {
        name: &'static str,
    },
    InvalidCratesIoBaseUrl {
        value: String,
    },
    PinAddConfigWrite {
        config_path: String,
        review_record_path: String,
        source: io::Error,
        cleanup_source: Option<io::Error>,
    },
    LockfileMissing {
        path: String,
    },
    LockfileParse {
        path: String,
        source: barbican::LockfileError,
    },
    LockfileRead {
        path: String,
        source: io::Error,
    },
    LockfileRestore {
        path: String,
        source: io::Error,
    },
    ManifestParse {
        path: String,
        source: barbican::CargoManifestError,
    },
    ManifestRead {
        path: String,
        source: io::Error,
    },
    ReviewedTargetsParse {
        path: String,
        source: Box<ReviewedTargetsError>,
    },
    ReviewedTargetsRead {
        path: String,
        source: io::Error,
    },
    ScaffoldIo {
        path: String,
        source: io::Error,
    },
    WorkspaceRootNotFound {
        start_dir: String,
    },
    WorkspaceRootDiscovery {
        start_dir: String,
        source: RunnerError,
    },
    WorkspaceRootOutput {
        output: String,
    },
    Io(io::Error),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CargoHomeUnresolved => write!(
                formatter,
                "unable to establish Cargo home: neither CARGO_HOME nor HOME is set; set one so user-level Cargo source policy can be inspected"
            ),
            Self::CargoConfigRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::Config(error) => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&error.to_string())
                )
            }
            Self::ConfigRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::GitRead { object, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to read {object} from git: {source}"
                    ))
                )
            }
            Self::InvalidEnvironment { name } => {
                write!(formatter, "environment variable {name} is not valid UTF-8")
            }
            Self::InvalidCratesIoBaseUrl { value } => write!(
                formatter,
                "{}",
                escape_diagnostic_for_terminal(&format!(
                    "{CRATES_IO_BASE_URL_ENV} must use https://, or http:// loopback for local tests: {value}"
                ))
            ),
            Self::PinAddConfigWrite {
                config_path,
                review_record_path,
                source,
                cleanup_source,
            } => {
                let cleanup = match cleanup_source {
                    Some(cleanup_source) => format!(
                        "; also unable to remove orphaned review record {review_record_path}: {cleanup_source}"
                    ),
                    None => format!("; removed orphaned review record {review_record_path}"),
                };
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to write {config_path} after creating review record {review_record_path}: {source}{cleanup}"
                    ))
                )
            }
            Self::LockfileMissing { path } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: lockfile not found"))
                )
            }
            Self::LockfileParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::LockfileRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::LockfileRestore { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to restore {path} after a failed lockfile operation: {source}"
                    ))
                )
            }
            Self::ManifestParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::ManifestRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::ReviewedTargetsParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::ReviewedTargetsRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::ScaffoldIo { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to update policy scaffold {path}: {source}"
                    ))
                )
            }
            Self::WorkspaceRootNotFound { start_dir } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "workspace root not found: no Cargo.toml in {start_dir} or any parent directory; commands anchor to the workspace Cargo selects with `cargo locate-project --workspace`, so run from inside a Cargo project"
                    ))
                )
            }
            Self::WorkspaceRootDiscovery { start_dir, source } => write!(
                formatter,
                "{}",
                escape_diagnostic_for_terminal(&format!(
                    "unable to locate Cargo workspace root from {start_dir}: {source}"
                ))
            ),
            Self::WorkspaceRootOutput { output } => write!(
                formatter,
                "{}",
                escape_diagnostic_for_terminal(&format!(
                    "cargo locate-project returned an invalid workspace manifest path: {output:?}"
                ))
            ),
            Self::Io(error) => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&error.to_string())
                )
            }
        }
    }
}

pub(crate) fn escape_diagnostic_for_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            // Preserve TOML's multi-line diagnostics while escaping terminal controls.
            '\n' | '\t' => escaped.push(character),
            '\r' => escaped.push_str("\\r"),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\u{0000}'..='\u{0008}'
            | '\u{000b}'..='\u{001f}'
            | '\u{007f}'
            | '\u{0080}'..='\u{009f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{feff}' => {
                write!(&mut escaped, "\\x{:02x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => escaped.push(character),
        }
    }

    escaped
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CargoHomeUnresolved => None,
            Self::CargoConfigRead { source, .. } => Some(source),
            Self::Config(error) => Some(error),
            Self::ConfigRead { source, .. } => Some(source),
            Self::GitRead { source, .. } => Some(source),
            Self::InvalidEnvironment { .. } => None,
            Self::InvalidCratesIoBaseUrl { .. } => None,
            Self::PinAddConfigWrite { source, .. } => Some(source),
            Self::LockfileMissing { .. } => None,
            Self::LockfileParse { source, .. } => Some(source),
            Self::LockfileRead { source, .. } => Some(source),
            Self::LockfileRestore { source, .. } => Some(source),
            Self::ManifestParse { source, .. } => Some(source),
            Self::ManifestRead { source, .. } => Some(source),
            Self::ReviewedTargetsParse { source, .. } => Some(source),
            Self::ReviewedTargetsRead { source, .. } => Some(source),
            Self::ScaffoldIo { source, .. } => Some(source),
            Self::WorkspaceRootNotFound { .. } => None,
            Self::WorkspaceRootDiscovery { source, .. } => Some(source),
            Self::WorkspaceRootOutput { .. } => None,
            Self::Io(error) => Some(error),
        }
    }
}

pub(crate) fn exit_code_from_policy_failures(failed: bool) -> ExitCode {
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::escape_diagnostic_for_terminal;

    #[test]
    fn escape_diagnostic_for_terminal_escapes_bidi_and_zero_width_controls() {
        assert_eq!(
            escape_diagnostic_for_terminal("line\u{2066}value\u{feff}\u{200f}\u{2060}\n\tcaret"),
            "line\\x2066value\\xfeff\\x200f\\x2060\n\tcaret"
        );
    }
}
