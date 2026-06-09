use std::path::PathBuf;

use barbican::MAXIMUM_RELEASE_AGE_MINIMUM_DAYS;
use clap::builder::RangedU64ValueParser;
use clap::{Args, Parser, Subcommand, ValueEnum};

pub(crate) const REVIEWED_TARGETS_CONFIG_FILE: &str = "reviewed-targets.toml";

#[derive(Debug, Parser)]
#[command(name = "cargo-barbican", bin_name = "cargo barbican")]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Age {
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(required = true)]
        specs: Vec<String>,
    },
    AgeLock {
        #[arg(long, conflicts_with = "base_lockfile")]
        base_ref: Option<String>,
        #[arg(long, conflicts_with = "base_ref")]
        base_lockfile: Option<PathBuf>,
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
    },
    Resolve {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(required = true)]
        specs: Vec<String>,
    },
    Assess {
        #[arg(long, conflicts_with = "base_dir")]
        base_ref: Option<String>,
        #[arg(long, conflicts_with = "base_ref")]
        base_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "strict")]
        policy_mode: AssessPolicyMode,
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
    },
    Inspect {
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(required = true)]
        specs: Vec<String>,
    },
    Gatehouse {
        #[command(subcommand)]
        command: GatehouseCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    PinCheck {
        #[arg(long, default_value = REVIEWED_TARGETS_CONFIG_FILE)]
        config: PathBuf,
    },
    Review {
        #[arg(long)]
        base_dir: Option<PathBuf>,
    },
    Audit,
    Verify,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GatehouseCommand {
    Candidate(GatehouseCandidateArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    Init,
}

#[derive(Debug, Args)]
pub(crate) struct GatehouseCandidateArgs {
    #[arg(long)]
    pub(crate) preserve_sandbox: bool,
    pub(crate) spec: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AssessPolicyMode {
    Strict,
    ElevatedRisk,
}

fn min_age_days_parser() -> RangedU64ValueParser<u64> {
    clap::value_parser!(u64).range(0..=MAXIMUM_RELEASE_AGE_MINIMUM_DAYS)
}
