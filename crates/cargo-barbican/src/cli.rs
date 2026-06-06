use std::path::PathBuf;

use barbican::MAXIMUM_RELEASE_AGE_MINIMUM_DAYS;
use clap::builder::RangedU64ValueParser;
use clap::{Parser, Subcommand};

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
        #[arg(long, default_value = "HEAD")]
        base_ref: String,
        #[arg(long, value_parser = min_age_days_parser())]
        min_age_days: Option<u64>,
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
    },
    Resolve {
        #[arg(required = true)]
        specs: Vec<String>,
    },
    Assess {
        #[arg(long, default_value = "HEAD")]
        base_ref: String,
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
    PinCheck {
        #[arg(long, default_value = REVIEWED_TARGETS_CONFIG_FILE)]
        config: PathBuf,
    },
    Review,
    Audit,
    Verify,
}

fn min_age_days_parser() -> RangedU64ValueParser<u64> {
    clap::value_parser!(u64).range(0..=MAXIMUM_RELEASE_AGE_MINIMUM_DAYS)
}
