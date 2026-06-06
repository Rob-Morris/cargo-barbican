use std::path::PathBuf;

use barbican::MAXIMUM_RELEASE_AGE_MINIMUM_DAYS;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "cargo-barbican", bin_name = "cargo barbican")]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Age {
        #[arg(
            long,
            value_parser = clap::value_parser!(u64).range(0..=MAXIMUM_RELEASE_AGE_MINIMUM_DAYS)
        )]
        min_age_days: Option<u64>,
        #[arg(required = true)]
        specs: Vec<String>,
    },
    AgeLock {
        #[arg(long, default_value = "HEAD")]
        base_ref: String,
        #[arg(
            long,
            value_parser = clap::value_parser!(u64).range(0..=MAXIMUM_RELEASE_AGE_MINIMUM_DAYS)
        )]
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
        #[arg(
            long,
            value_parser = clap::value_parser!(u64).range(0..=MAXIMUM_RELEASE_AGE_MINIMUM_DAYS)
        )]
        min_age_days: Option<u64>,
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
    },
    Review,
    Audit,
    Verify,
}
