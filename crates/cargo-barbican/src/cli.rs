use std::path::PathBuf;

use barbican::MAXIMUM_RELEASE_AGE_MINIMUM_DAYS;
use clap::builder::RangedU64ValueParser;
use clap::{Args, Parser, Subcommand, ValueEnum};

pub(crate) const REVIEWED_TARGETS_CONFIG_FILE: &str = "reviewed-targets.toml";

const MIN_AGE_DAYS_HELP: &str = "Override the configured release-age minimum for this invocation \
    (defaults to [release_age].minimum_days in barbican.toml, or 7 when unset)";

#[derive(Debug, Parser)]
#[command(
    name = "cargo-barbican",
    bin_name = "cargo barbican",
    version,
    about = "Supply-chain policy gate for a Rust repo's dependency intake",
    long_about = "cargo-barbican is a policy-first Cargo subcommand for Rust supply-chain \
        hardening. It gives a repo one gate for what enters its dependency graph: release-age \
        evidence, pre-add candidate inspection, reviewed-target enforcement, and delegated \
        advisory auditing. The default stance is fail-closed — when a policy fact cannot be \
        established, the command blocks and explains rather than passing silently."
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    #[command(
        about = "Check release age for exact crates.io versions",
        long_about = "Checks that each exact crate@version was published at least the \
            configured minimum number of days ago. A matching reviewed release-age exception in \
            reviewed-targets.toml can allow an otherwise too-fresh version when its review \
            record exists and its checksum matches the fetched crates.io artefact."
    )]
    Age {
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(
            required = true,
            help = "Exact crates.io candidate specs, crate@version"
        )]
        specs: Vec<String>,
    },
    #[command(
        about = "Check new lockfile selections against a baseline",
        long_about = "Diffs Cargo.lock against a baseline lockfile and checks release age for \
            every newly selected crates.io version, catching too-fresh transitive selections \
            that age alone cannot see."
    )]
    AgeLock {
        #[arg(
            long,
            conflicts_with = "base_lockfile",
            help = "Git ref to diff the current lockfile against (default: HEAD)"
        )]
        base_ref: Option<String>,
        #[arg(
            long,
            conflicts_with = "base_ref",
            help = "Explicit non-git baseline lockfile path instead of a git ref"
        )]
        base_lockfile: Option<PathBuf>,
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(
            long,
            default_value = "Cargo.lock",
            help = "Current lockfile path to check"
        )]
        lockfile: PathBuf,
    },
    #[command(
        about = "Update existing locked dependencies to exact versions",
        long_about = "Checks release age for each requested exact version, then runs cargo \
            update --workspace -p <package-id> --precise <version> and rechecks newly selected \
            crates.io versions against the pre-update Cargo.lock snapshot. --dry-run previews \
            the change in a temporary workspace instead of mutating the repo."
    )]
    Update {
        #[arg(
            long,
            help = "Preview the update in a temporary workspace instead of mutating the repo"
        )]
        dry_run: bool,
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(
            required = true,
            help = "Exact crates.io candidate specs, crate@version"
        )]
        specs: Vec<String>,
    },
    #[command(
        about = "Generate Cargo.lock for current manifests under release-age policy",
        long_about = "Snapshots the current Cargo.lock, runs cargo generate-lockfile against \
            the current manifests, rechecks newly selected crates.io versions against the \
            pre-resolve snapshot, and restores the original Cargo.lock if release-age policy \
            fails."
    )]
    Resolve {
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
    },
    #[command(
        about = "Classify a dependency diff",
        long_about = "Classifies the current Rust dependency state against a baseline as \
            routine-safe, elevated-risk, or policy-violating: new direct dependencies, \
            non-crates.io sources, release-age and yanked-version findings, checksum drift, new \
            native -sys crates, and new or changed build.rs / proc-macro surfaces. \
            --policy-mode elevated-risk accepts elevated-risk findings with exit 0 while still \
            failing policy-violating results."
    )]
    Assess {
        #[arg(
            long,
            conflicts_with = "base_dir",
            help = "Git ref to diff the current dependency state against (default: HEAD)"
        )]
        base_ref: Option<String>,
        #[arg(
            long,
            conflicts_with = "base_ref",
            help = "Explicit non-git baseline directory holding the comparison Cargo.lock and manifests"
        )]
        base_dir: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value = "strict",
            help = "Accept elevated-risk findings with exit 0 while still failing policy-violating results"
        )]
        policy_mode: AssessPolicyMode,
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(
            long,
            default_value = "Cargo.lock",
            help = "Current lockfile path to assess"
        )]
        lockfile: PathBuf,
    },
    #[command(
        about = "Inspect exact crates.io candidates before adding them",
        long_about = "Performs pre-add static review for exact crates.io candidates: release \
            age, published tarball checksum, .cargo_vcs_info.json provenance hints, build.rs, \
            proc-macro, and native -sys / FFI surfaces. Classifies each candidate as \
            routine-safe, elevated-risk, or policy-violating and exits 0 only when every \
            candidate is routine-safe."
    )]
    Inspect {
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(
            required = true,
            help = "Exact crates.io candidate specs, crate@version"
        )]
        specs: Vec<String>,
    },
    #[command(
        about = "Discover a policy-compliant exact crates.io version from a semver range",
        long_about = "Fetches the crates.io version list for one crate, applies Cargo-compatible \
            semver matching, drops yanked versions, pre-releases, semver-incompatible versions, \
            and versions below release-age policy, then prints the selected exact crate@version. \
            Read-only: it does not edit manifests or Cargo.lock."
    )]
    Pick {
        #[arg(long, value_parser = min_age_days_parser(), help = MIN_AGE_DAYS_HELP)]
        min_age_days: Option<u64>,
        #[arg(help = "Crate name, or crate@range using a Cargo semver requirement")]
        spec: String,
    },
    #[command(
        about = "Run supported gatehouse workflows over the base commands",
        long_about = "gatehouse is a workflow namespace: its subcommands coordinate existing \
            policy and evidence primitives with delegated Cargo checks rather than defining \
            separate policy semantics."
    )]
    Gatehouse {
        #[command(subcommand)]
        command: GatehouseCommand,
    },
    #[command(about = "Manage the explicit policy scaffold")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(
        about = "Report dependency inventory and reviewed-policy coverage",
        long_about = "Prints a read-only dependency inventory and reviewed-policy coverage \
            audit: direct dependency exact-pin status, resolved crates.io packages and \
            checksums, non-crates.io sources, reviewed-family coverage, declared allowed \
            execution surfaces, missing review records, and live graph execution surfaces from \
            cargo metadata --frozen. This is an audit view, not an enforcement gate."
    )]
    Inventory,
    #[command(about = "Manage reviewed-target policy")]
    Pin {
        #[command(subcommand)]
        command: PinCommand,
    },
    #[command(
        about = "Print a policy-focused review diff",
        long_about = "Prints a diff of policy-relevant files (Cargo.toml, Cargo.lock, \
            barbican.toml, deny.toml, reviewed-targets.toml, workspace manifests, and checked-in \
            dependency review records) with a review checklist. Does not itself decide whether a \
            change is acceptable."
    )]
    Review {
        #[arg(
            long,
            help = "Explicit non-git baseline directory instead of the default git-backed HEAD diff"
        )]
        base_dir: Option<PathBuf>,
    },
    #[command(
        about = "Run delegated advisory and source-policy checks",
        long_about = "Runs the configured scanner(s) (cargo-deny and/or cargo-audit) with native \
            advisory ignores neutralised, reconciles every finding against reviewed advisory \
            exceptions, and computes a Barbican-owned pass/fail verdict rather than inheriting \
            the scanner's own exit code."
    )]
    Audit,
    #[command(
        about = "Run the final local execution gate",
        long_about = "Runs pin check with the default reviewed-targets.toml, then cargo build \
            --locked, then cargo test --locked, in order. Fails closed when reviewed-targets.toml \
            is absent or configures no active reviewed family. Ends with Verify: PASS on success."
    )]
    Verify,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GatehouseCommand {
    #[command(
        about = "Build a pre-add intake dossier for one exact crates.io candidate",
        long_about = "Builds a human-readable pre-add intake dossier combining exact candidate \
            inspection, an isolated disposable Cargo project pinned to =version, a generated \
            sandbox Cargo.lock, cargo tree --edges normal, and cargo audit. Packages a common \
            pre-add evidence workflow; it does not replace the base commands or define new \
            policy semantics."
    )]
    Candidate(GatehouseCandidateArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    #[command(
        about = "Create the explicit policy scaffold for adoption",
        long_about = "Creates missing barbican.toml, deny.toml, reviewed-targets.toml, and \
            docs/dependency-reviews/ files, preserving existing regular files and validating an \
            existing barbican.toml. Does not review or certify existing dependencies."
    )]
    Init,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PinCommand {
    #[command(
        about = "Scaffold a reviewed family and review-record stub from Cargo.lock",
        long_about = "Reads the resolved version and checksum_sha256 for one crate already \
            resolved in Cargo.lock, fully offline, and appends a reviewed-targets.toml family \
            stub plus a review-record markdown stub pre-filled with the resolved facts. The \
            scaffold is not a completed review."
    )]
    Add {
        #[arg(help = "Crate name, optionally with @version when multiple versions are resolved")]
        spec: String,
    },
    #[command(
        about = "Enforce reviewed-target policy",
        long_about = "Checks active reviewed Rust families in reviewed-targets.toml against the \
            current workspace manifests and Cargo.lock: review records exist, direct \
            requirements and resolved versions/checksums match, and no patch table or cargo \
            config source override bypasses an active reviewed family. Skips successfully when \
            no reviewed-target manifest is present or no active Rust families are configured."
    )]
    Check {
        #[arg(
            long,
            default_value = REVIEWED_TARGETS_CONFIG_FILE,
            help = "Path to the reviewed-targets.toml manifest to enforce"
        )]
        config: PathBuf,
    },
}

#[derive(Debug, Args)]
pub(crate) struct GatehouseCandidateArgs {
    #[arg(
        long,
        help = "Keep the generated sandbox project on disk instead of removing it"
    )]
    pub(crate) preserve_sandbox: bool,
    #[arg(help = "Exact crates.io candidate spec, crate@version")]
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
