use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    BarbicanConfig, CargoManifestDirectRequirement, CargoManifestError, CargoManifestPackage,
    Inventory, InventoryAdvisoryExceptionStatus, InventoryDirectRequirements, InventoryGap,
    InventoryReadinessSummary, OffsetDateTime, WorkspacePackageIdentity, build_inventory,
    build_inventory_graph_facts, check_reviewed_rust_targets, parse_cargo_metadata,
    parse_manifest_package_identity, parse_workspace_dependency_requirements,
    parse_workspace_package_version,
};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::{
    CommandError, NativeDelegatedIgnore, check_review_record_paths, escape_render_field,
    load_config, load_current_lockfile, load_manifest_texts_from_root,
    load_native_delegated_ignores, load_reviewed_targets, parse_manifest_requirements,
    read_optional_text_no_symlink,
};

pub(super) fn run_inventory<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
    now: OffsetDateTime,
    enforce: bool,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let config = load_config(current_dir)?;
    let user_deny_toml = read_optional_text_no_symlink(current_dir, Path::new("deny.toml"))
        .map_err(CommandError::Io)?;
    let native_ignores = load_native_delegated_ignores(current_dir)?;
    let lockfile = load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let manifest_texts = load_manifest_texts_from_root(current_dir)?;
    let manifest_requirements = parse_manifest_requirements(&manifest_texts)?;
    let workspace_requirements = parse_workspace_requirements(&manifest_texts)?;
    let workspace_packages = parse_workspace_packages(&manifest_texts)?;
    let reviewed_targets =
        load_reviewed_targets(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
    let review_record_facts = reviewed_targets
        .as_ref()
        .map(|targets| check_review_record_paths(current_dir, targets))
        .unwrap_or_default();
    let reviewed_report = reviewed_targets
        .as_ref()
        .map(|targets| check_reviewed_rust_targets(targets, &manifest_requirements, &lockfile));
    let graph_collection = collect_graph_facts(current_dir, runner, &lockfile);

    let inventory = build_inventory(
        &lockfile,
        InventoryDirectRequirements::new(&manifest_requirements, &workspace_requirements),
        &workspace_packages,
        reviewed_report.as_ref(),
        &review_record_facts,
        now,
        Some(graph_collection.facts()),
    );

    let surface_report = build_surface_report(&inventory, &graph_collection);
    let delegation_report = InventoryDelegationReport {
        config: &config,
        deny_toml_present: user_deny_toml.is_some(),
        native_ignores: &native_ignores,
    };
    let readiness = inventory.readiness_summary();
    render_inventory(
        stdout,
        &inventory,
        &readiness,
        enforce,
        surface_report,
        delegation_report,
    )?;

    if !enforce {
        return Ok(ExitCode::SUCCESS);
    }

    let coverage_floor = readiness.coverage_floor();
    render_coverage_floor(stdout, coverage_floor)?;
    Ok(if coverage_floor.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Renders the `--enforce` coverage-floor verdict beneath the standard report.
/// The floor names each direct dependency that entered the graph without an
/// active reviewed family and teaches the `pin add` fix — the teaching moment
/// for a raw `cargo add` of an unreviewed crate. Undeclared execution surfaces
/// are a documented follow-up: they remain in the observational report above
/// and are not gated here.
fn render_coverage_floor(
    stdout: &mut dyn Write,
    coverage_floor: &barbican::InventoryCoverageFloor,
) -> Result<(), CommandError> {
    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Coverage floor enforcement:").map_err(CommandError::Io)?;
    if !coverage_floor.policy_configured() {
        writeln!(
            stdout,
            "  no reviewed-targets.toml policy is configured, so no direct dependency can be covered"
        )
        .map_err(CommandError::Io)?;
        writeln!(
            stdout,
            "  - run `cargo barbican policy init`, then `cargo barbican pin add <crate>` for each direct dependency"
        )
        .map_err(CommandError::Io)?;
    } else {
        let uncovered = coverage_floor.uncovered_direct_dependencies();
        let external = coverage_floor.external_non_crates_io_direct_dependencies();
        if !coverage_floor.graph_facts_collected() {
            writeln!(
                stdout,
                "  exact direct-dependency facts were not collected, so enforcement cannot establish coverage: {}",
                escape_render_field(
                    coverage_floor
                        .graph_facts_error()
                        .unwrap_or("no direct-dependency diagnostic was recorded")
                )
            )
            .map_err(CommandError::Io)?;
        } else if uncovered.is_empty() && external.is_empty() {
            writeln!(
                stdout,
                "  every direct dependency is covered by an active reviewed family"
            )
            .map_err(CommandError::Io)?;
        }
        if !uncovered.is_empty() {
            writeln!(
                stdout,
                "  direct dependencies entered the graph without an active reviewed family covering them (a raw `cargo add` of an unreviewed crate looks like this):"
            )
            .map_err(CommandError::Io)?;
            for spec in uncovered {
                writeln!(
                    stdout,
                    "  - {spec} is not covered by any reviewed family; run `cargo barbican pin add {}` to scaffold coverage",
                    spec.crate_name()
                )
                .map_err(CommandError::Io)?;
            }
        }
        if !external.is_empty() {
            writeln!(
                stdout,
                "  direct dependencies use a non-crates.io source a reviewed family cannot cover (git, alternate registry, or a path outside the workspace):"
            )
            .map_err(CommandError::Io)?;
            for source in external {
                let origin = source.source().unwrap_or("an unrecorded source");
                writeln!(
                    stdout,
                    "  - {}@{} resolves via {origin}; a reviewed family cannot cover a non-crates.io source — review it and pin to crates.io, or remove it",
                    source.name(),
                    source.version()
                )
                .map_err(CommandError::Io)?;
            }
        }
    }
    let verdict = if coverage_floor.passed() {
        "PASS"
    } else {
        "FAIL"
    };
    writeln!(
        stdout,
        "Inventory: {verdict} (direct-dependency coverage floor)"
    )
    .map_err(CommandError::Io)?;

    Ok(())
}

enum GraphCollection {
    Collected(barbican::InventoryGraphFacts),
    NotCollected(barbican::InventoryGraphFacts),
}

impl GraphCollection {
    fn facts(&self) -> &barbican::InventoryGraphFacts {
        match self {
            Self::Collected(facts) | Self::NotCollected(facts) => facts,
        }
    }
}

fn collect_graph_facts<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
    lockfile: &barbican::Lockfile,
) -> GraphCollection {
    match try_collect_graph_facts(current_dir, runner, lockfile) {
        Ok(facts) => GraphCollection::Collected(facts),
        Err(reason) => {
            GraphCollection::NotCollected(barbican::InventoryGraphFacts::unavailable(reason))
        }
    }
}

fn try_collect_graph_facts<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
    lockfile: &barbican::Lockfile,
) -> Result<barbican::InventoryGraphFacts, String> {
    let metadata_json = runner
        .cargo_metadata_frozen(current_dir)
        .map_err(|error| error.to_string())?;
    let metadata = parse_cargo_metadata(&metadata_json).map_err(|error| error.to_string())?;

    build_inventory_graph_facts(&metadata, lockfile).map_err(|error| error.to_string())
}

enum SurfaceReport<'a> {
    Collected(&'a [barbican::InventoryLiveSurface]),
    NotCollected(&'a str),
}

impl SurfaceReport<'_> {
    fn is_not_collected(&self) -> bool {
        matches!(self, Self::NotCollected(_))
    }
}

fn build_surface_report<'a>(
    inventory: &'a Inventory,
    graph_collection: &'a GraphCollection,
) -> SurfaceReport<'a> {
    match graph_collection {
        GraphCollection::Collected(_) => SurfaceReport::Collected(
            inventory
                .live_surfaces()
                .expect("build_inventory receives graph facts when metadata is collected"),
        ),
        GraphCollection::NotCollected(facts) => SurfaceReport::NotCollected(
            facts
                .surface_error()
                .expect("unavailable graph facts carry the collection error"),
        ),
    }
}

fn parse_workspace_requirements(
    manifest_texts: &[(String, String)],
) -> Result<Vec<CargoManifestDirectRequirement>, CommandError> {
    let root_text = root_manifest_text(manifest_texts);
    let parsed = parse_workspace_dependency_requirements("Cargo.toml", root_text)
        .map_err(|source| manifest_parse_error("Cargo.toml", source))?;

    Ok(parsed.into_iter().collect())
}

fn parse_workspace_packages(
    manifest_texts: &[(String, String)],
) -> Result<BTreeSet<WorkspacePackageIdentity>, CommandError> {
    let mut packages = BTreeSet::new();
    let root_text = root_manifest_text(manifest_texts);
    let workspace_package_version = parse_workspace_package_version("Cargo.toml", root_text)
        .map_err(|source| manifest_parse_error("Cargo.toml", source))?;

    for (relative_display, text) in manifest_texts {
        if let Some(package) = parse_manifest_package_identity(
            relative_display,
            text,
            workspace_package_version.as_deref(),
        )
        .map_err(|source| manifest_parse_error(relative_display, source))?
        {
            packages.insert(workspace_package_identity(package));
        }
    }

    Ok(packages)
}

fn root_manifest_text(manifest_texts: &[(String, String)]) -> &str {
    manifest_texts
        .iter()
        .find_map(|(relative_display, text)| (relative_display == "Cargo.toml").then_some(text))
        .expect("workspace_manifest_paths always includes Cargo.toml")
}

fn workspace_package_identity(package: CargoManifestPackage) -> WorkspacePackageIdentity {
    WorkspacePackageIdentity::new(package.name().to_owned(), package.version().to_owned())
}

fn manifest_parse_error(path: &str, source: CargoManifestError) -> CommandError {
    CommandError::ManifestParse {
        path: path.to_owned(),
        source,
    }
}

fn render_inventory(
    stdout: &mut dyn Write,
    inventory: &Inventory,
    readiness: &InventoryReadinessSummary,
    enforce: bool,
    surface_report: SurfaceReport<'_>,
    delegation_report: InventoryDelegationReport<'_>,
) -> Result<(), CommandError> {
    let rollup = inventory.rollup();
    let surfaces_not_collected = surface_report.is_not_collected();
    writeln!(stdout, "Dependency inventory:").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  direct dependencies: {}",
        rollup.direct_dependencies
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  resolved crates.io packages: {}",
        rollup.resolved_crates_io
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  non-crates.io sources: {}",
        rollup.non_crates_io_sources
    )
    .map_err(CommandError::Io)?;
    writeln!(stdout, "  reviewed families: {}", rollup.reviewed_families)
        .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  declared execution surfaces: {}",
        rollup.declared_surfaces
    )
    .map_err(CommandError::Io)?;
    render_readiness_summary(stdout, readiness, enforce)?;
    if surfaces_not_collected {
        writeln!(
            stdout,
            "  live graph surfaces: NOT COLLECTED - investigate before trusting this report"
        )
        .map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "  live graph surfaces: collected").map_err(CommandError::Io)?;
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Repository policy files:").map_err(CommandError::Io)?;
    if inventory.policy_configured() {
        writeln!(stdout, "  reviewed-targets.toml: configured").map_err(CommandError::Io)?;
    } else {
        writeln!(
            stdout,
            "  reviewed-targets.toml: not configured; inventory is observational only"
        )
        .map_err(CommandError::Io)?;
    }
    let deny_toml_status = if delegation_report.deny_toml_present {
        "configured; cargo-deny non-advisory posture would use checked-in deny.toml"
    } else {
        "not configured; cargo-deny non-advisory posture would use Barbican's generated default base"
    };
    writeln!(stdout, "  deny.toml: {deny_toml_status}").map_err(CommandError::Io)?;

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Direct dependencies:").map_err(CommandError::Io)?;
    if inventory.direct_dependencies().is_empty() {
        writeln!(stdout, "  none").map_err(CommandError::Io)?;
    }
    for dependency in inventory.direct_dependencies() {
        let requirement = dependency.version_requirement().unwrap_or("(no version)");
        let inherited = if dependency.inherited() {
            " inherited"
        } else {
            ""
        };
        let exact = if !dependency.effective_source_kind().requires_exact_pin() {
            "not applicable"
        } else if dependency.exact_pinned() {
            "exact"
        } else {
            "not exact"
        };
        writeln!(
            stdout,
            "  - {} {}:{} {} [{}{}; source={}; effective-source={}]",
            escape_render_field(dependency.name()),
            escape_render_field(dependency.manifest_path()),
            escape_render_field(dependency.section()),
            escape_render_field(requirement),
            exact,
            inherited,
            dependency.source_kind(),
            dependency.effective_source_kind()
        )
        .map_err(CommandError::Io)?;
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Resolved crates.io inventory:").map_err(CommandError::Io)?;
    if inventory.resolved_crates_io().is_empty() {
        writeln!(stdout, "  none").map_err(CommandError::Io)?;
    }
    for resolved in inventory.resolved_crates_io() {
        let checksum = resolved
            .checksum()
            .map(ToString::to_string)
            .unwrap_or_else(|| "(no checksum)".to_owned());
        writeln!(stdout, "  - {} checksum={}", resolved.spec(), checksum)
            .map_err(CommandError::Io)?;
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Non-crates.io sources:").map_err(CommandError::Io)?;
    if inventory.non_crates_io_sources().is_empty() {
        writeln!(stdout, "  none").map_err(CommandError::Io)?;
    }
    for source in inventory.non_crates_io_sources() {
        writeln!(
            stdout,
            "  - {}@{} source={}",
            escape_render_field(source.name()),
            escape_render_field(source.version()),
            escape_render_field(source.source().unwrap_or("(none)"))
        )
        .map_err(CommandError::Io)?;
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Execution surfaces:").map_err(CommandError::Io)?;
    match surface_report {
        SurfaceReport::Collected(live_surfaces) => {
            writeln!(
                stdout,
                "  live graph surface status: collected via cargo metadata --frozen"
            )
            .map_err(CommandError::Io)?;
            if live_surfaces.is_empty() {
                writeln!(
                    stdout,
                    "  live graph surface findings: no undeclared build.rs / proc-macro / native-sys surfaces detected"
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(stdout, "  live graph surface findings:").map_err(CommandError::Io)?;
                for surface in live_surfaces {
                    let status = if surface.declared() {
                        "declared"
                    } else {
                        "undeclared"
                    };
                    writeln!(
                        stdout,
                        "  - {} {} ({})",
                        surface.spec(),
                        surface.surface(),
                        status
                    )
                    .map_err(CommandError::Io)?;
                }
            }
        }
        SurfaceReport::NotCollected(reason) => {
            writeln!(
                stdout,
                "  live graph surface status: not collected; live graph surface collection failed: {}",
                escape_render_field(reason)
            )
            .map_err(CommandError::Io)?;
            writeln!(
                stdout,
                "  live graph surface remediation: resolve the reported graph or metadata issue, then rerun inventory"
            )
            .map_err(CommandError::Io)?;
        }
    }
    if inventory.declared_surfaces().is_empty() {
        writeln!(stdout, "  declared allowed surfaces: none").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "  declared allowed surfaces:").map_err(CommandError::Io)?;
        for surface in inventory.declared_surfaces() {
            writeln!(
                stdout,
                "  - {} {} allowed by {}",
                surface.spec(),
                surface.surface(),
                escape_render_field(surface.family())
            )
            .map_err(CommandError::Io)?;
        }
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    render_advisory_exceptions(stdout, inventory)?;

    writeln!(stdout).map_err(CommandError::Io)?;
    render_advisory_delegation(stdout, delegation_report)?;

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Reviewed-target coverage:").map_err(CommandError::Io)?;
    if !inventory.policy_configured() {
        writeln!(
            stdout,
            "  no policy configured yet; resolved crates are not classified as slipped-through policy gaps"
        )
        .map_err(CommandError::Io)?;
    } else if inventory.reviewed_families().is_empty() {
        writeln!(
            stdout,
            "  reviewed-targets.toml has no active Rust families"
        )
        .map_err(CommandError::Io)?;
    } else {
        for family in inventory.reviewed_families() {
            let record_status = if family.review_record_completed() {
                "record completed"
            } else {
                "record not completed"
            };
            writeln!(
                stdout,
                "  - {}: {} direct, {} resolved, {} ({})",
                escape_render_field(family.name()),
                family.direct_count(),
                family.resolved_count(),
                escape_render_field(family.review_record()),
                record_status
            )
            .map_err(CommandError::Io)?;
        }
    }

    let observational_findings = inventory.observational_findings();
    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Observational findings:").map_err(CommandError::Io)?;
    if observational_findings.is_empty() {
        writeln!(stdout, "  none").map_err(CommandError::Io)?;
    }
    for gap in observational_findings {
        writeln!(stdout, "  - {}", render_gap(gap)).map_err(CommandError::Io)?;
    }

    let policy_coverage_gaps = inventory.policy_coverage_gaps();
    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Reviewed-policy findings:").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  uncovered direct dependencies block when coverage enforcement is active (`inventory --enforce` or `gatehouse pre-release`); uncovered transitive packages and undeclared execution surfaces remain observational"
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  incomplete family review records are enforced by `pin check` and `verify`"
    )
    .map_err(CommandError::Io)?;
    if policy_coverage_gaps.is_empty() {
        writeln!(stdout, "  none").map_err(CommandError::Io)?;
    }
    for gap in policy_coverage_gaps {
        writeln!(stdout, "  - {}", render_gap(gap)).map_err(CommandError::Io)?;
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Suggested next actions:").map_err(CommandError::Io)?;
    if surfaces_not_collected {
        writeln!(
            stdout,
            "  - Resolve live graph surface collection before trusting this inventory report."
        )
        .map_err(CommandError::Io)?;
    } else if !inventory.policy_configured() {
        writeln!(
            stdout,
            "  - Run `cargo barbican policy init` to create the reviewed-target scaffold."
        )
        .map_err(CommandError::Io)?;
    } else if inventory.gaps().is_empty() {
        writeln!(
            stdout,
            "  - Run `cargo barbican gatehouse pre-release` for the complete release gate."
        )
        .map_err(CommandError::Io)?;
    } else {
        writeln!(
            stdout,
            "  - Review the labelled backlog, update reviewed-targets.toml and review records, then run `cargo barbican gatehouse pre-release`."
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_readiness_summary(
    stdout: &mut dyn Write,
    readiness: &InventoryReadinessSummary,
    enforce: bool,
) -> Result<(), CommandError> {
    let coverage_floor = readiness.coverage_floor();
    let floor_status = if !coverage_floor.policy_configured() {
        "NOT READY (reviewed-targets.toml is not configured)"
    } else if !coverage_floor.graph_facts_collected() {
        "NOT READY (exact direct-dependency graph facts were not collected)"
    } else if coverage_floor.passed() && enforce {
        "PASS (enforced in this run)"
    } else if coverage_floor.passed() {
        "PASS-ready (informational run)"
    } else if enforce {
        "FAIL (enforced in this run)"
    } else {
        "NOT READY (informational run; enforcement would fail)"
    };
    writeln!(stdout, "  direct-dependency coverage floor: {floor_status}")
        .map_err(CommandError::Io)?;

    if coverage_floor.graph_facts_collected() {
        writeln!(
            stdout,
            "  enforced uncovered direct crates.io dependencies: {}",
            coverage_floor.uncovered_direct_dependencies().len()
        )
        .map_err(CommandError::Io)?;
        writeln!(
            stdout,
            "  enforced external direct dependencies: {}",
            coverage_floor
                .external_non_crates_io_direct_dependencies()
                .len()
        )
        .map_err(CommandError::Io)?;
        writeln!(
            stdout,
            "  observational uncovered transitive crates.io packages: {}",
            readiness.uncovered_transitive_crates_io()
        )
        .map_err(CommandError::Io)?;
    } else {
        writeln!(
            stdout,
            "  unclassified uncovered crates.io packages: {} (direct/transitive split unavailable)",
            readiness.unclassified_uncovered_crates_io()
        )
        .map_err(CommandError::Io)?;
        writeln!(
            stdout,
            "  unclassified non-crates.io sources: {} (direct/transitive split unavailable)",
            readiness.unclassified_non_crates_io_sources()
        )
        .map_err(CommandError::Io)?;
    }

    writeln!(
        stdout,
        "  observational undeclared execution surfaces: {}",
        readiness.undeclared_execution_surfaces()
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  enforced incomplete review records (pin check/verify): {}",
        readiness.incomplete_review_records()
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  other observational manifest/source findings: {}",
        readiness.other_observational_findings()
    )
    .map_err(CommandError::Io)?;

    Ok(())
}

fn render_advisory_exceptions(
    stdout: &mut dyn Write,
    inventory: &Inventory,
) -> Result<(), CommandError> {
    writeln!(stdout, "Reviewed advisory exceptions:").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  expiry window: soon-to-expire means review_by within {} day(s)",
        barbican::INVENTORY_ADVISORY_SOON_TO_EXPIRE_DAYS
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  stale means the exception's crate@version is not present in the current Cargo.lock"
    )
    .map_err(CommandError::Io)?;
    if inventory.advisory_exceptions().is_empty() {
        writeln!(stdout, "  exceptions: none").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "  exceptions:").map_err(CommandError::Io)?;
        for exception in inventory.advisory_exceptions() {
            writeln!(
                stdout,
                "  - {} {} family={} review_record={} review_by={} status={} resolved-target={} review-record={}",
                exception.spec(),
                escape_render_field(exception.advisory_id()),
                escape_render_field(exception.family()),
                escape_render_field(exception.review_record()),
                exception.review_by(),
                render_advisory_exception_status(exception.status()),
                if exception.resolved_target_matches() { "matched" } else { "not matched" },
                if exception.review_record_completed() { "completed" } else { "not-completed" }
            )
            .map_err(CommandError::Io)?;
        }
    }

    Ok(())
}

struct InventoryDelegationReport<'a> {
    config: &'a BarbicanConfig,
    deny_toml_present: bool,
    native_ignores: &'a [NativeDelegatedIgnore],
}

fn render_advisory_delegation(
    stdout: &mut dyn Write,
    report: InventoryDelegationReport<'_>,
) -> Result<(), CommandError> {
    writeln!(stdout, "Advisory delegation:").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  lockfile scanner: {}",
        report.config.delegates.advisories.lockfile_scanner.as_str()
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  cargo-deny checks: {}",
        report
            .config
            .delegates
            .cargo_deny
            .checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  unmanaged delegated policy: {}",
        report.config.delegates.unmanaged_delegated_policy.as_str()
    )
    .map_err(CommandError::Io)?;
    if report.native_ignores.is_empty() {
        writeln!(stdout, "  native delegated advisory ignores: none").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "  native delegated advisory ignores:").map_err(CommandError::Io)?;
        for entry in report.native_ignores {
            writeln!(
                stdout,
                "  - {} ignores {}",
                entry.source(),
                entry
                    .advisory_ids()
                    .iter()
                    .map(|id| escape_render_field(id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .map_err(CommandError::Io)?;
        }
    }

    Ok(())
}

fn render_advisory_exception_status(status: InventoryAdvisoryExceptionStatus) -> &'static str {
    match status {
        InventoryAdvisoryExceptionStatus::Active => "active",
        InventoryAdvisoryExceptionStatus::SoonToExpire => "soon-to-expire",
        InventoryAdvisoryExceptionStatus::Expired => "expired",
        InventoryAdvisoryExceptionStatus::Stale => "stale",
    }
}

fn render_gap(gap: &InventoryGap) -> String {
    match gap {
        InventoryGap::IncompleteReviewRecord {
            family,
            review_record,
        } => {
            format!(
                "review record not completed for family {}: {}",
                escape_render_field(family),
                escape_render_field(review_record)
            )
        }
        InventoryGap::UncoveredResolvedCrate { spec } => {
            format!("resolved crates.io package is not covered by any reviewed family: {spec}")
        }
        InventoryGap::NonExactDirectPin {
            manifest_path,
            section,
            name,
            requirement,
            inherited,
        } => {
            let requirement = requirement.as_deref().unwrap_or("(no version)");
            let inherited = if *inherited { " inherited" } else { "" };
            format!(
                "direct dependency {} at {}:{} is not exact{inherited}: {}",
                escape_render_field(name),
                escape_render_field(manifest_path),
                escape_render_field(section),
                escape_render_field(requirement)
            )
        }
        InventoryGap::NonCratesIoSource {
            name,
            version,
            source,
        } => {
            let version = if version.is_empty() {
                "(no version)"
            } else {
                version
            };
            format!(
                "non-crates.io dependency source for {}@{}: {}",
                escape_render_field(name),
                escape_render_field(version),
                escape_render_field(source.as_deref().unwrap_or("(none)"))
            )
        }
        InventoryGap::UndeclaredExecutionSurface { spec, surface, .. } => {
            format!("live execution surface is not declared in reviewed policy: {spec} {surface}")
        }
    }
}
