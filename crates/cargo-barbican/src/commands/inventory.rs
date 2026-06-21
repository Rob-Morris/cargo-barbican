use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use std::collections::BTreeSet;

use barbican::{
    CargoManifestDirectRequirement, CargoManifestError, CargoManifestPackage, Inventory,
    InventoryDirectRequirements, InventoryGap, ReviewRecordFact, WorkspacePackageIdentity,
    build_graph_surfaces, build_inventory, parse_cargo_metadata, parse_manifest_package_identity,
    parse_workspace_dependency_requirements, parse_workspace_package_version,
};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::{
    CommandError, check_review_record_paths, load_current_lockfile, load_manifest_texts_from_root,
    load_reviewed_targets, parse_manifest_requirements,
};

pub(super) fn run_inventory<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let lockfile = load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let manifest_texts = load_manifest_texts_from_root(current_dir)?;
    let manifest_requirements = parse_manifest_requirements(&manifest_texts)?;
    let workspace_requirements = parse_workspace_requirements(&manifest_texts)?;
    let workspace_packages = parse_workspace_packages(&manifest_texts)?;
    let reviewed_targets =
        load_reviewed_targets(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
    let review_record_facts = reviewed_targets
        .as_ref()
        .map(|targets| {
            check_review_record_paths(current_dir, targets)
                .into_iter()
                .map(|check| {
                    ReviewRecordFact::new(
                        check.family_name().to_owned(),
                        check.review_record().to_owned(),
                        check.is_success(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let surface_collection = collect_graph_surfaces(current_dir, runner);

    let inventory = build_inventory(
        &lockfile,
        InventoryDirectRequirements::new(&manifest_requirements, &workspace_requirements),
        &workspace_packages,
        reviewed_targets.as_ref(),
        &review_record_facts,
        surface_collection.surfaces(),
    );

    let surface_report = build_surface_report(&inventory, &surface_collection);
    render_inventory(stdout, &inventory, surface_report)?;
    Ok(ExitCode::SUCCESS)
}

enum SurfaceCollection {
    Collected(barbican::GraphSurfaces),
    NotCollected(String),
}

impl SurfaceCollection {
    fn surfaces(&self) -> Option<&barbican::GraphSurfaces> {
        match self {
            Self::Collected(surfaces) => Some(surfaces),
            Self::NotCollected(_) => None,
        }
    }
}

fn collect_graph_surfaces<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
) -> SurfaceCollection {
    match try_collect_graph_surfaces(current_dir, runner) {
        Ok(surfaces) => SurfaceCollection::Collected(surfaces),
        Err(reason) => SurfaceCollection::NotCollected(reason),
    }
}

fn try_collect_graph_surfaces<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
) -> Result<barbican::GraphSurfaces, String> {
    let metadata_json = runner
        .cargo_metadata_frozen(current_dir)
        .map_err(|error| error.to_string())?;
    let metadata = parse_cargo_metadata(&metadata_json).map_err(|error| error.to_string())?;

    build_graph_surfaces(&metadata).map_err(|error| error.to_string())
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
    surface_collection: &'a SurfaceCollection,
) -> SurfaceReport<'a> {
    match surface_collection {
        SurfaceCollection::Collected(_) => SurfaceReport::Collected(
            inventory
                .live_surfaces()
                .expect("build_inventory receives surfaces when metadata is collected"),
        ),
        SurfaceCollection::NotCollected(reason) => SurfaceReport::NotCollected(reason),
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
    surface_report: SurfaceReport<'_>,
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
    writeln!(
        stdout,
        "  observational findings: {}",
        rollup.observational_findings
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  policy coverage gaps: {}",
        rollup.policy_coverage_gaps
    )
    .map_err(CommandError::Io)?;
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
            let record_status = if family.review_record_exists() {
                "record ok"
            } else {
                "record missing"
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
    writeln!(stdout, "Policy coverage gaps:").map_err(CommandError::Io)?;
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
            "  - Run `cargo barbican pin-check` or `cargo barbican verify` to enforce policy."
        )
        .map_err(CommandError::Io)?;
    } else {
        writeln!(
            stdout,
            "  - Review each finding or gap, update reviewed-targets.toml and review records, then run `cargo barbican verify`."
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_gap(gap: &InventoryGap) -> String {
    match gap {
        InventoryGap::MissingReviewRecord {
            family,
            review_record,
        } => {
            format!(
                "missing review record for family {}: {}",
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

fn escape_render_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {
                write!(&mut escaped, "\\x{:02x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => escaped.push(character),
        }
    }

    escaped
}
