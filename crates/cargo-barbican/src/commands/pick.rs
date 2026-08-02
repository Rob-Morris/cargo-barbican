use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, OffsetDateTime, PickError, PickExcludedVersion, PickExclusionReason,
    PickSelection, parse_pick_spec, pick_version,
};

use super::{
    CommandError, escape_render_field, exit_code_from_policy_failures, load_release_age_context,
    release_age_override_note, render_release_age_report,
};

pub(super) fn run_pick<C>(
    min_age_days: Option<u64>,
    raw_spec: String,
    current_dir: &Path,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let pick_spec = match parse_pick_spec(&raw_spec) {
        Ok(spec) => spec,
        Err(error) => {
            writeln!(stderr, "FAIL {raw_spec}: {error}").map_err(CommandError::Io)?;
            return Ok(exit_code_from_policy_failures(true));
        }
    };
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, min_age_days)?;
    if let Some(note) = release_age_override_note(current_dir, min_age_days)? {
        writeln!(stdout, "{note}").map_err(CommandError::Io)?;
    }
    let versions = match client.fetch_versions(pick_spec.crate_name()) {
        Ok(versions) => versions,
        Err(error) => {
            writeln!(stderr, "FAIL {}: {error}", pick_spec.crate_name())
                .map_err(CommandError::Io)?;
            return Ok(exit_code_from_policy_failures(true));
        }
    };
    let selection = match pick_version(
        pick_spec.crate_name(),
        pick_spec.requirement(),
        &versions,
        minimum_days,
        now,
        reviewed_release_age_exceptions.honoured(),
    ) {
        Ok(selection) => selection,
        Err(error) => {
            render_pick_error(
                pick_spec.crate_name(),
                pick_spec.requirement(),
                &error,
                stderr,
            )?;
            return Ok(exit_code_from_policy_failures(true));
        }
    };

    render_pick_selection(pick_spec.requirement(), &selection, stdout)?;

    Ok(ExitCode::SUCCESS)
}

fn render_pick_selection(
    requirement: &str,
    selection: &PickSelection,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    let selected = escape_render_field(&selection.selected().to_string());
    writeln!(stdout, "Pick {selected}").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  requirement: {}",
        escape_render_field(requirement)
    )
    .map_err(CommandError::Io)?;
    writeln!(stdout, "  selected: {selected}").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  release age: {}",
        render_release_age_report(selection.release_age())
    )
    .map_err(CommandError::Io)?;
    if selection.excluded().is_empty() {
        writeln!(stdout, "  excluded candidates: none").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "  excluded candidates:").map_err(CommandError::Io)?;
        render_pick_exclusions(selection.excluded(), stdout)?;
    }

    Ok(())
}

fn render_pick_error(
    crate_name: &str,
    requirement: &str,
    error: &PickError,
    stderr: &mut dyn Write,
) -> Result<(), CommandError> {
    writeln!(
        stderr,
        "FAIL {}@{}: no version satisfied requirement and policy",
        escape_render_field(crate_name),
        escape_render_field(requirement)
    )
    .map_err(CommandError::Io)?;
    if !error.excluded().is_empty() {
        writeln!(stderr, "  excluded candidates:").map_err(CommandError::Io)?;
        render_pick_exclusions(error.excluded(), stderr)?;
    }

    Ok(())
}

/// Itemises the policy-relevant exclusions (yanked, pre-release, too-fresh,
/// and malformed candidates) one per line, but collapses the plain
/// requirement-mismatch exclusions into a single summary line: a wide range
/// like `serde@^1` otherwise buries the few policy-driven exclusions under
/// ~90 identical "outside requested range" lines. Writes to whichever stream
/// the caller passes, so the selection path lands on stdout and the
/// no-candidate error path lands on stderr.
fn render_pick_exclusions(
    excluded: &[PickExcludedVersion],
    out: &mut dyn Write,
) -> Result<(), CommandError> {
    let mut outside_range = 0_usize;
    for candidate in excluded {
        if matches!(
            candidate.reason(),
            PickExclusionReason::DoesNotMatchRequirement
        ) {
            outside_range += 1;
            continue;
        }
        let reason = render_pick_exclusion(candidate.reason());
        writeln!(
            out,
            "  - {}: {}",
            escape_render_field(candidate.version()),
            escape_render_field(&reason)
        )
        .map_err(CommandError::Io)?;
    }

    if outside_range > 0 {
        let versions = if outside_range == 1 {
            "version"
        } else {
            "versions"
        };
        writeln!(
            out,
            "  - {outside_range} {versions} excluded: outside requested range"
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_pick_exclusion(reason: &PickExclusionReason) -> String {
    match reason {
        PickExclusionReason::InvalidSemver(error) => format!("invalid semver ({error})"),
        PickExclusionReason::InvalidExactSpec(error) => format!("invalid exact spec ({error})"),
        PickExclusionReason::DoesNotMatchRequirement => "does not match requirement".to_owned(),
        PickExclusionReason::PreRelease => "pre-release".to_owned(),
        PickExclusionReason::Yanked => "yanked".to_owned(),
        PickExclusionReason::TooFresh => "too fresh".to_owned(),
        PickExclusionReason::ReleaseAgeExceptionArtefactMismatch => {
            "release-age exception artefact mismatch".to_owned()
        }
    }
}
