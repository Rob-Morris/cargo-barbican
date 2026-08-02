use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::process::ExitCode;

use barbican::{ReleaseAgeOutcome, ReleaseAgeReport, ReviewedReleaseAgeException, format_age};

use super::{CommandError, escape_diagnostic_for_terminal};

/// Returns a bare detail — no `FAIL ` prefix — so every call site adds the
/// prefix exactly once, either directly (writing a raw stderr line) or via
/// [`fail`]/`push_failed_inspect` (which already prepend it). Baking the
/// prefix in here as well previously produced a doubled "FAIL FAIL " line
/// at the two call sites that route the string through those wrappers.
pub(crate) fn render_incomplete_release_age_exception_review_record(
    exception: &ReviewedReleaseAgeException,
) -> String {
    format!(
        "allowed release-age exception review record not completed for {}: {}",
        escape_render_field(&exception.spec().to_string()),
        escape_render_field(exception.review_record())
    )
}

/// `report.published_at_raw()` is the raw crates.io API `created_at` string —
/// network-sourced and therefore untrusted — so every branch below routes it,
/// the spec, and any reviewed-family/review-record strings from
/// `reviewed-targets.toml` through [`escape_render_field`] rather than
/// interpolating them directly.
pub(crate) fn render_release_age_report(report: &ReleaseAgeReport) -> String {
    let spec = escape_render_field(&report.spec().to_string());
    let published_at_raw = escape_render_field(report.published_at_raw());
    match report.outcome() {
        ReleaseAgeOutcome::Allowed => format!(
            "OK   {spec}: published {published_at_raw} ({} old)",
            format_age(report.age_seconds()),
        ),
        ReleaseAgeOutcome::AllowedByException {
            family,
            review_record,
        } => {
            let family = escape_render_field(family);
            let review_record = escape_render_field(review_record);
            format!(
                "ALLOW {spec}: published {published_at_raw} ({} old), below the {}-day minimum; release-age exception allowed by reviewed family {family} ({review_record})",
                format_age(report.age_seconds()),
                report.minimum_days(),
            )
        }
        ReleaseAgeOutcome::Yanked => {
            format!("FAIL {spec}: version is yanked on crates.io")
        }
        ReleaseAgeOutcome::TooFresh => format!(
            "FAIL {spec}: published {published_at_raw} ({} old), below the {}-day minimum; record a reviewed release-age exception in reviewed-targets.toml if this candidate is intentionally accepted",
            format_age(report.age_seconds()),
            report.minimum_days(),
        ),
        ReleaseAgeOutcome::ExceptionArtefactMismatch {
            family,
            review_record,
            expected,
            found,
        } => {
            let family = escape_render_field(family);
            let review_record = escape_render_field(review_record);
            format!(
                "FAIL {spec}: release-age exception artefact mismatch for reviewed family {family} ({review_record}): expected sha256 {expected}, found {found}",
            )
        }
    }
}

/// Untrusted-string choke point for list-shaped report fields: every caller
/// renders crate names, versions, requirements, or paths sourced from the
/// network, `Cargo.lock`, or manifests, so escaping happens once here rather
/// than being left to each call site to remember.
pub(crate) fn join_display<T: fmt::Display>(values: &[T], separator: &str) -> String {
    values
        .iter()
        .map(|value| escape_render_field(&value.to_string()))
        .collect::<Vec<_>>()
        .join(separator)
}

pub(crate) fn render_allowed_policy_exceptions<I, T>(
    stdout: &mut dyn Write,
    exceptions: I,
) -> Result<(), CommandError>
where
    I: IntoIterator<Item = T>,
    T: fmt::Display,
{
    let rendered = exceptions
        .into_iter()
        .map(|exception| escape_render_field(&exception.to_string()))
        .collect::<Vec<_>>();
    if rendered.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "Allowed policy exceptions:").map_err(CommandError::Io)?;
    for exception in rendered {
        writeln!(stdout, "  - {exception}").map_err(CommandError::Io)?;
    }

    Ok(())
}

pub(crate) fn escape_render_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
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

/// The single terminal-failure renderer: every failure path that is not
/// itself a stdout report writes through here, so `FAIL ` is always the
/// prefix a caller (or a `grep FAIL`) sees on stderr. Escaping the detail
/// here — rather than trusting each call site to have escaped it already —
/// closes the terminal-injection gap at one choke point instead of many.
pub(crate) fn fail(
    stderr: &mut dyn Write,
    detail: impl fmt::Display,
) -> Result<ExitCode, CommandError> {
    let detail = escape_diagnostic_for_terminal(&detail.to_string());
    writeln!(stderr, "FAIL {detail}").map_err(CommandError::Io)?;
    Ok(ExitCode::from(1))
}

#[cfg(test)]
mod tests {
    use super::escape_render_field;

    #[test]
    fn escape_render_field_escapes_bidi_and_zero_width_controls() {
        assert_eq!(
            escape_render_field("safe\u{202e}name\u{200b}field\u{200f}\u{2060}"),
            "safe\\x202ename\\x200bfield\\x200f\\x2060"
        );
    }
}
