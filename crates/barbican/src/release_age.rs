use time::OffsetDateTime;

use crate::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, ReviewedReleaseAgeException,
    Sha256Digest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseAgeOutcome {
    Allowed,
    AllowedByException {
        family: String,
        review_record: String,
    },
    Yanked,
    TooFresh,
    ExceptionArtefactMismatch {
        family: String,
        review_record: String,
        expected: Sha256Digest,
        found: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAgeReport {
    spec: ExactCrateSpec,
    published_at_raw: String,
    age_seconds: i64,
    minimum_days: u64,
    outcome: ReleaseAgeOutcome,
}

impl ReleaseAgeReport {
    pub fn is_success(&self) -> bool {
        matches!(
            self.outcome,
            ReleaseAgeOutcome::Allowed | ReleaseAgeOutcome::AllowedByException { .. }
        )
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn published_at_raw(&self) -> &str {
        &self.published_at_raw
    }

    pub fn age_seconds(&self) -> i64 {
        self.age_seconds
    }

    pub fn minimum_days(&self) -> u64 {
        self.minimum_days
    }

    pub fn outcome(&self) -> &ReleaseAgeOutcome {
        &self.outcome
    }
}

pub fn check_release_age<C>(
    client: &C,
    spec: &ExactCrateSpec,
    minimum_days: u64,
) -> Result<ReleaseAgeReport, CratesIoClientError>
where
    C: CratesIoClient + ?Sized,
{
    check_release_age_at(client, spec, OffsetDateTime::now_utc(), minimum_days, None)
}

pub fn check_release_age_at<C>(
    client: &C,
    spec: &ExactCrateSpec,
    now: OffsetDateTime,
    minimum_days: u64,
    exception: Option<&ReviewedReleaseAgeException>,
) -> Result<ReleaseAgeReport, CratesIoClientError>
where
    C: CratesIoClient + ?Sized,
{
    let release = client.fetch_release(spec)?;

    Ok(evaluate_release_age(
        spec.clone(),
        release,
        now,
        minimum_days,
        exception,
    ))
}

pub fn evaluate_release_age(
    spec: ExactCrateSpec,
    release: CrateRelease,
    now: OffsetDateTime,
    minimum_days: u64,
    exception: Option<&ReviewedReleaseAgeException>,
) -> ReleaseAgeReport {
    let age_seconds = (now - release.published_at).whole_seconds().max(0);
    let clamped_age_seconds = age_seconds as u64;
    let minimum_age_seconds = minimum_days.saturating_mul(86_400);

    let outcome = if release.yanked {
        ReleaseAgeOutcome::Yanked
    } else if clamped_age_seconds < minimum_age_seconds {
        match exception.filter(|exception| exception.spec() == &spec) {
            Some(exception) if exception.checksum_sha256() == &release.checksum_sha256_hex => {
                ReleaseAgeOutcome::AllowedByException {
                    family: exception.family().to_owned(),
                    review_record: exception.review_record().to_owned(),
                }
            }
            Some(exception) => ReleaseAgeOutcome::ExceptionArtefactMismatch {
                family: exception.family().to_owned(),
                review_record: exception.review_record().to_owned(),
                expected: exception.checksum_sha256().clone(),
                found: release.checksum_sha256_hex.clone(),
            },
            None => ReleaseAgeOutcome::TooFresh,
        }
    } else {
        ReleaseAgeOutcome::Allowed
    };

    ReleaseAgeReport {
        spec,
        published_at_raw: release.published_at_raw,
        age_seconds,
        minimum_days,
        outcome,
    }
}

pub fn format_age(seconds: i64) -> String {
    let total_seconds = seconds.max(0);
    let days = total_seconds / 86_400;
    let remainder = total_seconds % 86_400;
    let hours = remainder / 3_600;
    let minutes = (remainder % 3_600) / 60;
    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 || days > 0 {
        parts.push(format!("{hours}h"));
    }
    parts.push(format!("{minutes}m"));

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::{
        CrateRelease, ExactCrateSpec, ReviewedReleaseAgeException, Sha256Digest,
        parse_reviewed_targets_toml,
    };

    use super::{ReleaseAgeOutcome, evaluate_release_age, format_age};

    fn release(timestamp: &str, yanked: bool) -> CrateRelease {
        release_with_checksum(
            timestamp,
            yanked,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    fn release_with_checksum(timestamp: &str, yanked: bool, checksum: &str) -> CrateRelease {
        CrateRelease {
            checksum_sha256_hex: Sha256Digest::try_from(checksum)
                .expect("fixture checksum should parse"),
            published_at_raw: timestamp.to_owned(),
            published_at: OffsetDateTime::parse(
                timestamp,
                &time::format_description::well_known::Rfc3339,
            )
            .expect("timestamp should parse"),
            yanked,
        }
    }

    fn now(timestamp: &str) -> OffsetDateTime {
        OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
            .expect("timestamp should parse")
    }

    fn exception(version: &str, checksum: &str) -> ReviewedReleaseAgeException {
        let targets = parse_reviewed_targets_toml(&format!(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "{version}", checksum_sha256 = "{checksum}" }}

[rust.families.allowed_age_exceptions]
serde = "{version}"
"#
        ))
        .expect("exception fixture should parse");

        targets
            .release_age_exceptions()
            .into_iter()
            .next()
            .expect("exception should exist")
    }

    #[test]
    fn format_age_matches_undertask_shape() {
        assert_eq!(format_age(59), "0m");
        assert_eq!(format_age(3_661), "1h 1m");
        assert_eq!(format_age(176_400), "2d 1h 0m");
    }

    #[test]
    fn older_release_is_allowed() {
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-01T00:00:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            None,
        );

        assert!(report.is_success());
        assert_eq!(report.outcome(), &ReleaseAgeOutcome::Allowed);
        assert_eq!(report.spec().to_string(), "serde@1.0.228");
        assert_eq!(report.published_at_raw(), "2026-05-01T00:00:00Z");
        assert_eq!(report.minimum_days(), 7);
        assert_eq!(report.age_seconds(), 820_800);
    }

    #[test]
    fn too_fresh_release_fails_with_policy_message() {
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-05T18:00:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            None,
        );

        assert_eq!(report.outcome(), &ReleaseAgeOutcome::TooFresh);
        assert_eq!(report.spec().to_string(), "serde@1.0.228");
        assert_eq!(report.published_at_raw(), "2026-05-05T18:00:00Z");
        assert_eq!(report.minimum_days(), 7);
        assert_eq!(report.age_seconds(), 410_400);
    }

    #[test]
    fn yanked_release_fails_even_if_old_enough() {
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-01T00:00:00Z", true),
            now("2026-05-10T12:00:00Z"),
            7,
            Some(&exception(
                "1.0.228",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )),
        );

        assert_eq!(report.outcome(), &ReleaseAgeOutcome::Yanked);
        assert_eq!(report.spec().to_string(), "serde@1.0.228");
    }

    #[test]
    fn future_release_timestamps_clamp_to_zero_age_output() {
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-10T12:10:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            None,
        );

        assert_eq!(report.outcome(), &ReleaseAgeOutcome::TooFresh);
        assert_eq!(report.published_at_raw(), "2026-05-10T12:10:00Z");
        assert_eq!(format_age(report.age_seconds()), "0m");
    }

    #[test]
    fn too_fresh_release_matching_exception_is_allowed() {
        let exception = exception(
            "1.0.228",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-05T18:00:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            Some(&exception),
        );

        assert!(report.is_success());
        assert_eq!(
            report.outcome(),
            &ReleaseAgeOutcome::AllowedByException {
                family: "serde-family".to_owned(),
                review_record: "docs/dependency-reviews/2026-05-27-serde.md".to_owned(),
            }
        );
    }

    #[test]
    fn too_fresh_release_matching_exception_blocks_on_checksum_mismatch() {
        let exception = exception(
            "1.0.228",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-05T18:00:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            Some(&exception),
        );

        assert!(!report.is_success());
        assert_eq!(
            report.outcome(),
            &ReleaseAgeOutcome::ExceptionArtefactMismatch {
                family: "serde-family".to_owned(),
                review_record: "docs/dependency-reviews/2026-05-27-serde.md".to_owned(),
                expected: Sha256Digest::try_from(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                )
                .expect("checksum should parse"),
                found: Sha256Digest::try_from(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("checksum should parse"),
            }
        );
    }

    #[test]
    fn exception_for_other_version_does_not_waive_release_age() {
        let exception = exception(
            "1.0.227",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release("2026-05-05T18:00:00Z", false),
            now("2026-05-10T12:00:00Z"),
            7,
            Some(&exception),
        );

        assert_eq!(report.outcome(), &ReleaseAgeOutcome::TooFresh);
    }

    #[test]
    fn old_enough_release_ignores_matching_exception() {
        let exception = exception(
            "1.0.228",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let report = evaluate_release_age(
            "serde@1.0.228"
                .parse::<ExactCrateSpec>()
                .expect("spec should parse"),
            release_with_checksum(
                "2026-05-01T00:00:00Z",
                false,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            now("2026-05-10T12:00:00Z"),
            7,
            Some(&exception),
        );

        assert_eq!(report.outcome(), &ReleaseAgeOutcome::Allowed);
    }
}
