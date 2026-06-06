use time::OffsetDateTime;

use crate::{CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAgeOutcome {
    Allowed,
    Yanked,
    TooFresh,
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
        matches!(self.outcome, ReleaseAgeOutcome::Allowed)
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

    pub fn outcome(&self) -> ReleaseAgeOutcome {
        self.outcome
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
    check_release_age_at(client, spec, OffsetDateTime::now_utc(), minimum_days)
}

pub fn check_release_age_at<C>(
    client: &C,
    spec: &ExactCrateSpec,
    now: OffsetDateTime,
    minimum_days: u64,
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
    ))
}

pub fn evaluate_release_age(
    spec: ExactCrateSpec,
    release: CrateRelease,
    now: OffsetDateTime,
    minimum_days: u64,
) -> ReleaseAgeReport {
    let age_seconds = (now - release.published_at).whole_seconds();
    let clamped_age_seconds = age_seconds.max(0) as u64;
    let minimum_age_seconds = minimum_days.saturating_mul(86_400);

    let outcome = if release.yanked {
        ReleaseAgeOutcome::Yanked
    } else if clamped_age_seconds < minimum_age_seconds {
        ReleaseAgeOutcome::TooFresh
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

    use crate::{CrateRelease, ExactCrateSpec};

    use super::{ReleaseAgeOutcome, evaluate_release_age, format_age};

    fn release(timestamp: &str, yanked: bool) -> CrateRelease {
        CrateRelease {
            checksum_sha256_hex: "abc123".to_owned(),
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
        );

        assert!(report.is_success());
        assert_eq!(report.outcome(), ReleaseAgeOutcome::Allowed);
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
        );

        assert_eq!(report.outcome(), ReleaseAgeOutcome::TooFresh);
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
        );

        assert_eq!(report.outcome(), ReleaseAgeOutcome::Yanked);
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
        );

        assert_eq!(report.outcome(), ReleaseAgeOutcome::TooFresh);
        assert_eq!(report.published_at_raw(), "2026-05-10T12:10:00Z");
        assert_eq!(format_age(report.age_seconds()), "0m");
    }
}
