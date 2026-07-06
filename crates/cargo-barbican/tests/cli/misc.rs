use super::common::*;

#[test]
fn cli_rejects_excessive_min_age_days() {
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "age",
            "--min-age-days",
            "365001",
            "serde@1.0.228",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "age-lock", "--min-age-days", "365001",]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "update",
            "--min-age-days",
            "365001",
            "serde@1.0.228",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "resolve", "--min-age-days", "365001",]).is_err()
    );
    assert!(Cli::try_parse_from(["cargo-barbican", "resolve", "serde@1.0.228"]).is_err());
    assert!(
        Cli::try_parse_from(["cargo-barbican", "assess", "--min-age-days", "365001",]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "age-lock",
            "--base-ref",
            "HEAD",
            "--base-lockfile",
            "baseline/Cargo.lock",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "assess",
            "--base-ref",
            "HEAD",
            "--base-dir",
            "baseline",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "assess", "--policy-mode", "permissive",]).is_err()
    );
}
