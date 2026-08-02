use serde::Deserialize;
use thiserror::Error;

pub const MAXIMUM_RELEASE_AGE_MINIMUM_DAYS: u64 = 365_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BarbicanConfig {
    pub release_age: ReleaseAgeConfig,
    pub high_scrutiny: HighScrutinyConfig,
    pub delegates: DelegatesConfig,
}

impl BarbicanConfig {
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigLoadError> {
        let config: Self = toml::from_str(text).map_err(ConfigLoadError::Parse)?;
        config.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseAgeConfig {
    pub minimum_days: u64,
}

impl Default for ReleaseAgeConfig {
    fn default() -> Self {
        Self { minimum_days: 7 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HighScrutinyConfig {
    pub new_direct_dependencies: bool,
    pub non_crates_io_direct_dependencies: bool,
    pub non_crates_io_source_changes: bool,
    pub build_rs_changes: bool,
    pub proc_macro_changes: bool,
    pub native_sys_crates: bool,
}

impl Default for HighScrutinyConfig {
    fn default() -> Self {
        Self {
            new_direct_dependencies: true,
            non_crates_io_direct_dependencies: true,
            non_crates_io_source_changes: true,
            build_rs_changes: true,
            proc_macro_changes: true,
            native_sys_crates: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DelegatesConfig {
    pub unmanaged_delegated_policy: UnmanagedDelegatedPolicyMode,
    pub advisories: AdvisoryDelegatesConfig,
    pub cargo_deny: CargoDenyDelegatesConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UnmanagedDelegatedPolicyMode {
    #[default]
    Warn,
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AdvisoryDelegatesConfig {
    pub lockfile_scanner: LockfileAdvisoryScanner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LockfileAdvisoryScanner {
    #[default]
    CargoDeny,
    CargoAudit,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CargoDenyDelegatesConfig {
    pub checks: Option<Vec<CargoDenyCheck>>,
}

pub const DEFAULT_CARGO_DENY_CHECKS: [CargoDenyCheck; 3] = [
    CargoDenyCheck::Advisories,
    CargoDenyCheck::Bans,
    CargoDenyCheck::Sources,
];

impl CargoDenyDelegatesConfig {
    /// An explicit `checks` list is authoritative in both directions. When the
    /// list is unset, a checked-in `[licenses]` policy is treated as expressed
    /// intent to enforce it, so the licenses check joins the default set.
    pub fn resolved_checks(&self, deny_toml_declares_licenses_policy: bool) -> Vec<CargoDenyCheck> {
        match &self.checks {
            Some(checks) => checks.clone(),
            None => {
                let mut checks = DEFAULT_CARGO_DENY_CHECKS.to_vec();
                if deny_toml_declares_licenses_policy {
                    checks.push(CargoDenyCheck::Licenses);
                }
                checks
            }
        }
    }

    pub fn licenses_posture(
        &self,
        deny_toml_declares_licenses_policy: bool,
    ) -> CargoDenyLicensesPosture {
        match &self.checks {
            Some(checks) if checks.contains(&CargoDenyCheck::Licenses) => {
                CargoDenyLicensesPosture::EnforcedExplicitChecks
            }
            Some(_) => CargoDenyLicensesPosture::DisabledExplicitChecks,
            None if deny_toml_declares_licenses_policy => {
                CargoDenyLicensesPosture::EnforcedDenyTomlPolicy
            }
            None => CargoDenyLicensesPosture::SkippedNoPolicy,
        }
    }

    pub fn is_explicit(&self) -> bool {
        self.checks.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoDenyLicensesPosture {
    EnforcedDenyTomlPolicy,
    EnforcedExplicitChecks,
    SkippedNoPolicy,
    DisabledExplicitChecks,
}

impl CargoDenyLicensesPosture {
    pub fn is_enforced(self) -> bool {
        matches!(
            self,
            Self::EnforcedDenyTomlPolicy | Self::EnforcedExplicitChecks
        )
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::EnforcedDenyTomlPolicy | Self::EnforcedExplicitChecks => "enforced",
            Self::SkippedNoPolicy => "skipped",
            Self::DisabledExplicitChecks => "disabled",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::EnforcedDenyTomlPolicy => "deny.toml declares a [licenses] policy",
            Self::EnforcedExplicitChecks => "delegates.cargo_deny.checks includes licenses",
            Self::SkippedNoPolicy => "no [licenses] policy in deny.toml",
            Self::DisabledExplicitChecks => "delegates.cargo_deny.checks omits licenses",
        }
    }

    pub fn reason_token(self) -> &'static str {
        match self {
            Self::EnforcedDenyTomlPolicy => "deny-toml-policy",
            Self::EnforcedExplicitChecks | Self::DisabledExplicitChecks => "explicit-checks",
            Self::SkippedNoPolicy => "no-deny-toml-policy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoDenyCheck {
    Advisories,
    Bans,
    Sources,
    Licenses,
}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("unable to parse barbican.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error(
        "barbican.toml release_age.minimum_days {actual} exceeds the supported maximum of {max}"
    )]
    InvalidMinimumDays { actual: u64, max: u64 },
    #[error("barbican.toml delegates.cargo_deny.checks must not be empty")]
    EmptyCargoDenyChecks,
    #[error("barbican.toml delegates.cargo_deny.checks must not contain duplicates: {check}")]
    DuplicateCargoDenyCheck { check: &'static str },
    #[error(
        "barbican.toml delegates.cargo_deny.checks must include advisories when delegates.advisories.lockfile_scanner is {scanner}"
    )]
    CargoDenyAdvisoryCheckRequired { scanner: &'static str },
}

impl BarbicanConfig {
    fn validate(self) -> Result<Self, ConfigLoadError> {
        if self.release_age.minimum_days > MAXIMUM_RELEASE_AGE_MINIMUM_DAYS {
            return Err(ConfigLoadError::InvalidMinimumDays {
                actual: self.release_age.minimum_days,
                max: MAXIMUM_RELEASE_AGE_MINIMUM_DAYS,
            });
        }

        if let Some(checks) = &self.delegates.cargo_deny.checks {
            if checks.is_empty() {
                return Err(ConfigLoadError::EmptyCargoDenyChecks);
            }

            let mut cargo_deny_checks = Vec::new();
            for check in checks {
                if cargo_deny_checks.contains(check) {
                    return Err(ConfigLoadError::DuplicateCargoDenyCheck {
                        check: check.as_str(),
                    });
                }
                cargo_deny_checks.push(*check);
            }

            if matches!(
                self.delegates.advisories.lockfile_scanner,
                LockfileAdvisoryScanner::CargoDeny | LockfileAdvisoryScanner::Both
            ) && !checks.contains(&CargoDenyCheck::Advisories)
            {
                return Err(ConfigLoadError::CargoDenyAdvisoryCheckRequired {
                    scanner: self.delegates.advisories.lockfile_scanner.as_str(),
                });
            }
        }

        Ok(self)
    }
}

impl CargoDenyCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisories => "advisories",
            Self::Bans => "bans",
            Self::Sources => "sources",
            Self::Licenses => "licenses",
        }
    }
}

impl UnmanagedDelegatedPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

impl LockfileAdvisoryScanner {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoDeny => "cargo-deny",
            Self::CargoAudit => "cargo-audit",
            Self::Both => "both",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BarbicanConfig, CargoDenyCheck, CargoDenyLicensesPosture, ConfigLoadError,
        LockfileAdvisoryScanner, UnmanagedDelegatedPolicyMode,
    };

    #[test]
    fn empty_config_uses_defaults() {
        let config = BarbicanConfig::from_toml_str("").expect("empty config should parse");

        assert_eq!(config.release_age.minimum_days, 7);
        assert!(config.high_scrutiny.new_direct_dependencies);
        assert!(config.high_scrutiny.non_crates_io_direct_dependencies);
        assert!(config.high_scrutiny.non_crates_io_source_changes);
        assert!(config.high_scrutiny.build_rs_changes);
        assert!(config.high_scrutiny.proc_macro_changes);
        assert!(config.high_scrutiny.native_sys_crates);
        assert_eq!(
            config.delegates.unmanaged_delegated_policy,
            UnmanagedDelegatedPolicyMode::Warn
        );
        assert_eq!(
            config.delegates.advisories.lockfile_scanner,
            LockfileAdvisoryScanner::CargoDeny
        );
        assert_eq!(config.delegates.cargo_deny.checks, None);
        assert_eq!(
            config.delegates.cargo_deny.resolved_checks(false),
            vec![
                CargoDenyCheck::Advisories,
                CargoDenyCheck::Bans,
                CargoDenyCheck::Sources,
            ]
        );
    }

    #[test]
    fn unset_checks_resolve_licenses_from_deny_toml_policy_presence() {
        let config = BarbicanConfig::from_toml_str("").expect("empty config should parse");

        assert!(!config.delegates.cargo_deny.is_explicit());
        assert_eq!(
            config.delegates.cargo_deny.resolved_checks(true),
            vec![
                CargoDenyCheck::Advisories,
                CargoDenyCheck::Bans,
                CargoDenyCheck::Sources,
                CargoDenyCheck::Licenses,
            ]
        );
        assert_eq!(
            config.delegates.cargo_deny.licenses_posture(true),
            CargoDenyLicensesPosture::EnforcedDenyTomlPolicy
        );
        assert_eq!(
            config.delegates.cargo_deny.licenses_posture(false),
            CargoDenyLicensesPosture::SkippedNoPolicy
        );
    }

    #[test]
    fn explicit_checks_are_authoritative_in_both_directions() {
        let with_licenses = BarbicanConfig::from_toml_str(
            r#"
[delegates.cargo_deny]
checks = ["advisories", "bans", "sources", "licenses"]
"#,
        )
        .expect("config should parse");
        let without_licenses = BarbicanConfig::from_toml_str(
            r#"
[delegates.cargo_deny]
checks = ["advisories", "bans", "sources"]
"#,
        )
        .expect("config should parse");

        for declares_policy in [false, true] {
            assert!(
                with_licenses
                    .delegates
                    .cargo_deny
                    .resolved_checks(declares_policy)
                    .contains(&CargoDenyCheck::Licenses)
            );
            assert_eq!(
                with_licenses
                    .delegates
                    .cargo_deny
                    .licenses_posture(declares_policy),
                CargoDenyLicensesPosture::EnforcedExplicitChecks
            );
            assert!(
                !without_licenses
                    .delegates
                    .cargo_deny
                    .resolved_checks(declares_policy)
                    .contains(&CargoDenyCheck::Licenses)
            );
            assert_eq!(
                without_licenses
                    .delegates
                    .cargo_deny
                    .licenses_posture(declares_policy),
                CargoDenyLicensesPosture::DisabledExplicitChecks
            );
        }
    }

    #[test]
    fn release_age_section_overrides_default_days() {
        let config = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 21

[high_scrutiny]

[delegates]
"#,
        )
        .expect("config should parse");

        assert_eq!(config.release_age.minimum_days, 21);
    }

    #[test]
    fn delegates_section_overrides_defaults() {
        let config = BarbicanConfig::from_toml_str(
            r#"
[delegates]
unmanaged_delegated_policy = "deny"

[delegates.advisories]
lockfile_scanner = "both"

[delegates.cargo_deny]
checks = ["advisories", "bans", "sources", "licenses"]
"#,
        )
        .expect("config should parse");

        assert_eq!(
            config.delegates.unmanaged_delegated_policy,
            UnmanagedDelegatedPolicyMode::Deny
        );
        assert_eq!(
            config.delegates.advisories.lockfile_scanner,
            LockfileAdvisoryScanner::Both
        );
        assert_eq!(
            config.delegates.cargo_deny.checks,
            Some(vec![
                CargoDenyCheck::Advisories,
                CargoDenyCheck::Bans,
                CargoDenyCheck::Sources,
                CargoDenyCheck::Licenses,
            ])
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 7
unexpected = true
"#,
        )
        .expect_err("unknown config keys should fail");

        assert!(matches!(error, ConfigLoadError::Parse(_)));
    }

    #[test]
    fn rejects_unreasonably_large_minimum_days() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 365001
"#,
        )
        .expect_err("excessive minimum_days should fail");

        assert!(matches!(
            error,
            ConfigLoadError::InvalidMinimumDays {
                actual: 365001,
                max: 365000,
            }
        ));
    }

    #[test]
    fn rejects_unknown_delegate_values() {
        for text in [
            r#"
[delegates]
unmanaged_delegated_policy = "maybe"
"#,
            r#"
[delegates.advisories]
lockfile_scanner = "scanner"
"#,
            r#"
[delegates.cargo_deny]
checks = ["advisories", "unknown"]
"#,
        ] {
            let error =
                BarbicanConfig::from_toml_str(text).expect_err("unknown values should fail");

            assert!(matches!(error, ConfigLoadError::Parse(_)));
        }
    }

    #[test]
    fn rejects_empty_cargo_deny_checks() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[delegates.cargo_deny]
checks = []
"#,
        )
        .expect_err("empty checks should fail");

        assert!(matches!(error, ConfigLoadError::EmptyCargoDenyChecks));
    }

    #[test]
    fn rejects_duplicate_cargo_deny_checks() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[delegates.cargo_deny]
checks = ["advisories", "bans", "advisories"]
"#,
        )
        .expect_err("duplicate checks should fail");

        assert!(matches!(
            error,
            ConfigLoadError::DuplicateCargoDenyCheck {
                check: "advisories"
            }
        ));
    }

    #[test]
    fn requires_cargo_deny_advisories_check_when_cargo_deny_scans_advisories() {
        for (scanner, expected) in [("cargo-deny", "cargo-deny"), ("both", "both")] {
            let error = BarbicanConfig::from_toml_str(&format!(
                r#"
[delegates.advisories]
lockfile_scanner = "{scanner}"

[delegates.cargo_deny]
checks = ["bans", "sources"]
"#
            ))
            .expect_err("cargo-deny advisory scanner requires advisory checks");

            assert!(matches!(
                error,
                ConfigLoadError::CargoDenyAdvisoryCheckRequired { scanner } if scanner == expected
            ));
        }
    }

    #[test]
    fn allows_omitting_cargo_deny_advisories_check_when_cargo_audit_scans_advisories() {
        let config = BarbicanConfig::from_toml_str(
            r#"
[delegates.advisories]
lockfile_scanner = "cargo-audit"

[delegates.cargo_deny]
checks = ["bans", "sources"]
"#,
        )
        .expect("cargo-audit may own advisory scanning");

        assert_eq!(
            config.delegates.advisories.lockfile_scanner,
            LockfileAdvisoryScanner::CargoAudit
        );
        assert_eq!(
            config.delegates.cargo_deny.checks,
            Some(vec![CargoDenyCheck::Bans, CargoDenyCheck::Sources])
        );
    }

    #[test]
    fn lockfile_scanner_error_names_match_wire_values() {
        for (scanner, expected) in [
            (LockfileAdvisoryScanner::CargoDeny, "cargo-deny"),
            (LockfileAdvisoryScanner::CargoAudit, "cargo-audit"),
            (LockfileAdvisoryScanner::Both, "both"),
        ] {
            let text = format!(
                r#"
[delegates.advisories]
lockfile_scanner = "{expected}"
"#
            );
            let parsed = BarbicanConfig::from_toml_str(&text).expect("scanner should parse");

            assert_eq!(parsed.delegates.advisories.lockfile_scanner, scanner);
            assert_eq!(scanner.as_str(), expected);
        }
    }
}
