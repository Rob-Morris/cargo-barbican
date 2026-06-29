use std::collections::BTreeSet;

use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    CargoDenyCheck, ExactCrateSpec, ExactCrateSpecError, LockfileAdvisoryScanner,
    ReviewedAdvisoryException, RustSecAdvisoryId,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdvisoryFinding {
    advisory_id: AdvisoryFindingId,
    package: ExactCrateSpec,
}

impl AdvisoryFinding {
    pub fn new(advisory_id: AdvisoryFindingId, package: ExactCrateSpec) -> Self {
        Self {
            advisory_id,
            package,
        }
    }

    pub fn advisory_id(&self) -> &AdvisoryFindingId {
        &self.advisory_id
    }

    pub fn package(&self) -> &ExactCrateSpec {
        &self.package
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisoryFindingId {
    RustSec(RustSecAdvisoryId),
    Unnormalised(String),
}

impl AdvisoryFindingId {
    pub fn parse(value: &str) -> Self {
        RustSecAdvisoryId::parse(value)
            .map_or_else(|_| Self::Unnormalised(value.to_owned()), Self::RustSec)
    }

    fn matches_reviewed(&self, reviewed: &RustSecAdvisoryId) -> bool {
        matches!(self, Self::RustSec(id) if id == reviewed)
    }
}

impl std::fmt::Display for AdvisoryFindingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RustSec(id) => write!(formatter, "{id}"),
            Self::Unnormalised(id) => write!(formatter, "{id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenyAdvisoryReport {
    findings: Vec<AdvisoryFinding>,
    summary_counts: Vec<CargoDenySummaryCount>,
    no_advisory_diagnostics: Vec<CargoDenyNoAdvisoryDiagnostic>,
}

impl CargoDenyAdvisoryReport {
    pub fn findings(&self) -> &[AdvisoryFinding] {
        &self.findings
    }

    pub fn summary_counts(&self) -> &[CargoDenySummaryCount] {
        &self.summary_counts
    }

    pub fn non_advisory_error_counts(&self) -> Vec<&CargoDenySummaryCount> {
        self.summary_counts
            .iter()
            .filter(|count| {
                count.check() != CargoDenyCheck::Advisories.as_str() && count.errors() > 0
            })
            .collect()
    }

    pub fn no_advisory_diagnostics(&self) -> &[CargoDenyNoAdvisoryDiagnostic] {
        &self.no_advisory_diagnostics
    }

    fn summary_count_for(&self, check: CargoDenyCheck) -> Option<&CargoDenySummaryCount> {
        self.summary_counts
            .iter()
            .find(|count| count.check() == check.as_str())
    }

    fn has_unenumerated_advisory_errors(&self) -> bool {
        self.summary_count_for(CargoDenyCheck::Advisories)
            .is_some_and(|count| count.errors() > 0)
            && self.findings.is_empty()
            && self
                .no_advisory_diagnostics
                .iter()
                .all(CargoDenyNoAdvisoryDiagnostic::is_known_benign)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenySummaryCount {
    check: String,
    errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenyNoAdvisoryDiagnostic {
    line: usize,
    severity: Option<String>,
    code: Option<String>,
}

impl CargoDenyNoAdvisoryDiagnostic {
    pub fn line(&self) -> usize {
        self.line
    }

    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    fn is_known_benign(&self) -> bool {
        matches!(self.severity(), Some("warning" | "note" | "help"))
    }
}

impl CargoDenySummaryCount {
    pub fn check(&self) -> &str {
        &self.check
    }

    pub fn errors(&self) -> u64 {
        self.errors
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoAuditAdvisoryReport {
    findings: Vec<AdvisoryFinding>,
    settings_ignore: Vec<String>,
    idless_warnings: usize,
}

impl CargoAuditAdvisoryReport {
    pub fn findings(&self) -> &[AdvisoryFinding] {
        &self.findings
    }

    pub fn settings_ignore(&self) -> &[String] {
        &self.settings_ignore
    }

    pub fn idless_warnings(&self) -> usize {
        self.idless_warnings
    }
}

pub fn parse_cargo_deny_json_lines(
    text: &str,
) -> Result<CargoDenyAdvisoryReport, AdvisoryParseError> {
    let mut findings = BTreeSet::new();
    let mut summary_counts = Vec::new();
    let mut no_advisory_diagnostics = Vec::new();
    let mut saw_summary = false;

    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|source| AdvisoryParseError::JsonLine {
                line: index + 1,
                source,
            })?;
        let record_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("line {} missing type", index + 1),
            })?;
        if saw_summary {
            return Err(AdvisoryParseError::CargoDenyShape {
                reason: format!("line {} follows terminal summary record", index + 1),
            });
        }

        match record_type {
            "summary" => {
                summary_counts = parse_cargo_deny_summary(index + 1, &value)?;
                saw_summary = true;
            }
            "diagnostic" => collect_cargo_deny_diagnostic(
                index + 1,
                &value,
                &mut findings,
                &mut no_advisory_diagnostics,
            )?,
            _ => {}
        }
    }

    if !saw_summary {
        return Err(AdvisoryParseError::CargoDenyMissingSummary);
    }

    Ok(CargoDenyAdvisoryReport {
        findings: findings.into_iter().collect(),
        summary_counts,
        no_advisory_diagnostics,
    })
}

fn parse_cargo_deny_summary(
    line: usize,
    value: &serde_json::Value,
) -> Result<Vec<CargoDenySummaryCount>, AdvisoryParseError> {
    let fields = value
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("summary line {line} missing fields"),
        })?;
    fields
        .iter()
        .map(|(check, counts)| {
            let counts = counts
                .as_object()
                .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                    reason: format!("summary line {line} {check} is not an object"),
                })?;
            let errors = counts
                .get("errors")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                    reason: format!("summary line {line} {check}.errors missing or invalid"),
                })?;
            Ok(CargoDenySummaryCount {
                check: check.to_owned(),
                errors,
            })
        })
        .collect()
}

fn collect_cargo_deny_diagnostic(
    line: usize,
    value: &serde_json::Value,
    findings: &mut BTreeSet<AdvisoryFinding>,
    no_advisory_diagnostics: &mut Vec<CargoDenyNoAdvisoryDiagnostic>,
) -> Result<(), AdvisoryParseError> {
    let fields = value
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} missing fields"),
        })?;
    let Some(advisory) = fields.get("advisory") else {
        no_advisory_diagnostics.push(CargoDenyNoAdvisoryDiagnostic {
            line,
            severity: fields
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            code: fields
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
        return Ok(());
    };
    let advisory_id = advisory
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory missing id"),
        })?;
    let graphs = fields
        .get("graphs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory missing graphs"),
        })?;
    if graphs.is_empty() {
        return Err(AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory present but graphs empty"),
        });
    }

    for graph in graphs {
        let krate = graph
            .get("Krate")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} graph missing Krate"),
            })?;
        let name = krate
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} Krate missing name"),
            })?;
        let version = krate
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} Krate missing version"),
            })?;

        findings.insert(finding_from_parts(advisory_id, name, version)?);
    }

    Ok(())
}

pub fn parse_cargo_audit_json(text: &str) -> Result<CargoAuditAdvisoryReport, AdvisoryParseError> {
    let raw: serde_json::Value =
        serde_json::from_str(text).map_err(AdvisoryParseError::CargoAuditJson)?;
    let vulnerabilities = raw
        .get("vulnerabilities")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing vulnerabilities object".to_owned(),
        })?;
    let list = vulnerabilities
        .get("list")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing vulnerabilities.list array".to_owned(),
        })?;
    let settings = raw
        .get("settings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing settings object".to_owned(),
        })?;
    let ignore = settings
        .get("ignore")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing settings.ignore array".to_owned(),
        })?;
    let warnings = raw
        .get("warnings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing warnings object".to_owned(),
        })?;
    let mut findings = BTreeSet::new();
    let mut idless_warnings = 0;

    for vulnerability in list {
        let Some(finding) = cargo_audit_finding(
            vulnerability,
            "vulnerabilities.list entry",
            MissingAdvisory::Error,
        )?
        else {
            continue;
        };
        findings.insert(finding);
    }
    for (kind, entries) in warnings {
        let entries = entries
            .as_array()
            .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
                reason: format!("warnings.{kind} is not an array"),
            })?;
        for entry in entries {
            if entry.get("advisory").is_none_or(serde_json::Value::is_null) {
                idless_warnings += 1;
            }
            let Some(finding) = cargo_audit_finding(
                entry,
                &format!("warnings.{kind} entry"),
                MissingAdvisory::Skip,
            )?
            else {
                continue;
            };
            findings.insert(finding);
        }
    }
    let settings_ignore = ignore
        .iter()
        .map(|ignored| {
            ignored
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
                    reason: "settings.ignore entry is not a string".to_owned(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CargoAuditAdvisoryReport {
        findings: findings.into_iter().collect(),
        settings_ignore,
        idless_warnings,
    })
}

fn cargo_audit_finding(
    value: &serde_json::Value,
    context: &str,
    missing_advisory: MissingAdvisory,
) -> Result<Option<AdvisoryFinding>, AdvisoryParseError> {
    let entry = value
        .as_object()
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} is not an object"),
        })?;
    let Some(advisory) = entry.get("advisory").filter(|advisory| !advisory.is_null()) else {
        return match missing_advisory {
            MissingAdvisory::Skip => Ok(None),
            MissingAdvisory::Error => Err(AdvisoryParseError::CargoAuditShape {
                reason: format!("{context} advisory missing id"),
            }),
        };
    };
    let advisory = advisory
        .as_object()
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} advisory is not an object"),
        })?;
    let advisory_id = advisory
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} advisory missing id"),
        })?;
    let package = entry
        .get("package")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} missing package object"),
        })?;
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} package missing name"),
        })?;
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} package missing version"),
        })?;

    Ok(Some(finding_from_parts(advisory_id, name, version)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingAdvisory {
    Error,
    Skip,
}

fn finding_from_parts(
    advisory_id: &str,
    crate_name: &str,
    version: &str,
) -> Result<AdvisoryFinding, AdvisoryParseError> {
    Ok(AdvisoryFinding {
        advisory_id: AdvisoryFindingId::parse(advisory_id),
        package: ExactCrateSpec::from_parts(crate_name, version)
            .map_err(AdvisoryParseError::InvalidPackageSpec)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryReconciliationReport {
    dispositions: Vec<AdvisoryDisposition>,
}

impl AdvisoryReconciliationReport {
    pub fn dispositions(&self) -> &[AdvisoryDisposition] {
        &self.dispositions
    }

    pub fn accepted_exceptions(&self) -> Vec<&ReviewedAdvisoryException> {
        self.dispositions
            .iter()
            .filter_map(AdvisoryDisposition::accepted_exception)
            .collect()
    }

    pub fn is_success(&self) -> bool {
        self.dispositions
            .iter()
            .all(|disposition| matches!(disposition, AdvisoryDisposition::Accepted { .. }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryDisposition {
    Accepted {
        finding: AdvisoryFinding,
        exception: ReviewedAdvisoryException,
    },
    Expired {
        finding: AdvisoryFinding,
        exception: ReviewedAdvisoryException,
    },
    Unreviewed {
        finding: AdvisoryFinding,
    },
}

impl AdvisoryDisposition {
    pub fn finding(&self) -> &AdvisoryFinding {
        match self {
            Self::Accepted { finding, .. }
            | Self::Expired { finding, .. }
            | Self::Unreviewed { finding } => finding,
        }
    }

    pub fn accepted_exception(&self) -> Option<&ReviewedAdvisoryException> {
        match self {
            Self::Accepted { exception, .. } => Some(exception),
            Self::Expired { .. } | Self::Unreviewed { .. } => None,
        }
    }
}

pub fn reconcile_advisory_findings(
    findings: &[AdvisoryFinding],
    exceptions: &[&ReviewedAdvisoryException],
    now: OffsetDateTime,
) -> AdvisoryReconciliationReport {
    let now_date = now.date();
    let dispositions = findings
        .iter()
        .cloned()
        .map(|finding| {
            // First-match is deterministic because reviewed-targets parsing
            // rejects duplicate (RustSec advisory id, exact crate spec) bindings.
            let exception = exceptions.iter().find(|exception| {
                finding
                    .advisory_id()
                    .matches_reviewed(exception.advisory_id())
                    && finding.package() == exception.spec()
            });

            match exception {
                Some(exception) if exception.review_by() >= now_date => {
                    AdvisoryDisposition::Accepted {
                        finding,
                        exception: (*exception).clone(),
                    }
                }
                Some(exception) => AdvisoryDisposition::Expired {
                    finding,
                    exception: (*exception).clone(),
                },
                None => AdvisoryDisposition::Unreviewed { finding },
            }
        })
        .collect();

    AdvisoryReconciliationReport { dispositions }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryAuditOutcome {
    reconciliation: AdvisoryReconciliationReport,
    completeness_failures: Vec<AdvisoryAuditCompletenessFailure>,
    cargo_deny_no_advisory_errors: Vec<CargoDenyNoAdvisoryDiagnostic>,
    cargo_deny_non_advisory_errors: Vec<CargoDenySummaryCount>,
    cargo_audit_settings_ignore: Vec<String>,
    cargo_audit_idless_warnings: usize,
}

impl AdvisoryAuditOutcome {
    pub fn reconciliation(&self) -> &AdvisoryReconciliationReport {
        &self.reconciliation
    }

    pub fn accepted_exceptions(&self) -> Vec<&ReviewedAdvisoryException> {
        self.reconciliation.accepted_exceptions()
    }

    pub fn completeness_failures(&self) -> &[AdvisoryAuditCompletenessFailure] {
        &self.completeness_failures
    }

    pub fn cargo_deny_no_advisory_errors(&self) -> &[CargoDenyNoAdvisoryDiagnostic] {
        &self.cargo_deny_no_advisory_errors
    }

    pub fn cargo_deny_non_advisory_errors(&self) -> &[CargoDenySummaryCount] {
        &self.cargo_deny_non_advisory_errors
    }

    pub fn cargo_audit_settings_ignore(&self) -> &[String] {
        &self.cargo_audit_settings_ignore
    }

    pub fn cargo_audit_idless_warnings(&self) -> usize {
        self.cargo_audit_idless_warnings
    }

    pub fn is_success(&self) -> bool {
        self.reconciliation.is_success()
            && self.completeness_failures.is_empty()
            && self.cargo_deny_no_advisory_errors.is_empty()
            && self.cargo_deny_non_advisory_errors.is_empty()
            && self.cargo_audit_settings_ignore.is_empty()
            && self.cargo_audit_idless_warnings == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryAuditCompletenessFailure {
    MissingCargoDenyReport,
    MissingCargoAuditReport,
    MissingCargoDenySummaryCheck { check: CargoDenyCheck },
    CargoDenyAdvisoryErrorsUnenumerated,
}

pub fn evaluate_advisory_audit(
    scanner: LockfileAdvisoryScanner,
    cargo_deny_checks: &[CargoDenyCheck],
    cargo_deny_report: Option<&CargoDenyAdvisoryReport>,
    cargo_audit_report: Option<&CargoAuditAdvisoryReport>,
    exceptions: &[&ReviewedAdvisoryException],
    now: OffsetDateTime,
) -> AdvisoryAuditOutcome {
    let mut findings = BTreeSet::new();
    let mut completeness_failures = Vec::new();
    let mut cargo_deny_no_advisory_errors = Vec::new();
    let mut cargo_deny_non_advisory_errors = Vec::new();
    let mut cargo_audit_settings_ignore = Vec::new();
    let mut cargo_audit_idless_warnings = 0;

    if !cargo_deny_checks.is_empty() {
        match cargo_deny_report {
            Some(report) => {
                findings.extend(report.findings().iter().cloned());
                cargo_deny_no_advisory_errors.extend(
                    report
                        .no_advisory_diagnostics()
                        .iter()
                        .filter(|diagnostic| !diagnostic.is_known_benign())
                        .cloned(),
                );
                cargo_deny_non_advisory_errors
                    .extend(report.non_advisory_error_counts().into_iter().cloned());
                if report.has_unenumerated_advisory_errors() {
                    completeness_failures.push(
                        AdvisoryAuditCompletenessFailure::CargoDenyAdvisoryErrorsUnenumerated,
                    );
                }
                for check in cargo_deny_checks {
                    if report.summary_count_for(*check).is_none() {
                        completeness_failures.push(
                            AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck {
                                check: *check,
                            },
                        );
                    }
                }
            }
            None => {
                completeness_failures.push(AdvisoryAuditCompletenessFailure::MissingCargoDenyReport)
            }
        }
    }
    if matches!(
        scanner,
        LockfileAdvisoryScanner::CargoAudit | LockfileAdvisoryScanner::Both
    ) {
        match cargo_audit_report {
            Some(report) => {
                findings.extend(report.findings().iter().cloned());
                cargo_audit_settings_ignore.extend(report.settings_ignore().iter().cloned());
                cargo_audit_idless_warnings += report.idless_warnings();
            }
            None => completeness_failures
                .push(AdvisoryAuditCompletenessFailure::MissingCargoAuditReport),
        }
    }

    let findings = findings.into_iter().collect::<Vec<_>>();
    AdvisoryAuditOutcome {
        reconciliation: reconcile_advisory_findings(&findings, exceptions, now),
        completeness_failures,
        cargo_deny_no_advisory_errors,
        cargo_deny_non_advisory_errors,
        cargo_audit_settings_ignore,
        cargo_audit_idless_warnings,
    }
}

#[derive(Debug, Error)]
pub enum AdvisoryParseError {
    #[error("unable to parse cargo-deny JSON line {line}: {source}")]
    JsonLine {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("cargo-deny JSON output is incomplete: missing terminal summary record")]
    CargoDenyMissingSummary,
    #[error("cargo-deny JSON output has unsupported shape: {reason}")]
    CargoDenyShape { reason: String },
    #[error("unable to parse cargo-audit JSON: {0}")]
    CargoAuditJson(#[source] serde_json::Error),
    #[error("cargo-audit JSON output has unsupported shape: {reason}")]
    CargoAuditShape { reason: String },
    #[error("scanner advisory package is not an exact crate spec: {0}")]
    InvalidPackageSpec(#[source] ExactCrateSpecError),
}

#[cfg(test)]
mod tests {
    use super::{
        AdvisoryAuditCompletenessFailure, AdvisoryAuditOutcome, AdvisoryDisposition,
        AdvisoryFindingId, evaluate_advisory_audit, parse_cargo_audit_json,
        parse_cargo_deny_json_lines, reconcile_advisory_findings,
    };
    use crate::{
        CargoAuditAdvisoryReport, CargoDenyAdvisoryReport, CargoDenyCheck, LockfileAdvisoryScanner,
        ReviewedAdvisoryException, ReviewedTargetsError, parse_reviewed_targets_toml,
    };
    use time::{Date, Month, OffsetDateTime};

    const CHECKSUM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CARGO_AUDIT_CLEAN: &str =
        include_str!("../tests/fixtures/advisory/cargo-audit-clean.json");
    const CARGO_AUDIT_WITH_FINDINGS: &str =
        include_str!("../tests/fixtures/advisory/cargo-audit-findings.json");
    const CARGO_DENY_CLEAN: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-clean.jsonl");
    const CARGO_DENY_BANS_FINDING: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-bans-finding.jsonl");
    const CARGO_DENY_WITH_FINDINGS: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-findings.jsonl");

    #[test]
    fn parses_cargo_deny_json_advisory_diagnostics() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#
        )
        .expect("cargo-deny output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.summary_counts().len(), 1);
        assert_eq!(report.summary_counts()[0].check(), "advisories");
        assert_eq!(report.summary_counts()[0].errors(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2026-0001"
        );
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
    }

    #[test]
    fn parses_cargo_audit_json_advisories_and_settings_ignore() {
        let report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0001",
          "title": "extra scanner metadata"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [], "unaffected": [] }
      }
    ]
  },
  "settings": { "ignore": ["RUSTSEC-2025-0001"], "target_arch": null },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2026-0001"
        );
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
        assert_eq!(report.settings_ignore(), &["RUSTSEC-2025-0001".to_owned()]);
    }

    #[test]
    fn cargo_deny_requires_terminal_summary_record() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}"#,
        )
        .expect_err("truncated cargo-deny output should fail");

        assert!(error.to_string().contains("missing terminal summary"));
    }

    #[test]
    fn cargo_deny_requires_summary_to_be_terminal_record() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
"#,
        )
        .expect_err("records after the summary should fail closed");

        assert!(error.to_string().contains("follows terminal summary"));
    }

    #[test]
    fn parses_clean_empty_scanner_outputs_as_empty_findings() {
        let deny_report = parse_cargo_deny_json_lines(r#"{"type":"summary","fields":{}}"#)
            .expect("cargo-deny summary-only output is a complete clean report");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": {
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": ["unmaintained", "unsound", "notice"]
  },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit complete empty output should parse");

        assert!(deny_report.findings().is_empty());
        assert!(audit_report.findings().is_empty());
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_clean_scanner_fixtures() {
        let deny_report = parse_cargo_deny_json_lines(CARGO_DENY_CLEAN)
            .expect("real cargo-deny clean fixture should parse");
        let audit_report =
            parse_cargo_audit_json(CARGO_AUDIT_CLEAN).expect("real cargo-audit clean fixture");

        assert!(deny_report.findings().is_empty());
        assert!(audit_report.findings().is_empty());
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_advisory_scanner_fixtures() {
        let deny_report = parse_cargo_deny_json_lines(CARGO_DENY_WITH_FINDINGS)
            .expect("real cargo-deny advisory fixture should parse");
        let audit_report = parse_cargo_audit_json(CARGO_AUDIT_WITH_FINDINGS)
            .expect("real cargo-audit advisory fixture should parse");

        assert_eq!(deny_report.findings().len(), 2);
        assert_eq!(
            deny_report
                .findings()
                .iter()
                .map(|finding| (
                    finding.advisory_id().to_string(),
                    finding.package().to_string()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("RUSTSEC-2021-0145".to_owned(), "atty@0.2.14".to_owned()),
                ("RUSTSEC-2024-0375".to_owned(), "atty@0.2.14".to_owned()),
            ]
        );
        assert_eq!(audit_report.findings().len(), 3);
        assert_eq!(
            audit_report
                .findings()
                .iter()
                .map(|finding| (
                    finding.advisory_id().to_string(),
                    finding.package().to_string()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("RUSTSEC-2021-0145".to_owned(), "atty@0.2.14".to_owned()),
                (
                    "RUSTSEC-2023-0018".to_owned(),
                    "remove_dir_all@0.5.3".to_owned()
                ),
                ("RUSTSEC-2024-0375".to_owned(), "atty@0.2.14".to_owned()),
            ]
        );
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_cargo_deny_non_advisory_summary_errors() {
        let report = parse_cargo_deny_json_lines(CARGO_DENY_BANS_FINDING)
            .expect("real cargo-deny bans fixture should parse");

        assert!(report.findings().is_empty());
        assert_eq!(
            report
                .summary_counts()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("advisories".to_owned(), 3), ("bans".to_owned(), 1)]
        );
        assert_eq!(
            report
                .non_advisory_error_counts()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn cargo_audit_requires_complete_top_level_object() {
        let error = parse_cargo_audit_json(r#"{"vulnerabilities":{"list":[]}}"#)
            .expect_err("truncated cargo-audit output should fail");

        assert!(error.to_string().contains("unsupported shape"));
        assert!(error.to_string().contains("missing settings object"));
    }

    #[test]
    fn cargo_audit_rejects_non_string_settings_ignore_entries() {
        let error = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [42] },
  "warnings": {}
}"#,
        )
        .expect_err("non-string ignore entries should fail closed");

        assert!(error.to_string().contains("settings.ignore entry"));
    }

    #[test]
    fn cargo_audit_warning_advisories_are_findings() {
        let report = parse_cargo_audit_json(
            r#"{
  "database": { "advisory-count": 1138 },
  "lockfile": { "dependency-count": 2 },
  "settings": {
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": ["unmaintained", "unsound", "notice"]
  },
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "warnings": {
    "unmaintained": [
      {
        "kind": "unmaintained",
        "package": {
          "name": "atty",
          "version": "0.2.14",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "checksum": "d9b39be18770d11421cdb1b9947a45dd3f37e93092cbf377614828a319d5fee8"
        },
        "advisory": {
          "id": "RUSTSEC-2024-0375",
          "package": "atty",
          "title": "`atty` is unmaintained",
          "informational": "unmaintained"
        },
        "versions": { "patched": [], "unaffected": [] }
      }
    ],
    "yanked": [
      {
        "kind": "yanked",
        "package": { "name": "gone", "version": "1.2.3" }
      }
    ]
  }
}"#,
        )
        .expect("cargo-audit warnings should parse");
        let reconciled = reconcile_advisory_findings(report.findings(), &[], fixed_now());

        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.idless_warnings(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2024-0375"
        );
        assert_eq!(report.findings()[0].package().to_string(), "atty@0.2.14");
        assert!(matches!(
            reconciled.dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn cargo_audit_malformed_advisory_warnings_fail_closed() {
        for advisory in [r#"{}"#, r#"{"id": 123}"#] {
            let error = parse_cargo_audit_json(&format!(
                r#"{{
  "vulnerabilities": {{ "found": false, "count": 0, "list": [] }},
  "settings": {{ "ignore": [] }},
  "warnings": {{
    "unmaintained": [
      {{
        "kind": "unmaintained",
        "package": {{ "name": "atty", "version": "0.2.14" }},
        "advisory": {advisory}
      }}
    ]
  }}
}}"#
            ))
            .expect_err("malformed advisory-bearing warning should fail closed");

            assert!(error.to_string().contains("advisory missing id"));
        }
    }

    #[test]
    fn cargo_deny_unrecognised_advisory_shape_fails_closed() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect_err("unsupported shape should fail");

        assert!(error.to_string().contains("unsupported shape"));
    }

    #[test]
    fn cargo_deny_rejects_advisory_diagnostics_with_empty_graphs() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect_err("known advisory with no graph evidence must fail closed");

        assert!(error.to_string().contains("graphs empty"));
    }

    #[test]
    fn cargo_deny_skips_non_advisory_diagnostics_and_keeps_advisories() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"source-not-allowed","message":"source policy finding"}}
{"type":"diagnostic","fields":{"code":"unmaintained","advisory":{"id":"RUSTSEC-2024-0375"},"graphs":[{"Krate":{"name":"atty","version":"0.2.14"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("mixed cargo-deny output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2024-0375"
        );
        assert_eq!(report.findings()[0].package().to_string(), "atty@0.2.14");
    }

    #[test]
    fn cargo_deny_collects_multiple_graphs_and_deduplicates_findings() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}},{"Krate":{"name":"serde","version":"1.0.228"}},{"Krate":{"name":"toml","version":"0.8.0"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("multi-graph cargo-deny advisory should parse");

        assert_eq!(report.findings().len(), 2);
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
        assert_eq!(report.findings()[1].package().to_string(), "toml@0.8.0");
    }

    #[test]
    fn unparseable_advisory_ids_are_not_dropped_and_reconcile_unreviewed() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"GHSA-0000"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("finding should still parse");
        let reconciled = reconcile_advisory_findings(report.findings(), &[], fixed_now());

        assert!(matches!(
            report.findings()[0].advisory_id(),
            AdvisoryFindingId::Unnormalised(id) if id == "GHSA-0000"
        ));
        assert!(matches!(
            reconciled.dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
        assert!(!reconciled.is_success());
    }

    #[test]
    fn reconciles_accepted_unreviewed_and_expired_dispositions() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0002"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, fixed_now());

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(matches!(
            report.dispositions()[1],
            AdvisoryDisposition::Expired { .. }
        ));
        assert!(matches!(
            report.dispositions()[2],
            AdvisoryDisposition::Unreviewed { .. }
        ));
        assert!(!report.is_success());
    }

    #[test]
    fn accepts_exception_on_exact_review_by_boundary() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");
        let boundary = Date::from_calendar_date(2026, Month::December, 31)
            .expect("date should parse")
            .midnight()
            .assume_utc();

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, boundary);

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(report.is_success());
    }

    #[test]
    fn exact_scanner_versions_match_reviewed_specs() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, fixed_now());

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(report.is_success());
    }

    #[test]
    fn verdict_fails_on_any_unreviewed_or_expired_disposition() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let accepted_finding = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");
        let mixed_findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        assert!(
            reconcile_advisory_findings(accepted_finding.findings(), &exception_refs, fixed_now())
                .is_success()
        );
        assert!(
            !reconcile_advisory_findings(mixed_findings.findings(), &exception_refs, fixed_now())
                .is_success()
        );
    }

    #[test]
    fn audit_outcome_passes_when_all_findings_are_accepted() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("findings should parse");

        let outcome = evaluate_deny(&deny_report, &exception_refs, fixed_now());

        assert!(outcome.is_success());
        assert_eq!(outcome.accepted_exceptions().len(), 1);
        assert!(outcome.cargo_deny_non_advisory_errors().is_empty());
    }

    #[test]
    fn audit_outcome_fails_on_unreviewed_findings() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");

        let outcome = evaluate_deny(&deny_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_expired_findings_but_accepts_boundary_date() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let accepted = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");
        let expired = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0002"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");
        let boundary = Date::from_calendar_date(2026, Month::December, 31)
            .expect("date should parse")
            .midnight()
            .assume_utc();

        assert!(evaluate_deny(&accepted, &exception_refs, boundary).is_success());
        let outcome = evaluate_deny(&expired, &exception_refs, fixed_now());

        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Expired { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_non_advisory_cargo_deny_errors() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0},"bans":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories, CargoDenyCheck::Bans],
            Some(&deny_report),
            None,
            &exception_refs,
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert!(outcome.reconciliation().is_success());
        assert_eq!(
            outcome
                .cargo_deny_non_advisory_errors()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn audit_outcome_fails_on_cargo_deny_error_diagnostic_without_advisory_id() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"yanked","message":"crate is yanked","severity":"error"}}
{"type":"summary","fields":{"advisories":{"errors":2,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_deny(&deny_report, &exception_refs, fixed_now());

        assert!(!outcome.is_success());
        assert!(outcome.reconciliation().is_success());
        assert_eq!(outcome.cargo_deny_no_advisory_errors().len(), 1);
        assert_eq!(
            outcome.cargo_deny_no_advisory_errors()[0].code(),
            Some("yanked")
        );
    }

    #[test]
    fn audit_outcome_allows_known_benign_cargo_deny_diagnostics_without_advisory_id() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"context","message":"warning only","severity":"warning"}}
{"type":"diagnostic","fields":{"code":"context","message":"note only","severity":"note"}}
{"type":"diagnostic","fields":{"code":"context","message":"help only","severity":"help"}}
{"type":"summary","fields":{"advisories":{"errors":0,"warnings":1,"helps":1,"notes":1}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_deny(&deny_report, &[], fixed_now());

        assert!(outcome.is_success());
        assert!(outcome.cargo_deny_no_advisory_errors().is_empty());
    }

    #[test]
    fn audit_outcome_fails_when_expected_scanner_reports_are_absent() {
        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::Both,
            &[CargoDenyCheck::Advisories],
            None,
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[
                AdvisoryAuditCompletenessFailure::MissingCargoDenyReport,
                AdvisoryAuditCompletenessFailure::MissingCargoAuditReport,
            ]
        );
    }

    #[test]
    fn audit_outcome_fails_when_configured_cargo_deny_check_is_missing_from_summary() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories, CargoDenyCheck::Bans],
            Some(&deny_report),
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[
                AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck {
                    check: CargoDenyCheck::Bans,
                }
            ]
        );
    }

    #[test]
    fn audit_outcome_fails_when_cargo_deny_advisory_errors_are_unenumerated() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories],
            Some(&deny_report),
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[AdvisoryAuditCompletenessFailure::CargoDenyAdvisoryErrorsUnenumerated]
        );
    }

    #[test]
    fn audit_outcome_still_fails_cargo_deny_bans_when_cargo_audit_scans_advisories() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"banned","message":"crate is banned","severity":"error"}}
{"type":"summary","fields":{"bans":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[CargoDenyCheck::Bans],
            Some(&deny_report),
            Some(&audit_report),
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_deny_no_advisory_errors().len(), 1);
        assert_eq!(
            outcome
                .cargo_deny_non_advisory_errors()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn audit_outcome_uses_cargo_audit_findings_when_cargo_deny_is_clean() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"bans":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": { "id": "RUSTSEC-2026-0003" },
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[CargoDenyCheck::Bans],
            Some(&deny_report),
            Some(&audit_report),
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert!(outcome.cargo_deny_no_advisory_errors().is_empty());
        assert!(outcome.cargo_deny_non_advisory_errors().is_empty());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_cargo_audit_ignored_settings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": ["RUSTSEC-2026-0001"] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.cargo_audit_settings_ignore(),
            &["RUSTSEC-2026-0001".to_owned()]
        );
    }

    #[test]
    fn audit_outcome_fails_on_cargo_audit_idless_warnings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "yanked": [
      { "kind": "yanked", "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_fails_on_non_yanked_cargo_audit_idless_warnings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "future-warning": [
      { "kind": "future-warning", "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_counts_null_advisory_warnings_as_idless() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "future-warning": [
      { "advisory": null, "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_deduplicates_findings_across_scanners() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": { "id": "RUSTSEC-2026-0001" },
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::Both,
            &[CargoDenyCheck::Advisories],
            Some(&deny_report),
            Some(&audit_report),
            &exception_refs,
            fixed_now(),
        );

        assert!(outcome.is_success());
        assert_eq!(outcome.reconciliation().dispositions().len(), 1);
    }

    #[test]
    fn rejects_cross_family_duplicate_advisory_bindings() {
        let error = parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "first"
review_record = "docs/dependency-reviews/first.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "second"
review_record = "docs/dependency-reviews/second.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-10-21" }},
]
"#
        ))
        .expect_err("duplicate advisory binding should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::DuplicateAllowedAdvisoryBinding { .. }
        ));
    }

    #[test]
    fn allows_cross_family_advisory_bindings_for_different_versions() {
        let targets = parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "first"
review_record = "docs/dependency-reviews/first.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "second"
review_record = "docs/dependency-reviews/second.md"

[rust.families.resolved]
serde = {{ version = "1.0.229", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-10-21" }},
]
"#
        ))
        .expect("different-version advisory bindings should parse");

        assert_eq!(targets.advisory_exceptions().len(), 2);
    }

    fn reviewed_targets_with_advisories() -> crate::ReviewedTargets {
        parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-12-31" }},
  {{ id = "RUSTSEC-2026-0002", review_by = "2025-12-31" }},
]
"#
        ))
        .expect("reviewed targets should parse")
    }

    fn evaluate_deny(
        report: &CargoDenyAdvisoryReport,
        exceptions: &[&ReviewedAdvisoryException],
        now: OffsetDateTime,
    ) -> AdvisoryAuditOutcome {
        evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories],
            Some(report),
            None,
            exceptions,
            now,
        )
    }

    fn evaluate_audit(
        report: &CargoAuditAdvisoryReport,
        exceptions: &[&ReviewedAdvisoryException],
        now: OffsetDateTime,
    ) -> AdvisoryAuditOutcome {
        evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[],
            None,
            Some(report),
            exceptions,
            now,
        )
    }

    fn fixed_now() -> OffsetDateTime {
        Date::from_calendar_date(2026, Month::June, 24)
            .expect("date should parse")
            .midnight()
            .assume_utc()
    }
}
