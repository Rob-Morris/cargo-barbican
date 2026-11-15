use super::*;
use crate::{ExactCrateSpec, GitSourceIdentity, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Origin {
    CratesIo {
        archive_sha256: Sha256Digest,
    },
    Git {
        url: String,
        rev: String,
        subdirectory: String,
        materialisation_sha256: Sha256Digest,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub name: String,
    pub version: String,
    pub origin: Origin,
}
impl Source {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > 256 || self.version.len() > 128 {
            return Err("IOC package identity exceeds bounds".into());
        }
        let spec = format!("{}@{}", self.name, self.version)
            .parse::<ExactCrateSpec>()
            .map_err(|e| e.to_string())?;
        let version = semver::Version::parse(&self.version).map_err(|e| e.to_string())?;
        if version.to_string() != self.version {
            return Err("noncanonical IOC source version".into());
        }
        if spec.crate_name() != self.name || spec.version() != self.version {
            return Err("noncanonical IOC source identity".into());
        }
        if let Origin::Git {
            url,
            rev,
            subdirectory,
            ..
        } = &self.origin
        {
            if url.len() > 4096 {
                return Err("IOC Git URL exceeds bounds".into());
            }
            GitSourceIdentity::new(url, rev).map_err(|e| e.to_string())?;
            if subdirectory != "." {
                relative_path(subdirectory)?;
            }
        }
        Ok(())
    }
    pub fn semantics(&self) -> &'static str {
        match self.origin {
            Origin::CratesIo { .. } => SEMANTICS,
            Origin::Git { .. } => GIT_SEMANTICS,
        }
    }
    pub fn id(&self) -> Result<Sha256Digest, String> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Occurrence {
    pub start: u64,
    pub end: u64,
    pub snippet: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub complete: bool,
    pub source_id: Sha256Digest,
    pub path: String,
    pub file_sha256: Sha256Digest,
    pub rule: String,
    pub semantics: String,
    pub occurrences: Vec<Occurrence>,
}
impl Finding {
    pub fn validate(&self) -> Result<(), String> {
        relative_path(&self.path)?;
        let rule = rule(&self.rule).ok_or("unknown IOC rule")?;
        if !matches!(self.semantics.as_str(), SEMANTICS | GIT_SEMANTICS)
            || self.occurrences.is_empty()
            || self.occurrences.len() > MAX_OCCURRENCES
        {
            return Err("unsupported IOC semantics or occurrence bounds".into());
        }
        let mut previous = None;
        for occurrence in &self.occurrences {
            if occurrence.end.checked_sub(occurrence.start) != Some(rule.pattern.len() as u64)
                || occurrence.snippet.len() > MAX_SNIPPET_BYTES * 4
                || occurrence.snippet.chars().any(char::is_control)
                || previous.is_some_and(|start| start >= occurrence.start)
            {
                return Err("invalid IOC occurrence".into());
            }
            previous = Some(occurrence.start);
        }
        Ok(())
    }
    pub fn id(&self) -> Result<Sha256Digest, String> {
        self.validate()?;
        if !self.complete {
            return Err("incomplete IOC occurrence set has no grantable identity".into());
        }
        let spans: Vec<_> = self.occurrences.iter().map(|o| (o.start, o.end)).collect();
        canonical_digest(&(
            &self.source_id,
            &self.path,
            &self.file_sha256,
            &self.rule,
            &self.semantics,
            spans,
        ))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Coverage {
    Complete,
    Incomplete { reason: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub source: Source,
    pub semantics: String,
    pub coverage: Coverage,
    pub findings: Vec<Finding>,
    pub input_files: u64,
    pub input_bytes: u64,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}
impl Inspection {
    pub fn validate(&self) -> Result<(), String> {
        self.source.validate()?;
        if self.semantics != self.source.semantics()
            || self.findings.len() > MAX_FINDINGS
            || self.input_files > 100_000
            || self.input_bytes > 1024 * 1024 * 1024
            || self.scanned_files > self.input_files
            || self.scanned_bytes > self.input_bytes
        {
            return Err("unsupported IOC inspection semantics or bounds".into());
        }
        if let Coverage::Incomplete { reason } = &self.coverage
            && (reason.trim().is_empty() || reason.len() > 16_384)
        {
            return Err("invalid coverage diagnostic".into());
        }
        validate_findings(&self.source, &self.findings, &mut || Ok(()))?;
        Ok(())
    }
}
pub(super) fn validate_findings(
    source: &Source,
    findings: &[Finding],
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), String> {
    check()?;
    let source_id = source.id()?;
    if findings.len() > MAX_FINDINGS {
        return Err("IOC finding limit exceeded".into());
    }
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    for finding in findings {
        check()?;
        finding.validate()?;
        count = count
            .checked_add(finding.occurrences.len())
            .ok_or("occurrence overflow")?;
        if finding.source_id != source_id
            || finding.semantics != source.semantics()
            || !seen.insert((&finding.path, &finding.rule))
            || count > MAX_OCCURRENCES
        {
            return Err("unbound, duplicate or excessive IOC findings".into());
        }
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    pub scope: String,
    pub sources: Vec<Inspection>,
    pub excluded: Vec<String>,
    pub errors: Vec<String>,
}
impl Report {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION
            || self.scope.trim().is_empty()
            || self.scope.len() > 4096
            || self.sources.len() > 100_000
            || self.excluded.len() > 100_000
            || self.errors.len() > 100_000
        {
            return Err("invalid IOC report schema or bounds".into());
        }
        let mut sources = BTreeSet::new();
        let mut occurrences = 0usize;
        let mut findings = 0usize;
        for inspection in &self.sources {
            inspection.validate()?;
            if !sources.insert(inspection.source.id()?) {
                return Err("duplicate IOC source inspection".into());
            }
            findings += inspection.findings.len();
            occurrences += inspection
                .findings
                .iter()
                .map(|f| f.occurrences.len())
                .sum::<usize>();
            if findings > MAX_FINDINGS || occurrences > MAX_OCCURRENCES {
                return Err("aggregate IOC report budget exceeded".into());
            }
        }
        if self
            .excluded
            .iter()
            .chain(&self.errors)
            .any(|s| s.len() > 16_384)
        {
            return Err("IOC diagnostic exceeds bound".into());
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = encode_bounded(self)?;
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_REPORT_BYTES {
            return Err("IOC report exceeds 8 MiB".into());
        }
        let report: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        report.validate()?;
        Ok(report)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub package: Option<String>,
    pub source_id: Option<String>,
    pub paths: BTreeSet<String>,
    pub rules: BTreeSet<String>,
}
pub fn select(report: &Report, selection: &Selection) -> Result<Inspection, String> {
    report.validate()?;
    for path in &selection.paths {
        relative_path(path)?;
    }
    if selection.rules.iter().any(|id| rule(id).is_none()) {
        return Err("unknown selected IOC rule".into());
    }
    let candidates = report
        .sources
        .iter()
        .filter(|inspection| {
            selection.package.as_ref().is_none_or(|s| {
                s == &inspection.source.name
                    || s == &format!("{}@{}", inspection.source.name, inspection.source.version)
            }) && selection
                .source_id
                .as_ref()
                .is_none_or(|s| inspection.source.id().is_ok_and(|id| id.as_str() == s))
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(
            "IOC selection must identify one exact source; use --source-id from the report".into(),
        );
    }
    let mut selected = candidates[0].clone();
    selected.findings.retain(|finding| {
        (selection.paths.is_empty() || selection.paths.contains(&finding.path))
            && (selection.rules.is_empty() || selection.rules.contains(&finding.rule))
    });
    if selected.findings.is_empty() {
        return Err("IOC selection matches no findings".into());
    }
    if selection
        .paths
        .iter()
        .any(|p| !selected.findings.iter().any(|f| &f.path == p))
        || selection
            .rules
            .iter()
            .any(|r| !selected.findings.iter().any(|f| &f.rule == r))
    {
        return Err("unmatched IOC selector".into());
    }
    Ok(selected)
}
