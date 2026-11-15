use super::*;
use crate::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Conclusion {
    Pending,
    ExpectedBehaviour,
    FalsePositive,
    Unresolved,
    Rejected,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRecord {
    pub schema_version: u32,
    pub source: Source,
    pub findings: Vec<Finding>,
    pub reviewer: String,
    pub reviewed_at_utc: Option<i64>,
    pub conclusion: Conclusion,
    pub rationale: String,
    pub review_by_utc: Option<i64>,
}
impl ReviewRecord {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_checked(&mut || Ok(()))
    }
    pub fn validate_checked(
        &self,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        check()?;
        if self.schema_version != SCHEMA_VERSION
            || self.findings.is_empty()
            || self.findings.len() > MAX_FINDINGS
            || self.reviewer.len() > 4096
            || self.rationale.len() > MAX_REPORT_BYTES / 2
        {
            return Err("invalid IOC review schema or bounds".into());
        }
        if self.findings.iter().any(|f| !f.complete) {
            return Err("incomplete IOC finding cannot be reviewed as complete".into());
        }
        super::model::validate_findings(&self.source, &self.findings, check)?;
        if self.reviewed_at_utc.is_some_and(|t| t < 0) || self.review_by_utc.is_some_and(|t| t < 0)
        {
            return Err("invalid IOC review timestamp".into());
        }
        if let (Some(reviewed), Some(deadline)) = (self.reviewed_at_utc, self.review_by_utc)
            && deadline <= reviewed
        {
            return Err("IOC review deadline precedes completion".into());
        }
        Ok(())
    }
    pub fn validate_completed(&self, now: i64) -> Result<(), String> {
        self.validate_completed_checked(now, &mut || Ok(()))
    }
    pub fn validate_completed_checked(
        &self,
        now: i64,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.validate_checked(check)?;
        if !matches!(
            self.conclusion,
            Conclusion::ExpectedBehaviour | Conclusion::FalsePositive
        ) || self.reviewer.trim().is_empty()
            || self.rationale.trim().is_empty()
            || self.reviewer.contains("PENDING")
            || self.rationale.contains("PENDING")
            || self.reviewed_at_utc.is_none_or(|t| t > now)
            || self.review_by_utc.is_some_and(|t| now >= t)
        {
            return Err("IOC review is pending, unresolved, expired or not completed".into());
        }
        Ok(())
    }
}
const OPEN: &str = "```barbican-ioc-review-v1\n";
const CLOSE: &str = "\n```";
pub fn render_review(record: &ReviewRecord) -> Result<String, String> {
    record.validate()?;
    let json = String::from_utf8(encode_pretty_bounded(record)?).expect("JSON is UTF8");
    if json.len() > MAX_REPORT_BYTES - 512 {
        return Err("IOC review exceeds 8 MiB".into());
    }
    let marker = if matches!(record.conclusion, Conclusion::Pending) {
        format!("{}\n\n", crate::REVIEW_RECORD_SCAFFOLD_MARKER)
    } else {
        String::new()
    };
    let result = format!(
        "# Exact IOC source review\n\nThis record explains exact textual findings; it does not prove benignness or grant authority by itself.\n\n{marker}{OPEN}{json}{CLOSE}\n"
    );
    if result.len() > MAX_REPORT_BYTES {
        return Err("IOC review exceeds 8 MiB".into());
    }
    Ok(result)
}
pub fn scaffold_review(inspection: &Inspection) -> Result<String, String> {
    inspection.validate()?;
    if !matches!(inspection.coverage, Coverage::Complete) {
        return Err("incomplete IOC coverage cannot produce a complete review scaffold".into());
    }
    if inspection.findings.is_empty() {
        return Err("no IOC findings to review".into());
    }
    render_review(&ReviewRecord {schema_version:SCHEMA_VERSION,source:inspection.source.clone(),findings:inspection.findings.clone(),reviewer:"PENDING".into(),reviewed_at_utc:None,conclusion:Conclusion::Pending,rationale:"PENDING: Explain the original source, each selected file/rule and why its complete occurrence set is expected behaviour or a false positive.".into(),review_by_utc:None})
}
pub fn parse_review(text: &str) -> Result<ReviewRecord, String> {
    if text.len() > MAX_REPORT_BYTES {
        return Err("IOC review exceeds 8 MiB".into());
    }
    let (before, rest) = text
        .split_once(OPEN)
        .ok_or("missing IOC review machine block")?;
    if before.contains("```barbican-ioc-review") {
        return Err("ambiguous IOC review block".into());
    }
    let (json, after) = rest
        .split_once(CLOSE)
        .ok_or("unterminated IOC review block")?;
    if after.contains("```barbican-ioc-review") {
        return Err("multiple IOC review blocks".into());
    }
    let record: ReviewRecord = serde_json::from_str(json).map_err(|e| e.to_string())?;
    record.validate()?;
    if !matches!(record.conclusion, Conclusion::Pending)
        && !crate::classify_review_record(Some(text)).is_satisfied()
    {
        return Err("IOC record retains the pending scaffold marker".into());
    }
    Ok(record)
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub record: ReviewRecord,
    pub review_record_sha256: Sha256Digest,
}
impl Allowance {
    pub fn from_text(text: &str) -> Result<Self, String> {
        Ok(Self {
            record: parse_review(text)?,
            review_record_sha256: digest(text.as_bytes()),
        })
    }
    pub fn allows(&self, source: &Source, finding: &Finding, now: i64) -> Result<bool, String> {
        self.record.validate_completed(now)?;
        Ok(self.record.source == *source
            && self
                .record
                .findings
                .iter()
                .any(|f| f.id().ok() == finding.id().ok()))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub complete: bool,
    pub allowed: BTreeSet<Sha256Digest>,
    pub blocked: BTreeSet<Sha256Digest>,
    pub errors: Vec<String>,
}
impl Decision {
    pub fn is_success(&self) -> bool {
        self.complete && self.blocked.is_empty() && self.errors.is_empty()
    }
}
pub struct AllowanceIndex {
    pub allowed: BTreeSet<(Sha256Digest, Sha256Digest)>,
    pub errors: BTreeMap<Sha256Digest, Vec<String>>,
}
pub fn index_allowances(allowances: &[Allowance], now: i64) -> Result<AllowanceIndex, String> {
    index_allowances_checked(allowances, now, &mut || Ok(()))
}
pub fn index_allowances_checked<'a>(
    allowances: impl IntoIterator<Item = &'a Allowance>,
    now: i64,
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<AllowanceIndex, String> {
    prepare_index(allowances, Some(now), check)
}
pub(crate) fn index_allowances_structural<'a>(
    allowances: impl IntoIterator<Item = &'a Allowance>,
) -> Result<AllowanceIndex, String> {
    prepare_index(allowances, None, &mut || Ok(()))
}
fn prepare_index<'a>(
    allowances: impl IntoIterator<Item = &'a Allowance>,
    now: Option<i64>,
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<AllowanceIndex, String> {
    let mut index = AllowanceIndex {
        allowed: BTreeSet::new(),
        errors: BTreeMap::new(),
    };
    for allowance in allowances {
        check()?;
        let source_id = allowance.record.source.id()?;
        let at = now.unwrap_or_else(|| allowance.record.reviewed_at_utc.unwrap_or(0));
        let mut cancellation = None;
        let result = allowance.record.validate_completed_checked(at, &mut || {
            let result = check();
            if let Err(error) = &result {
                cancellation = Some(error.clone());
            }
            result
        });
        if let Some(error) = cancellation {
            return Err(error);
        }
        if let Err(error) = result {
            index.errors.entry(source_id).or_default().push(error);
            continue;
        }
        for finding in &allowance.record.findings {
            check()?;
            index.allowed.insert((source_id.clone(), finding.id()?));
        }
    }
    Ok(index)
}

pub fn adjudicate(
    inspection: &Inspection,
    allowances: &[Allowance],
    now: i64,
) -> Result<Decision, String> {
    let index = index_allowances(allowances, now)?;
    adjudicate_indexed(inspection, &index)
}
pub fn adjudicate_indexed(
    inspection: &Inspection,
    index: &AllowanceIndex,
) -> Result<Decision, String> {
    inspection.validate()?;
    let source_id = inspection.source.id()?;
    let mut result = Decision {
        complete: matches!(inspection.coverage, Coverage::Complete),
        allowed: BTreeSet::new(),
        blocked: BTreeSet::new(),
        errors: index.errors.get(&source_id).cloned().unwrap_or_default(),
    };
    for finding in &inspection.findings {
        if !finding.complete {
            result.complete = false;
            continue;
        }
        let id = finding.id()?;
        if index.allowed.contains(&(source_id.clone(), id.clone())) {
            result.allowed.insert(id);
        } else {
            result.blocked.insert(id);
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IocRecordReference {
    pub record: String,
    pub record_sha256: Sha256Digest,
}
impl IocRecordReference {
    pub fn validate(&self) -> Result<(), String> {
        relative_path(&self.record)
    }
}
