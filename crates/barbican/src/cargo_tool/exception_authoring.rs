use super::*;
use crate::Sha256Digest;

/// Selects one registry finding from stored typed evidence, including blocked reviews.
pub fn select_exception_finding<'a>(
    subject: &Subject,
    content: &'a EvidenceContent,
    advisory: Option<&str>,
    package: Option<&str>,
    source_id: Option<&str>,
) -> Result<&'a Finding, ToolError> {
    subject.validate()?;
    content.validate()?;
    require(
        content.subject_id == subject.id()?,
        "exception evidence subject mismatch",
    )?;
    if let Some(id) = advisory {
        crate::RustSecAdvisoryId::parse(id)
            .map_err(|e| ToolError(format!("assigned canonical RustSec ID required: {e}")))?;
    }
    let packages = subject.graph.packages();
    let mut candidates = Vec::new();
    for finding in &content.findings {
        let kind_matches = match advisory {
            Some(id) => finding.kind == FindingKind::Advisory && finding.identity == id,
            None => finding.kind == FindingKind::ReleaseAge,
        };
        if !kind_matches {
            continue;
        }
        require(
            packages.contains(&finding.package),
            "exception finding outside subject graph",
        )?;
        if !matches!(finding.package.source, PackageSource::CratesIo { .. }) {
            continue;
        }
        candidates.push(finding);
    }
    let mut selected = Vec::new();
    for finding in &candidates {
        let exact = format!("{}@{}", finding.package.name, finding.package.version);
        let source = crate::ioc::Source::from(&finding.package)
            .id()
            .map_err(ToolError)?;
        if package.is_none_or(|p| p == finding.package.name || p == exact)
            && source_id.is_none_or(|s| s == source.as_str())
        {
            selected.push(*finding);
        }
    }
    require(
        selected.len() == 1,
        &format!(
            "select exactly one eligible registry finding; candidates: {}",
            candidates
                .iter()
                .map(|f| format!(
                    "{}@{} source-id={}",
                    f.package.name,
                    f.package.version,
                    crate::ioc::Source::from(&f.package)
                        .id()
                        .expect("validated registry source")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )?;
    Ok(selected[0])
}

impl ToolException {
    pub fn pending(
        subject: RecordId,
        policy: Sha256Digest,
        finding: &Finding,
        expiry: i64,
    ) -> Result<Self, ToolError> {
        let exception = match finding.kind {
            FindingKind::ReleaseAge => ExceptionKind::ReleaseAge,
            FindingKind::Advisory => {
                crate::RustSecAdvisoryId::parse(&finding.identity)
                    .map_err(|e| ToolError(e.to_string()))?;
                ExceptionKind::Advisory {
                    identity: finding.identity.clone(),
                    detail_sha256: finding.detail_sha256.clone(),
                }
            }
            _ => {
                return Err(ToolError(
                    "finding cannot receive a registry tool exception".into(),
                ));
            }
        };
        require(
            matches!(finding.package.source, PackageSource::CratesIo { .. }),
            "registry finding required",
        )?;
        Ok(Self {
            subject_id: subject,
            package: finding.package.clone(),
            policy_sha256: policy,
            exception,
            expires_at_utc: expiry,
            reviewed_at_utc: 0,
            reviewer: "PENDING".into(),
            review_record: format!(
                "{}\nPENDING\nExplain the exact risk, evidence, mitigations and finite review deadline.",
                crate::REVIEW_RECORD_SCAFFOLD_MARKER
            ),
            review_record_sha256: sha256(b""),
        })
    }

    /// Normalisation is permitted only for an unreferenced draft at explicit publication.
    pub fn complete_draft(&mut self, now: i64) -> Result<(), ToolError> {
        if self.reviewed_at_utc == 0 {
            self.reviewed_at_utc = now;
            self.review_record_sha256 = sha256(self.review_record.as_bytes());
        }
        self.validate_authoring(now)
    }

    pub fn validate_authoring(&self, now: i64) -> Result<(), ToolError> {
        require(
            !self
                .reviewer
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| {
                    matches!(
                        word.to_ascii_uppercase().as_str(),
                        "PENDING" | "TODO" | "TBD" | "SCAFFOLD"
                    )
                }),
            "exception reviewer must be completed, without placeholder text",
        )?;
        self.validate()?;
        require(
            self.reviewed_at_utc > 0 && self.reviewed_at_utc <= now && now < self.expires_at_utc,
            "exception completion is missing, future or expired",
        )
    }
}
