use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub schema_version: u32,
    pub minimum_days: u64,
    /// Visible invocation-override provenance, not an implicit saved override.
    pub override_reason: Option<String>,
}
impl EffectivePolicy {
    pub fn id(&self) -> Result<Sha256Digest> {
        version(self.schema_version)?;
        require(
            self.minimum_days <= crate::config::MAXIMUM_RELEASE_AGE_MINIMUM_DAYS,
            "release-age minimum exceeds limit",
        )?;
        if let Some(reason) = &self.override_reason {
            text(reason)?;
        }
        record_id("rust-toolchain-effective-policy-v1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainAgeException {
    pub subject_id: Sha256Digest,
    pub policy_id: Sha256Digest,
    /// Explicit repository scope chosen by its governance, not a crate-family grant.
    pub scope: String,
    pub review: RecordReference,
    pub expires_at: i64,
}
impl ToolchainAgeException {
    pub fn id(&self) -> Result<Sha256Digest> {
        text(&self.scope)?;
        self.review.validate()?;
        timestamp(self.expires_at)?;
        record_id("rust-toolchain-age-exception-v1", self)
    }
}

/// Portable repository policy reference. It is not proof of a local installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedToolchainAdmission {
    pub schema_version: u32,
    pub subject_id: Sha256Digest,
    pub policy_id: Sha256Digest,
    pub assessment_id: Sha256Digest,
    pub scope: String,
    pub review_record: String,
    pub review_record_sha256: Sha256Digest,
    pub evidence_record: String,
    pub evidence_record_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_exception: Option<ToolchainAgeException>,
}
impl ReviewedToolchainAdmission {
    /// Schema/scope coherence only. Current authority is checked by `evaluate_eligibility`.
    pub fn validate(&self) -> Result<()> {
        version(self.schema_version)?;
        text(&self.scope)?;
        self.review().validate()?;
        self.evidence().validate()?;
        if let Some(day) = &self.review_by {
            crate::parse_iso_date(day).map_err(|e| AdmissionError(e.to_string()))?;
        }
        if let Some(exception) = &self.age_exception {
            exception.id()?;
            require(
                exception.subject_id == self.subject_id
                    && exception.policy_id == self.policy_id
                    && exception.scope == self.scope,
                "age exception scope mismatch",
            )?;
        }
        Ok(())
    }
    pub fn id(&self) -> Result<Sha256Digest> {
        self.validate()?;
        record_id("rust-toolchain-repository-admission-v1", self)
    }
    pub fn review(&self) -> RecordReference {
        RecordReference {
            path: self.review_record.clone(),
            sha256: self.review_record_sha256.clone(),
        }
    }
    pub fn evidence(&self) -> RecordReference {
        RecordReference {
            path: self.evidence_record.clone(),
            sha256: self.evidence_record_sha256.clone(),
        }
    }
}

pub fn render_admission_fragment(admission: &ReviewedToolchainAdmission) -> Result<String> {
    admission.validate()?;
    #[derive(Serialize)]
    struct Fragment<'a> {
        rust: Toolchains<'a>,
    }
    #[derive(Serialize)]
    struct Toolchains<'a> {
        toolchains: [&'a ReviewedToolchainAdmission; 1],
    }
    let body = toml::to_string(&Fragment {
        rust: Toolchains {
            toolchains: [admission],
        },
    })
    .map_err(|e| AdmissionError(e.to_string()))?;
    Ok(format!("\n{body}"))
}

/// Local durable association established after fresh repository admission.
/// The shell derives consumer_context_id from the actual consumer, not portable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuingUseBinding {
    pub schema_version: u32,
    pub subject_id: Sha256Digest,
    pub admission_id: Sha256Digest,
    pub consumer_context_id: Sha256Digest,
    pub installation_id: Sha256Digest,
}

/// Current independently checked local correspondence, supplied by the static verifier.
/// Deserialising a saved correspondence is never a substitute for that inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledCorrespondence {
    pub subject_id: Sha256Digest,
    pub mapping_sha256: Sha256Digest,
    pub installation_id: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityPurpose {
    PersonalAcceptance,
    RepositoryAdmission,
    Installation,
    FirstAdoption,
    InstallationInspection,
    ContinuingUse,
    Activation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessRequest {
    Online {
        operation_started_at: i64,
    },
    Cached {
        reason: String,
    },
    /// Only an unchanged applicable local admission may use this mode.
    Local,
}

#[derive(Debug, Clone, Default)]
pub struct CurrentKnowledge {
    pub adverse_subjects: BTreeSet<Sha256Digest>,
    pub adverse_signers: BTreeSet<String>,
    /// Most recent locally retained successful observations; cannot be rolled back.
    pub source_checks: BTreeMap<SourceId, i64>,
    pub source_contents: BTreeMap<SourceId, Sha256Digest>,
}

pub struct PersonalApproval<'a> {
    pub acceptance: &'a PersonalAcceptance,
    pub assessment: &'a HumanAssessment,
    pub review_bytes: &'a [u8],
}
pub struct RepositoryContext<'a> {
    pub scope: &'a str,
    pub consumer_context_id: &'a Sha256Digest,
    pub admission: &'a ReviewedToolchainAdmission,
    pub evidence_bytes: &'a [u8],
    pub exception_review_bytes: Option<&'a [u8]>,
    pub continuing: Option<&'a ContinuingUseBinding>,
}
pub struct EligibilityInput<'a> {
    pub purpose: EligibilityPurpose,
    pub subject: &'a Subject,
    pub evidence: &'a EvidenceRecord,
    pub source_snapshots: &'a BTreeMap<String, Vec<u8>>,
    pub policy: &'a EffectivePolicy,
    /// The assessment for this effective policy; may differ from personal approval.
    pub assessment: &'a HumanAssessment,
    pub review_bytes: &'a [u8],
    pub personal: Option<PersonalApproval<'a>>,
    pub repository: Option<RepositoryContext<'a>>,
    pub installed: Option<&'a InstalledCorrespondence>,
    pub knowledge: &'a CurrentKnowledge,
    pub freshness: FreshnessRequest,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityMode {
    Online,
    ExplicitCached {
        reason: String,
        oldest_check: i64,
        expires_at: i64,
    },
    ContinuingLocal,
    StaticInspection,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eligibility {
    pub subject_id: Sha256Digest,
    pub policy_id: Sha256Digest,
    pub evidence_id: Sha256Digest,
    pub mode: EligibilityMode,
    pub age_exception_id: Option<Sha256Digest>,
}

pub fn evaluate_eligibility(input: EligibilityInput<'_>) -> Result<Eligibility> {
    let EligibilityInput {
        purpose,
        subject,
        evidence,
        source_snapshots,
        policy,
        assessment,
        review_bytes,
        personal,
        repository,
        installed,
        knowledge,
        freshness,
        now,
    } = input;
    timestamp(now)?;
    require(
        knowledge
            .source_checks
            .keys()
            .eq(knowledge.source_contents.keys()),
        "retained source checks and content identities are unpaired",
    )?;
    for checked_at in knowledge.source_checks.values() {
        timestamp(*checked_at)?;
        require(*checked_at <= now, "future retained source observation")?;
    }
    let policy_id = policy.id()?;
    let evidence_id = evidence.content_id(subject)?;
    evidence.verify_snapshots(source_snapshots)?;
    let maturity_start = evidence.publication.maturity_start(subject, now)?;
    require(
        !knowledge.adverse_subjects.contains(subject.id())
            && !knowledge
                .adverse_signers
                .contains(&subject.record().authentication.primary_fingerprint)
            && !knowledge
                .adverse_signers
                .contains(&subject.record().authentication.signing_fingerprint),
        "retained adverse knowledge blocks subject",
    )?;
    validate_assessment(
        assessment,
        subject,
        &evidence_id,
        evidence,
        review_bytes,
        now,
    )?;
    require(
        assessment.policy_id == policy_id,
        "assessment effective policy mismatch",
    )?;
    if let Some(approval) = personal {
        validate_assessment(
            approval.assessment,
            subject,
            &evidence_id,
            evidence,
            approval.review_bytes,
            now,
        )?;
        let acceptance = approval.acceptance;
        require(
            &acceptance.subject_id == subject.id()
                && acceptance.assessment_id == approval.assessment.id()?,
            "personal acceptance identity mismatch",
        )?;
        require(
            acceptance.accepted_at >= approval.assessment.assessed_at
                && acceptance.accepted_at <= now,
            "invalid personal acceptance time",
        )?;
        acceptance.id()?;
    } else {
        require(
            purpose == EligibilityPurpose::PersonalAcceptance,
            "personal acceptance required",
        )?;
    }
    if let Some(actual) = installed {
        require(
            &actual.subject_id == subject.id()
                && actual.mapping_sha256 == subject.record().mapping_sha256,
            "current installed correspondence mismatch",
        )?;
    }
    if matches!(
        purpose,
        EligibilityPurpose::ContinuingUse
            | EligibilityPurpose::Activation
            | EligibilityPurpose::InstallationInspection
    ) {
        require(
            installed.is_some(),
            "current installed correspondence required",
        )?;
    }
    let mut continuing = false;
    let mut age_exception_id = None;
    if let Some(repo) = &repository {
        let admission = repo.admission;
        admission.validate()?;
        require(
            admission.scope == repo.scope
                && &admission.subject_id == subject.id()
                && admission.policy_id == policy_id
                && admission.assessment_id == assessment.id()?,
            "repository admission scope or identity mismatch",
        )?;
        require(
            admission.review() == assessment.review,
            "repository assessment prose mismatch",
        )?;
        admission.evidence().verify(repo.evidence_bytes)?;
        let stored: PortableReview = parse_record(repo.evidence_bytes)?;
        stored.validate(subject)?;
        require(
            stored.evidence.content_id(subject)? == evidence_id
                && stored.assessment == *assessment
                && stored.policy == *policy,
            "portable review content mismatch",
        )?;
        if let Some(day) = &admission.review_by {
            let deadline = crate::parse_iso_date(day)
                .map_err(|e| AdmissionError(e.to_string()))?
                .next_day()
                .ok_or_else(|| AdmissionError("review deadline overflow".into()))?
                .midnight()
                .assume_utc()
                .unix_timestamp();
            require(now < deadline, "repository review deadline expired")?;
        }
        if let Some(exception) = &admission.age_exception {
            require(now < exception.expires_at, "age exception expired")?;
            exception
                .review
                .verify_completed(repo.exception_review_bytes.ok_or_else(|| {
                    AdmissionError("age exception completed prose required".into())
                })?)?;
            age_exception_id = Some(exception.id()?);
        }
        if matches!(
            purpose,
            EligibilityPurpose::ContinuingUse | EligibilityPurpose::Activation
        ) && let (Some(binding), Some(actual)) = (repo.continuing, installed)
        {
            version(binding.schema_version)?;
            continuing = &binding.subject_id == subject.id()
                && binding.admission_id == admission.id()?
                && &binding.consumer_context_id == repo.consumer_context_id
                && binding.installation_id == actual.installation_id;
        }
    } else {
        require(
            !matches!(
                purpose,
                EligibilityPurpose::RepositoryAdmission
                    | EligibilityPurpose::ContinuingUse
                    | EligibilityPurpose::Activation
            ),
            "repository admission context required",
        )?;
    }
    require(
        crate::release_age::meets_minimum_age((now - maturity_start).max(0), policy.minimum_days)
            && now >= maturity_start
            || age_exception_id.is_some(),
        "release is too fresh for effective policy",
    )?;
    let mut oldest = now;
    let mut expires = i64::MAX;
    for source in &evidence.observations {
        require(source.checked_at <= now, "future evidence check time")?;
        require(
            knowledge
                .source_checks
                .get(&source.source)
                .is_none_or(|known| source.checked_at >= *known),
            "older evidence cannot replace newer local knowledge",
        )?;
        if let Some(known_time) = knowledge.source_checks.get(&source.source) {
            let known_content = knowledge
                .source_contents
                .get(&source.source)
                .ok_or_else(|| {
                    AdmissionError("retained source check lacks content identity".into())
                })?;
            require(
                source.checked_at != *known_time || &source.content_id()? == known_content,
                "different evidence at the same check time cannot replace local knowledge",
            )?;
        }
        if let Some(expiry) = source.expires_at {
            require(now < expiry, "source evidence expired")?;
            expires = expires.min(expiry);
        }
        oldest = oldest.min(source.checked_at);
    }
    let mode = if purpose == EligibilityPurpose::InstallationInspection {
        require(
            matches!(freshness, FreshnessRequest::Local),
            "static installation inspection does not use a fresh-admission mode",
        )?;
        EligibilityMode::StaticInspection
    } else if continuing {
        EligibilityMode::ContinuingLocal
    } else {
        require(
            purpose != EligibilityPurpose::ContinuingUse,
            "continuing use binding does not match current consumer/admission/installation",
        )?;
        expires = expires.min(
            oldest
                .checked_add(86_400)
                .ok_or_else(|| AdmissionError("evidence expiry overflow".into()))?,
        );
        require(
            now <= expires && now - oldest <= 86_400,
            "required evidence exceeds 24-hour freshness limit",
        )?;
        match freshness {
            FreshnessRequest::Online {
                operation_started_at,
            } => {
                timestamp(operation_started_at)?;
                require(
                    operation_started_at <= now && oldest >= operation_started_at,
                    "required online sources were not refreshed for this operation",
                )?;
                EligibilityMode::Online
            }
            FreshnessRequest::Cached { reason } => {
                text(&reason)?;
                EligibilityMode::ExplicitCached {
                    reason,
                    oldest_check: oldest,
                    expires_at: expires,
                }
            }
            FreshnessRequest::Local => {
                return Err(AdmissionError(
                    "fresh evidence required for this operation".into(),
                ));
            }
        }
    };
    Ok(Eligibility {
        subject_id: subject.id().clone(),
        policy_id,
        evidence_id,
        mode,
        age_exception_id,
    })
}

fn validate_assessment(
    assessment: &HumanAssessment,
    subject: &Subject,
    evidence_id: &Sha256Digest,
    evidence: &EvidenceRecord,
    review: &[u8],
    now: i64,
) -> Result<()> {
    assessment.id()?;
    require(
        &assessment.subject_id == subject.id() && &assessment.evidence_id == evidence_id,
        "human assessment identity mismatch",
    )?;
    require(assessment.assessed_at <= now, "future human assessment")?;
    require(
        assessment.assessed_unknowns == evidence.residual_unknowns(),
        "residual unknown coverage not explicitly assessed",
    )?;
    require(
        assessment.assessed_findings == evidence.findings.iter().map(|f| f.id.clone()).collect(),
        "findings not explicitly assessed",
    )?;
    require(
        !evidence
            .findings
            .iter()
            .any(|f| f.exposure == Exposure::Known && f.change != FindingChange::Resolved),
        "known applicable adverse finding blocks admission",
    )?;
    assessment.review.verify_completed(review)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableReview {
    pub schema_version: u32,
    pub subject: SubjectRecord,
    pub evidence: EvidenceRecord,
    pub policy: EffectivePolicy,
    pub assessment: HumanAssessment,
}
impl PortableReview {
    /// Identity coherence only; this does not validate prose, freshness or local approval.
    pub fn validate(&self, subject: &Subject) -> Result<()> {
        version(self.schema_version)?;
        self.subject.validate_against(subject)?;
        require(
            self.evidence.content_id(subject)? == self.assessment.evidence_id
                && self.policy.id()? == self.assessment.policy_id
                && &self.assessment.subject_id == subject.id(),
            "portable review binding mismatch",
        )
    }
}
