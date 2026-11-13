use super::{review::ReconstructedReview, store::PrivateStore};
use barbican::Sha256Digest;
use barbican::toolchain_admission::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) type Result<T> = std::result::Result<T, String>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcceptanceRecord {
    pub schema_version: u32,
    pub review_id: Sha256Digest,
    pub assessment: HumanAssessment,
    pub acceptance: PersonalAcceptance,
    pub prose: Vec<u8>,
    pub eligibility: super::operation::OperationEvidence,
}

pub(super) fn template(review: &ReconstructedReview, id: &Sha256Digest) -> Result<String> {
    let evidence_id = review
        .record
        .evidence
        .content_id(&review.subject)
        .map_err(|e| e.to_string())?;
    let mut text = format!(
        "# Rust toolchain review\n\nPENDING — complete this review before acceptance.\n\nToolchain-Review: {id}\nSubject: {}\nEvidence: {evidence_id}\nPolicy: {}\nDecision: PENDING\n\n",
        review.subject.id(),
        review.record.policy.id().map_err(|e| e.to_string())?
    );
    for row in &review.record.evidence.component_sources {
        text.push_str(&format!("Component: {}/{} archive {}\nSource: {} @ {} ({:?})\nRelationship: {}\nCoverage limits: {}\n\n", row.archive.package, row.archive.target, row.archive.sha256, row.corpus.repository(), row.source_revision, row.corpus, row.relationship, row.residual_coverage));
        if let Some(assets) = &row.documentation_assets {
            text.push_str(&format!("Docs assets: {} files, {} bytes, {} JavaScript files, {} CSS files; payload {}. Static only.\n\n", assets.files, assets.bytes, assets.javascript_files, assets.css_files, assets.payload_sha256));
        }
    }
    for unknown in review.record.evidence.residual_unknowns() {
        text.push_str(&format!("Assessed-Unknown: {}\n", source_key(&unknown)?));
    }
    for finding in &review.record.evidence.findings {
        text.push_str(&format!(
            "Assessed-Finding: {}\nFinding context: {}\n",
            finding.id, finding.rationale
        ));
    }
    text.push_str("\nRationale: PENDING — review every source snapshot and finding, explain accepted residual uncertainty and relevant applicability. Set Decision: ACCEPT and remove all PENDING markers only after human review.\n");
    Ok(text)
}
fn source_key(source: &SourceId) -> Result<String> {
    serde_json::to_string(source).map_err(|e| e.to_string())
}

pub(super) fn assess(
    review: &ReconstructedReview,
    id: &Sha256Digest,
    prose: &[u8],
    now: i64,
) -> Result<HumanAssessment> {
    if prose.len() > MAX_RECORD_BYTES {
        return Err("completed review exceeds byte limit".into());
    }
    let text = std::str::from_utf8(prose).map_err(|e| e.to_string())?;
    if !barbican::classify_review_record(Some(text)).is_satisfied() || text.contains("PENDING") {
        return Err("review prose is still pending".into());
    }
    let evidence_id = review
        .record
        .evidence
        .content_id(&review.subject)
        .map_err(|e| e.to_string())?;
    let policy_id = review.record.policy.id().map_err(|e| e.to_string())?;
    for (name, expected) in [
        ("Toolchain-Review", id.as_str()),
        ("Subject", review.subject.id().as_str()),
        ("Evidence", evidence_id.as_str()),
        ("Policy", policy_id.as_str()),
        ("Decision", "ACCEPT"),
    ] {
        let values: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{name}: ")))
            .collect();
        if values != [expected] {
            return Err(format!(
                "completed review must contain exactly one matching {name}: {expected}"
            ));
        }
    }
    let rationale: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("Rationale: "))
        .collect();
    if rationale.len() != 1 || rationale[0].trim().len() < 20 {
        return Err(
            "completed review needs one concrete Rationale: of at least 20 characters".into(),
        );
    }
    let unknowns = review.record.evidence.residual_unknowns();
    let expected_unknowns: BTreeSet<_> = unknowns.iter().map(source_key).collect::<Result<_>>()?;
    let assessed_unknowns: BTreeSet<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("Assessed-Unknown: "))
        .map(str::to_owned)
        .collect();
    if assessed_unknowns != expected_unknowns {
        return Err("completed prose must explicitly assess the exact listed residual unknown source scopes".into());
    }
    let expected_findings: BTreeSet<_> = review
        .record
        .evidence
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect();
    let assessed_findings: BTreeSet<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("Assessed-Finding: "))
        .map(str::to_owned)
        .collect();
    if assessed_findings != expected_findings {
        return Err("completed prose must explicitly assess every exact finding".into());
    }
    Ok(HumanAssessment {
        schema_version: 1,
        subject_id: review.subject.id().clone(),
        evidence_id,
        policy_id,
        review: RecordReference {
            path: format!("docs/dependency-reviews/toolchains/{id}/review.md"),
            sha256: digest_bytes(prose),
        },
        assessed_at: now,
        assessed_unknowns: unknowns,
        assessed_findings,
    })
}

pub(super) fn publish_personal(
    data: &PrivateStore,
    id: &Sha256Digest,
    review: &ReconstructedReview,
    assessment: HumanAssessment,
    prose: Vec<u8>,
    freshness: FreshnessRequest,
    knowledge: &CurrentKnowledge,
    repo: Option<&super::repo::RepoContext>,
    now: i64,
) -> Result<(AcceptanceRecord, super::operation::OperationEvidence)> {
    let repo_evidence = repo
        .map(|repo| existing_admission(repo, review))
        .transpose()?
        .flatten();
    let context_id = repo.map(super::admission::consumer_id).transpose()?;
    let repository = match (repo, repo_evidence.as_ref(), context_id.as_ref()) {
        (Some(repo), Some((admission, evidence, exception)), Some(context_id)) => {
            Some(RepositoryContext {
                scope: repo
                    .config
                    .toolchain
                    .admission_scope
                    .as_deref()
                    .ok_or("current repository scope is missing")?,
                consumer_context_id: context_id,
                admission,
                evidence_bytes: evidence,
                exception_review_bytes: exception.as_deref(),
                continuing: None,
            })
        }
        _ => None,
    };
    let evaluated = evaluate_eligibility(EligibilityInput {
        purpose: EligibilityPurpose::PersonalAcceptance,
        subject: &review.subject,
        evidence: &review.record.evidence,
        source_snapshots: &review.source_snapshots,
        policy: &review.record.policy,
        assessment: &assessment,
        review_bytes: &prose,
        personal: None,
        repository,
        installed: None,
        knowledge,
        freshness,
        now,
    })
    .map_err(|e| e.to_string())?;
    let operation = super::operation::OperationEvidence::new("accept", &evaluated, now);
    operation.retain(data)?;
    let path = format!("acceptances/{id}.json");
    if let Some(existing) = data.read_optional(Path::new(&path), MAX_RECORD_BYTES as u64)? {
        let existing: AcceptanceRecord =
            parse_record(existing.bytes()).map_err(|e| e.to_string())?;
        if existing.schema_version != 1
            || existing.review_id != *id
            || existing.assessment.review.sha256 != assessment.review.sha256
        {
            return Err("existing personal acceptance conflicts; prior approval retained".into());
        }
        return Ok((existing, operation));
    }
    let acceptance = PersonalAcceptance {
        schema_version: 1,
        subject_id: review.subject.id().clone(),
        assessment_id: assessment.id().map_err(|e| e.to_string())?,
        accepted_at: now,
    };
    let record = AcceptanceRecord {
        schema_version: 1,
        review_id: id.clone(),
        assessment,
        acceptance,
        prose,
        eligibility: operation.clone(),
    };
    data.publish(
        Path::new(&path),
        &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )?;
    Ok((record, operation))
}

pub(super) fn load(data: &PrivateStore, id: &Sha256Digest) -> Result<AcceptanceRecord> {
    let captured = data.read(
        Path::new(&format!("acceptances/{id}.json")),
        MAX_RECORD_BYTES as u64,
    )?;
    let record: AcceptanceRecord = parse_record(captured.bytes()).map_err(|e| e.to_string())?;
    if record.schema_version != 1
        || record.review_id != *id
        || record.acceptance.assessment_id != record.assessment.id().map_err(|e| e.to_string())?
    {
        return Err("personal acceptance binding mismatch".into());
    }
    record
        .assessment
        .review
        .verify_completed(&record.prose)
        .map_err(|e| e.to_string())?;
    Ok(record)
}

pub(super) fn portable_assessment(
    repo: &super::repo::RepoContext,
    review: &ReconstructedReview,
    id: &Sha256Digest,
    prose: &[u8],
) -> Result<Option<HumanAssessment>> {
    let Some(policy) = super::repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?
    else {
        return Ok(None);
    };
    let targets = barbican::parse_reviewed_targets_toml(
        std::str::from_utf8(&policy).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let path = format!("docs/dependency-reviews/toolchains/{id}/evidence.json");
    let matches: Vec<_> = targets
        .rust_toolchains()
        .iter()
        .filter(|entry| entry.subject_id == *review.subject.id() && entry.evidence_record == path)
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }
    let [admission] = matches.as_slice() else {
        return Err("ambiguous portable review assessment".into());
    };
    let bytes = super::repo::read_optional(&repo.root, Path::new(&admission.evidence_record))?
        .ok_or("portable evidence missing")?;
    admission
        .evidence()
        .verify(&bytes)
        .map_err(|e| e.to_string())?;
    let portable: PortableReview = parse_record(&bytes).map_err(|e| e.to_string())?;
    portable
        .validate(&review.subject)
        .map_err(|e| e.to_string())?;
    portable
        .assessment
        .review
        .verify_completed(prose)
        .map_err(|e| e.to_string())?;
    let reconstructed = assess(review, id, prose, portable.assessment.assessed_at)?;
    if reconstructed != portable.assessment {
        return Err(
            "portable assessment differs from exact current review facts and completed prose"
                .into(),
        );
    }
    Ok(Some(portable.assessment))
}

type ExistingAdmission = (ReviewedToolchainAdmission, Vec<u8>, Option<Vec<u8>>);
fn existing_admission(
    repo: &super::repo::RepoContext,
    review: &ReconstructedReview,
) -> Result<Option<ExistingAdmission>> {
    let Some(bytes) = super::repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?
    else {
        return Ok(None);
    };
    let targets = barbican::parse_reviewed_targets_toml(
        std::str::from_utf8(&bytes).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let matches: Vec<_> = targets
        .rust_toolchains()
        .iter()
        .filter(|admission| admission.subject_id == *review.subject.id())
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }
    let [admission] = matches.as_slice() else {
        return Err("ambiguous current repository admission".into());
    };
    if super::review::policy(Some(repo), None)
        .id()
        .map_err(|e| e.to_string())?
        != review.record.policy.id().map_err(|e| e.to_string())?
    {
        return Err("current repository policy differs from reviewed policy".into());
    }
    let evidence = super::repo::read_optional(&repo.root, Path::new(&admission.evidence_record))?
        .ok_or("existing portable evidence missing")?;
    let exception = admission
        .age_exception
        .as_ref()
        .map(|exception| {
            super::repo::read_optional(&repo.root, Path::new(&exception.review.path)).and_then(
                |bytes| bytes.ok_or("completed toolchain age-exception prose missing".into()),
            )
        })
        .transpose()?;
    repo.recheck()?;
    Ok(Some(((*admission).clone(), evidence, exception)))
}
