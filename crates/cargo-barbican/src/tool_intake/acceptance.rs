use barbican::cargo_tool::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
    apply_records, collection,
    frontend::{Context, StoredReview},
    output_files,
};
use crate::cli::{ToolAcceptArgs, ToolFreshnessArgs};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    pub acceptance_id: RecordId,
    pub assessment_id: RecordId,
    pub completed_record: PathBuf,
    pub completed_record_sha256: barbican::Sha256Digest,
}

pub(super) fn now() -> Result<i64> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    )
    .map_err(|e| e.to_string())
}

fn field<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    let prefix = format!("{key}: ");
    let found: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    if found.len() != 1 || found[0].trim().is_empty() {
        return Err(format!(
            "completed assessment requires exactly one {key} field"
        ));
    }
    Ok(found[0])
}

pub(super) fn assess(review: &Review, bytes: &[u8], completed_at_utc: i64) -> Result<Assessment> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("assessment exceeds record bound".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    if text.contains("PENDING")
        || field(text, "Decision")? != "ACCEPT"
        || field(text, "Cargo-Tool-Review")? != review.id().map_err(|e| e.to_string())?.to_string()
    {
        return Err("assessment is pending or does not explicitly accept this exact review".into());
    }
    let mut responses = BTreeMap::new();
    for line in text
        .lines()
        .filter_map(|line| line.strip_prefix("Response: "))
    {
        let (key, value) = line
            .split_once('=')
            .ok_or("assessment response requires requirement=completed prose")?;
        if responses.insert(key.into(), value.into()).is_some() {
            return Err("duplicate assessment requirement response".into());
        }
    }
    let assessment = Assessment {
        schema_version: SCHEMA_VERSION,
        review_id: review.id().map_err(|e| e.to_string())?,
        reviewer: field(text, "Reviewer")?.into(),
        completed_at_utc,
        prose: text.into(),
        responses,
    };
    assessment
        .applicable(review, completed_at_utc)
        .map_err(|e| e.to_string())?;
    let acknowledgement = field(text, "Risk-Acknowledgement")?;
    if !barbican::classify_review_record(Some(acknowledgement)).is_satisfied() {
        return Err("risk acknowledgement is incomplete".into());
    }
    Ok(assessment)
}

pub(super) fn freshness(
    options: &ToolFreshnessArgs,
    operation: OperationKind,
    started_at_utc: i64,
) -> Result<OperationIntent> {
    let freshness =
        match (options.cached_admission, options.cache_reason.as_deref()) {
            (false, None) => FreshnessIntent::Online { started_at_utc },
            (true, Some(reason)) if !reason.trim().is_empty() => FreshnessIntent::Cached {
                reason: reason.into(),
            },
            _ => return Err(
                "cached admission requires both --cached-admission and a nonempty --cache-reason"
                    .into(),
            ),
        };
    Ok(OperationIntent {
        operation,
        freshness,
    })
}

pub(super) fn eligible(
    ctx: &Context,
    review: &StoredReview,
    intent: &OperationIntent,
) -> Result<()> {
    review
        .review
        .applicable(&review.subject, &review.policy, &review.evidence.content)
        .map_err(|e| e.to_string())?;
    check_eligibility_checked(
        &review.subject,
        &review.policy,
        &review.evidence,
        &ctx.knowledge()?,
        intent,
        now()?,
        &mut || ctx.budget.check(),
    )
    .map_err(|e| e.to_string())?;
    ctx.check()
}

pub(super) fn eligible_after_build(
    ctx: &Context,
    review: &StoredReview,
    intent: &OperationIntent,
) -> Result<()> {
    review
        .review
        .applicable(&review.subject, &review.policy, &review.evidence.content)
        .map_err(|e| e.to_string())?;
    let budget = super::process::Budget::native(ctx.budget.cancelled.clone());
    check_eligibility_checked(
        &review.subject,
        &review.policy,
        &review.evidence,
        &ctx.knowledge()?,
        intent,
        now()?,
        &mut || budget.check(),
    )
    .map_err(|e| e.to_string())?;
    ctx.check_after_build()
}

pub(super) fn load(
    ctx: &Context,
    review: &StoredReview,
) -> Result<(Authority, LocalAcceptance, Assessment)> {
    let review_id = review.review.id().map_err(|e| e.to_string())?;
    let authority: Authority = apply_records::read(
        &ctx.stores.data,
        &apply_records::acceptance_path(&review_id),
    )?
    .ok_or("review has no explicit local acceptance")?;
    let acceptance: LocalAcceptance = ctx.stores.read(&authority.acceptance_id)?;
    let assessment: Assessment = ctx.stores.read(&authority.assessment_id)?;
    acceptance
        .applicable(&review.review, &assessment, &ctx.local_user()?, now()?)
        .map_err(|e| e.to_string())?;
    review
        .review
        .applicable(&review.subject, &review.policy, &review.evidence.content)
        .map_err(|e| e.to_string())?;
    let current = output_files::read_record(
        &authority.completed_record,
        ctx.uid()?,
        MAX_RECORD_BYTES,
        ctx.cancelled(),
    )?;
    if sha256(&current) != authority.completed_record_sha256
        || current != assessment.prose.as_bytes()
    {
        return Err(
            "completed assessment changed after local acceptance; explicitly reassess and accept"
                .into(),
        );
    }
    Ok((authority, acceptance, assessment))
}

pub(super) fn accept(ctx: &Context, stored: &StoredReview, args: &ToolAcceptArgs) -> Result<Value> {
    let started = ctx.now;
    let intent = freshness(&args.options, OperationKind::Accept, started)?;
    let refreshed = collection::refresh(ctx, stored, args.options.cache_reason.as_deref())?;
    eligible(ctx, &refreshed, &intent)?;
    let path = absolute_record(ctx, &args.record)?;
    let bytes = output_files::read_record(&path, ctx.uid()?, MAX_RECORD_BYTES, ctx.cancelled())?;
    let review_id = refreshed.review.id().map_err(|e| e.to_string())?;
    let existing: Option<Authority> = apply_records::read(
        &ctx.stores.data,
        &apply_records::acceptance_path(&review_id),
    )?;
    let assessment = if let Some(authority) = &existing {
        let previous: Assessment = ctx.stores.read(&authority.assessment_id)?;
        if previous.prose.as_bytes() == bytes {
            previous
        } else {
            assess(&refreshed.review, &bytes, now()?)?
        }
    } else {
        assess(&refreshed.review, &bytes, now()?)?
    };
    assessment
        .applicable(&refreshed.review, now()?)
        .map_err(|e| e.to_string())?;
    let cached_use_record = apply_records::cached_use(
        &ctx.stores.data,
        &refreshed.review,
        &refreshed
            .evidence
            .observation
            .id()
            .map_err(|error| error.to_string())?,
        &intent,
        || ctx.check(),
    )?;
    let assessment_id = ctx.stores.write(&assessment)?;
    let mut acceptance = LocalAcceptance {
        schema_version: SCHEMA_VERSION,
        review_id: review_id.clone(),
        assessment_id: assessment_id.clone(),
        subject_id: refreshed.review.subject_id.clone(),
        evidence_content_id: refreshed.review.evidence_content_id.clone(),
        policy_id: refreshed.review.policy_id.clone(),
        local_user: ctx.local_user()?,
        accepted_at_utc: now()?,
        deployment: DeploymentScope::OrdinaryCargoRoots,
        risk_acknowledgement: field(&assessment.prose, "Risk-Acknowledgement")?.into(),
    };
    if let Some(authority) = existing {
        let previous: LocalAcceptance = ctx.stores.read(&authority.acceptance_id)?;
        if previous.assessment_id == assessment_id {
            acceptance = previous;
        }
    }
    acceptance
        .applicable(&refreshed.review, &assessment, &ctx.local_user()?, now()?)
        .map_err(|e| e.to_string())?;
    if args.approve_repo != args.repo_record.is_some()
        || (args.approve_repo && args.options.standalone)
    {
        return Err("repository approval requires both --approve-repo and --repo-record in actual repository context".into());
    }
    let repo_approval = args
        .repo_record
        .as_ref()
        .map(|record| super::repository::prepare(ctx, &refreshed, record))
        .transpose()?;
    eligible(ctx, &refreshed, &intent)?;
    let acceptance_id = ctx.stores.write(&acceptance)?;
    let authority = Authority {
        acceptance_id: acceptance_id.clone(),
        assessment_id: assessment_id.clone(),
        completed_record: path.clone(),
        completed_record_sha256: sha256(&bytes),
    };
    apply_records::index(
        &ctx.stores.data,
        &apply_records::acceptance_path(&review_id),
        &authority,
        || {
            eligible(ctx, &refreshed, &intent)?;
            if output_files::read_record(&path, ctx.uid()?, MAX_RECORD_BYTES, ctx.cancelled())?
                != bytes
            {
                return Err("assessment changed during acceptance".into());
            }
            Ok(())
        },
    )?;
    let repo_admission = repo_approval
        .map(|prepared| {
            super::repository::publish(ctx, prepared).map_err(|error| {
                format!("local acceptance retained; repository approval failed: {error}")
            })
        })
        .transpose()?;
    Ok(
        serde_json::json!({"schema_version":1,"status":"locally-accepted","cached_use_record":cached_use_record,"review_id":review_id.to_string(),"assessment_id":assessment_id.to_string(),"acceptance_id":acceptance_id.to_string(),"repository_admission":repo_admission.map(|id|id.to_string())}),
    )
}

pub(super) fn absolute_record(ctx: &Context, path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        ctx.current.join(path)
    };
    output_files::absolute(&path)?;
    Ok(path)
}
