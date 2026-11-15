use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    acceptance, context,
    frontend::{Context, StoredReview},
    output_files,
};
use barbican::cargo_tool::*;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableAdmission {
    schema_version: u32,
    subject: Subject,
    policy: OriginPolicy,
    review: Review,
    evidence: EvidenceContent,
    assessment: Assessment,
    admission: RepoAdmission,
}

fn record_hashes(
    subject: &Subject,
    policy: &OriginPolicy,
    review: &Review,
    evidence: &EvidenceContent,
    assessment: &Assessment,
) -> Result<BTreeSet<barbican::Sha256Digest>> {
    [
        encode_record(subject),
        encode_record(policy),
        encode_record(review),
        encode_record(evidence),
        encode_record(assessment),
    ]
    .into_iter()
    .map(|bytes| bytes.map(|bytes| sha256(&bytes)).map_err(|e| e.to_string()))
    .collect()
}

impl PortableAdmission {
    fn validate(&self, governance: &str) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("invalid portable Cargo tool schema".into());
        }
        self.subject.validate().map_err(|e| e.to_string())?;
        self.policy.validate().map_err(|e| e.to_string())?;
        self.evidence
            .applicable(&self.subject, &self.policy)
            .map_err(|e| e.to_string())?;
        self.review
            .applicable(&self.subject, &self.policy, &self.evidence)
            .map_err(|e| e.to_string())?;
        self.admission
            .applicable(
                &self.review,
                &self.assessment,
                &self.policy,
                governance,
                acceptance::now()?,
            )
            .map_err(|e| e.to_string())?;
        if self.admission.portable_record_sha256
            != record_hashes(
                &self.subject,
                &self.policy,
                &self.review,
                &self.evidence,
                &self.assessment,
            )?
        {
            return Err("portable tool evidence hash references disagree".into());
        }
        Ok(())
    }
}

fn governance(ctx: &Context) -> Result<(&context::RepoContext, &str)> {
    let repo = ctx
        .repo
        .as_ref()
        .ok_or("repository approval requires actual governance context")?;
    let scope = repo
        .config
        .tools
        .admission_scope
        .as_deref()
        .ok_or("repository tool admission requires explicit [tools].admission_scope")?;
    Ok((repo, scope))
}

fn targets(ctx: &Context) -> Result<barbican::ReviewedTargets> {
    targets_with_budget(ctx, &ctx.budget)
}

fn targets_with_budget(
    ctx: &Context,
    budget: &super::process::Budget,
) -> Result<barbican::ReviewedTargets> {
    let repo = ctx.repo.as_ref().ok_or("repository context missing")?;
    let bytes = context::read_optional(&repo.root, Path::new("reviewed-targets.toml"), budget)?
        .unwrap_or_default();
    barbican::parse_reviewed_targets_toml(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn read_bundle(
    ctx: &Context,
    row: &barbican::reviewed_targets::ReviewedCargoTool,
    governance: &str,
    budget: &super::process::Budget,
) -> Result<PortableAdmission> {
    let repo = ctx.repo.as_ref().ok_or("repository context missing")?;
    let bytes = context::read_optional(&repo.root, Path::new(&row.record), budget)?
        .ok_or("repository tool admission bundle missing")?;
    if sha256(&bytes) != row.record_sha256 {
        return Err("repository tool admission bundle digest changed".into());
    }
    let bundle: PortableAdmission = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid portable tool admission: {e}"))?;
    bundle.validate(governance)?;
    if bundle.subject.id().map_err(|e| e.to_string())? != row.subject_id {
        return Err("repository declaration names another tool subject".into());
    }
    Ok(bundle)
}

pub(super) fn check(ctx: &Context, review: &StoredReview) -> Result<Option<RecordId>> {
    check_with_budget(ctx, review, &ctx.budget)
}

pub(super) fn check_after_build(ctx: &Context, review: &StoredReview) -> Result<Option<RecordId>> {
    check_with_budget(
        ctx,
        review,
        &super::process::Budget::native(ctx.budget.cancelled.clone()),
    )
}

fn check_with_budget(
    ctx: &Context,
    review: &StoredReview,
    budget: &super::process::Budget,
) -> Result<Option<RecordId>> {
    let Some(repo) = &ctx.repo else {
        return Ok(None);
    };
    let Some(scope) = repo.config.tools.admission_scope.as_deref() else {
        return Ok(None);
    };
    repo.recheck(budget)?;
    let subject_id = review.subject.id().map_err(|e| e.to_string())?;
    let targets = targets_with_budget(ctx, budget)?;
    let matching: Vec<_> = targets
        .rust_tools()
        .iter()
        .filter(|row| row.subject_id == subject_id)
        .collect();
    if matching.len() != 1 {
        return Err(
            "repository requires exactly one current reviewed declaration for this tool subject"
                .into(),
        );
    }
    let bundle = read_bundle(ctx, matching[0], scope, budget)?;
    if bundle.review != review.review
        || bundle.policy != review.policy
        || bundle.evidence != review.evidence.content
        || bundle.subject != review.subject
    {
        return Err(
            "repository admission differs from current tool review, policy or evidence".into(),
        );
    }
    Ok(Some(bundle.admission.id().map_err(|e| e.to_string())?))
}

pub(super) struct PreparedApproval {
    bundle_path: PathBuf,
    bytes: Vec<u8>,
    new_targets: Option<Vec<u8>>,
    admission_id: RecordId,
}

pub(super) fn prepare(
    ctx: &Context,
    review: &StoredReview,
    record: &Path,
) -> Result<PreparedApproval> {
    let (repo, scope) = governance(ctx)?;
    if review.policy.scope
        != (PolicyScope::Repository {
            governance_id: scope.into(),
        })
    {
        return Err("tool review does not bind the actual repository admission scope".into());
    }
    let completed = acceptance::absolute_record(ctx, record)?;
    if !completed.starts_with(&repo.root) {
        return Err("repository assessment must belong to the actual governance root".into());
    }
    let prose =
        output_files::read_record(&completed, ctx.uid()?, MAX_RECORD_BYTES, ctx.cancelled())?;
    let subject_id = review.subject.id().map_err(|e| e.to_string())?;
    let targets = targets(ctx)?;
    if let Some(row) = targets
        .rust_tools()
        .iter()
        .find(|row| row.subject_id == subject_id)
    {
        let previous = read_bundle(ctx, row, scope, &ctx.budget)?;
        if previous.assessment.prose.as_bytes() == prose
            && previous.review == review.review
            && previous.policy == review.policy
            && previous.evidence == review.evidence.content
        {
            return Ok(PreparedApproval {
                bundle_path: row.record.clone().into(),
                bytes: canonical_bytes(&previous).map_err(|e| e.to_string())?,
                new_targets: None,
                admission_id: previous.admission.id().map_err(|e| e.to_string())?,
            });
        }
    }
    let assessment = acceptance::assess(&review.review, &prose, acceptance::now()?)?;
    let admission = RepoAdmission {
        schema_version: SCHEMA_VERSION,
        governance_id: scope.into(),
        review_id: review.review.id().map_err(|e| e.to_string())?,
        assessment_id: assessment.id().map_err(|e| e.to_string())?,
        subject_id: subject_id.clone(),
        evidence_content_id: review.evidence.content.id().map_err(|e| e.to_string())?,
        policy_id: review.policy.id().map_err(|e| e.to_string())?,
        portable_record_sha256: record_hashes(
            &review.subject,
            &review.policy,
            &review.review,
            &review.evidence.content,
            &assessment,
        )?,
        approved_by: assessment.reviewer.clone(),
        approved_at_utc: acceptance::now()?,
    };
    let admission_id = admission.id().map_err(|e| e.to_string())?;
    let bundle = PortableAdmission {
        schema_version: SCHEMA_VERSION,
        subject: review.subject.clone(),
        policy: review.policy.clone(),
        review: review.review.clone(),
        evidence: review.evidence.content.clone(),
        assessment,
        admission,
    };
    bundle.validate(scope)?;
    let bytes = canonical_bytes(&bundle).map_err(|e| e.to_string())?;
    let bundle_path = PathBuf::from(format!("docs/tool-reviews/{}.json", admission_id.sha256));
    let original =
        context::read_optional(&repo.root, Path::new("reviewed-targets.toml"), &ctx.budget)?
            .unwrap_or_default();
    let row = barbican::reviewed_targets::ReviewedCargoTool {
        subject_id,
        record: bundle_path
            .to_str()
            .ok_or("portable bundle path is not UTF-8")?
            .into(),
        record_sha256: sha256(&bytes),
    };
    let new_targets = barbican::reviewed_targets::rewrite_reviewed_cargo_tool(
        std::str::from_utf8(&original).map_err(|e| e.to_string())?,
        &row,
    )?;
    Ok(PreparedApproval {
        bundle_path,
        bytes,
        new_targets: Some(new_targets.into_bytes()),
        admission_id,
    })
}

pub(super) fn publish(ctx: &Context, prepared: PreparedApproval) -> Result<RecordId> {
    let (repo, _) = governance(ctx)?;
    ctx.check()?;
    let path = contained_publication_path(&repo.root, &prepared.bundle_path, ctx.uid()?)?;
    match context::read_optional(&repo.root, &prepared.bundle_path, &ctx.budget)? {
        Some(bytes) if bytes == prepared.bytes => {}
        Some(_) => {
            return Err("portable tool evidence publication conflicts with existing bytes".into());
        }
        None => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(&prepared.bytes).map_err(|e| {
                format!(
                    "partial supporting evidence retained, admission declaration not published: {e}"
                )
            })?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
    }
    if let Some(bytes) = prepared.new_targets {
        let temporary = repo.root.join(format!(
            ".barbican-tool-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let result: Result<()> = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            ctx.check()?;
            let observed =
                output_files::read_record(&path, ctx.uid()?, MAX_RECORD_BYTES, ctx.cancelled())?;
            if observed != prepared.bytes {
                return Err("supporting repository evidence changed before declaration".into());
            }
            fs::rename(&temporary, repo.root.join("reviewed-targets.toml"))
                .map_err(|e| e.to_string())?;
            if context::read_optional(&repo.root, Path::new("reviewed-targets.toml"), &ctx.budget)?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Err("repository admission declaration changed after publication".into());
            }
            Ok(())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
    }
    output_files::check_cancelled(ctx.cancelled()).map_err(|e| {
        format!("repository publication completed before cancellation was observed: {e}")
    })?;
    Ok(prepared.admission_id)
}

fn contained_publication_path(root: &Path, relative: &Path, uid: u32) -> Result<PathBuf> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("invalid portable evidence destination".into());
    }
    let mut path = root.to_owned();
    for component in relative
        .parent()
        .ok_or("portable record has no parent")?
        .components()
    {
        path.push(component);
        if !path.try_exists().map_err(|e| e.to_string())? {
            fs::create_dir(&path).map_err(|e| e.to_string())?;
        }
        output_files::protected_ancestors(&path, uid)?;
    }
    Ok(root.join(relative))
}
