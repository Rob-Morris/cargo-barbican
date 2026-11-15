use super::{
    frontend::{Context, load_review},
    process::{Budget, Result, err},
};
use crate::cli::ToolIocExceptionArgs;
use crate::commands::ioc as frontend;
use barbican::{OffsetDateTime, Sha256Digest, cargo_tool::*, ioc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolIocRecordReference {
    record_kind: String,
    schema_version: u32,
    subject_id: RecordId,
    policy_sha256: Sha256Digest,
    record: String,
    record_sha256: Sha256Digest,
}
impl ToolIocRecordReference {
    pub fn load(&self, ctx: &Context, budget: &Budget) -> Result<ToolIocException> {
        if self.record_kind != "ioc" || self.schema_version != 1 {
            return Err("unsupported tool IOC reference schema".into());
        }
        self.subject_id
            .require_kind(RecordKind::Subject)
            .map_err(err)?;
        ioc::relative_path(&self.record)?;
        let bytes = read_record(ctx, Path::new(&self.record), budget)?;
        if ioc::digest(&bytes) != self.record_sha256 {
            return Err(
                "tool IOC review record changed; explicitly review and republish its reference"
                    .into(),
            );
        }
        let exception = ToolIocException {
            subject_id: self.subject_id.clone(),
            policy_sha256: self.policy_sha256.clone(),
            allowance: ioc::Allowance::from_text(std::str::from_utf8(&bytes).map_err(err)?)?,
        };
        exception.validate().map_err(err)?;
        Ok(exception)
    }
}

pub(crate) fn report_path(review: &RecordId) -> PathBuf {
    PathBuf::from(format!("cargo-tools/v1/ioc-reports/{}.json", review.sha256))
}

fn read_record(ctx: &Context, path: &Path, budget: &Budget) -> Result<Vec<u8>> {
    if let Some(repo) = &ctx.repo {
        crate::verified_source::read_optional(&repo.root, path, budget)?
            .ok_or("tool IOC authority record missing".into())
    } else {
        Ok(ctx
            .stores
            .data
            .read(path, ioc::MAX_REPORT_BYTES as u64)?
            .bytes()
            .to_vec())
    }
}

pub(crate) fn run(
    ctx: &Context,
    args: &ToolIocExceptionArgs,
    now: OffsetDateTime,
) -> Result<Value> {
    let id: RecordId = args.review_id.parse().map_err(err)?;
    let stored = load_review(ctx, &id)?;
    let (scope, base) = super::policy::origin_binding(ctx)?;
    if stored.policy.scope != scope || stored.policy.policy_sha256 != base {
        return Err("tool review belongs to another current originating policy; recollect it under this authority".into());
    }
    let bytes = ctx
        .stores
        .data
        .read(&report_path(&id), ioc::MAX_REPORT_BYTES as u64)?;
    let report = ioc::Report::parse(bytes.bytes())?;
    for inspected in &report.sources {
        if !stored
            .subject
            .graph
            .packages()
            .contains(&PackageIdentity::from(&inspected.source))
        {
            return Err(
                "stored IOC report contains a source outside the reviewed tool subject".into(),
            );
        }
    }
    let selected = ioc::select(&report, &frontend::selection(&args.selection))?;
    let authority_root = ctx
        .repo
        .as_ref()
        .map(|repo| repo.root.as_path())
        .unwrap_or(ctx.stores.data.root());
    match (&args.review_record, &args.record) {
        (Some(path), None) => {
            let relative = frontend::relative_record(path)?;
            let mut record = ioc::parse_review(&ioc::scaffold_review(&selected)?)?;
            record.review_by_utc = frontend::deadline_utc(args.review_by.as_deref())?;
            let text = ioc::render_review(&record)?;
            if ctx.repo.is_some() {
                frontend::write_new(
                    authority_root,
                    Path::new(&relative),
                    text.as_bytes(),
                    || ctx.check(),
                )?;
            } else {
                ctx.stores
                    .data
                    .publish_checked(Path::new(&relative), text.as_bytes(), || ctx.check())?;
            }
            Ok(
                json!({"schema_version":1,"operation":"exception","status":"pending-scaffold","review_id":id.to_string(),"subject_id":stored.review.subject_id.to_string(),"record":authority_root.join(&relative),"grant_fragment":{"record_kind":"ioc","schema_version":1,"subject_id":stored.review.subject_id,"policy_sha256":base,"record":relative,"record_sha256":"PENDING: derive after completing the record"},"next_action":"Complete the review, then rerun tool exception with --record at this authority-relative path. No policy authority was written."}),
            )
        }
        (None, Some(path)) => {
            let relative = frontend::relative_record(path)?;
            let bytes = read_record(ctx, Path::new(&relative), &ctx.budget)?;
            let allowance = ioc::Allowance::from_text(std::str::from_utf8(&bytes).map_err(err)?)?;
            frontend::validate_attachment(&selected, &allowance, args.review_by.as_deref(), now)?;
            let current = crate::ioc_intake::revalidate_with(&ctx.stores, &ctx.budget, &selected)?;
            frontend::validate_current_selection(&selected, &current)?;
            let reference = ToolIocRecordReference {
                record_kind: "ioc".into(),
                schema_version: 1,
                subject_id: stored.review.subject_id.clone(),
                policy_sha256: base.clone(),
                record: relative.clone(),
                record_sha256: ioc::digest(&bytes),
            };
            let reference_bytes = serde_json::to_vec(&reference).map_err(err)?;
            let reference_name = format!("ioc-grant-{}.json", ioc::digest(&reference_bytes));
            let reference_path = Path::new(&relative)
                .parent()
                .unwrap_or(Path::new(""))
                .join(reference_name);
            let config = super::policy::configuration(ctx)?;
            for path in &config.tools.exception_records {
                let old = read_record(ctx, Path::new(path), &ctx.budget)?;
                if let Ok(previous) = serde_json::from_slice::<ToolIocRecordReference>(&old)
                    && previous.record == relative
                    && previous.subject_id == reference.subject_id
                    && previous.record_sha256 != reference.record_sha256
                {
                    return Err("this tool record has an older authority reference; review and remove that explicit reference before publishing its changed bytes".into());
                }
            }
            let config_path = if ctx.repo.is_some() {
                Path::new("barbican.toml")
            } else {
                Path::new("cargo-tools/v1/policy.toml")
            };
            let existing = if let Some(repo) = &ctx.repo {
                crate::verified_source::read_optional(&repo.root, config_path, &ctx.budget)?
            } else {
                ctx.stores
                    .data
                    .read_optional(config_path, MAX_RECORD_BYTES as u64)?
                    .map(|file| file.bytes().to_vec())
            };
            let text = std::str::from_utf8(existing.as_deref().unwrap_or(b"")).map_err(err)?;
            let next = barbican::append_tool_exception_record(
                text,
                reference_path
                    .to_str()
                    .ok_or("non-UTF8 tool reference path")?,
            )?;
            ctx.check()?;
            frontend::validate_attachment(
                &selected,
                &allowance,
                args.review_by.as_deref(),
                frontend::current_time(now)?,
            )?;
            if super::policy::origin_binding(ctx)? != (scope.clone(), base.clone())
                || read_record(ctx, Path::new(&relative), &ctx.budget)? != bytes
            {
                return Err("tool IOC authority changed before publication".into());
            }
            if let Some(repo) = &ctx.repo {
                match crate::verified_source::read_optional(
                    &repo.root,
                    &reference_path,
                    &ctx.budget,
                )? {
                    Some(old) if old == reference_bytes => {}
                    Some(_) => return Err("conflicting tool IOC authority reference".into()),
                    None => {
                        frontend::write_new(&repo.root, &reference_path, &reference_bytes, || {
                            ctx.check()
                        })?;
                    }
                }
                if crate::verified_source::read_optional(&repo.root, config_path, &ctx.budget)?
                    != existing
                    || read_record(ctx, Path::new(&relative), &ctx.budget)? != bytes
                {
                    return Err("tool IOC policy changed before publication; unreferenced grant file retained".into());
                }
                ctx.check()?;
                frontend::validate_attachment(
                    &selected,
                    &allowance,
                    args.review_by.as_deref(),
                    frontend::current_time(now)?,
                )?;
                if next.as_bytes() != existing.as_deref().unwrap_or(b"") {
                    crate::commands::ioc::replace_policy(&repo.root.join(config_path), &next)?;
                }
            } else {
                match ctx
                    .stores
                    .data
                    .read_optional(&reference_path, MAX_RECORD_BYTES as u64)?
                {
                    Some(old) if old.bytes() == reference_bytes => {}
                    Some(_) => return Err("conflicting tool IOC authority reference".into()),
                    None => ctx.stores.data.publish_checked(
                        &reference_path,
                        &reference_bytes,
                        || ctx.check(),
                    )?,
                }
                let captured = ctx
                    .stores
                    .data
                    .read_optional(config_path, MAX_RECORD_BYTES as u64)?;
                if captured.as_ref().map(|file| file.bytes()) != existing.as_deref() {
                    return Err("standalone tool policy changed before publication".into());
                }
                let guard = || {
                    ctx.check()?;
                    frontend::validate_attachment(
                        &selected,
                        &allowance,
                        args.review_by.as_deref(),
                        frontend::current_time(now)?,
                    )?;
                    if read_record(ctx, Path::new(&relative), &ctx.budget)? != bytes {
                        return Err("tool IOC record changed before publication".into());
                    }
                    Ok(())
                };
                if let Some(captured) = captured {
                    ctx.stores
                        .data
                        .replace_checked(&captured, next.as_bytes(), guard)?;
                } else {
                    ctx.stores
                        .data
                        .publish_checked(config_path, next.as_bytes(), guard)?;
                }
            }
            Ok(
                json!({"schema_version":1,"operation":"exception","status":"current","review_id":id.to_string(),"subject_id":stored.review.subject_id.to_string(),"record":authority_root.join(relative),"authority_reference":authority_root.join(reference_path),"next_action":"Recollect tool review under the updated policy. This IOC grant does not accept, install or grant repository tool admission."}),
            )
        }
        _ => Err("choose exactly one of --review-record or --record".into()),
    }
}
