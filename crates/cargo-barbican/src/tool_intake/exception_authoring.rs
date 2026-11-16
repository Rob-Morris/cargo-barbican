use super::{
    frontend::{Context, load_review},
    process::{Result, err},
};
use crate::{cli::ToolIocExceptionArgs, commands::ioc as frontend};
use barbican::{BarbicanConfig, OffsetDateTime, cargo_tool::*};
use serde_json::{Value, json};
use std::path::Path;

fn read(ctx: &Context, path: &Path) -> Result<Option<Vec<u8>>> {
    let bytes = if let Some(repo) = &ctx.repo {
        crate::verified_source::read_optional(&repo.root, path, &ctx.budget)?
    } else {
        ctx.stores
            .data
            .read_optional(path, MAX_RECORD_BYTES as u64)?
            .map(|f| f.bytes().to_vec())
    };
    if bytes.as_ref().is_some_and(|b| b.len() > MAX_RECORD_BYTES) {
        return Err("tool exception authority exceeds record bound".into());
    }
    Ok(bytes)
}

pub(crate) fn run(
    ctx: &Context,
    args: &ToolIocExceptionArgs,
    now: OffsetDateTime,
) -> Result<Value> {
    if !args.selection.paths.is_empty() || !args.selection.rules.is_empty() {
        return Err("--path and --rule are IOC-only selectors".into());
    }
    let id: RecordId = args.review_id.parse().map_err(err)?;
    let stored = load_review(ctx, &id)?;
    let (scope, base) = super::policy::origin_binding(ctx)?;
    if stored.policy.scope != scope || stored.policy.policy_sha256 != base {
        return Err("tool review belongs to another current originating policy; recollect it under this authority".into());
    }
    let selected = select_exception_finding(
        &stored.subject,
        &stored.evidence.content,
        args.advisory.as_deref(),
        args.selection.package.as_deref(),
        args.selection.source_id.as_deref(),
    )
    .map_err(err)?;
    let config_path = Path::new(if ctx.repo.is_some() {
        "barbican.toml"
    } else {
        "cargo-tools/v1/policy.toml"
    });
    let config_bytes = read(ctx, config_path)?;
    let config_text = std::str::from_utf8(config_bytes.as_deref().unwrap_or(b"")).map_err(err)?;
    let config = BarbicanConfig::from_toml_str(config_text).map_err(err)?;
    if serde_json::to_vec(&config).map_err(err)?
        != serde_json::to_vec(&super::policy::configuration(ctx)?).map_err(err)?
    {
        return Err("tool origin configuration changed since capture".into());
    }
    let root = ctx
        .repo
        .as_ref()
        .map(|r| r.root.as_path())
        .unwrap_or(ctx.stores.data.root());
    let deadline = frontend::deadline_utc(args.review_by.as_deref())?;
    let (path, scaffold) = match (&args.review_record, &args.record) {
        (Some(path), None) => (path, true),
        (None, Some(path)) => (path, false),
        _ => return Err("choose exactly one of --review-record or --record".into()),
    };
    let relative = frontend::relative_record(path)?;
    let path = Path::new(&relative);
    if scaffold {
        let expiry =
            deadline.ok_or("new age/advisory records require explicit --review-by YYYY-MM-DD")?;
        if expiry <= now.unix_timestamp() {
            return Err("review deadline must be in the future".into());
        }
        let record =
            ToolException::pending(stored.review.subject_id.clone(), base, selected, expiry)
                .map_err(err)?;
        let bytes = serde_json::to_vec_pretty(&record).map_err(err)?;
        let guard = || {
            ctx.check()?;
            if expiry <= frontend::current_time(now)?.unix_timestamp()
                || read(ctx, config_path)? != config_bytes
                || super::policy::origin_binding(ctx)?
                    != (scope.clone(), record.policy_sha256.clone())
            {
                return Err("tool policy or deadline changed before scaffolding".into());
            }
            Ok(())
        };
        if let Some(repo) = &ctx.repo {
            frontend::write_new(&repo.root, path, &bytes, guard)?;
        } else {
            ctx.stores.data.publish_checked(path, &bytes, guard)?;
        }
        let kind = args
            .advisory
            .as_ref()
            .map(|a| format!("--advisory {a}"))
            .unwrap_or("--age".into());
        let source = barbican::ioc::Source::from(&selected.package).id()?;
        let command = format!(
            "cargo-barbican --data-dir '{}' --cache-dir '{}' {}tool exception {} {} --package {}@{} --source-id {} --record '{}'{}",
            ctx.stores
                .data
                .root()
                .display()
                .to_string()
                .replace('\'', "'\\''"),
            ctx.stores
                .cache
                .root()
                .display()
                .to_string()
                .replace('\'', "'\\''"),
            ctx.repo
                .as_ref()
                .map(|r| format!(
                    "--repo '{}' ",
                    r.root.display().to_string().replace('\'', "'\\''")
                ))
                .unwrap_or_default(),
            id,
            kind,
            selected.package.name,
            selected.package.version,
            source,
            relative.replace('\'', "'\\''"),
            if ctx.repo.is_none() {
                " --standalone"
            } else {
                ""
            }
        );
        return Ok(
            json!({"schema_version":1,"operation":"exception","status":"pending-scaffold","review_id":id.to_string(),"record":root.join(path),
            "publication_command":command,"next_action":"Complete reviewer and embedded review_record prose. Leave reviewed_at_utc=0 and the digest unchanged; explicit publication derives them. This pending file grants no authority."}),
        );
    }
    let original = read(ctx, path)?.ok_or("tool exception draft missing")?;
    let mut record: ToolException = serde_json::from_slice(&original).map_err(err)?;
    let referenced = config.tools.exception_records.contains(&relative);
    // Capture every live record before normalising a draft: base hashing intentionally excludes references.
    let mut captured = Vec::new();
    if referenced {
        record.validate_authoring(now.unix_timestamp()).map_err(|e| format!("active exception must validate unchanged: {e}; remove its reference, review and re-add explicitly"))?;
    }
    let existing_exceptions = super::policy::load_exceptions(ctx, &config, &base, &ctx.budget)?;
    let mut prospective = existing_exceptions.0.clone();
    for name in &config.tools.exception_records {
        let bytes = read(ctx, Path::new(name))?.ok_or("configured tool exception missing")?;
        captured.push((name, bytes));
    }
    if !referenced {
        record.complete_draft(now.unix_timestamp()).map_err(err)?;
        if !prospective.insert(record.clone()) {
            return Err("duplicate tool exception under another configured path".into());
        }
    }
    let validate = || -> Result<()> {
        ctx.check()?;
        load_review(ctx, &id)?;
        let time = frontend::current_time(now)?.unix_timestamp();
        record.validate_authoring(time).map_err(err)?;
        if deadline.is_some_and(|d| d != record.expires_at_utc)
            || !record
                .applies_to(selected, &stored.review.subject_id, &base, time)
                .map_err(err)?
        {
            return Err(
                "exception does not match selected finding, subject, policy or deadline".into(),
            );
        }
        if super::policy::origin_binding(ctx)? != (scope.clone(), base.clone())
            || read(ctx, config_path)? != config_bytes
        {
            return Err("tool origin policy changed before publication".into());
        }
        if super::policy::load_exceptions(ctx, &config, &base, &ctx.budget)? != existing_exceptions
        {
            return Err("configured exception authority changed before publication".into());
        }
        for (name, bytes) in &captured {
            if read(ctx, Path::new(name))?.as_ref() != Some(bytes) {
                return Err("configured exception changed before publication".into());
            }
        }
        Ok(())
    };
    #[cfg(test)]
    tests::before_write("record");
    validate()?;
    if read(ctx, path)?.as_ref() != Some(&original) {
        return Err("tool exception draft changed before finalisation".into());
    }
    if referenced {
        return Ok(
            json!({"schema_version":1,"operation":"exception","status":"current","record":root.join(path),"next_action":"Existing authority validated unchanged. Recollect tool review before assessment and acceptance."}),
        );
    }
    let next = barbican::append_tool_exception_record(config_text, &relative)?;
    let final_bytes = serde_json::to_vec_pretty(&record).map_err(err)?;
    if final_bytes.len() > MAX_RECORD_BYTES {
        return Err("completed tool exception exceeds record bound".into());
    }
    if final_bytes != original {
        if let Some(repo) = &ctx.repo {
            validate()?;
            if read(ctx, path)?.as_ref() != Some(&original) {
                return Err("tool exception draft changed before finalisation".into());
            }
            frontend::replace_policy(
                &repo.root.join(path),
                std::str::from_utf8(&final_bytes).map_err(err)?,
            )?;
        } else {
            let previous = ctx.stores.data.read(path, MAX_RECORD_BYTES as u64)?;
            if previous.bytes() != original {
                return Err("tool exception draft changed before finalisation".into());
            }
            ctx.stores
                .data
                .replace_checked(&previous, &final_bytes, validate)?;
        }
    }
    let publish = || -> Result<()> {
        validate()?;
        if read(ctx, path)?.as_ref() != Some(&final_bytes) {
            return Err("completed tool exception changed before publication".into());
        }
        Ok(())
    };
    #[cfg(test)]
    tests::before_write("config");
    let result = (|| {
        publish()?;
        if let Some(repo) = &ctx.repo {
            frontend::replace_policy(&repo.root.join(config_path), &next)
        } else {
            let previous = ctx
                .stores
                .data
                .read_optional(config_path, MAX_RECORD_BYTES as u64)?;
            if previous.as_ref().map(|p| p.bytes()) != config_bytes.as_deref() {
                return Err("tool policy changed before publication".into());
            }
            match previous {
                Some(previous) => {
                    ctx.stores
                        .data
                        .replace_checked(&previous, next.as_bytes(), publish)
                }
                None => ctx
                    .stores
                    .data
                    .publish_checked(config_path, next.as_bytes(), publish),
            }
        }
    })();
    result.map_err(|e: String| {
        format!(
            "{e}; completed unreferenced record retained at {}",
            root.join(path).display()
        )
    })?;
    Ok(
        json!({"schema_version":1,"operation":"exception","status":"current","review_id":id.to_string(),"record":root.join(path),
        "next_action":"Recollect tool review under the updated policy, complete assessment and accept. This exception does not install or grant repository admission."}),
    )
}

#[cfg(test)]
#[path = "exception_authoring_tests.rs"]
mod tests;
