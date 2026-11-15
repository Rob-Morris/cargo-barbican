use super::{
    acceptance, apply_records, check, collection, consumer,
    frontend::{self, Context},
    output_files,
};
use crate::cli::ToolAdmissionArgs;
use barbican::cargo_tool::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerGrant {
    schema_version: u32,
    installation_id: RecordId,
    acceptance_id: RecordId,
    policy_id: RecordId,
    repository_admission: Option<RecordId>,
    context: ConsumerContext,
    selection: ConsumerSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerContext {
    cwd: PathBuf,
    governance_root: Option<PathBuf>,
    admission_scope: Option<String>,
}
impl ConsumerContext {
    fn capture(ctx: &Context) -> Result<Self> {
        ctx.check_consumer_context()?;
        let cwd = std::fs::canonicalize(&ctx.current).map_err(|e| e.to_string())?;
        let actual = super::context::RepoContext::capture_consumer(&cwd, None, false, &ctx.budget)?;
        Ok(Self {
            cwd,
            governance_root: actual.as_ref().map(|repo| repo.root.clone()),
            admission_scope: actual.and_then(|repo| repo.config.tools.admission_scope),
        })
    }
}

fn consumer_operation(previous: Option<&ConsumerGrant>, current: &ConsumerGrant) -> OperationKind {
    if previous == Some(current) {
        OperationKind::ContinuingUse
    } else {
        OperationKind::NewAdmission
    }
}

fn text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "consumer path is not UTF-8".into())
}

fn selection(
    ctx: &Context,
    subject: &Subject,
    args: &ToolAdmissionArgs,
) -> Result<(consumer::ConsumerSnapshot, ConsumerSelection)> {
    if usize::from(args.executable.is_some())
        + usize::from(args.lookup_path)
        + usize::from(args.cargo_subcommand.is_some())
        != 1
    {
        return Err("exactly one actual consumer selector is required".into());
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let cwd = std::fs::canonicalize(&ctx.current).map_err(|e| e.to_string())?;
    let entries = || {
        std::env::split_paths(&path)
            .map(|entry| text(&entry))
            .collect::<Result<Vec<_>>>()
    };
    if let Some(executable) = &args.executable {
        let snapshot = consumer::direct(executable, &cwd)?;
        let selection = ConsumerSelection::Direct {
            executable: text(&snapshot.selected)?,
        };
        return Ok((snapshot, selection));
    }
    if args.lookup_path {
        let snapshot = consumer::lookup(&args.bin, &path, &cwd, &ctx.budget)?;
        let selection = ConsumerSelection::ProcessPath {
            path_entries: entries()?,
            selected_executable: text(&snapshot.selected)?,
        };
        return Ok((snapshot, selection));
    }
    let command = args
        .cargo_subcommand
        .as_deref()
        .ok_or("Cargo subcommand selector missing")?;
    let evaluator = ctx.evaluator()?;
    evaluator.cargo.recheck(&ctx.budget)?;
    if evaluator.cargo.sha256 != subject.evaluator.cargo.sha256 {
        return Err(
            "actual trusted Cargo differs from the qualified accepted Cargo identity".into(),
        );
    }
    let actual_cargo =
        consumer::trusted_cargo(&path, &evaluator.cargo.sha256, ctx.uid()?, &ctx.budget)?;
    let mut snapshot = consumer::cargo(
        command,
        &args.bin,
        &path,
        &cwd,
        &ctx.original_cargo_home,
        ctx.uid()?,
        &ctx.budget,
    )?;
    snapshot.cargo_executable = Some(actual_cargo.clone());
    let selection = ConsumerSelection::CargoExternal {
        subcommand: command.into(),
        cargo: Box::new(subject.evaluator.cargo.clone()),
        cargo_path: text(&actual_cargo.0)?,
        cwd: text(&cwd)?,
        cargo_home: text(&ctx.original_cargo_home)?,
        config_sha256: sha256(
            &canonical_bytes(&snapshot.configurations).map_err(|e| e.to_string())?,
        ),
        path_entries: entries()?,
        selected_executable: text(&snapshot.selected)?,
    };
    Ok((snapshot, selection))
}

pub(super) fn admission_check(
    ctx: &Context,
    id: &RecordId,
    args: &ToolAdmissionArgs,
) -> Result<Value> {
    ctx.check_consumer_context()?;
    let started = ctx.now;
    let binding: InstalledBinding = ctx.stores.read(id)?;
    check::correspondence(ctx, &binding)?;
    let stored = frontend::load_review(ctx, &binding.review_id)?;
    collection::validate_current(ctx, &stored)?;
    let (_, local, _) = acceptance::load(ctx, &stored)?;
    binding
        .applicable(&stored.subject, &local)
        .map_err(|e| e.to_string())?;
    let (consumer_before, selected) = selection(ctx, &stored.subject, args)?;
    selected.validate().map_err(|e| e.to_string())?;
    let expected = binding
        .outputs
        .iter()
        .find(|output| output.name == args.bin)
        .ok_or("binary is outside the accepted installation")?;
    if selected.selected_path() != expected.path {
        return Err(format!(
            "consumer selects {} instead of accepted {}",
            selected.selected_path(),
            expected.path
        ));
    }
    let observation =
        output_files::observe(&consumer_before.selected, ctx.uid()?, true, ctx.cancelled())?;
    output_files::require_native_executable(&consumer_before.selected)?;
    let observed = OutputObservation {
        name: args.bin.clone(),
        path: text(&consumer_before.selected)?,
        mode: observation.mode,
        sha256: observation.sha256,
        native_owner: expected.native_owner.clone(),
    };
    check_consumer_selection(&binding, &args.bin, &selected, &observed)
        .map_err(|e| e.to_string())?;
    let repo_admission = super::repository::check(ctx, &stored)?;
    let grant = ConsumerGrant {
        schema_version: SCHEMA_VERSION,
        installation_id: id.clone(),
        acceptance_id: local.id().map_err(|e| e.to_string())?,
        policy_id: stored.policy.id().map_err(|e| e.to_string())?,
        repository_admission: repo_admission,
        context: ConsumerContext::capture(ctx)?,
        selection: selected.clone(),
    };
    let grant_key = sha256(&canonical_bytes(&grant).map_err(|e| e.to_string())?);
    let path = PathBuf::from(format!("cargo-tools/v1/consumers/{grant_key}.json"));
    let previous: Option<ConsumerGrant> = apply_records::read(&ctx.stores.data, &path)?;
    let operation_kind = consumer_operation(previous.as_ref(), &grant);
    let continuing = operation_kind == OperationKind::ContinuingUse;
    let operation = acceptance::freshness(&args.options, operation_kind, started)?;
    let current = if continuing {
        stored
    } else {
        collection::refresh(ctx, &stored, args.options.cache_reason.as_deref())?
    };
    acceptance::eligible(ctx, &current, &operation)?;
    acceptance::load(ctx, &current)?;
    super::repository::check(ctx, &current)?;
    check::correspondence(ctx, &binding)?;
    let (consumer_after, selected_after) = selection(ctx, &current.subject, args)?;
    if consumer_after != consumer_before || selected_after != selected {
        return Err("actual consumer selection changed during admission".into());
    }
    let cached_use_record = apply_records::cached_use(
        &ctx.stores.data,
        &current.review,
        &current
            .evidence
            .observation
            .id()
            .map_err(|error| error.to_string())?,
        &operation,
        || ctx.check(),
    )?;
    apply_records::publish(&ctx.stores.data, &path, &grant, || {
        ctx.check_consumer_context()?;
        if ConsumerContext::capture(ctx)? != grant.context {
            return Err(
                "actual consumer governance or working directory changed during admission".into(),
            );
        }
        collection::validate_current(ctx, &current)?;
        acceptance::eligible(ctx, &current, &operation)?;
        super::repository::check(ctx, &current)?;
        check::correspondence(ctx, &binding)?;
        let (latest_snapshot, latest_selection) = selection(ctx, &current.subject, args)?;
        if latest_snapshot != consumer_before || latest_selection != selected {
            return Err("actual consumer selection changed before admission publication".into());
        }
        Ok(())
    })?;
    Ok(
        serde_json::json!({"schema_version":1,"status":"consumer-admission","cached_use_record":cached_use_record,"installation_id":id.to_string(),"bin":args.bin,"selection":selected,"continuing_unchanged_context":continuing,"repository_admission":grant.repository_admission.map(|id|id.to_string()),"scope":"Current static process selection; no interactive shell state or future filesystem changes are certified."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_cwd_or_actual_governance_requires_new_admission_for_direct_and_path() {
        let id = |kind| RecordId {
            kind,
            schema_version: SCHEMA_VERSION,
            sha256: sha256(b"accepted fixture"),
        };
        for selection in [
            ConsumerSelection::Direct {
                executable: "/owned/bin/tool".into(),
            },
            ConsumerSelection::ProcessPath {
                path_entries: vec!["/owned/bin".into()],
                selected_executable: "/owned/bin/tool".into(),
            },
        ] {
            let original = ConsumerGrant {
                schema_version: SCHEMA_VERSION,
                installation_id: id(RecordKind::InstalledBinding),
                acceptance_id: id(RecordKind::LocalAcceptance),
                policy_id: id(RecordKind::OriginPolicy),
                repository_admission: None,
                context: ConsumerContext {
                    cwd: "/consumer/a".into(),
                    governance_root: None,
                    admission_scope: None,
                },
                selection,
            };
            assert_eq!(
                consumer_operation(Some(&original), &original),
                OperationKind::ContinuingUse
            );
            let mut moved = original.clone();
            moved.context.cwd = "/consumer/b".into();
            assert_eq!(
                consumer_operation(Some(&original), &moved),
                OperationKind::NewAdmission
            );
            assert_ne!(
                sha256(&canonical_bytes(&original).unwrap()),
                sha256(&canonical_bytes(&moved).unwrap())
            );
            let mut governed = original.clone();
            governed.context.governance_root = Some("/consumer".into());
            governed.context.admission_scope = Some("actual-consumer".into());
            assert_eq!(
                consumer_operation(Some(&original), &governed),
                OperationKind::NewAdmission
            );
        }
    }
}
