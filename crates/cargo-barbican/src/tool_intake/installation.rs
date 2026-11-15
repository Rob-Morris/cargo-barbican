use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use barbican::cargo_tool::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    acceptance, apply_records, check, collection,
    frontend::{Context, StoredReview},
    native, output_files, process,
};
use crate::cli::ToolInstallArgs;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    installation_id: RecordId,
}

fn create_root(path: &Path, uid: u32) -> Result<()> {
    create_directories(path, uid)?;
    if fs::symlink_metadata(path).map_err(|e| e.to_string())?.uid() != uid {
        return Err("installation destination is not owned by the current user".into());
    }
    Ok(())
}

fn create_directories(path: &Path, uid: u32) -> Result<()> {
    output_files::absolute(path)?;
    if !path.try_exists().map_err(|e| e.to_string())? {
        create_directories(path.parent().ok_or("installation root has no parent")?, uid)?;
        fs::DirBuilder::new()
            .mode(0o755)
            .create(path)
            .map_err(|e| e.to_string())?;
    }
    output_files::protected_ancestors(path, uid)?;
    Ok(())
}

fn prior(
    ctx: &Context,
    subject: &Subject,
    root: &Path,
    before: &native::NativeSnapshot,
    replace_existing: bool,
) -> Result<(PriorInstallation, Option<InstalledBinding>, Option<String>)> {
    let root_text = root.to_str().ok_or("installation root is not UTF-8")?;
    let package = subject.root.package();
    let index = apply_records::deployment_path(root_text, &package.name);
    if let Some(saved) = apply_records::read::<Deployment>(&ctx.stores.data, &index)? {
        let binding: InstalledBinding = ctx.stores.read(&saved.installation_id)?;
        let old: Subject = ctx.stores.read(&binding.subject_id)?;
        let old_acceptance: LocalAcceptance = ctx.stores.read(&binding.acceptance_id)?;
        binding
            .applicable(&old, &old_acceptance)
            .map_err(|e| e.to_string())?;
        let observed = check::correspondence(ctx, &binding)?;
        let old_native_names: BTreeSet<_> = before
            .owners
            .iter()
            .filter(|(_, owner)| *owner == &binding.native_owner)
            .map(|(name, _)| name.clone())
            .collect();
        if old_native_names != binding.outputs.iter().map(|o| o.name.clone()).collect() {
            return Err("native owner has outputs outside the prior accepted binding".into());
        }
        return Ok((
            PriorInstallation::Known {
                installation_id: saved.installation_id,
                subject_id: binding.subject_id.clone(),
                outputs: observed,
            },
            Some(binding.clone()),
            Some(binding.native_owner),
        ));
    }
    let mut owners = BTreeSet::new();
    for owner in before.packages.keys() {
        if let Ok(parsed) = parse_native_original_owner(owner)
            && parsed.family == package.family()
        {
            owners.insert(owner.clone());
        }
    }
    for bin in subject.selection.bins.keys() {
        if let Some(owner) = before.owners.get(bin) {
            owners.insert(owner.clone());
        }
    }
    if owners.is_empty() {
        return Ok((PriorInstallation::Absent, None, None));
    }
    if owners.len() != 1 || !replace_existing {
        return Err("occupied native installation has no accepted baseline; a fully reconciled original-source owner requires explicit --replace-existing".into());
    }
    let owner = owners.into_iter().next().ok_or("native owner absent")?;
    let original = parse_native_original_owner(&owner).map_err(|e| e.to_string())?;
    if original.family != package.family() {
        return Err("native output owner is a different original source family".into());
    }
    let old_bins = before
        .owners
        .iter()
        .filter(|(_, candidate)| **candidate == owner)
        .map(|(name, _)| name.clone())
        .collect();
    let old_outputs = check::observations(root, before, &old_bins)?;
    Ok((
        PriorInstallation::TrackedBootstrap {
            old_package: original,
            new_package: package,
            old_outputs,
        },
        None,
        Some(owner),
    ))
}

pub(super) fn guard_independent_evaluator(
    ctx: &Context,
    root: &Path,
    bins: &BTreeSet<String>,
) -> Result<()> {
    let running = fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let evaluator = ctx.evaluator()?;
    for name in bins {
        let output = output_files::output_path(root, name)?;
        if output == running {
            return Err("self-update requires a separate already trusted running Barbican copy outside every affected output".into());
        }
        if [
            &evaluator.cargo.path,
            &evaluator.rustc.path,
            &evaluator.deny.path,
        ]
        .into_iter()
        .chain(evaluator.audit.as_ref().map(|e| &e.path))
        .any(|path| path == &output)
        {
            return Err("installation would replace an active trusted evaluator; select an independent already trusted evaluator copy before applying".into());
        }
    }
    Ok(())
}

pub(super) fn artifact_outputs(
    stdout: &[u8],
    prepared_target: &Path,
    selected: &BTreeSet<String>,
    uid: u32,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<std::collections::BTreeMap<String, output_files::FileObservation>> {
    let mut artifacts = std::collections::BTreeMap::new();
    for line in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 16 * 1024 {
            return Err("native artifact line exceeds supported bound".into());
        }
        let message: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid native artifact protocol: {e}"))?;
        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let target = message
            .get("target")
            .ok_or("native artifact lacks target")?;
        let is_bin = target
            .get("kind")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")));
        if !is_bin {
            continue;
        }
        let name = target
            .get("name")
            .and_then(Value::as_str)
            .ok_or("native binary artifact lacks name")?;
        if !selected.contains(name) {
            return Err("native install built an unselected binary".into());
        }
        let executable = PathBuf::from(
            message
                .get("executable")
                .and_then(Value::as_str)
                .ok_or("native binary artifact lacks executable")?,
        );
        if !executable.starts_with(prepared_target) {
            return Err("native artifact is outside fresh build state".into());
        }
        let observed = output_files::observe(&executable, uid, true, cancelled)?;
        if artifacts.insert(name.into(), observed).is_some() {
            return Err("ambiguous duplicate native binary artifact".into());
        }
    }
    if artifacts.keys().cloned().collect::<BTreeSet<_>>() != *selected {
        return Err(
            "native success did not establish every selected output from the accepted build".into(),
        );
    }
    Ok(artifacts)
}

// Diagnostic persistence is secondary to reporting the native outcome and retained
// state. A broken state directory must not erase the recovery information.
pub(super) fn failure_report(
    store: &crate::private_store::PrivateStore,
    intent_id: &RecordId,
    completed_id: Option<&RecordId>,
    error: &str,
    diagnosis: &Value,
) -> String {
    let status = if completed_id.is_some() {
        "installation-completed-before-late-failure"
    } else {
        "installation-incomplete"
    };
    let completed = completed_id.map(ToString::to_string);
    let primary = format!(
        "{error}; publication state {status}, intent {intent_id}, completed installation {}; retained effects: {diagnosis}",
        completed.as_deref().unwrap_or("none")
    );
    let record = serde_json::json!({"schema_version":1,"status":status,"completed_installation_id":completed_id,"intent_id":intent_id,"error":error,"retained_effects":diagnosis});
    // The suffix is only a local filename, never evidence or an authority time.
    // Clock failure must not prevent reporting the already-observed native result.
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = PathBuf::from(format!(
        "cargo-tools/v1/install-diagnostics/{}-{sequence}.json",
        intent_id.sha256
    ));
    match apply_records::publish(store, &path, &record, || store.recheck()) {
        Ok(()) => format!("{primary}; diagnostic {}", path.display()),
        Err(secondary) => format!(
            "{primary}; diagnostic persistence failed at {}: {secondary}",
            path.display()
        ),
    }
}

pub(super) fn install(
    ctx: &Context,
    stored: &StoredReview,
    args: &ToolInstallArgs,
) -> Result<Value> {
    let uid = ctx.uid()?;
    let started = ctx.now;
    let operation = acceptance::freshness(&args.options, OperationKind::Install, started)?;
    let (refreshed, prepared) =
        collection::refresh_for_install(ctx, stored, args.options.cache_reason.as_deref())?;
    acceptance::eligible(ctx, &refreshed, &operation)?;
    let (_, local, _) = acceptance::load(ctx, &refreshed)?;
    super::repository::check(ctx, &refreshed)?;
    let cached_use_record = apply_records::cached_use(
        &ctx.stores.data,
        &refreshed.review,
        &refreshed
            .evidence
            .observation
            .id()
            .map_err(|error| error.to_string())?,
        &operation,
        || ctx.check(),
    )?;
    let root = native::resolve_root(
        args.root.as_deref(),
        None,
        Some(&ctx.native_root),
        &ctx.original_cargo_home,
        &ctx.current,
    )?;
    let root_text = root
        .to_str()
        .ok_or("installation root is not UTF-8")?
        .to_owned();
    local.permits_root(&root_text).map_err(|e| e.to_string())?;
    create_root(&root, uid)?;
    let root_lock = native::RootLock::acquire(&root, uid)?;
    let before = native::snapshot(&root, uid, ctx.cancelled())?;
    let (prior, known, old_owner) = prior(
        ctx,
        &refreshed.subject,
        &root,
        &before,
        args.replace_existing,
    )?;
    let selected: BTreeSet<String> = refreshed.subject.selection.bins.keys().cloned().collect();
    let old_outputs = prior.outputs();
    let affected = selected
        .union(&old_outputs.iter().map(|o| o.name.clone()).collect())
        .cloned()
        .collect();
    let intent = InstallIntent {
        schema_version: SCHEMA_VERSION,
        subject_id: refreshed.subject.id().map_err(|e| e.to_string())?,
        acceptance_id: local.id().map_err(|e| e.to_string())?,
        root: root_text.clone(),
        prior,
        affected_bins: affected,
    };
    validate_install_intent(
        &intent,
        &refreshed.subject,
        &local,
        known.as_ref(),
        &old_outputs,
        args.replace_existing,
    )
    .map_err(|e| e.to_string())?;
    native::preflight_names(&root, &before, &intent.affected_bins, old_owner.as_deref())?;
    if let Some(binding) = &known
        && binding.subject_id == intent.subject_id
        && binding.acceptance_id == intent.acceptance_id
    {
        binding
            .applicable(&refreshed.subject, &local)
            .map_err(|e| e.to_string())?;
        acceptance::eligible(ctx, &refreshed, &operation)?;
        super::repository::check(ctx, &refreshed)?;
        root_lock.recheck()?;
        return Ok(
            serde_json::json!({"schema_version":1,"status":"installed-complete","cached_use_record":cached_use_record,"installation_id":binding.id().map_err(|e|e.to_string())?.to_string(),"root":root,"unchanged":true,"consumer_selection":"not-requested"}),
        );
    }
    guard_independent_evaluator(ctx, &root, &intent.affected_bins)?;
    if prepared.subject != refreshed.subject {
        return Err(
            "rematerialised source/build identity differs from the accepted subject".into(),
        );
    }
    if refreshed.subject.native_mode != NativeMode::VerifiedPath {
        return Err("accepted native mode is not the qualified public verified-path route".into());
    }
    prepared.recheck(ctx)?;
    acceptance::eligible(ctx, &refreshed, &operation)?;
    acceptance::load(ctx, &refreshed)?;
    super::repository::check(ctx, &refreshed)?;
    if native::snapshot(&root, uid, ctx.cancelled())? != before {
        return Err("native destination changed during preparation".into());
    }
    let intent_id = ctx.stores.write_checked(&intent, || ctx.check())?;
    let bin_paths: Vec<_> = intent
        .affected_bins
        .iter()
        .map(|name| output_files::output_path(&root, name))
        .collect::<Result<_>>()?;
    let on_path = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|entry| entry == root.join("bin")));
    eprintln!(
        "Cargo tool install root: {}\nAffected outputs: {:?}\nNative tracking: verified public path; original provenance retained separately.\nRoot bin directory is on process PATH: {on_path}; publication can immediately change selected use.",
        root.display(),
        bin_paths
    );
    eprintln!(
        "Prior native ownership and output scope: {}",
        serde_json::to_string(&intent.prior).map_err(|e| e.to_string())?
    );
    if matches!(intent.prior, PriorInstallation::TrackedBootstrap { .. }) {
        eprintln!(
            "Baseline unavailable: --replace-existing acknowledges observed native ownership only; no provenance is claimed for the old executable bytes."
        );
    }
    let mut native_args: Vec<OsString> = vec![
        "install".into(),
        "--path".into(),
        prepared
            .manifest
            .parent()
            .ok_or("selected manifest has no parent")?
            .as_os_str()
            .into(),
        "--root".into(),
        root.as_os_str().into(),
        "--frozen".into(),
        "--offline".into(),
        "--message-format=json".into(),
        "--target".into(),
        refreshed.subject.selection.target.clone().into(),
        "--profile".into(),
        match refreshed.subject.selection.profile {
            BuildProfile::Release => "release",
            BuildProfile::Dev => "dev",
        }
        .into(),
    ];
    for bin in &selected {
        native_args.extend(["--bin".into(), bin.into()]);
    }
    if refreshed.subject.selection.all_features {
        native_args.push("--all-features".into());
    }
    if !refreshed.subject.selection.default_features {
        native_args.push("--no-default-features".into());
    }
    if !refreshed.subject.selection.requested_features.is_empty() {
        native_args.extend([
            "--features".into(),
            refreshed
                .subject
                .selection
                .requested_features
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
                .into(),
        ]);
    }
    let environment = prepared.environment(ctx)?;
    let build_budget = process::Budget::native(ctx.budget.cancelled.clone());
    let mut completed_id = None;
    let outcome = (|| {
        prepared.recheck(ctx)?;
        root_lock.recheck()?;
        let output = process::run(
            &ctx.evaluator()?.cargo,
            &native_args,
            &prepared.workspace_root,
            &environment,
            &build_budget,
        )?;
        if !output.status.success() {
            return Err(format!(
                "native Cargo install failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(16 * 1024)])
            ));
        }
        let artifacts = artifact_outputs(
            &output.stdout,
            &prepared.target_dir,
            &selected,
            uid,
            ctx.cancelled(),
        )?;
        prepared.recheck_after_build(ctx)?;
        acceptance::eligible_after_build(ctx, &refreshed, &operation)?;
        if super::policy::capture_after_build(ctx)? != refreshed.policy {
            return Err(
                "originating policy or exception records changed during native installation".into(),
            );
        }
        super::repository::check_after_build(ctx, &refreshed)?;
        root_lock.recheck()?;
        acceptance::load(ctx, &refreshed)?;
        let after = native::snapshot(&root, uid, ctx.cancelled())?;
        native::preserved(&before, &after, &intent.affected_bins, old_owner.as_deref())?;
        let outputs = check::observations(&root, &after, &selected)?;
        for observed in &outputs {
            if artifacts.get(&observed.name).is_none_or(|artifact| {
                artifact.sha256 != observed.sha256 || artifact.mode != observed.mode
            }) {
                return Err(
                    "published output does not match the accepted native build artifact".into(),
                );
            }
        }
        let owners: BTreeSet<_> = outputs
            .iter()
            .map(|output| output.native_owner.clone())
            .collect();
        if owners.len() != 1 {
            return Err("new outputs have conflicting native owners".into());
        }
        let owner = owners
            .into_iter()
            .next()
            .ok_or("new output owner missing")?;
        native::validate_published_owner(
            &after,
            &owner,
            &refreshed.subject,
            prepared
                .manifest
                .parent()
                .ok_or("selected manifest has no parent")?,
            &ctx.evaluator()?.rustc_version,
        )?;
        let mut affected_outputs = std::collections::BTreeMap::new();
        for name in &intent.affected_bins {
            let path = output_files::output_path(&root, name)?;
            let observation = match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
                Ok(_) => check::observations(&root, &after, &BTreeSet::from([name.clone()]))?
                    .into_iter()
                    .next(),
            };
            affected_outputs.insert(name.clone(), observation);
        }
        let native_tracking_sha256 = sha256(
            &canonical_bytes(after.packages.get(&owner).ok_or("native owner missing")?)
                .map_err(|e| e.to_string())?,
        );
        let completion = InstallCompletion {
            native_success: true,
            cancelled: ctx.cancelled().load(Ordering::SeqCst),
            inputs_rechecked: true,
            context_rechecked: true,
            outputs,
            affected_outputs,
            native_owner: owner,
            native_tracking_sha256,
            completed_at_utc: acceptance::now()?,
        };
        let binding = complete_install(&intent, &refreshed.subject, &local, &completion)
            .map_err(|e| e.to_string())?;
        let installation_id = ctx.stores.write_checked(&binding, || {
            prepared.recheck_after_build(ctx)?;
            if super::policy::capture_after_build(ctx)? != refreshed.policy { return Err("originating policy or exception records changed before installation publication".into()); }
            super::repository::check_after_build(ctx, &refreshed)?;
            acceptance::eligible_after_build(ctx, &refreshed, &operation)?;
            acceptance::load(ctx, &refreshed)?;
            check::correspondence(ctx, &binding)?;
            root_lock.recheck()?;
            Ok(())
        })?;
        completed_id = Some(installation_id.clone());
        apply_records::index(
            &ctx.stores.data,
            &apply_records::deployment_path(&root_text, &refreshed.subject.root.package().name),
            &Deployment {
                installation_id: installation_id.clone(),
            },
            || ctx.check_after_build(),
        )?;
        let excluded_outputs: std::collections::BTreeMap<_, _> = completion
            .affected_outputs
            .iter()
            .filter(|(name, _)| !selected.contains(*name))
            .collect();
        let retained: Vec<_> = excluded_outputs
            .iter()
            .filter(|(_, output)| output.is_some())
            .map(|(name, _)| *name)
            .collect();
        let removed: Vec<_> = excluded_outputs
            .iter()
            .filter(|(_, output)| output.is_none())
            .map(|(name, _)| *name)
            .collect();
        Ok(
            serde_json::json!({"schema_version":1,"status":"installed-complete","cached_use_record":cached_use_record,"installation_id":installation_id.to_string(),"intent_id":intent_id.to_string(),"root":root,"outputs":binding.outputs,"retained_excluded_outputs":retained,"removed_excluded_outputs":removed,"excluded_output_observations":excluded_outputs,"consumer_selection":"not-requested","on_process_path":on_path}),
        )
    })();
    match outcome {
        Ok(result) => Ok(result),
        Err(error) => {
            let diagnosis = native::diagnose(&root, &intent.affected_bins, &before, uid);
            Err(failure_report(
                &ctx.stores.data,
                &intent_id,
                completed_id.as_ref(),
                &error,
                &diagnosis,
            ))
        }
    }
}
