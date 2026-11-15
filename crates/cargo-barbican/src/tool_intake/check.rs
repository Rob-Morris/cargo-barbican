use super::{frontend::Context, native};
use barbican::cargo_tool::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

type Result<T> = std::result::Result<T, String>;

pub(super) fn observations(
    root: &Path,
    state: &native::NativeSnapshot,
    bins: &BTreeSet<String>,
) -> Result<BTreeSet<OutputObservation>> {
    bins.iter()
        .map(|name| {
            let file = state
                .outputs
                .get(name)
                .ok_or_else(|| format!("selected native output missing: {name}"))?;
            let owner = state
                .owners
                .get(name)
                .ok_or_else(|| format!("selected output has no native owner: {name}"))?;
            let path = super::output_files::output_path(root, name)?;
            Ok(OutputObservation {
                name: name.clone(),
                path: path.to_str().ok_or("output path is not UTF-8")?.into(),
                mode: file.mode,
                sha256: file.sha256.clone(),
                native_owner: owner.clone(),
            })
        })
        .collect()
}

pub(super) fn correspondence(
    ctx: &Context,
    binding: &InstalledBinding,
) -> Result<BTreeSet<OutputObservation>> {
    binding.validate().map_err(|e| e.to_string())?;
    if binding.local_user != ctx.local_user()? {
        return Err("installation belongs to another local user".into());
    }
    let bins = binding
        .outputs
        .iter()
        .map(|output| output.name.clone())
        .collect();
    let state = native::snapshot_scope(
        Path::new(&binding.root),
        ctx.uid()?,
        ctx.cancelled(),
        Some(&bins),
    )?;
    let observed = observations(Path::new(&binding.root), &state, &bins)?;
    let native_tracking = state
        .packages
        .get(&binding.native_owner)
        .ok_or("recorded native owner is missing")?;
    let native_tracking_sha256 =
        sha256(&canonical_bytes(native_tracking).map_err(|e| e.to_string())?);
    binding
        .corresponds(&observed, &binding.native_owner, &native_tracking_sha256)
        .map_err(|e| e.to_string())?;
    super::output_files::check_cancelled(ctx.cancelled())?;
    ctx.stores.data.recheck()?;
    Ok(observed)
}

pub(super) fn installation_check(ctx: &Context, id: &RecordId) -> Result<Value> {
    let binding: InstalledBinding = ctx.stores.read(id)?;
    let outputs = correspondence(ctx, &binding)?;
    Ok(
        serde_json::json!({"schema_version":1,"status":"local-correspondence","installation_id":id.to_string(),"root":binding.root,"outputs":outputs,"scope":"Static correspondence at the recorded root; consumer selection and current admission are separate checks."}),
    )
}
