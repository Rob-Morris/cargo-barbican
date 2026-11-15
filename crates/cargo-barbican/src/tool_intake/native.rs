use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::output_files::{self, FileObservation};

type Result<T> = std::result::Result<T, String>;

pub(super) struct RootLock {
    root: PathBuf,
    path: PathBuf,
    uid: u32,
    root_identity: (u64, u64),
    file_identity: (u64, u64),
    bytes: Vec<u8>,
}
impl RootLock {
    pub fn acquire(root: &Path, uid: u32) -> Result<Self> {
        output_files::protected_ancestors(root, uid)?;
        let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        let path = root.join(".barbican-cargo-tool-operation.lock");
        let bytes = format!("Cargo tool installation in progress; pid {}. Remove this lock only after independently confirming its operation has ended and reconciling retained installation effects.\n", std::process::id()).into_bytes();
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|e|format!("cannot acquire ordinary-root Cargo tool operation lock {}: {e}; an existing lock requires explicit recovery, never automatic deletion", path.display()))?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let lock = file.metadata().map_err(|e| e.to_string())?;
        Ok(Self {
            root: root.into(),
            path,
            uid,
            root_identity: (metadata.dev(), metadata.ino()),
            file_identity: (lock.dev(), lock.ino()),
            bytes,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        output_files::protected_ancestors(&self.root, self.uid)?;
        let root = fs::symlink_metadata(&self.root).map_err(|e| e.to_string())?;
        let lock = fs::symlink_metadata(&self.path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        fs::File::open(&self.path)
            .map_err(|e| e.to_string())?
            .take(self.bytes.len() as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if (root.dev(), root.ino()) != self.root_identity
            || !lock.is_file()
            || (lock.dev(), lock.ino()) != self.file_identity
            || lock.uid() != self.uid
            || lock.mode() & 0o777 != 0o600
            || lock.nlink() != 1
            || lock.len() != self.bytes.len() as u64
            || bytes != self.bytes
        {
            return Err("installation root or cooperating-writer lock changed".into());
        }
        Ok(())
    }
}
impl Drop for RootLock {
    fn drop(&mut self) {
        if self.recheck().is_ok() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn validate_published_owner(
    state: &NativeSnapshot,
    owner: &str,
    subject: &barbican::cargo_tool::Subject,
    source: &Path,
    rustc_version: &str,
) -> Result<()> {
    use barbican::cargo_tool::BuildProfile;
    let package = subject.root.package();
    let prefix = format!("{} {} (path+file://", package.name, package.version);
    let path = owner
        .strip_prefix(&prefix)
        .and_then(|text| text.strip_suffix(')'))
        .ok_or("published native owner does not identify the selected package and verified path")?;
    if path.contains(['?', '#']) {
        return Err("native path ownership has unsupported URL semantics".into());
    }
    let mut decoded = Vec::new();
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let digits = bytes
                .get(index + 1..index + 3)
                .ok_or("truncated native path URL")?;
            let digits = std::str::from_utf8(digits).map_err(|e| e.to_string())?;
            decoded.push(u8::from_str_radix(digits, 16).map_err(|e| e.to_string())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    if std::str::from_utf8(&decoded).map_err(|e| e.to_string())?
        != source.to_str().ok_or("source path is not UTF-8")?
    {
        return Err("native owner records another source path".into());
    }
    let record = state
        .packages
        .get(owner)
        .ok_or("published native owner missing")?;
    let features: BTreeSet<String> = record
        .get("features")
        .and_then(Value::as_array)
        .ok_or("native feature tracking missing")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("invalid native feature tracking".to_owned())
        })
        .collect::<Result<_>>()?;
    let profile = match subject.selection.profile {
        BuildProfile::Release => "release",
        BuildProfile::Dev => "dev",
    };
    if features != subject.selection.requested_features
        || record.get("all_features").and_then(Value::as_bool)
            != Some(subject.selection.all_features)
        || record.get("no_default_features").and_then(Value::as_bool)
            != Some(!subject.selection.default_features)
        || record.get("profile").and_then(Value::as_str) != Some(profile)
        || record.get("target").and_then(Value::as_str) != Some(subject.selection.target.as_str())
        || record.get("rustc").and_then(Value::as_str) != Some(rustc_version)
    {
        return Err(
            "native selection/compiler bookkeeping differs from accepted build context".into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeSnapshot {
    pub packages: BTreeMap<String, Value>,
    pub owners: BTreeMap<String, String>,
    pub outputs: BTreeMap<String, FileObservation>,
}

fn optional_record(path: &Path, uid: u32, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => output_files::read_record(path, uid, 8 * 1024 * 1024, cancelled).map(Some),
    }
}

pub(super) fn snapshot(root: &Path, uid: u32, cancelled: &AtomicBool) -> Result<NativeSnapshot> {
    snapshot_scope(root, uid, cancelled, None)
}

pub(super) fn snapshot_scope(
    root: &Path,
    uid: u32,
    cancelled: &AtomicBool,
    selected: Option<&BTreeSet<String>>,
) -> Result<NativeSnapshot> {
    output_files::protected_ancestors(root, uid)?;
    let v1 = optional_record(&root.join(".crates.toml"), uid, cancelled)?;
    let v2 = optional_record(&root.join(".crates2.json"), uid, cancelled)?;
    let (v1, v2) = match (v1, v2) {
        (None, None) => {
            return Ok(NativeSnapshot {
                packages: BTreeMap::new(),
                owners: BTreeMap::new(),
                outputs: BTreeMap::new(),
            });
        }
        (Some(a), Some(b)) => (a, b),
        _ => {
            return Err(
                "native Cargo tracking is incomplete; both tracking records are required".into(),
            );
        }
    };
    let v1 =
        barbican::cargo_tool::parse_native_v1(std::str::from_utf8(&v1).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let v2: Value =
        serde_json::from_slice(&v2).map_err(|e| format!("invalid native Cargo tracking: {e}"))?;
    let top = v2.as_object().ok_or("native tracking must be an object")?;
    if top.len() != 1 {
        return Err("unqualified native Cargo tracking schema".into());
    }
    let installs = top
        .get("installs")
        .and_then(Value::as_object)
        .ok_or("native Cargo tracking has no installs map")?;
    if installs.len() != v1.len() {
        return Err("native Cargo tracking records disagree".into());
    }
    let mut result = NativeSnapshot {
        packages: BTreeMap::new(),
        owners: BTreeMap::new(),
        outputs: BTreeMap::new(),
    };
    for (owner, record) in installs {
        let bins = record
            .get("bins")
            .and_then(Value::as_array)
            .ok_or("native owner has no binary list")?;
        let mut observed = BTreeSet::new();
        for bin in bins {
            let bin = bin.as_str().ok_or("native binary name is not text")?;
            let path = output_files::output_path(root, bin)?;
            if !observed.insert(bin.to_owned())
                || result
                    .owners
                    .insert(bin.to_owned(), owner.clone())
                    .is_some()
            {
                return Err("duplicate native binary ownership".into());
            }
            if selected.is_none_or(|names| names.contains(bin)) {
                result.outputs.insert(
                    bin.into(),
                    output_files::observe(&path, uid, true, cancelled)?,
                );
            }
        }
        let expected: BTreeSet<String> = v1
            .get(owner)
            .ok_or("native owner absent from legacy tracking")?
            .iter()
            .cloned()
            .collect();
        if expected != observed || observed.is_empty() {
            return Err("native Cargo tracking binary lists disagree".into());
        }
        result.packages.insert(owner.clone(), record.clone());
    }
    Ok(result)
}

pub(super) fn preflight_names(
    root: &Path,
    snapshot: &NativeSnapshot,
    bins: &BTreeSet<String>,
    permitted_owner: Option<&str>,
) -> Result<()> {
    for bin in bins {
        let path = output_files::output_path(root, bin)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if snapshot.owners.contains_key(bin) {
                    return Err(format!("tracked output is missing: {bin}"));
                }
            }
            Err(e) => return Err(e.to_string()),
            Ok(_) => {
                let owner = snapshot
                    .owners
                    .get(bin)
                    .ok_or_else(|| format!("unmanaged output collision: {bin}"))?;
                if Some(owner.as_str()) != permitted_owner {
                    return Err(format!("output belongs to another native owner: {bin}"));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn preserved(
    before: &NativeSnapshot,
    after: &NativeSnapshot,
    affected: &BTreeSet<String>,
    old_owner: Option<&str>,
) -> Result<()> {
    for (name, observation) in &before.outputs {
        if !affected.contains(name)
            && (after.outputs.get(name) != Some(observation)
                || after.owners.get(name) != before.owners.get(name))
        {
            return Err(format!("unrelated native output changed: {name}"));
        }
    }
    for (owner, record) in &before.packages {
        if Some(owner.as_str()) != old_owner && after.packages.get(owner) != Some(record) {
            return Err(format!("unrelated native tracking changed: {owner}"));
        }
    }
    Ok(())
}

pub(super) fn diagnose(
    root: &Path,
    names: &BTreeSet<String>,
    before: &NativeSnapshot,
    uid: u32,
) -> Value {
    // A cancellation must prevent authority publication without suppressing retained-effect diagnosis.
    let diagnostic_cancel = AtomicBool::new(false);
    let mut outputs = serde_json::Map::new();
    for name in names {
        let observation = output_files::output_path(root, name)
            .and_then(|path| output_files::observe(&path, uid, true, &diagnostic_cancel));
        let value = match observation {
            Ok(ref now) if before.outputs.get(name) == Some(now) => {
                serde_json::json!({"state":"old-unchanged","observation":now})
            }
            Ok(now) => serde_json::json!({"state":"changed-or-new-unbound","observation":now}),
            Err(error) => {
                serde_json::json!({"state":"missing-wrong-type-or-conflicting","error":error})
            }
        };
        outputs.insert(name.clone(), value);
    }
    let tracking = match snapshot(root, uid, &diagnostic_cancel) {
        Ok(state) => serde_json::json!({"state":"reconciled","native":state}),
        Err(error) => serde_json::json!({"state":"incomplete-or-conflicting","error":error}),
    };
    serde_json::json!({"outputs":outputs,"tracking":tracking,"recovery":"Preserve current files and prior history. Reconcile every affected output and native owner before a fresh eligible retry; no automatic rollback was attempted."})
}

pub(super) fn resolve_root(
    explicit: Option<&Path>,
    environment: Option<&Path>,
    configured: Option<&Path>,
    cargo_home: &Path,
    cwd: &Path,
) -> Result<PathBuf> {
    let selected = explicit
        .or(environment)
        .or(configured)
        .unwrap_or(cargo_home);
    let absolute = if selected.is_absolute() {
        selected.to_owned()
    } else {
        cwd.join(selected)
    };
    output_files::absolute(&absolute)?;
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.try_exists().map_err(|e| e.to_string())? {
        missing.push(
            ancestor
                .file_name()
                .ok_or("installation root has no ancestor")?
                .to_owned(),
        );
        ancestor = ancestor.parent().ok_or("installation root has no parent")?;
    }
    let mut resolved = fs::canonicalize(ancestor).map_err(|e| e.to_string())?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}
