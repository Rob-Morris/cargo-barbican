use crate::private_store::PrivateStore;
use barbican::cargo_tool::{MAX_RECORD_BYTES, RecordId};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

pub(super) fn read<T: DeserializeOwned>(store: &PrivateStore, path: &Path) -> Result<Option<T>> {
    store
        .read_optional(path, MAX_RECORD_BYTES as u64)?
        .map(|captured| {
            serde_json::from_slice(captured.bytes())
                .map_err(|e| format!("invalid local tool lifecycle record: {e}"))
        })
        .transpose()
}

pub(super) fn publish<T: Serialize>(
    store: &PrivateStore,
    path: &Path,
    record: &T,
    check: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let bytes = barbican::cargo_tool::canonical_bytes(record).map_err(|e| e.to_string())?;
    if let Some(old) = store.read_optional(path, MAX_RECORD_BYTES as u64)? {
        if old.bytes() == bytes {
            check()?;
            return store.check_capture(&old);
        }
        return Err(
            "immutable tool lifecycle record already exists with different contents".into(),
        );
    }
    store.publish_checked(path, &bytes, check)
}

pub(super) fn index<T: Serialize>(
    store: &PrivateStore,
    path: &Path,
    record: &T,
    check: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let bytes = barbican::cargo_tool::canonical_bytes(record).map_err(|e| e.to_string())?;
    match store.read_optional(path, MAX_RECORD_BYTES as u64)? {
        Some(old) => store.replace_checked(&old, &bytes, check),
        None => store.publish_checked(path, &bytes, check),
    }
}

pub(super) fn acceptance_path(review: &RecordId) -> PathBuf {
    PathBuf::from(format!("cargo-tools/v1/authority/{}.json", review.sha256))
}
pub(super) fn deployment_path(root: &str, package: &str) -> PathBuf {
    let key = barbican::cargo_tool::sha256(format!("{root}\0{package}").as_bytes());
    PathBuf::from(format!("cargo-tools/v1/deployments/{key}.json"))
}

/// Record an explicitly requested use of cached evidence before any grant or build.
/// This is invocation history, not reusable authority or a persisted default mode.
pub(super) fn cached_use(
    store: &PrivateStore,
    review: &barbican::cargo_tool::Review,
    observation: &RecordId,
    intent: &barbican::cargo_tool::OperationIntent,
    check: impl FnOnce() -> Result<()>,
) -> Result<Option<PathBuf>> {
    use barbican::cargo_tool::{FreshnessIntent, RecordKind, ToolRecord, canonical_bytes, sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let FreshnessIntent::Cached { reason } = &intent.freshness else {
        return Ok(None);
    };
    if reason.trim().is_empty() {
        return Err("cached-use record requires an explicit nonempty reason".into());
    }
    review.validate().map_err(|error| error.to_string())?;
    observation
        .require_kind(RecordKind::Observation)
        .map_err(|error| error.to_string())?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    let record = serde_json::json!({
        "schema_version":1,
        "status":"requested",
        "freshness_mode":"cached",
        "operation":intent.operation,
        "review_id":review.id().map_err(|error| error.to_string())?,
        "subject_id":review.subject_id,
        "policy_id":review.policy_id,
        "evidence_content_id":review.evidence_content_id,
        "observation_id":observation,
        "cache_reason":reason,
        "requested_at_utc":time.as_secs(),
        "invocation":format!("{}-{}-{}", std::process::id(), time.as_nanos(), NEXT.fetch_add(1, Ordering::Relaxed)),
    });
    let digest = sha256(&canonical_bytes(&record).map_err(|error| error.to_string())?);
    let path = PathBuf::from(format!("cargo-tools/v1/cached-uses/{digest}.json"));
    publish(store, &path, &record, check)?;
    Ok(Some(store.root().join(path)))
}
