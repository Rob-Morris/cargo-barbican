use crate::controlled_process::{Result, err};
use crate::private_store::PrivateStore;
use barbican::cargo_tool::{self, KnowledgeEntry, RecordId, SourceKnowledge, ToolRecord};
use std::path::{Path, PathBuf};

pub(crate) struct Stores {
    pub data: PrivateStore,
    pub cache: PrivateStore,
    _operation: OperationLock,
}
impl Stores {
    pub fn open(
        current: &Path,
        repo: Option<&Path>,
        data: Option<&Path>,
        cache: Option<&Path>,
    ) -> Result<Self> {
        let home = crate::controlled_process::absolute_home()?;
        let absolute = |path: &Path| {
            if path.is_absolute() {
                path.to_owned()
            } else {
                current.join(path)
            }
        };
        let default_data = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/cargo-barbican")
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or(home.join(".local/share"))
                .join("cargo-barbican")
        };
        let default_cache = if cfg!(target_os = "macos") {
            home.join("Library/Caches/cargo-barbican")
        } else {
            std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .unwrap_or(home.join(".cache"))
                .join("cargo-barbican")
        };
        let data_path = data.map(absolute).unwrap_or(default_data);
        let cache_path = cache.map(absolute).unwrap_or(default_cache);
        let mut forbidden: Vec<&Path> = repo.into_iter().collect();
        let data = PrivateStore::open(&data_path, &forbidden)?;
        forbidden.push(data.root());
        let cache = PrivateStore::open(&cache_path, &forbidden)?;
        let relative = Path::new("cargo-tools/v1/operation.lock");
        data.publish(relative,format!("pid={}\n",std::process::id()).as_bytes()).map_err(|error|format!("tool operation lock unavailable: {error}; if a previous process was forcibly stopped, confirm it is no longer active before removing the private cargo-tools/v1/operation.lock"))?;
        let path = data.root().join(relative);
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&path).map_err(err)?;
        let operation = OperationLock {
            path,
            identity: (metadata.dev(), metadata.ino()),
        };
        Ok(Self {
            data,
            cache,
            _operation: operation,
        })
    }
    fn record_path(id: &RecordId) -> Result<PathBuf> {
        id.require_kind(id.kind).map_err(err)?;
        let kind = serde_json::to_value(id.kind).map_err(err)?;
        Ok(PathBuf::from(format!(
            "cargo-tools/v1/records/{}/{}.json",
            kind.as_str().ok_or("invalid record kind")?,
            id.sha256
        )))
    }
    pub fn read<T: ToolRecord>(&self, id: &RecordId) -> Result<T> {
        id.require_kind(T::KIND).map_err(err)?;
        let bytes = self
            .data
            .read(&Self::record_path(id)?, cargo_tool::MAX_RECORD_BYTES as u64)?;
        let record: T = cargo_tool::parse_record(bytes.bytes()).map_err(err)?;
        if record.id().map_err(err)? != *id {
            return Err("tool record content does not match ID".into());
        }
        Ok(record)
    }
    pub fn write<T: ToolRecord>(&self, record: &T) -> Result<RecordId> {
        self.write_checked(record, || Ok(()))
    }
    pub fn write_checked<T: ToolRecord>(
        &self,
        record: &T,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<RecordId> {
        let id = record.id().map_err(err)?;
        let bytes = cargo_tool::encode_record(record).map_err(err)?;
        let path = Self::record_path(&id)?;
        if let Some(existing) = self
            .data
            .read_optional(&path, cargo_tool::MAX_RECORD_BYTES as u64)?
        {
            if existing.bytes() != bytes {
                return Err("conflicting content-addressed tool record".into());
            }
            check()?;
        } else {
            self.data.publish_checked(&path, &bytes, check)?;
        }
        Ok(id)
    }
    pub fn knowledge(&self) -> Result<SourceKnowledge> {
        self.data
            .read_optional(
                Path::new("cargo-tools/v1/source-knowledge.json"),
                cargo_tool::MAX_RECORD_BYTES as u64,
            )?
            .map(|bytes| cargo_tool::parse_record(bytes.bytes()).map_err(err))
            .transpose()
            .map(|value| value.unwrap_or_default())
    }
    pub fn remember(&self, entry: KnowledgeEntry, now: i64) -> Result<()> {
        self.remember_many(std::iter::once(entry), now)
    }
    pub fn remember_many(
        &self,
        entries: impl IntoIterator<Item = KnowledgeEntry>,
        now: i64,
    ) -> Result<()> {
        let path = Path::new("cargo-tools/v1/source-knowledge.json");
        let previous = self
            .data
            .read_optional(path, cargo_tool::MAX_RECORD_BYTES as u64)?;
        let mut knowledge: SourceKnowledge = previous
            .as_ref()
            .map(|bytes| cargo_tool::parse_record(bytes.bytes()).map_err(err))
            .transpose()?
            .unwrap_or_default();
        let mut observed = Ok(());
        for entry in entries {
            observed = knowledge.remember(entry, now).map_err(err);
            if observed.is_err() {
                break;
            }
        }
        let bytes = cargo_tool::encode_record(&knowledge).map_err(err)?;
        match previous {
            Some(previous) => self.data.replace(&previous, &bytes)?,
            None => self.data.publish(path, &bytes)?,
        }
        observed
    }
    pub fn begin_source(&self, key: &str) -> Result<()> {
        let path = source_pending_path(key);
        if self.data.read_optional(&path, 8192)?.is_none() {
            self.data.publish(&path, key.as_bytes())?;
        }
        Ok(())
    }
    pub fn finish_source(&self, key: &str) -> Result<()> {
        let path = source_pending_path(key);
        if let Some(captured) = self.data.read_optional(&path, 8192)? {
            if captured.bytes() != key.as_bytes() {
                return Err("source-observation barrier identity mismatch".into());
            }
            self.data.check_capture(&captured)?;
            std::fs::remove_file(self.data.root().join(&path)).map_err(err)?;
            self.data.recheck()?;
        }
        Ok(())
    }
    pub fn ensure_source_complete(&self, key: &str) -> Result<()> {
        if self
            .data
            .read_optional(&source_pending_path(key), 8192)?
            .is_some()
        {
            return Err("a relevant source observation is incomplete; fresh complete reconciliation required".into());
        }
        Ok(())
    }
    pub fn ensure_sources_complete(&self, subject: &cargo_tool::Subject) -> Result<()> {
        for package in subject.graph.packages() {
            for key in [
                package_source_observation_key(&package.family(), &package.version)?,
                package_advisory_observation_key(&package)?,
                format!("ioc:{}", barbican::ioc::Source::from(&package).id()?),
            ] {
                if self
                    .data
                    .read_optional(&source_pending_path(&key), 8192)?
                    .is_some()
                {
                    return Err("a relevant source observation was interrupted or could not be saved; fresh complete reconciliation is required before cached or continuing admission".into());
                }
            }
        }
        Ok(())
    }
}
pub(crate) fn package_source_observation_key(
    family: &cargo_tool::PackageFamily,
    version: &str,
) -> Result<String> {
    serde_json::to_string(&("source", family, version)).map_err(err)
}
pub(crate) fn package_advisory_observation_key(
    package: &cargo_tool::PackageIdentity,
) -> Result<String> {
    serde_json::to_string(&("advisories", package)).map_err(err)
}
fn source_pending_path(key: &str) -> PathBuf {
    PathBuf::from(format!(
        "cargo-tools/v1/source-observations/{}.pending",
        cargo_tool::sha256(key.as_bytes())
    ))
}

struct OperationLock {
    path: PathBuf,
    identity: (u64, u64),
}
impl Drop for OperationLock {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.is_file() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbican::cargo_tool::{KnowledgeKey, SecurityStatus, SourceFact, sha256};
    fn stores(stage: &crate::verified_source::Stage) -> Stores {
        Stores::open(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap()
    }
    #[test]
    fn cooperating_operation_lock_cannot_be_overwritten_or_removed_by_failed_opener() {
        let stage = crate::verified_source::Stage::new().unwrap();
        let first = stores(&stage);
        assert!(
            Stores::open(
                &stage.root,
                None,
                Some(first.data.root()),
                Some(first.cache.root())
            )
            .is_err()
        );
        assert!(
            first
                .data
                .root()
                .join("cargo-tools/v1/operation.lock")
                .is_file()
        );
        drop(first);
        let _next = stores(&stage);
    }
    #[test]
    fn conflicting_source_observation_survives_the_reported_failure() {
        let stage = crate::verified_source::Stage::new().unwrap();
        let stores = stores(&stage);
        let fact = SourceFact {
            key: KnowledgeKey::Evaluator {
                sha256: sha256(b"trusted"),
            },
            facts_sha256: sha256(b"original"),
            status: SecurityStatus::Clear,
            expires_at_utc: None,
        };
        stores
            .remember(
                KnowledgeEntry {
                    fact: fact.clone(),
                    source_version: 1,
                    checked_at_utc: 10,
                },
                10,
            )
            .unwrap();
        let mut contradictory = fact;
        contradictory.status = SecurityStatus::Adverse;
        contradictory.facts_sha256 = sha256(b"new adverse");
        assert!(
            stores
                .remember(
                    KnowledgeEntry {
                        fact: contradictory,
                        source_version: 1,
                        checked_at_utc: 11
                    },
                    11
                )
                .is_err()
        );
        let durable = stores.knowledge().unwrap();
        assert_eq!(durable.conflicts.len(), 1);
        assert_eq!(durable.entries[0].checked_at_utc, 10);
    }
    #[test]
    fn source_intent_is_durable_until_explicit_successful_reconciliation() {
        let stage = crate::verified_source::Stage::new().unwrap();
        let stores = stores(&stage);
        let key = "one exact source observation";
        stores.begin_source(key).unwrap();
        let pending = source_pending_path(key);
        assert!(stores.data.read_optional(&pending, 8192).unwrap().is_some());
        drop(stores);
        let stores = Stores::open(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        assert!(stores.data.read_optional(&pending, 8192).unwrap().is_some());
        stores.finish_source(key).unwrap();
        assert!(stores.data.read_optional(&pending, 8192).unwrap().is_none());
    }
    #[test]
    fn successful_git_revision_does_not_clear_another_revisions_advisory_intent() {
        use barbican::cargo_tool::{PackageIdentity, PackageSource};
        let stage = crate::verified_source::Stage::new().unwrap();
        let stores = stores(&stage);
        let package = |rev: &str, subdirectory: &str| PackageIdentity {
            name: "fixture".into(),
            version: "1.0.0".into(),
            source: PackageSource::Git {
                url: "https://example.com/fixture.git".into(),
                rev: rev.repeat(40),
                subdirectory: subdirectory.into(),
                materialisation_sha256: sha256(b"fixture"),
            },
        };
        let original = package_advisory_observation_key(&package("a", "crates/one")).unwrap();
        let other_revision = package_advisory_observation_key(&package("b", "crates/one")).unwrap();
        let other_directory =
            package_advisory_observation_key(&package("a", "crates/two")).unwrap();
        for key in [&original, &other_revision, &other_directory] {
            stores.begin_source(key).unwrap();
        }
        stores.finish_source(&other_revision).unwrap();
        stores.finish_source(&other_directory).unwrap();
        assert!(
            stores
                .data
                .read_optional(&source_pending_path(&original), 8192)
                .unwrap()
                .is_some()
        );
    }
}
