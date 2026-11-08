use super::*;
use crate::rust_distribution::{
    ArchiveIdentity, ArchiveInventory, Encoding, EntryKind, Manifest, Profile, Selection,
    SelectionInventory, SelectionRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Facts emitted by the separately qualified authentication adapter, never by parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationIdentity {
    pub manifest_sha256: Sha256Digest,
    pub signature_sha256: Sha256Digest,
    pub certificate_sha256: Sha256Digest,
    pub primary_fingerprint: String,
    pub signing_fingerprint: String,
    pub verification_policy_sha256: Sha256Digest,
}
impl AuthenticationIdentity {
    fn validate(&self) -> Result<()> {
        for fingerprint in [&self.primary_fingerprint, &self.signing_fingerprint] {
            require(
                fingerprint.len() == 40
                    && fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "expected canonical full v4 fingerprint",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRecord {
    pub package: String,
    pub target: String,
    pub component: String,
    pub root: String,
    pub encoding: String,
    pub url: String,
    pub sha256: Sha256Digest,
}
impl From<&ArchiveIdentity> for ArchiveRecord {
    fn from(a: &ArchiveIdentity) -> Self {
        Self {
            package: a.package.clone(),
            target: a.target.clone(),
            component: a.component.clone(),
            root: a.root.clone(),
            encoding: match a.encoding {
                Encoding::Xz => "xz",
                Encoding::Gzip => "gzip",
            }
            .into(),
            url: a.url.clone(),
            sha256: a.sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRecord {
    pub schema_version: u32,
    pub supplier: String,
    pub release: String,
    pub publication_date: String,
    pub authentication: AuthenticationIdentity,
    pub host: String,
    pub profile: String,
    pub requested_components: Vec<String>,
    pub requested_targets: Vec<String>,
    pub archives: Vec<ArchiveRecord>,
    pub host_inapplicable_profile_members: Vec<String>,
    pub mapping_version: String,
    pub mapping_sha256: Sha256Digest,
}
impl SubjectRecord {
    pub fn validate_against(&self, subject: &Subject) -> Result<()> {
        require(
            self == subject.record(),
            "stored subject differs from authenticated reconstructed subject",
        )
    }
}

#[derive(Debug, Clone)]
pub struct Subject {
    record: SubjectRecord,
    id: Sha256Digest,
}
impl Subject {
    pub fn reconstruct(
        manifest: &Manifest,
        request: &SelectionRequest,
        authentication: AuthenticationIdentity,
        mut inventories: Vec<ArchiveInventory>,
    ) -> Result<Self> {
        authentication.validate()?;
        require(
            authentication.manifest_sha256 == manifest.sha256(),
            "authentication document identity mismatch",
        )?;
        let selected = manifest
            .select(request)
            .map_err(|e| AdmissionError(e.to_string()))?;
        require(
            inventories.len() == selected.archives.len(),
            "incomplete selected archive inventories",
        )?;
        inventories.sort_by(|a, b| {
            (&a.identity.package, &a.identity.target)
                .cmp(&(&b.identity.package, &b.identity.target))
        });
        let mut combined = SelectionInventory::default();
        let mut metadata = Vec::new();
        for inventory in inventories {
            require(
                selected.archives.iter().any(|a| a == &inventory.identity),
                "inventory is not the exact selected archive",
            )?;
            let required = BTreeSet::from([
                "components".to_owned(),
                "rust-installer-version".to_owned(),
                format!("{}/manifest.in", inventory.identity.component),
            ]);
            require(
                inventory
                    .installer_metadata
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    == required,
                "incomplete installer metadata",
            )?;
            for (path, body) in &inventory.installer_metadata {
                require(
                    body.len() <= crate::rust_distribution::MAX_METADATA_BYTES
                        && inventory.package_metadata.get(path).is_some_and(|entry| {
                            entry.kind
                                == EntryKind::File {
                                    size: body.len() as u64,
                                    sha256: digest_bytes(body.as_bytes()),
                                }
                        }),
                    "installer metadata content identity mismatch",
                )?;
            }
            for (path, entry) in &inventory.package_metadata {
                metadata.push(MappingEntry::new(
                    &format!("{}/{}", inventory.identity.root, path),
                    entry,
                ));
            }
            combined
                .add(inventory)
                .map_err(|e| AdmissionError(e.to_string()))?;
        }
        metadata.sort_by(|a, b| a.path.cmp(&b.path));
        let payload: Vec<_> = combined
            .payload
            .iter()
            .map(|(p, e)| MappingEntry::new(p, e))
            .collect();
        let mapping_sha256 = record_id(
            MAPPING_VERSION,
            &Mapping {
                payload,
                package_metadata: metadata,
            },
        )?;
        Self::from_selection(selected, request, authentication, mapping_sha256)
    }

    fn from_selection(
        selected: Selection,
        request: &SelectionRequest,
        authentication: AuthenticationIdentity,
        mapping_sha256: Sha256Digest,
    ) -> Result<Self> {
        let normalise = |values: &[String]| -> Result<Vec<String>> {
            require(values.len() <= 64, "selection request count limit")?;
            for value in values {
                text(value)?;
            }
            Ok(values
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect())
        };
        let mut archives: Vec<_> = selected.archives.iter().map(ArchiveRecord::from).collect();
        archives.sort_by(|a, b| (&a.package, &a.target).cmp(&(&b.package, &b.target)));
        let mut skipped = selected.host_inapplicable_profile_members;
        skipped.sort();
        let record = SubjectRecord {
            schema_version: SCHEMA_VERSION,
            supplier: "https://static.rust-lang.org".into(),
            release: selected.release,
            publication_date: selected.date,
            authentication,
            host: selected.host,
            profile: match selected.profile {
                Profile::Minimal => "minimal",
                Profile::Default => "default",
            }
            .into(),
            requested_components: normalise(&request.components)?,
            requested_targets: normalise(&request.targets)?,
            archives,
            host_inapplicable_profile_members: skipped,
            mapping_version: MAPPING_VERSION.into(),
            mapping_sha256,
        };
        let id = record_id("rust-toolchain-subject-v1", &record)?;
        Ok(Self { record, id })
    }
    pub fn record(&self) -> &SubjectRecord {
        &self.record
    }
    pub fn id(&self) -> &Sha256Digest {
        &self.id
    }
}

#[derive(Serialize)]
struct Mapping {
    payload: Vec<MappingEntry>,
    package_metadata: Vec<MappingEntry>,
}
#[derive(Serialize)]
struct MappingEntry {
    path: String,
    kind: &'static str,
    mode: u32,
    size: u64,
    sha256: Option<Sha256Digest>,
}
impl MappingEntry {
    fn new(path: &str, entry: &crate::rust_distribution::ExpectedEntry) -> Self {
        let (kind, size, sha256) = match &entry.kind {
            EntryKind::File { size, sha256 } => ("file", *size, Some(sha256.clone())),
            EntryKind::Directory => ("directory", 0, None),
        };
        Self {
            path: path.into(),
            kind,
            mode: entry.mode,
            size,
            sha256,
        }
    }
}
