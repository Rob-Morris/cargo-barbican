use super::*;
use crate::rust_distribution::{ArchiveInventory, EntryKind, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentCorpus {
    RustRoot,
    StandardLibrary,
    Cargo,
}
impl ComponentCorpus {
    pub fn for_package(package: &str) -> Result<Self> {
        match package {
            "cargo" => Ok(Self::Cargo),
            "rust-std" | "rust-src" => Ok(Self::StandardLibrary),
            "rustc" | "rust-docs" | "clippy-preview" | "rustfmt-preview" => Ok(Self::RustRoot),
            _ => Err(AdmissionError(
                "component source relationship is not qualified".into(),
            )),
        }
    }
    pub fn inventory_path(self) -> &'static str {
        match self {
            Self::StandardLibrary => "library/Cargo.lock",
            _ => "Cargo.lock",
        }
    }
    pub fn repository(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            _ => "rust",
        }
    }
}

pub fn component_source_paths(package: &str) -> Result<&'static [(&'static str, &'static str)]> {
    match package {
        "rustc" => Ok(&[
            ("compiler/rustc/Cargo.toml", "rustc-main"),
            ("src/librustdoc/Cargo.toml", "rustdoc"),
        ]),
        "cargo" => Ok(&[("Cargo.toml", "cargo")]),
        "rust-std" => Ok(&[("library/std/Cargo.toml", "std")]),
        "rust-src" => Ok(&[
            ("library/std/Cargo.toml", "std"),
            ("library/Cargo.toml", ""),
            ("src/bootstrap/src/core/build_steps/dist.rs", ""),
        ]),
        "rust-docs" => Ok(&[
            ("src/librustdoc/Cargo.toml", "rustdoc"),
            ("src/bootstrap/src/core/build_steps/doc.rs", ""),
        ]),
        "clippy-preview" => Ok(&[("src/tools/clippy/Cargo.toml", "clippy")]),
        "rustfmt-preview" => Ok(&[("src/tools/rustfmt/Cargo.toml", "rustfmt-nightly")]),
        _ => Err(AdmissionError(
            "component source relationship is not qualified".into(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationAssets {
    pub files: u64,
    pub bytes: u64,
    pub javascript_files: u64,
    pub css_files: u64,
    pub payload_sha256: Sha256Digest,
}
impl DocumentationAssets {
    pub fn from_inventory(inventory: &ArchiveInventory) -> Result<Self> {
        let mut value = Self {
            files: 0,
            bytes: 0,
            javascript_files: 0,
            css_files: 0,
            payload_sha256: record_id(
                "rust-documentation-assets-v1",
                &inventory
                    .payload
                    .iter()
                    .map(|(path, entry)| super::identity::MappingEntry::new(path, entry))
                    .collect::<Vec<_>>(),
            )?,
        };
        for (path, entry) in &inventory.payload {
            if let EntryKind::File { size, .. } = entry.kind {
                value.files += 1;
                value.bytes = value
                    .bytes
                    .checked_add(size)
                    .ok_or_else(|| AdmissionError("docs asset byte overflow".into()))?;
                value.javascript_files += u64::from(path.ends_with(".js"));
                value.css_files += u64::from(path.ends_with(".css"));
            }
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentEvidence {
    pub archive: ArchiveRecord,
    pub rust_revision: String,
    pub source_revision: String,
    pub corpus: ComponentCorpus,
    pub source_paths: Vec<String>,
    pub inventory_sha256: Sha256Digest,
    pub source_packages: BTreeMap<String, String>,
    pub documentation_assets: Option<DocumentationAssets>,
    pub relationship: String,
    pub residual_coverage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSourceDocument {
    pub location: String,
    pub sha256: Sha256Digest,
    pub body: String,
}
impl ComponentSourceDocument {
    pub fn package_version(&self, package: &str) -> Result<String> {
        self.verify()?;
        let manifest: toml::Value =
            toml::from_str(&self.body).map_err(|e| AdmissionError(e.to_string()))?;
        let metadata = manifest
            .get("package")
            .ok_or_else(|| AdmissionError("source package metadata missing".into()))?;
        require(
            metadata.get("name").and_then(toml::Value::as_str) == Some(package),
            "component source package mismatch",
        )?;
        metadata
            .get("version")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AdmissionError("source package exact version missing".into()))
    }
    fn verify(&self) -> Result<()> {
        text(&self.location)?;
        require(
            !self.body.is_empty() && digest_bytes(self.body.as_bytes()) == self.sha256,
            "missing or changed component source document",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSourceSnapshot {
    pub component: ComponentEvidence,
    pub identity_documents: Vec<ComponentSourceDocument>,
    pub inventory: ComponentSourceDocument,
    pub source_documents: Vec<ComponentSourceDocument>,
}
impl ComponentSourceSnapshot {
    fn identity_document(&self, location: &str) -> Result<serde_json::Value> {
        let documents: Vec<_> = self
            .identity_documents
            .iter()
            .filter(|d| d.location == location)
            .collect();
        let first = documents
            .first()
            .ok_or_else(|| AdmissionError("required component source provenance missing".into()))?;
        require(
            documents.iter().all(|d| d.sha256 == first.sha256),
            "conflicting component source provenance",
        )?;
        serde_json::from_str(&first.body).map_err(|e| AdmissionError(e.to_string()))
    }
    fn tree_entry(&self, revision: &str, path: &str, kind: &str) -> Result<String> {
        let value = self.identity_document(&format!(
            "https://api.github.com/repos/rust-lang/rust/git/trees/{revision}"
        ))?;
        require(
            value["sha"].as_str() == Some(revision) && value["truncated"].as_bool() != Some(true),
            "component source tree mismatch or incomplete",
        )?;
        let entries = value["tree"]
            .as_array()
            .ok_or_else(|| AdmissionError("component source tree entries missing".into()))?;
        let found: Vec<_> = entries
            .iter()
            .filter(|e| e["path"].as_str() == Some(path))
            .collect();
        require(
            found.len() == 1 && found[0]["type"].as_str() == Some(kind),
            "component source tree relationship missing or ambiguous",
        )?;
        let revision = found[0]["sha"]
            .as_str()
            .ok_or_else(|| AdmissionError("component source tree revision missing".into()))?;
        require(
            revision.len() == 40
                && revision
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "component source tree revision is not exact",
        )?;
        Ok(revision.into())
    }
    fn validate_identity_chain(&self) -> Result<()> {
        let row = &self.component;
        let commit = self.identity_document(&format!(
            "https://api.github.com/repos/rust-lang/rust/git/commits/{}",
            row.rust_revision
        ))?;
        require(
            commit["sha"].as_str() == Some(row.rust_revision.as_str()),
            "component source root differs from signed Rust commit",
        )?;
        let root = commit["tree"]["sha"]
            .as_str()
            .ok_or_else(|| AdmissionError("component source root tree missing".into()))?;
        let src = self.tree_entry(root, "src", "tree")?;
        match row.archive.package.as_str() {
            "cargo" | "clippy-preview" | "rustfmt-preview" => {
                let tools = self.tree_entry(&src, "tools", "tree")?;
                match row.archive.package.as_str() {
                    "cargo" => require(
                        self.tree_entry(&tools, "cargo", "commit")? == row.source_revision,
                        "Cargo component gitlink mismatch",
                    )?,
                    "clippy-preview" => {
                        self.tree_entry(&tools, "clippy", "tree")?;
                    }
                    _ => {
                        self.tree_entry(&tools, "rustfmt", "tree")?;
                    }
                }
            }
            "rustc" => {
                self.tree_entry(root, "compiler", "tree")?;
                self.tree_entry(&src, "librustdoc", "tree")?;
            }
            "rust-std" | "rust-src" => {
                self.tree_entry(root, "library", "tree")?;
                if row.archive.package == "rust-src" {
                    self.tree_entry(&src, "llvm-project", "commit")?;
                }
            }
            "rust-docs" => {
                self.tree_entry(&src, "doc", "tree")?;
                self.tree_entry(&src, "librustdoc", "tree")?;
            }
            _ => {
                return Err(AdmissionError(
                    "unqualified component source relationship".into(),
                ));
            }
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        let row = &self.component;
        row.validate()?;
        require(
            !self.identity_documents.is_empty() && self.identity_documents.len() <= 32,
            "required component provenance missing or excessive",
        )?;
        for document in &self.identity_documents {
            document.verify()?;
        }
        self.validate_identity_chain()?;
        self.inventory.verify()?;
        require(
            self.inventory.sha256 == row.inventory_sha256,
            "component inventory identity mismatch",
        )?;
        let base = format!(
            "https://raw.githubusercontent.com/rust-lang/{}/{}/",
            row.corpus.repository(),
            row.source_revision
        );
        require(
            self.inventory.location == format!("{base}{}", row.corpus.inventory_path()),
            "component inventory source/corpus mismatch",
        )?;
        let inventory = parse_source_package_inventory(&self.inventory.body)?;
        let paths = component_source_paths(&row.archive.package)?;
        require(
            self.source_documents.len() == paths.len(),
            "required component source documents missing",
        )?;
        for (document, (path, package)) in self.source_documents.iter().zip(paths) {
            document.verify()?;
            require(
                document.location == format!("{base}{path}"),
                "component source document relationship mismatch",
            )?;
            if !package.is_empty() {
                let version = document.package_version(package)?;
                require(
                    row.source_packages.get(*package).map(String::as_str) == Some(version.as_str())
                        && inventory.iter().any(|p| {
                            p.name == *package && p.version == version && p.source.is_none()
                        }),
                    "component package is absent from its represented source inventory",
                )?;
            }
        }
        Ok(())
    }
}
impl ComponentEvidence {
    pub fn validate(&self) -> Result<()> {
        for revision in [&self.rust_revision, &self.source_revision] {
            require(
                revision.len() == 40
                    && revision
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "component source commit must be exact",
            )?;
        }
        require(
            self.corpus == ComponentCorpus::for_package(&self.archive.package)?,
            "component/corpus relationship mismatch",
        )?;
        require(
            self.corpus == ComponentCorpus::Cargo || self.source_revision == self.rust_revision,
            "component source is outside the signed Rust tree",
        )?;
        let paths = component_source_paths(&self.archive.package)?;
        require(
            self.source_paths
                == paths
                    .iter()
                    .map(|(path, _)| path.to_string())
                    .collect::<Vec<_>>(),
            "required component source paths mismatch",
        )?;
        require(
            self.source_packages
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == paths
                    .iter()
                    .map(|(_, package)| *package)
                    .filter(|p| !p.is_empty())
                    .collect(),
            "required component package relationship missing",
        )?;
        require(
            self.documentation_assets.is_some() == (self.archive.package == "rust-docs"),
            "documentation asset coverage missing or misattributed",
        )?;
        text(&self.relationship)?;
        text(&self.residual_coverage)
    }
}

impl EvidenceRecord {
    pub fn validate_component_inputs(
        &self,
        manifest: &Manifest,
        inventories: &[ArchiveInventory],
    ) -> Result<()> {
        for row in &self.component_sources {
            require(
                manifest
                    .package_source_metadata(&row.archive.package)
                    .and_then(|m| m.git_commit_hash)
                    == Some(row.rust_revision.as_str()),
                "component source revision differs from authenticated package metadata",
            )?;
            let inventory = inventories
                .iter()
                .find(|i| ArchiveRecord::from(&i.identity) == row.archive)
                .ok_or_else(|| AdmissionError("component archive inventory missing".into()))?;
            if let Some(assets) = &row.documentation_assets {
                require(
                    assets == &DocumentationAssets::from_inventory(inventory)?,
                    "documentation asset inventory differs from authenticated payload",
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;

    pub(in crate::toolchain_admission) fn snapshot(
        archive: &ArchiveRecord,
    ) -> ComponentSourceSnapshot {
        let rust = "1".repeat(40);
        let cargo = "2".repeat(40);
        let root = "3".repeat(40);
        let src = "4".repeat(40);
        let tools = "5".repeat(40);
        let other = "6".repeat(40);
        let corpus = ComponentCorpus::for_package(&archive.package).unwrap();
        let revision = if corpus == ComponentCorpus::Cargo {
            &cargo
        } else {
            &rust
        };
        let document = |location: String, body: String| ComponentSourceDocument {
            location,
            sha256: digest_bytes(body.as_bytes()),
            body,
        };
        let mut identity_documents = vec![document(
            format!("https://api.github.com/repos/rust-lang/rust/git/commits/{rust}"),
            json!({"sha":rust,"tree":{"sha":root}}).to_string(),
        )];
        for (sha, entries) in [
            (
                &root,
                vec![
                    ("src", "tree", &src),
                    ("compiler", "tree", &other),
                    ("library", "tree", &other),
                ],
            ),
            (
                &src,
                vec![
                    ("tools", "tree", &tools),
                    ("librustdoc", "tree", &other),
                    ("doc", "tree", &other),
                    ("llvm-project", "commit", &other),
                ],
            ),
            (
                &tools,
                vec![
                    ("cargo", "commit", &cargo),
                    ("clippy", "tree", &other),
                    ("rustfmt", "tree", &other),
                ],
            ),
        ] {
            identity_documents.push(document(format!("https://api.github.com/repos/rust-lang/rust/git/trees/{sha}"), json!({"sha":sha,"truncated":false,"tree":entries.into_iter().map(|(path,kind,sha)|json!({"path":path,"type":kind,"sha":sha})).collect::<Vec<_>>()} ).to_string()));
        }
        let paths = component_source_paths(&archive.package).unwrap();
        let packages: BTreeMap<_, _> = paths
            .iter()
            .filter(|(_, p)| !p.is_empty())
            .map(|(_, p)| (p.to_string(), "1.0.0".to_owned()))
            .collect();
        let lock = format!(
            "version=4\n{}",
            packages
                .iter()
                .map(|(p, v)| format!("[[package]]\nname='{p}'\nversion='{v}'\n"))
                .collect::<String>()
        );
        let base = format!(
            "https://raw.githubusercontent.com/rust-lang/{}/{revision}/",
            corpus.repository()
        );
        let inventory = document(format!("{base}{}", corpus.inventory_path()), lock);
        let source_documents = paths
            .iter()
            .map(|(path, p)| {
                document(
                    format!("{base}{path}"),
                    if p.is_empty() {
                        "// Authored documentation build source fixture".into()
                    } else {
                        format!("[package]\nname='{p}'\nversion='1.0.0'\n")
                    },
                )
            })
            .collect();
        let component = ComponentEvidence {
            archive: archive.clone(),
            rust_revision: rust.clone(),
            source_revision: revision.clone(),
            corpus,
            source_paths: paths.iter().map(|(p, _)| p.to_string()).collect(),
            inventory_sha256: inventory.sha256.clone(),
            source_packages: packages,
            documentation_assets: (archive.package == "rust-docs").then(|| DocumentationAssets {
                files: 1,
                bytes: 10,
                javascript_files: 1,
                css_files: 0,
                payload_sha256: digest_bytes(b"authored payload"),
            }),
            relationship: "Authored component/source relationship fixture".into(),
            residual_coverage:
                "No fixture claim of binary reachability or complete dependency coverage".into(),
        };
        ComponentSourceSnapshot {
            component,
            identity_documents,
            inventory,
            source_documents,
        }
    }

    #[test]
    fn exact_component_relationships_share_rust_sources_without_sharing_corpus_authority() {
        for package in [
            "rustc",
            "cargo",
            "rust-std",
            "rust-src",
            "rust-docs",
            "clippy-preview",
            "rustfmt-preview",
        ] {
            let archive = ArchiveRecord {
                package: package.into(),
                target: if package == "rust-src" {
                    "*"
                } else {
                    "aarch64-apple-darwin"
                }
                .into(),
                component: package.into(),
                root: package.into(),
                encoding: "xz".into(),
                url: "https://static.rust-lang.org/dist/fixture".into(),
                sha256: digest_bytes(package.as_bytes()),
            };
            let good = snapshot(&archive);
            good.validate().unwrap();
            let mut wrong = good.clone();
            wrong.component.corpus = if good.component.corpus == ComponentCorpus::Cargo {
                ComponentCorpus::RustRoot
            } else {
                ComponentCorpus::Cargo
            };
            assert!(wrong.validate().unwrap_err().to_string().contains("corpus"));
            let mut wrong = good.clone();
            wrong.source_documents.pop();
            assert!(wrong.validate().is_err());
            let mut wrong = good.clone();
            wrong.identity_documents.clear();
            assert!(wrong.validate().is_err());
            let mut wrong = good.clone();
            wrong.inventory.body =
                "version=4\n[[package]]\nname='unrelated'\nversion='1.0.0'\n".into();
            wrong.inventory.sha256 = digest_bytes(wrong.inventory.body.as_bytes());
            wrong.component.inventory_sha256 = wrong.inventory.sha256.clone();
            assert!(
                wrong
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("represented source inventory")
            );
            if package == "cargo" {
                let mut wrong = good.clone();
                wrong.component.source_revision = "a".repeat(40);
                assert!(
                    wrong
                        .validate()
                        .unwrap_err()
                        .to_string()
                        .contains("gitlink")
                );
            }
            if package == "rust-docs" {
                let mut wrong = good.clone();
                wrong.component.documentation_assets = None;
                assert!(wrong.validate().is_err());
            }
        }
    }
}
