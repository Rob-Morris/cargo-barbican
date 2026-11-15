use super::{RecordKind, ToolError, ToolRecord, record::*, require};
use crate::{GitSourceIdentity, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PackageSource {
    CratesIo {
        archive_sha256: Sha256Digest,
    },
    Git {
        url: String,
        rev: String,
        subdirectory: String,
        materialisation_sha256: Sha256Digest,
    },
}
impl PackageSource {
    pub fn validate(&self) -> Result<(), ToolError> {
        match self {
            Self::CratesIo { .. } => Ok(()),
            Self::Git {
                url,
                rev,
                subdirectory,
                ..
            } => {
                GitSourceIdentity::new(url, rev).map_err(|e| ToolError(e.to_string()))?;
                if subdirectory != "." {
                    relative_path(subdirectory)?;
                }
                Ok(())
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
}
impl PackageIdentity {
    pub fn validate(&self) -> Result<(), ToolError> {
        name(&self.name)?;
        let parsed = semver::Version::parse(&self.version)
            .map_err(|_| ToolError("invalid exact package version".into()))?;
        require(
            parsed.to_string() == self.version,
            "noncanonical exact version",
        )?;
        self.source.validate()
    }
    pub fn family(&self) -> PackageFamily {
        match &self.source {
            PackageSource::CratesIo { .. } => PackageFamily::CratesIo {
                name: self.name.clone(),
            },
            PackageSource::Git { url, .. } => PackageFamily::Git {
                url: url.clone(),
                package: self.name.clone(),
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PackageFamily {
    CratesIo { name: String },
    Git { url: String, package: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RootSourceIdentity {
    CratesIo {
        name: String,
        version: String,
        archive_sha256: Sha256Digest,
    },
    Git {
        url: String,
        rev: String,
        package: String,
        version: String,
        workspace_manifest: String,
        package_manifest: String,
        materialisation_sha256: Sha256Digest,
    },
}
impl RootSourceIdentity {
    pub fn package(&self) -> PackageIdentity {
        match self {
            Self::CratesIo {
                name,
                version,
                archive_sha256,
            } => PackageIdentity {
                name: name.clone(),
                version: version.clone(),
                source: PackageSource::CratesIo {
                    archive_sha256: archive_sha256.clone(),
                },
            },
            Self::Git {
                url,
                rev,
                package,
                version,
                package_manifest,
                materialisation_sha256,
                ..
            } => PackageIdentity {
                name: package.clone(),
                version: version.clone(),
                source: PackageSource::Git {
                    url: url.clone(),
                    rev: rev.clone(),
                    subdirectory: package_manifest
                        .rsplit_once('/')
                        .map_or(".", |(p, _)| p)
                        .into(),
                    materialisation_sha256: materialisation_sha256.clone(),
                },
            },
        }
    }
    pub fn validate(&self) -> Result<(), ToolError> {
        self.package().validate()?;
        if let Self::Git {
            workspace_manifest,
            package_manifest,
            ..
        } = self
        {
            relative_path(workspace_manifest)?;
            relative_path(package_manifest)?;
            require(
                workspace_manifest.rsplit('/').next() == Some("Cargo.toml")
                    && package_manifest.rsplit('/').next() == Some("Cargo.toml"),
                "Git manifest roles must name Cargo.toml",
            )?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OriginalLock {
    Absent,
    Usable {
        sha256: Sha256Digest,
    },
    Unusable {
        sha256: Sha256Digest,
        reason: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EffectiveLock {
    Upstream {
        sha256: Sha256Digest,
    },
    Derived {
        sha256: Sha256Digest,
        reason: String,
    },
}
impl EffectiveLock {
    pub fn sha256(&self) -> &Sha256Digest {
        match self {
            Self::Upstream { sha256 } | Self::Derived { sha256, .. } => sha256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompilationContext {
    Target,
    HostBuild,
    HostProcMacro,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub package: PackageIdentity,
    pub context: CompilationContext,
    pub features: BTreeSet<String>,
    pub build_script: bool,
    pub proc_macro: bool,
    pub native_links: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    Normal,
    Build,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: DependencyKind,
    // Cargo metadata preserves all declaration alternatives, even after native
    // filtering. Selection belongs to the tree, not to any one of these strings.
    // The empty string denotes an unconditional declaration.
    pub declared_targets: BTreeSet<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallGraph {
    pub root: String,
    pub nodes: BTreeMap<String, GraphNode>,
    pub edges: BTreeSet<GraphEdge>,
}
impl InstallGraph {
    pub fn validate(&self) -> Result<(), ToolError> {
        require(
            !self.nodes.is_empty() && self.nodes.len() <= MAX_GRAPH_NODES,
            "invalid graph node count",
        )?;
        require(self.nodes.contains_key(&self.root), "graph root missing")?;
        require(
            self.edges.len() <= MAX_GRAPH_NODES * 8,
            "graph edge budget exceeded",
        )?;
        let mut identities = BTreeSet::new();
        for (key, node) in &self.nodes {
            text(key)?;
            node.package.validate()?;
            require(
                identities.insert((&node.package, &node.context)),
                "ambiguous duplicate graph package/context",
            )?;
            for feature in &node.features {
                feature_name(feature)?;
            }
            require(
                !node.proc_macro || node.context == CompilationContext::HostProcMacro,
                "proc macro must be host context",
            )?;
        }
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut indegrees: BTreeMap<&str, usize> =
            self.nodes.keys().map(|key| (key.as_str(), 0)).collect();
        let mut selected_edges = BTreeSet::new();
        let mut declarations = 0usize;
        let mut declaration_bytes = 0usize;
        for edge in &self.edges {
            require(
                self.nodes.contains_key(&edge.from) && self.nodes.contains_key(&edge.to),
                "graph edge has unknown node",
            )?;
            require(
                selected_edges.insert((&edge.from, &edge.to, &edge.kind)),
                "duplicate selected graph edge",
            )?;
            require(
                !edge.declared_targets.is_empty() && edge.declared_targets.len() <= MAX_GRAPH_NODES,
                "invalid declared target count",
            )?;
            declarations += edge.declared_targets.len();
            require(
                declarations <= MAX_GRAPH_NODES * 8,
                "graph declaration count budget exceeded",
            )?;
            for target in &edge.declared_targets {
                require(
                    target.len() <= MAX_LINE_BYTES && !target.chars().any(char::is_control),
                    "invalid declared target",
                )?;
                declaration_bytes += target.len();
                require(
                    declaration_bytes <= MAX_RECORD_BYTES,
                    "graph declaration byte budget exceeded",
                )?;
            }
            if edge.kind == DependencyKind::Build {
                require(
                    self.nodes[&edge.to].context != CompilationContext::Target,
                    "build edge targets non-host context",
                )?;
            }
            children.entry(&edge.from).or_default().push(&edge.to);
            *indegrees.get_mut(edge.to.as_str()).expect("known node") += 1;
        }
        let mut queue: Vec<&str> = indegrees
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(key, _)| *key)
            .collect();
        let mut visited = 0;
        let mut depths: BTreeMap<&str, usize> = BTreeMap::from([(self.root.as_str(), 0)]);
        while let Some(key) = queue.pop() {
            visited += 1;
            for child in children.get(key).into_iter().flatten() {
                if let Some(depth) = depths.get(key).copied() {
                    let next = depth + 1;
                    require(next <= MAX_DEPTH, "graph depth exceeds 128")?;
                    depths
                        .entry(child)
                        .and_modify(|d| *d = (*d).max(next))
                        .or_insert(next);
                }
                let remaining = indegrees.get_mut(child).expect("known node");
                *remaining -= 1;
                if *remaining == 0 {
                    queue.push(child);
                }
            }
        }
        require(visited == self.nodes.len(), "cyclic install graph")?;
        require(
            depths.len() == self.nodes.len(),
            "install graph contains unreachable nodes",
        )
    }
    pub fn packages(&self) -> BTreeSet<PackageIdentity> {
        self.nodes.values().map(|n| n.package.clone()).collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildProfile {
    Release,
    Dev,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSelection {
    pub bins: BTreeMap<String, BTreeSet<String>>,
    pub requested_features: BTreeSet<String>,
    pub default_features: bool,
    pub all_features: bool,
    pub profile: BuildProfile,
    pub host: String,
    pub target: String,
    pub resolver: u8,
}
impl BuildSelection {
    pub fn validate(&self) -> Result<(), ToolError> {
        require(!self.bins.is_empty(), "tool selection contains no binaries")?;
        for (bin, features) in &self.bins {
            name(bin)?;
            for feature in features {
                feature_name(feature)?;
            }
        }
        for feature in &self.requested_features {
            feature_name(feature)?;
        }
        require(
            !self.all_features || (self.default_features && self.requested_features.is_empty()),
            "all-features conflicts with feature selection",
        )?;
        name(&self.host)?;
        name(&self.target)?;
        require(
            self.host == self.target && !self.host.is_empty(),
            "only native target is supported",
        )?;
        require(matches!(self.resolver, 2 | 3), "unqualified Cargo resolver")
    }
}
pub(crate) fn feature_name(value: &str) -> Result<(), ToolError> {
    require(
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-/+?.".contains(&c)),
        "invalid feature name",
    )
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub sha256: Sha256Digest,
    pub version: String,
    pub commit: String,
    pub host: String,
}
impl ExecutableIdentity {
    pub fn validate(&self) -> Result<(), ToolError> {
        let version = semver::Version::parse(&self.version)
            .map_err(|_| ToolError("invalid exact evaluator version".into()))?;
        require(
            version.to_string() == self.version,
            "noncanonical evaluator version",
        )?;
        name(&self.host)?;
        require(
            self.commit.len() == 40
                && self
                    .commit
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "evaluator commit must be full lower-case hexadecimal",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEvaluator {
    pub cargo: ExecutableIdentity,
    pub rustc: ExecutableIdentity,
    pub qualification_sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeMode {
    VerifiedPath,
    RegistryDirectory,
    ExactGit,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputKind {
    RegularFile,
    Directory,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    pub path: String,
    pub kind: InputKind,
    pub mode: u32,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub schema_version: u32,
    pub root: RootSourceIdentity,
    pub original_lock: OriginalLock,
    pub effective_lock: EffectiveLock,
    pub graph: InstallGraph,
    pub selection: BuildSelection,
    pub evaluator: BuildEvaluator,
    pub config_sha256: Sha256Digest,
    pub native_mode: NativeMode,
    pub inputs: BTreeSet<InputFile>,
}
pub type ToolSubject = Subject;
impl ToolRecord for Subject {
    const KIND: RecordKind = RecordKind::Subject;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.root.validate()?;
        require(
            matches!(
                (&self.native_mode, &self.root),
                (NativeMode::VerifiedPath, _)
                    | (
                        NativeMode::RegistryDirectory,
                        RootSourceIdentity::CratesIo { .. }
                    )
                    | (NativeMode::ExactGit, RootSourceIdentity::Git { .. })
            ),
            "native source mode conflicts with original source",
        )?;
        self.graph.validate()?;
        self.selection.validate()?;
        require(
            self.graph.nodes[&self.graph.root].package == self.root.package(),
            "root source differs from graph root",
        )?;
        require(
            self.graph.nodes[&self.graph.root].context == CompilationContext::Target,
            "tool root must be target context",
        )?;
        let root_features = &self.graph.nodes[&self.graph.root].features;
        require(
            self.selection
                .bins
                .values()
                .all(|required| required.is_subset(root_features)),
            "selected binary required features unavailable",
        )?;
        self.evaluator.cargo.validate()?;
        self.evaluator.rustc.validate()?;
        require(
            self.evaluator.cargo.host == self.selection.host
                && self.evaluator.rustc.host == self.selection.host,
            "compiler host mismatch",
        )?;
        match (&self.original_lock, &self.effective_lock) {
            (OriginalLock::Usable { sha256: a }, EffectiveLock::Upstream { sha256: b }) => {
                require(a == b, "upstream effective lock changed")?
            }
            (OriginalLock::Usable { .. }, EffectiveLock::Derived { .. }) => {
                return Err(ToolError("usable upstream lock must be retained".into()));
            }
            (
                OriginalLock::Absent | OriginalLock::Unusable { .. },
                EffectiveLock::Derived { reason, .. },
            ) => text(reason)?,
            _ => {
                return Err(ToolError(
                    "effective lock has false upstream provenance".into(),
                ));
            }
        }
        if let OriginalLock::Unusable { reason, .. } = &self.original_lock {
            text(reason)?;
        }
        require(
            !self.inputs.is_empty() && self.inputs.len() <= MAX_FILES,
            "invalid input file count",
        )?;
        let mut paths = BTreeSet::new();
        let mut total = 0u64;
        for file in &self.inputs {
            relative_path(&file.path)?;
            require(paths.insert(&file.path), "duplicate input path")?;
            if file.kind == InputKind::Directory {
                require(
                    file.bytes == 0 && file.sha256 == sha256(b""),
                    "directory cannot carry file bytes",
                )?;
            }
            require(
                file.mode <= 0o777 && file.bytes <= MAX_FILE_BYTES,
                "invalid input mode or file size",
            )?;
            total = total
                .checked_add(file.bytes)
                .ok_or_else(|| ToolError("source byte count overflow".into()))?;
            require(total <= MAX_SOURCE_BYTES, "aggregate source limit exceeded")?;
        }
        let entries: BTreeMap<_, _> = self
            .inputs
            .iter()
            .map(|entry| (entry.path.as_str(), &entry.kind))
            .collect();
        for entry in &self.inputs {
            let mut parent = entry.path.as_str();
            while let Some((ancestor, _)) = parent.rsplit_once('/') {
                require(
                    entries.get(ancestor) == Some(&&InputKind::Directory),
                    "input ancestor is absent or not a represented directory",
                )?;
                parent = ancestor;
            }
        }
        Ok(())
    }
}

impl From<&PackageIdentity> for crate::ioc::Source {
    fn from(package: &PackageIdentity) -> Self {
        let origin = match &package.source {
            PackageSource::CratesIo { archive_sha256 } => crate::ioc::Origin::CratesIo {
                archive_sha256: archive_sha256.clone(),
            },
            PackageSource::Git {
                url,
                rev,
                subdirectory,
                materialisation_sha256,
            } => crate::ioc::Origin::Git {
                url: url.clone(),
                rev: rev.clone(),
                subdirectory: subdirectory.clone(),
                materialisation_sha256: materialisation_sha256.clone(),
            },
        };
        Self {
            name: package.name.clone(),
            version: package.version.clone(),
            origin,
        }
    }
}
impl From<&crate::ioc::Source> for PackageIdentity {
    fn from(source: &crate::ioc::Source) -> Self {
        let origin = match &source.origin {
            crate::ioc::Origin::CratesIo { archive_sha256 } => PackageSource::CratesIo {
                archive_sha256: archive_sha256.clone(),
            },
            crate::ioc::Origin::Git {
                url,
                rev,
                subdirectory,
                materialisation_sha256,
            } => PackageSource::Git {
                url: url.clone(),
                rev: rev.clone(),
                subdirectory: subdirectory.clone(),
                materialisation_sha256: materialisation_sha256.clone(),
            },
        };
        Self {
            name: source.name.clone(),
            version: source.version.clone(),
            source: origin,
        }
    }
}
