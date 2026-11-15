use super::{
    record::{absolute_path, name, schema, text, time},
    *,
};
use crate::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputObservation {
    pub name: String,
    pub path: String,
    pub mode: u32,
    pub sha256: Sha256Digest,
    pub native_owner: String,
}
impl OutputObservation {
    pub fn validate(&self, root: &str) -> Result<(), ToolError> {
        name(&self.name)?;
        absolute_path(&self.path)?;
        require(
            self.path == format!("{root}/bin/{}", self.name),
            "output is outside the exact installation root/bin",
        )?;
        require(
            self.mode <= 0o777 && self.mode & 0o111 != 0,
            "output is not an ordinary executable file",
        )?;
        text(&self.native_owner)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledBinding {
    pub schema_version: u32,
    pub root_package: PackageIdentity,
    pub subject_id: RecordId,
    pub review_id: RecordId,
    pub acceptance_id: RecordId,
    pub local_user: String,
    pub root: String,
    pub outputs: BTreeSet<OutputObservation>,
    pub native_owner: String,
    pub native_tracking_sha256: Sha256Digest,
    pub installed_at_utc: i64,
}
impl ToolRecord for InstalledBinding {
    const KIND: RecordKind = RecordKind::InstalledBinding;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.root_package.validate()?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.review_id.require_kind(RecordKind::Review)?;
        self.acceptance_id
            .require_kind(RecordKind::LocalAcceptance)?;
        text(&self.local_user)?;
        absolute_path(&self.root)?;
        time(self.installed_at_utc)?;
        text(&self.native_owner)?;
        require(!self.outputs.is_empty(), "installed binding has no outputs")?;
        let mut names = BTreeSet::new();
        for output in &self.outputs {
            output.validate(&self.root)?;
            require(
                output.native_owner == self.native_owner,
                "output native ownership mismatch",
            )?;
            require(names.insert(&output.name), "duplicate installed output")?;
        }
        Ok(())
    }
}
impl InstalledBinding {
    pub fn corresponds(
        &self,
        observed: &BTreeSet<OutputObservation>,
        native_owner: &str,
        native_tracking_sha256: &Sha256Digest,
    ) -> Result<(), ToolError> {
        self.validate()?;
        require(
            native_owner == self.native_owner
                && observed == &self.outputs
                && *native_tracking_sha256 == self.native_tracking_sha256,
            "installed bytes, paths, modes or native ownership drifted",
        )
    }
    pub fn applicable(
        &self,
        subject: &Subject,
        acceptance: &LocalAcceptance,
    ) -> Result<(), ToolError> {
        self.validate()?;
        acceptance.validate()?;
        require(
            self.root_package == subject.root.package()
                && self.subject_id == subject.id()?
                && self.subject_id == acceptance.subject_id
                && self.acceptance_id == acceptance.id()?
                && self.review_id == acceptance.review_id
                && self.local_user == acceptance.local_user,
            "installation authority or subject mismatch",
        )?;
        acceptance.permits_root(&self.root)?;
        require(
            self.outputs
                .iter()
                .map(|o| o.name.clone())
                .collect::<BTreeSet<_>>()
                == subject.selection.bins.keys().cloned().collect(),
            "installed outputs differ from selected binaries",
        )?;
        require(
            self.installed_at_utc >= acceptance.accepted_at_utc,
            "installation predates acceptance",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOriginalOwner {
    pub family: PackageFamily,
    pub version: String,
    pub git_commit: Option<String>,
    pub native_owner: String,
}
impl NativeOriginalOwner {
    pub fn validate(&self) -> Result<(), ToolError> {
        let parsed = parse_native_original_owner(&self.native_owner)?;
        require(
            *self == parsed,
            "native original-owner fields do not match native record",
        )
    }
}
pub fn parse_native_original_owner(owner: &str) -> Result<NativeOriginalOwner, ToolError> {
    let (identity, source) = owner
        .strip_suffix(')')
        .and_then(|v| v.split_once(" ("))
        .ok_or_else(|| ToolError("unsupported native package owner".into()))?;
    let (package, version) = identity
        .split_once(' ')
        .ok_or_else(|| ToolError("native owner lacks package/version".into()))?;
    name(package)?;
    let parsed = semver::Version::parse(version)
        .map_err(|_| ToolError("invalid native package version".into()))?;
    require(parsed.to_string() == version, "noncanonical native version")?;
    let (family, git_commit) = if matches!(
        source,
        "registry+https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
    ) {
        (
            PackageFamily::CratesIo {
                name: package.into(),
            },
            None,
        )
    } else if let Some(git) = source.strip_prefix("git+") {
        let (url_selector, commit) = git
            .rsplit_once('#')
            .ok_or_else(|| ToolError("native Git owner lacks resolved full commit".into()))?;
        let url = url_selector
            .split_once('?')
            .map_or(url_selector, |(url, _)| url);
        crate::GitSourceIdentity::new(url, commit).map_err(|e| ToolError(e.to_string()))?;
        if let Some((_, selector)) = url_selector.split_once('?') {
            let (kind, value) = selector
                .split_once('=')
                .ok_or_else(|| ToolError("unsupported native Git selector".into()))?;
            require(
                matches!(kind, "rev" | "branch" | "tag")
                    && !value.is_empty()
                    && !value.contains('&')
                    && !value.chars().any(char::is_control),
                "unsupported native Git selector",
            )?;
        }
        (
            PackageFamily::Git {
                url: url.into(),
                package: package.into(),
            },
            Some(commit.into()),
        )
    } else {
        return Err(ToolError(
            "native owner lacks provable original registry/Git source".into(),
        ));
    };
    Ok(NativeOriginalOwner {
        family,
        version: version.into(),
        git_commit,
        native_owner: owner.into(),
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PriorInstallation {
    Absent,
    Known {
        installation_id: RecordId,
        subject_id: RecordId,
        outputs: BTreeSet<OutputObservation>,
    },
    TrackedBootstrap {
        old_package: NativeOriginalOwner,
        new_package: PackageIdentity,
        old_outputs: BTreeSet<OutputObservation>,
    },
}
impl PriorInstallation {
    pub fn outputs(&self) -> BTreeSet<OutputObservation> {
        match self {
            Self::Absent => BTreeSet::new(),
            Self::Known { outputs, .. } => outputs.clone(),
            Self::TrackedBootstrap { old_outputs, .. } => old_outputs.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallIntent {
    pub schema_version: u32,
    pub subject_id: RecordId,
    pub acceptance_id: RecordId,
    pub root: String,
    pub prior: PriorInstallation,
    pub affected_bins: BTreeSet<String>,
}
impl ToolRecord for InstallIntent {
    const KIND: RecordKind = RecordKind::InstallIntent;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.acceptance_id
            .require_kind(RecordKind::LocalAcceptance)?;
        absolute_path(&self.root)?;
        require(
            !self.affected_bins.is_empty(),
            "install intent has no affected outputs",
        )?;
        for bin in &self.affected_bins {
            name(bin)?;
        }
        let mut prior_names = BTreeSet::new();
        for output in self.prior.outputs() {
            require(
                prior_names.insert(output.name.clone()),
                "duplicate prior output name",
            )?;
            output.validate(&self.root)?;
            require(
                self.affected_bins.contains(&output.name),
                "intent omits old output",
            )?;
        }
        match &self.prior {
            PriorInstallation::Absent => {}
            PriorInstallation::Known {
                installation_id,
                subject_id,
                outputs,
            } => {
                installation_id.require_kind(RecordKind::InstalledBinding)?;
                subject_id.require_kind(RecordKind::Subject)?;
                require(!outputs.is_empty(), "known prior binding has no outputs")?;
            }
            PriorInstallation::TrackedBootstrap {
                old_package,
                new_package,
                old_outputs,
            } => {
                old_package.validate()?;
                new_package.validate()?;
                require(
                    old_package.family == new_package.family(),
                    "tracked bootstrap is another source/package family",
                )?;
                require(
                    !old_outputs.is_empty(),
                    "tracked bootstrap has no old outputs",
                )?;
                require(
                    old_outputs
                        .iter()
                        .all(|output| output.native_owner == old_package.native_owner),
                    "bootstrap outputs are owned by another native package",
                )?;
            }
        }
        Ok(())
    }
}

pub fn validate_install_intent(
    intent: &InstallIntent,
    subject: &Subject,
    acceptance: &LocalAcceptance,
    known_prior: Option<&InstalledBinding>,
    observed_old: &BTreeSet<OutputObservation>,
    replace_existing: bool,
) -> Result<(), ToolError> {
    intent.validate()?;
    subject.validate()?;
    acceptance.validate()?;
    require(
        intent.subject_id == subject.id()?
            && intent.acceptance_id == acceptance.id()?
            && acceptance.subject_id == intent.subject_id,
        "intent/acceptance/subject mismatch",
    )?;
    acceptance.permits_root(&intent.root)?;
    validate_affected_scope(intent, subject)?;
    require(
        &intent.prior.outputs() == observed_old,
        "prior output observation changed",
    )?;
    match (&intent.prior, known_prior) {
        (PriorInstallation::Absent, None) => {
            require(observed_old.is_empty(), "unmanaged occupied destination")?
        }
        (
            PriorInstallation::Known {
                installation_id,
                subject_id,
                outputs,
            },
            Some(prior),
        ) => {
            prior.validate()?;
            require(
                prior.root_package.family() == subject.root.package().family(),
                "known update is another source/package family",
            )?;
            require(
                *installation_id == prior.id()?
                    && *subject_id == prior.subject_id
                    && prior.root == intent.root
                    && prior.local_user == acceptance.local_user
                    && *outputs == prior.outputs,
                "known previous binding mismatch",
            )?;
            prior.corresponds(
                observed_old,
                &prior.native_owner,
                &prior.native_tracking_sha256,
            )?;
        }
        (PriorInstallation::TrackedBootstrap { new_package, .. }, None) => {
            require(
                replace_existing,
                "tracked pre-feature replacement requires explicit replace-existing",
            )?;
            require(
                *new_package == subject.root.package(),
                "bootstrap new source does not match accepted subject",
            )?;
        }
        _ => {
            return Err(ToolError(
                "known installation cannot be bypassed by bootstrap or replace-existing".into(),
            ));
        }
    }
    Ok(())
}
fn validate_affected_scope(intent: &InstallIntent, subject: &Subject) -> Result<(), ToolError> {
    let expected: BTreeSet<String> = subject
        .selection
        .bins
        .keys()
        .cloned()
        .chain(
            intent
                .prior
                .outputs()
                .iter()
                .map(|output| output.name.clone()),
        )
        .collect();
    require(
        expected == intent.affected_bins,
        "intent must cover exactly the union of old and new binaries",
    )
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCompletion {
    pub native_success: bool,
    pub cancelled: bool,
    pub inputs_rechecked: bool,
    pub context_rechecked: bool,
    pub outputs: BTreeSet<OutputObservation>,
    pub affected_outputs: BTreeMap<String, Option<OutputObservation>>,
    pub native_owner: String,
    pub native_tracking_sha256: Sha256Digest,
    pub completed_at_utc: i64,
}
pub fn complete_install(
    intent: &InstallIntent,
    subject: &Subject,
    acceptance: &LocalAcceptance,
    completion: &InstallCompletion,
) -> Result<InstalledBinding, ToolError> {
    intent.validate()?;
    subject.validate()?;
    acceptance.validate()?;
    require(
        intent.subject_id == subject.id()? && intent.acceptance_id == acceptance.id()?,
        "completion does not match install intent",
    )?;
    validate_affected_scope(intent, subject)?;
    require(
        completion.native_success
            && !completion.cancelled
            && completion.inputs_rechecked
            && completion.context_rechecked,
        "incomplete or cancelled installation cannot publish binding",
    )?;
    require(
        completion
            .affected_outputs
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            == intent.affected_bins,
        "completion must observe every old/new affected output",
    )?;
    for (name, output) in &completion.affected_outputs {
        if let Some(output) = output {
            output.validate(&intent.root)?;
            require(output.name == *name, "affected output name mismatch")?;
            if !subject.selection.bins.contains_key(name) {
                require(
                    intent.prior.outputs().contains(output),
                    "excluded old output changed unexpectedly",
                )?;
            }
        }
    }
    for output in &completion.outputs {
        require(
            completion.affected_outputs.get(&output.name) == Some(&Some(output.clone())),
            "selected output missing from complete affected observation",
        )?;
    }
    let result = InstalledBinding {
        schema_version: SCHEMA_VERSION,
        root_package: subject.root.package(),
        subject_id: subject.id()?,
        review_id: acceptance.review_id.clone(),
        acceptance_id: acceptance.id()?,
        local_user: acceptance.local_user.clone(),
        root: intent.root.clone(),
        outputs: completion.outputs.clone(),
        native_owner: completion.native_owner.clone(),
        native_tracking_sha256: completion.native_tracking_sha256.clone(),
        installed_at_utc: completion.completed_at_utc,
    };
    result.applicable(subject, acceptance)?;
    Ok(result)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConsumerSelection {
    Direct {
        executable: String,
    },
    ProcessPath {
        path_entries: Vec<String>,
        selected_executable: String,
    },
    CargoExternal {
        subcommand: String,
        cargo: Box<ExecutableIdentity>,
        cargo_path: String,
        cwd: String,
        cargo_home: String,
        config_sha256: Sha256Digest,
        path_entries: Vec<String>,
        selected_executable: String,
    },
}
impl ConsumerSelection {
    pub fn selected_path(&self) -> &str {
        match self {
            Self::Direct { executable } => executable,
            Self::ProcessPath {
                selected_executable,
                ..
            }
            | Self::CargoExternal {
                selected_executable,
                ..
            } => selected_executable,
        }
    }
    pub fn validate(&self) -> Result<(), ToolError> {
        absolute_path(self.selected_path())?;
        match self {
            Self::Direct { .. } => {}
            Self::ProcessPath { path_entries, .. } => {
                validate_path_entries(path_entries)?;
            }
            Self::CargoExternal {
                subcommand,
                cargo,
                cargo_path,
                cwd,
                cargo_home,
                path_entries,
                ..
            } => {
                name(subcommand)?;
                cargo.validate()?;
                absolute_path(cargo_path)?;
                absolute_path(cwd)?;
                absolute_path(cargo_home)?;
                validate_path_entries(path_entries)?;
            }
        }
        Ok(())
    }
}
fn validate_path_entries(entries: &[String]) -> Result<(), ToolError> {
    require(!entries.is_empty(), "empty process PATH")?;
    for entry in entries {
        absolute_path(entry)?;
    }
    Ok(())
}
pub fn check_consumer_selection(
    binding: &InstalledBinding,
    bin: &str,
    selection: &ConsumerSelection,
    selected: &OutputObservation,
) -> Result<(), ToolError> {
    binding.validate()?;
    selection.validate()?;
    name(bin)?;
    let expected = binding
        .outputs
        .iter()
        .find(|o| o.name == bin)
        .ok_or_else(|| ToolError("binary is outside accepted installed scope".into()))?;
    if let ConsumerSelection::CargoExternal { subcommand, .. } = selection {
        require(
            bin == format!("cargo-{subcommand}"),
            "Cargo external subcommand/bin mismatch",
        )?;
    }
    require(
        selection.selected_path() == expected.path && selected == expected,
        "consumer selects a different executable",
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ToolDelta {
    BaselineUnavailable,
    Compared {
        previous_subject: RecordId,
        next_subject: RecordId,
        added: BTreeSet<PackageIdentity>,
        removed: BTreeSet<PackageIdentity>,
        changed_selection: bool,
        changed_graph: bool,
        changed_inputs: bool,
        new_findings: BTreeSet<Finding>,
    },
}
/// The caller establishes local authority and scoped native tracking before supplying a baseline.
pub fn tool_delta(
    next: &Subject,
    next_evidence: &EvidenceContent,
    prior: Option<(
        &Subject,
        &EvidenceContent,
        &InstalledBinding,
        &BTreeSet<OutputObservation>,
    )>,
) -> Result<ToolDelta, ToolError> {
    next.validate()?;
    next_evidence.validate()?;
    require(
        next_evidence.subject_id == next.id()?,
        "delta evidence differs from proposed subject",
    )?;
    let Some((old, old_evidence, binding, observed)) = prior else {
        return Ok(ToolDelta::BaselineUnavailable);
    };
    old.validate()?;
    old_evidence.validate()?;
    binding.corresponds(
        observed,
        &binding.native_owner,
        &binding.native_tracking_sha256,
    )?;
    require(
        binding.subject_id == old.id()?
            && old_evidence.subject_id == old.id()?
            && binding.root_package == old.root.package()
            && old_evidence.complete,
        "delta prior binding/evidence mismatch",
    )?;
    let before = old.graph.packages();
    let after = next.graph.packages();
    Ok(ToolDelta::Compared {
        previous_subject: old.id()?,
        next_subject: next.id()?,
        added: after.difference(&before).cloned().collect(),
        removed: before.difference(&after).cloned().collect(),
        changed_selection: old.selection != next.selection,
        changed_graph: old.graph != next.graph,
        changed_inputs: old.root != next.root
            || old.inputs != next.inputs
            || old.original_lock != next.original_lock
            || old.effective_lock != next.effective_lock
            || old.evaluator != next.evaluator
            || old.config_sha256 != next.config_sha256
            || old.native_mode != next.native_mode,
        new_findings: next_evidence
            .findings
            .difference(&old_evidence.findings)
            .cloned()
            .collect(),
    })
}

pub fn parse_native_v1(input: &str) -> Result<BTreeMap<String, Vec<String>>, ToolError> {
    require(
        input.len() <= MAX_RECORD_BYTES,
        "native ledger exceeds 8 MiB",
    )?;
    let value: toml::Value =
        toml::from_str(input).map_err(|_| ToolError("invalid Cargo native TOML ledger".into()))?;
    let root = value
        .as_table()
        .ok_or_else(|| ToolError("invalid Cargo native ledger table".into()))?;
    require(
        root.len() == 1 && root.contains_key("v1"),
        "unsupported Cargo native ledger schema",
    )?;
    let entries = root["v1"]
        .as_table()
        .ok_or_else(|| ToolError("invalid Cargo native ledger entries".into()))?;
    let mut result = BTreeMap::new();
    let mut names = BTreeSet::new();
    for (owner, bins) in entries {
        text(owner)?;
        let bins = bins
            .as_array()
            .ok_or_else(|| ToolError("invalid Cargo native bins".into()))?;
        let mut output = Vec::new();
        for bin in bins {
            let bin = bin
                .as_str()
                .ok_or_else(|| ToolError("invalid Cargo native bin".into()))?;
            name(bin)?;
            require(
                names.insert(bin.to_owned()),
                "native binary has multiple owners",
            )?;
            output.push(bin.to_owned());
        }
        require(!output.is_empty(), "native owner has no bins")?;
        output.sort();
        result.insert(owner.clone(), output);
    }
    Ok(result)
}
pub fn consumer_config_safe(input: &str, subcommand: &str) -> Result<(), ToolError> {
    require(
        input.len() <= MAX_RECORD_BYTES,
        "Cargo consumer config exceeds 8 MiB",
    )?;
    name(subcommand)?;
    let value: toml::Value =
        toml::from_str(input).map_err(|_| ToolError("invalid Cargo consumer config".into()))?;
    require(
        value.get("include").is_none(),
        "Cargo consumer config includes unsupported indirection",
    )?;
    require(
        value.get("alias").and_then(|v| v.get(subcommand)).is_none(),
        "Cargo consumer alias overrides subcommand",
    )?;
    require(
        value.get("env").is_none(),
        "Cargo consumer config environment redirection is unsupported",
    )?;
    Ok(())
}
