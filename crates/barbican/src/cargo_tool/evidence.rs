use super::{
    record::{schema, text, time},
    *,
};
use crate::{ReviewRecordStatus, Sha256Digest, classify_review_record};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyScope {
    Standalone,
    Repository { governance_id: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginPolicy {
    pub schema_version: u32,
    pub scope: PolicyScope,
    pub policy_sha256: Sha256Digest,
    pub required_checks: BTreeSet<String>,
    pub evaluator_sha256: BTreeSet<Sha256Digest>,
    pub tool_exceptions: BTreeSet<ToolException>,
    pub ioc_exceptions: BTreeSet<ToolIocException>,
}
impl ToolRecord for OriginPolicy {
    const KIND: RecordKind = RecordKind::OriginPolicy;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        if let PolicyScope::Repository { governance_id } = &self.scope {
            text(governance_id)?;
        }
        require(
            !self.required_checks.is_empty() && !self.evaluator_sha256.is_empty(),
            "policy requires checks and trusted evaluator identities",
        )?;
        for check in &self.required_checks {
            text(check)?;
        }
        for exception in &self.tool_exceptions {
            exception.validate()?;
            require(
                exception.policy_sha256 == self.policy_sha256,
                "exception base policy mismatch",
            )?;
        }
        for exception in &self.ioc_exceptions {
            exception.validate()?;
            require(
                exception.policy_sha256 == self.policy_sha256,
                "IOC exception base policy mismatch",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AdvisoryIdentity {
    Assigned { rustsec_id: String },
    Provisional { body_sha256: Sha256Digest },
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum KnowledgeKey {
    Package {
        package: PackageIdentity,
    },
    Advisory {
        package: PackageIdentity,
        source: String,
        identity: AdvisoryIdentity,
    },
    Inspection {
        package: PackageIdentity,
        inspector_sha256: Sha256Digest,
    },
    Ioc {
        package: PackageIdentity,
        finding_id: Sha256Digest,
    },
    Evaluator {
        sha256: Sha256Digest,
    },
}
impl KnowledgeKey {
    pub fn package(&self) -> Option<&PackageIdentity> {
        match self {
            Self::Package { package }
            | Self::Advisory { package, .. }
            | Self::Inspection { package, .. }
            | Self::Ioc { package, .. } => Some(package),
            Self::Evaluator { .. } => None,
        }
    }
    fn source_key(&self) -> (u8, &str, &str, &str, &str, &str, &str, &str) {
        let package = self.package().map(package_scope);
        let (name, version, url, rev, subdirectory) = package.unwrap_or(("", "", "", "", ""));
        match self {
            Self::Package { .. } => (0, name, version, url, rev, subdirectory, "", ""),
            Self::Inspection {
                inspector_sha256, ..
            } => (
                1,
                name,
                version,
                url,
                rev,
                subdirectory,
                inspector_sha256.as_str(),
                "",
            ),
            Self::Advisory {
                source, identity, ..
            } => match identity {
                AdvisoryIdentity::Assigned { rustsec_id } => {
                    (2, name, version, url, rev, subdirectory, source, rustsec_id)
                }
                AdvisoryIdentity::Provisional { body_sha256 } => (
                    3,
                    name,
                    version,
                    url,
                    rev,
                    subdirectory,
                    source,
                    body_sha256.as_str(),
                ),
            },
            Self::Ioc { finding_id, .. } => (
                5,
                name,
                version,
                url,
                rev,
                subdirectory,
                finding_id.as_str(),
                "",
            ),
            Self::Evaluator { sha256 } => (4, sha256.as_str(), "", "", "", "", "", ""),
        }
    }
    fn validate(&self) -> Result<(), ToolError> {
        match self {
            Self::Package { package }
            | Self::Inspection { package, .. }
            | Self::Ioc { package, .. } => package.validate(),
            Self::Advisory {
                package,
                source,
                identity,
            } => {
                package.validate()?;
                text(source)?;
                match identity {
                    AdvisoryIdentity::Assigned { rustsec_id } => {
                        crate::RustSecAdvisoryId::parse(rustsec_id)
                            .map(|_| ())
                            .map_err(|e| ToolError(e.to_string()))
                    }
                    AdvisoryIdentity::Provisional { .. } => Ok(()),
                }
            }
            Self::Evaluator { .. } => Ok(()),
        }
    }
}
fn package_scope(package: &PackageIdentity) -> (&str, &str, &str, &str, &str) {
    match &package.source {
        PackageSource::CratesIo { .. } => (&package.name, &package.version, "crates.io", "", ""),
        PackageSource::Git {
            url,
            rev,
            subdirectory,
            ..
        } => (&package.name, &package.version, url, rev, subdirectory),
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityStatus {
    Clear,
    Adverse,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFact {
    pub key: KnowledgeKey,
    pub facts_sha256: Sha256Digest,
    pub status: SecurityStatus,
    pub expires_at_utc: Option<i64>,
}
impl SourceFact {
    pub fn semantic_sha256(&self) -> Result<Sha256Digest, ToolError> {
        Ok(sha256(&canonical_bytes(self)?))
    }
    fn validate(&self) -> Result<(), ToolError> {
        self.key.validate()?;
        if let KnowledgeKey::Ioc { finding_id, .. } = &self.key {
            require(
                self.status == SecurityStatus::Adverse && self.facts_sha256 == *finding_id,
                "raw IOC facts retain exact adverse finding identity",
            )?;
        }
        if let Some(expiry) = self.expires_at_utc {
            time(expiry)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Checksum,
    Yank,
    Ioc,
    RequiredCoverage,
    Advisory,
    ReleaseAge,
    SourceReview,
    ExecutionSurface,
    ResidualRisk,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub identity: String,
    pub package: PackageIdentity,
    pub kind: FindingKind,
    pub blocking: bool,
    pub detail_sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExceptionKind {
    ReleaseAge,
    Advisory {
        identity: String,
        detail_sha256: Sha256Digest,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolException {
    pub subject_id: RecordId,
    pub package: PackageIdentity,
    pub policy_sha256: Sha256Digest,
    pub exception: ExceptionKind,
    pub expires_at_utc: i64,
    pub reviewed_at_utc: i64,
    pub reviewer: String,
    pub review_record: String,
    pub review_record_sha256: Sha256Digest,
}
impl ToolException {
    pub fn validate(&self) -> Result<(), ToolError> {
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.package.validate()?;
        require(
            matches!(self.package.source, PackageSource::CratesIo { .. }),
            "Git cannot inherit registry advisory/age exception",
        )?;
        text(&self.reviewer)?;
        completed(&self.review_record)?;
        require(
            sha256(self.review_record.as_bytes()) == self.review_record_sha256,
            "exception completed record digest mismatch",
        )?;
        time(self.reviewed_at_utc)?;
        time(self.expires_at_utc)?;
        require(
            self.expires_at_utc > self.reviewed_at_utc,
            "exception needs finite future expiry",
        )?;
        if let ExceptionKind::Advisory { identity, .. } = &self.exception {
            crate::RustSecAdvisoryId::parse(identity).map_err(|e| ToolError(e.to_string()))?;
        }
        Ok(())
    }
    pub fn applies_to(
        &self,
        finding: &Finding,
        subject_id: &RecordId,
        policy_sha256: &Sha256Digest,
        now: i64,
    ) -> Result<bool, ToolError> {
        self.validate()?;
        time(now)?;
        Ok(self.subject_id == *subject_id
            && self.package == finding.package
            && self.policy_sha256 == *policy_sha256
            && self.reviewed_at_utc <= now
            && now < self.expires_at_utc
            && self.matches_kind(finding))
    }
    fn matches_kind(&self, finding: &Finding) -> bool {
        match &self.exception {
            ExceptionKind::ReleaseAge => finding.kind == FindingKind::ReleaseAge,
            ExceptionKind::Advisory {
                identity,
                detail_sha256,
            } => {
                finding.kind == FindingKind::Advisory
                    && finding.identity == *identity
                    && finding.detail_sha256 == *detail_sha256
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContent {
    pub schema_version: u32,
    pub subject_id: RecordId,
    pub policy_id: RecordId,
    pub evaluator_sha256: BTreeSet<Sha256Digest>,
    pub covered_checks: BTreeSet<String>,
    pub facts: BTreeSet<SourceFact>,
    pub findings: BTreeSet<Finding>,
    pub complete: bool,
}
impl ToolRecord for EvidenceContent {
    const KIND: RecordKind = RecordKind::EvidenceContent;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.policy_id.require_kind(RecordKind::OriginPolicy)?;
        require(!self.evaluator_sha256.is_empty(), "missing evaluator")?;
        let mut keys = BTreeSet::new();
        for fact in &self.facts {
            fact.validate()?;
            require(
                keys.insert(fact.key.source_key()),
                "conflicting duplicate source fact",
            )?;
        }
        let mut findings = BTreeSet::new();
        for f in &self.findings {
            text(&f.identity)?;
            f.package.validate()?;
            require(
                findings.insert((&f.identity, &f.package)),
                "duplicate finding identity",
            )?;
            require(
                f.blocking
                    || !matches!(
                        f.kind,
                        FindingKind::Checksum | FindingKind::Yank | FindingKind::RequiredCoverage
                    ),
                "hard security finding cannot be nonblocking",
            )?;
        }
        Ok(())
    }
}
impl EvidenceContent {
    pub fn applicable(&self, subject: &Subject, policy: &OriginPolicy) -> Result<(), ToolError> {
        let index = ToolIocIndex::structural(policy, &self.subject_id)?;
        self.applicable_with_ioc(subject, policy, &index)
            .map(|_| ())
    }
    fn applicable_with_ioc<'a>(
        &'a self,
        subject: &Subject,
        policy: &OriginPolicy,
        index: &ToolIocIndex,
    ) -> Result<IocContentIndex<'a>, ToolError> {
        self.validate()?;
        require(
            index.subject_id == self.subject_id && index.policy_sha256 == policy.policy_sha256,
            "IOC index authority differs from evidence",
        )?;
        require(
            self.subject_id == subject.id()? && self.policy_id == policy.id()?,
            "evidence subject or policy mismatch",
        )?;
        require(self.complete, "incomplete evidence")?;
        require(
            self.evaluator_sha256 == policy.evaluator_sha256,
            "evaluator set changed",
        )?;
        require(
            policy.required_checks.is_subset(&self.covered_checks),
            "required policy coverage missing",
        )?;
        require(
            !self.findings.iter().any(|f| f.blocking),
            "blocking security finding",
        )?;
        for finding in &self.findings {
            if matches!(
                finding.kind,
                FindingKind::Advisory | FindingKind::ReleaseAge
            ) {
                require(
                    policy.tool_exceptions.iter().any(|exception| {
                        exception.subject_id == self.subject_id
                            && exception.package == finding.package
                            && exception.policy_sha256 == policy.policy_sha256
                            && exception.matches_kind(finding)
                    }),
                    "nonblocking advisory/age finding lacks exact completed tool exception",
                )?;
            }
        }
        let mut covered_iocs = BTreeSet::new();
        for finding in self.findings.iter().filter(|f| f.kind == FindingKind::Ioc) {
            require(
                index.allows(finding),
                "IOC finding lacks exact current completed allowance",
            )?;
            covered_iocs.insert((&finding.package, &finding.detail_sha256));
        }
        let packages = subject.graph.packages();
        let fact_keys: BTreeSet<_> = self.facts.iter().map(|fact| &fact.key).collect();
        for package in &packages {
            require(
                fact_keys.contains(&KnowledgeKey::Package {
                    package: package.clone(),
                }),
                "graph package security facts missing",
            )?;
        }
        for evaluator in &self.evaluator_sha256 {
            require(
                fact_keys.contains(&KnowledgeKey::Evaluator {
                    sha256: evaluator.clone(),
                }),
                "trusted evaluator status missing",
            )?;
        }
        require(
            self.findings.iter().all(|f| packages.contains(&f.package)),
            "finding outside exact graph",
        )?;
        require(
            self.facts.iter().all(|fact| {
                fact.status == SecurityStatus::Clear
                    || fact_exception_covered(fact, self, policy, &covered_iocs)
            }),
            "adverse or unavailable source/evaluator facts",
        )?;
        Ok(covered_iocs)
    }
}
type IocContentIndex<'a> = BTreeSet<(&'a PackageIdentity, &'a Sha256Digest)>;
fn fact_exception_covered(
    fact: &SourceFact,
    content: &EvidenceContent,
    policy: &OriginPolicy,
    covered_iocs: &IocContentIndex<'_>,
) -> bool {
    if fact.status != SecurityStatus::Adverse {
        return false;
    }
    if let KnowledgeKey::Ioc {
        package,
        finding_id,
    } = &fact.key
    {
        return fact.facts_sha256 == *finding_id && covered_iocs.contains(&(package, finding_id));
    }
    let KnowledgeKey::Advisory {
        package,
        identity: AdvisoryIdentity::Assigned { rustsec_id },
        ..
    } = &fact.key
    else {
        return false;
    };
    content.findings.iter().any(|finding| {
        finding.kind == FindingKind::Advisory
            && !finding.blocking
            && finding.package == *package
            && finding.identity == *rustsec_id
            && finding.detail_sha256 == fact.facts_sha256
            && policy.tool_exceptions.iter().any(|exception| {
                exception.subject_id == content.subject_id
                    && exception.package == *package
                    && exception.policy_sha256 == policy.policy_sha256
                    && exception.matches_kind(finding)
            })
    })
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservation {
    pub key: KnowledgeKey,
    pub semantic_sha256: Sha256Digest,
    pub source_version: u64,
    pub checked_at_utc: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub content_id: RecordId,
    pub sources: BTreeSet<SourceObservation>,
    pub completed_at_utc: i64,
    pub fresh_until_utc: i64,
}
pub type EvidenceObservation = Observation;
impl ToolRecord for Observation {
    const KIND: RecordKind = RecordKind::Observation;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.content_id.require_kind(RecordKind::EvidenceContent)?;
        time(self.completed_at_utc)?;
        time(self.fresh_until_utc)?;
        require(
            self.fresh_until_utc >= self.completed_at_utc,
            "observation freshness precedes completion",
        )?;
        let mut keys = BTreeSet::new();
        for source in &self.sources {
            source.key.validate()?;
            time(source.checked_at_utc)?;
            require(
                source.checked_at_utc <= self.completed_at_utc,
                "source observation follows collection completion",
            )?;
            require(
                keys.insert(source.key.source_key()),
                "duplicate observation source",
            )?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub content: EvidenceContent,
    pub observation: Observation,
}
impl EvidenceRecord {
    pub fn content_id(&self) -> Result<RecordId, ToolError> {
        self.content.id()
    }
    pub fn validate(&self) -> Result<(), ToolError> {
        self.content.validate()?;
        self.observation.validate()?;
        require(
            self.content_id()? == self.observation.content_id,
            "observation/content mismatch",
        )?;
        require(
            self.content.facts.len() == self.observation.sources.len(),
            "incomplete source observations",
        )?;
        let observations: BTreeMap<_, _> = self
            .observation
            .sources
            .iter()
            .map(|observation| (&observation.key, observation))
            .collect();
        for fact in &self.content.facts {
            require(
                observations.get(&fact.key).is_some_and(|observation| {
                    fact.semantic_sha256()
                        .is_ok_and(|digest| digest == observation.semantic_sha256)
                }),
                "source observation does not bind semantic facts",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEntry {
    pub fact: SourceFact,
    pub source_version: u64,
    pub checked_at_utc: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConflict {
    pub key: KnowledgeKey,
    pub retained_fact_sha256: Sha256Digest,
    pub observed_fact_sha256: Sha256Digest,
    pub retained_source_version: u64,
    pub observed_source_version: u64,
    pub detected_at_utc: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceKnowledge {
    pub schema_version: u32,
    pub entries: Vec<KnowledgeEntry>,
    pub conflicts: Vec<SourceConflict>,
    pub last_clock_utc: i64,
}
impl Default for SourceKnowledge {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
            conflicts: Vec::new(),
            last_clock_utc: 0,
        }
    }
}
impl ToolRecord for SourceKnowledge {
    const KIND: RecordKind = RecordKind::SourceKnowledge;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        time(self.last_clock_utc)?;
        require(
            self.entries.len() <= MAX_GRAPH_NODES * 4,
            "source knowledge budget exceeded",
        )?;
        let mut last = None;
        for entry in &self.entries {
            entry.fact.validate()?;
            time(entry.checked_at_utc)?;
            require(
                entry.checked_at_utc <= self.last_clock_utc,
                "source knowledge clock mismatch",
            )?;
            if let Some(key) = last {
                require(
                    key < entry.fact.key.source_key(),
                    "source knowledge keys must be unique and sorted",
                )?;
            }
            last = Some(entry.fact.key.source_key());
        }
        require(
            self.conflicts.len() <= MAX_GRAPH_NODES * 4,
            "source conflict budget exceeded",
        )?;
        let mut last = None;
        for conflict in &self.conflicts {
            conflict.key.validate()?;
            time(conflict.detected_at_utc)?;
            require(
                conflict.detected_at_utc <= self.last_clock_utc,
                "future retained source conflict",
            )?;
            if let Some(key) = last {
                require(
                    key < conflict.key.source_key(),
                    "source conflicts must be unique and sorted",
                )?;
            }
            last = Some(conflict.key.source_key());
        }
        Ok(())
    }
}
impl SourceKnowledge {
    pub fn entry_for(&self, key: &KnowledgeKey) -> Option<&KnowledgeEntry> {
        self.entries
            .binary_search_by(|entry| entry.fact.key.source_key().cmp(&key.source_key()))
            .ok()
            .map(|index| &self.entries[index])
    }
    /// Persist immediately after authenticated collection, including when this returns an error:
    /// a contradictory source leaves a durable conflict tombstone instead of losing adverse facts.
    pub fn remember(&mut self, entry: KnowledgeEntry, now: i64) -> Result<(), ToolError> {
        self.validate()?;
        time(now)?;
        require(now >= self.last_clock_utc, "clock rollback")?;
        entry.fact.validate()?;
        time(entry.checked_at_utc)?;
        require(entry.checked_at_utc <= now, "future source check")?;
        let position = self
            .entries
            .binary_search_by(|old| old.fact.key.source_key().cmp(&entry.fact.key.source_key()));
        let conflict_position = self.conflicts.binary_search_by(|conflict| {
            conflict.key.source_key().cmp(&entry.fact.key.source_key())
        });
        require(
            conflict_position.is_err(),
            "retained source conflict requires independent remediation",
        )?;
        if let Ok(index) = position {
            let old = &self.entries[index];
            let conflict = if entry.source_version < old.source_version
                || entry.checked_at_utc < old.checked_at_utc
            {
                Some("source rollback")
            } else if entry.source_version == old.source_version && entry.fact != old.fact {
                Some("same-version conflicting source facts")
            } else if entry.checked_at_utc == old.checked_at_utc && entry != *old {
                Some("same-time conflicting source observation")
            } else {
                None
            };
            if let Some(reason) = conflict {
                require(
                    self.conflicts.len() < MAX_GRAPH_NODES * 4,
                    "source conflict budget exceeded",
                )?;
                let retained = SourceConflict {
                    key: entry.fact.key.clone(),
                    retained_fact_sha256: old.fact.semantic_sha256()?,
                    observed_fact_sha256: entry.fact.semantic_sha256()?,
                    retained_source_version: old.source_version,
                    observed_source_version: entry.source_version,
                    detected_at_utc: now,
                };
                self.conflicts.insert(
                    conflict_position.expect_err("known absent conflict"),
                    retained,
                );
                self.last_clock_utc = now;
                return Err(ToolError(reason.into()));
            }
        }
        match position {
            Ok(index) => self.entries[index] = entry,
            Err(index) => {
                require(
                    self.entries.len() < MAX_GRAPH_NODES * 4,
                    "source knowledge budget exceeded",
                )?;
                self.entries.insert(index, entry);
            }
        }
        self.last_clock_utc = now;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    Accept,
    Install,
    NewAdmission,
    ContinuingUse,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FreshnessIntent {
    Online { started_at_utc: i64 },
    Cached { reason: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIntent {
    pub operation: OperationKind,
    pub freshness: FreshnessIntent,
}

pub fn check_eligibility(
    subject: &Subject,
    policy: &OriginPolicy,
    evidence: &EvidenceRecord,
    knowledge: &SourceKnowledge,
    intent: &OperationIntent,
    now: i64,
) -> Result<(), ToolError> {
    check_eligibility_checked(
        subject,
        policy,
        evidence,
        knowledge,
        intent,
        now,
        &mut || Ok(()),
    )
}
pub fn check_eligibility_checked(
    subject: &Subject,
    policy: &OriginPolicy,
    evidence: &EvidenceRecord,
    knowledge: &SourceKnowledge,
    intent: &OperationIntent,
    now: i64,
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), ToolError> {
    check().map_err(ToolError)?;
    subject.validate()?;
    policy.validate()?;
    evidence.validate()?;
    knowledge.validate()?;
    time(now)?;
    require(
        now >= knowledge.last_clock_utc && now >= evidence.observation.completed_at_utc,
        "clock rollback or future evidence",
    )?;
    let ioc_index = ToolIocIndex::prepare(policy, &evidence.content.subject_id, now, check)?;
    let covered_iocs = evidence
        .content
        .applicable_with_ioc(subject, policy, &ioc_index)?;
    for finding in &evidence.content.findings {
        if matches!(
            finding.kind,
            FindingKind::Advisory | FindingKind::ReleaseAge
        ) {
            require(
                policy.tool_exceptions.iter().any(|exception| {
                    exception
                        .applies_to(
                            finding,
                            &evidence.content.subject_id,
                            &policy.policy_sha256,
                            now,
                        )
                        .unwrap_or(false)
                }),
                "tool exception expired or inapplicable",
            )?;
        }
    }
    let packages = subject.graph.packages();
    let package_scopes: BTreeSet<_> = packages.iter().map(package_scope).collect();
    let relevant_key = |key: &KnowledgeKey| match key {
        KnowledgeKey::Evaluator { sha256 } => policy.evaluator_sha256.contains(sha256),
        key => key
            .package()
            .is_some_and(|package| package_scopes.contains(&package_scope(package))),
    };
    require(
        !knowledge
            .conflicts
            .iter()
            .any(|conflict| relevant_key(&conflict.key)),
        "retained source conflict invalidates this tool",
    )?;
    for entry in &knowledge.entries {
        check().map_err(ToolError)?;
        let relevant = match &entry.fact.key {
            KnowledgeKey::Evaluator { sha256 } => policy.evaluator_sha256.contains(sha256),
            key => key
                .package()
                .is_some_and(|package| package_scopes.contains(&package_scope(package))),
        };
        if relevant && entry.fact.status != SecurityStatus::Clear {
            require(
                evidence.content.facts.contains(&entry.fact)
                    && fact_exception_covered(
                        &entry.fact,
                        &evidence.content,
                        policy,
                        &covered_iocs,
                    ),
                "retained adverse source/evaluator knowledge requires current exact review",
            )?;
        }
    }
    let observations: BTreeMap<_, _> = evidence
        .observation
        .sources
        .iter()
        .map(|observation| (&observation.key, observation))
        .collect();
    for fact in &evidence.content.facts {
        check().map_err(ToolError)?;
        let observed = observations
            .get(&fact.key)
            .ok_or_else(|| ToolError("source observation missing".into()))?;
        let latest = knowledge
            .entry_for(&fact.key)
            .ok_or_else(|| ToolError("source knowledge missing".into()))?;
        require(
            latest.source_version >= observed.source_version
                && latest.checked_at_utc >= observed.checked_at_utc,
            "observation ahead of durable source knowledge",
        )?;
        require(
            latest.fact == *fact,
            "newer changed or adverse source knowledge requires fresh review",
        )?;
        require(
            fact.expires_at_utc.is_none_or(|expiry| now < expiry),
            "source-imposed expiry reached",
        )?;
        if intent.operation != OperationKind::ContinuingUse {
            require(
                now <= evidence.observation.fresh_until_utc,
                "evidence freshness expired",
            )?;
            require(
                matches!(fact.key, KnowledgeKey::Ioc { .. })
                    || now
                        .checked_sub(observed.checked_at_utc)
                        .is_some_and(|age| age <= MAX_CACHE_SECONDS),
                "source observation exceeds 24-hour bound",
            )?;
            match &intent.freshness {
                FreshnessIntent::Online { started_at_utc } => {
                    time(*started_at_utc)?;
                    require(
                        *started_at_utc <= now
                            && (matches!(fact.key, KnowledgeKey::Ioc { .. })
                                || observed.checked_at_utc >= *started_at_utc),
                        "required online refresh not completed for this operation",
                    )?;
                }
                FreshnessIntent::Cached { reason } => text(reason)?,
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema_version: u32,
    pub subject_id: RecordId,
    pub policy_id: RecordId,
    pub evidence_content_id: RecordId,
    pub assessment_requirements: BTreeSet<String>,
}
impl ToolRecord for Review {
    const KIND: RecordKind = RecordKind::Review;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.policy_id.require_kind(RecordKind::OriginPolicy)?;
        self.evidence_content_id
            .require_kind(RecordKind::EvidenceContent)?;
        require(
            !self.assessment_requirements.is_empty(),
            "assessment requirements missing",
        )?;
        for item in &self.assessment_requirements {
            text(item)?;
        }
        Ok(())
    }
}
impl Review {
    pub fn applicable(
        &self,
        subject: &Subject,
        policy: &OriginPolicy,
        content: &EvidenceContent,
    ) -> Result<(), ToolError> {
        self.validate()?;
        require(
            self.subject_id == subject.id()?
                && self.policy_id == policy.id()?
                && self.evidence_content_id == content.id()?,
            "review no longer matches subject/policy/evidence",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema_version: u32,
    pub review_id: RecordId,
    pub reviewer: String,
    pub completed_at_utc: i64,
    pub prose: String,
    pub responses: BTreeMap<String, String>,
}
impl ToolRecord for Assessment {
    const KIND: RecordKind = RecordKind::Assessment;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.review_id.require_kind(RecordKind::Review)?;
        text(&self.reviewer)?;
        time(self.completed_at_utc)?;
        completed(&self.prose)?;
        require(!self.responses.is_empty(), "assessment responses missing")?;
        for (key, response) in &self.responses {
            text(key)?;
            completed(response)?;
        }
        Ok(())
    }
}
fn completed(value: &str) -> Result<(), ToolError> {
    require(
        classify_review_record(Some(value)) == ReviewRecordStatus::Completed,
        "assessment is pending or empty",
    )?;
    require(
        !value.lines().any(|line| {
            matches!(
                line.trim().to_ascii_uppercase().as_str(),
                "PENDING" | "TODO" | "TBD"
            )
        }),
        "assessment contains incomplete response",
    )
}
impl Assessment {
    pub fn applicable(&self, review: &Review, now: i64) -> Result<(), ToolError> {
        self.validate()?;
        require(
            self.review_id == review.id()?,
            "assessment belongs to another review",
        )?;
        require(self.completed_at_utc <= now, "future human assessment")?;
        require(
            self.responses.keys().cloned().collect::<BTreeSet<_>>()
                == review.assessment_requirements,
            "assessment requirements not completed exactly",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DeploymentScope {
    OrdinaryCargoRoots,
    Roots { roots: BTreeSet<String> },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAcceptance {
    pub schema_version: u32,
    pub review_id: RecordId,
    pub assessment_id: RecordId,
    pub subject_id: RecordId,
    pub evidence_content_id: RecordId,
    pub policy_id: RecordId,
    pub local_user: String,
    pub accepted_at_utc: i64,
    pub deployment: DeploymentScope,
    pub risk_acknowledgement: String,
}
impl ToolRecord for LocalAcceptance {
    const KIND: RecordKind = RecordKind::LocalAcceptance;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        self.review_id.require_kind(RecordKind::Review)?;
        self.assessment_id.require_kind(RecordKind::Assessment)?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.evidence_content_id
            .require_kind(RecordKind::EvidenceContent)?;
        self.policy_id.require_kind(RecordKind::OriginPolicy)?;
        text(&self.local_user)?;
        time(self.accepted_at_utc)?;
        completed(&self.risk_acknowledgement)?;
        if let DeploymentScope::Roots { roots } = &self.deployment {
            require(!roots.is_empty(), "empty deployment scope")?;
            for root in roots {
                super::record::absolute_path(root)?;
            }
        }
        Ok(())
    }
}
impl LocalAcceptance {
    pub fn applicable(
        &self,
        review: &Review,
        assessment: &Assessment,
        local_user: &str,
        now: i64,
    ) -> Result<(), ToolError> {
        self.validate()?;
        assessment.applicable(review, now)?;
        require(
            self.review_id == review.id()?
                && self.assessment_id == assessment.id()?
                && self.subject_id == review.subject_id
                && self.evidence_content_id == review.evidence_content_id
                && self.policy_id == review.policy_id,
            "local acceptance binding changed",
        )?;
        require(
            self.local_user == local_user,
            "another user's local acceptance",
        )?;
        require(
            self.accepted_at_utc >= assessment.completed_at_utc && self.accepted_at_utc <= now,
            "invalid local acceptance time",
        )
    }
    pub fn permits_root(&self, root: &str) -> Result<(), ToolError> {
        super::record::absolute_path(root)?;
        match &self.deployment {
            DeploymentScope::OrdinaryCargoRoots => Ok(()),
            DeploymentScope::Roots { roots } => require(
                roots.contains(root),
                "installation root outside accepted deployment scope",
            ),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoAdmission {
    pub schema_version: u32,
    pub governance_id: String,
    pub review_id: RecordId,
    pub assessment_id: RecordId,
    pub subject_id: RecordId,
    pub evidence_content_id: RecordId,
    pub policy_id: RecordId,
    pub portable_record_sha256: BTreeSet<Sha256Digest>,
    pub approved_by: String,
    pub approved_at_utc: i64,
}
impl ToolRecord for RepoAdmission {
    const KIND: RecordKind = RecordKind::RepoAdmission;
    fn validate(&self) -> Result<(), ToolError> {
        schema(self.schema_version)?;
        text(&self.governance_id)?;
        text(&self.approved_by)?;
        time(self.approved_at_utc)?;
        self.review_id.require_kind(RecordKind::Review)?;
        self.assessment_id.require_kind(RecordKind::Assessment)?;
        self.subject_id.require_kind(RecordKind::Subject)?;
        self.evidence_content_id
            .require_kind(RecordKind::EvidenceContent)?;
        self.policy_id.require_kind(RecordKind::OriginPolicy)?;
        require(
            !self.portable_record_sha256.is_empty(),
            "repository portable evidence missing",
        )
    }
}
impl RepoAdmission {
    pub fn applicable(
        &self,
        review: &Review,
        assessment: &Assessment,
        policy: &OriginPolicy,
        governance_id: &str,
        now: i64,
    ) -> Result<(), ToolError> {
        self.validate()?;
        assessment.applicable(review, now)?;
        require(
            self.governance_id == governance_id
                && policy.scope
                    == PolicyScope::Repository {
                        governance_id: governance_id.into(),
                    },
            "repository governance mismatch",
        )?;
        require(
            self.review_id == review.id()?
                && self.assessment_id == assessment.id()?
                && self.subject_id == review.subject_id
                && self.evidence_content_id == review.evidence_content_id
                && self.policy_id == policy.id()?
                && review.policy_id == self.policy_id,
            "repository admission binding changed",
        )?;
        require(
            self.approved_at_utc >= assessment.completed_at_utc && self.approved_at_utc <= now,
            "invalid repository approval time",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIocException {
    pub subject_id: RecordId,
    pub policy_sha256: Sha256Digest,
    pub allowance: crate::ioc::Allowance,
}
impl ToolIocException {
    pub fn validate(&self) -> Result<(), ToolError> {
        self.subject_id.require_kind(RecordKind::Subject)?;
        let reviewed = self
            .allowance
            .record
            .reviewed_at_utc
            .ok_or_else(|| ToolError("pending IOC review".into()))?;
        self.allowance
            .record
            .validate_completed(reviewed)
            .map_err(ToolError)
    }
    pub fn applies_to(
        &self,
        finding: &Finding,
        subject: &RecordId,
        policy: &Sha256Digest,
        now: i64,
    ) -> Result<bool, ToolError> {
        if self.subject_id != *subject || self.policy_sha256 != *policy {
            return Ok(false);
        }
        self.subject_id.require_kind(RecordKind::Subject)?;
        let index = crate::ioc::index_allowances_checked(
            std::iter::once(&self.allowance),
            now,
            &mut || Ok(()),
        )
        .map_err(ToolError)?;
        Ok(ioc_index_allows(&index, finding))
    }
}

impl SourceKnowledge {
    pub fn ioc_decision(
        &self,
        sources: &[crate::ioc::Source],
        allowances: &[crate::ioc::Allowance],
        now: i64,
    ) -> Result<crate::ioc::Decision, ToolError> {
        let index = crate::ioc::index_allowances(allowances, now).map_err(ToolError)?;
        self.ioc_decision_indexed(sources, &index, now)
    }
    pub fn ioc_decision_indexed(
        &self,
        sources: &[crate::ioc::Source],
        index: &crate::ioc::AllowanceIndex,
        now: i64,
    ) -> Result<crate::ioc::Decision, ToolError> {
        self.validate()?;
        time(now)?;
        require(
            now >= self.last_clock_utc,
            "clock rollback during IOC knowledge check",
        )?;
        let packages: Vec<_> = sources.iter().map(PackageIdentity::from).collect();
        let scopes: BTreeSet<_> = packages.iter().map(package_scope).collect();
        let relevant = |key: &KnowledgeKey| {
            key.package()
                .is_some_and(|p| scopes.contains(&package_scope(p)))
        };
        let mut decision = crate::ioc::Decision {
            complete: true,
            allowed: BTreeSet::new(),
            blocked: BTreeSet::new(),
            errors: vec![],
        };
        for conflict in self.conflicts.iter().filter(|c| relevant(&c.key)) {
            if matches!(
                conflict.key,
                KnowledgeKey::Ioc { .. } | KnowledgeKey::Inspection { .. }
            ) {
                decision
                    .errors
                    .push("retained IOC/inspection conflict".into());
            }
        }
        for entry in self.entries.iter().filter(|e| relevant(&e.fact.key)) {
            if let KnowledgeKey::Ioc {
                package,
                finding_id,
            } = &entry.fact.key
            {
                require(
                    entry.fact.status == SecurityStatus::Adverse
                        && entry.fact.facts_sha256 == *finding_id,
                    "invalid raw IOC knowledge",
                )?;
                let source_id = crate::ioc::Source::from(package).id().map_err(ToolError)?;
                let allowed = index.allowed.contains(&(source_id, finding_id.clone()));
                if allowed {
                    decision.allowed.insert(finding_id.clone());
                } else {
                    decision.blocked.insert(finding_id.clone());
                }
            } else if matches!(entry.fact.key, KnowledgeKey::Inspection { .. })
                && entry.fact.status != SecurityStatus::Clear
            {
                decision
                    .errors
                    .push("retained unresolved source inspection cause".into());
            }
        }
        Ok(decision)
    }
}

pub struct ToolIocIndex {
    subject_id: RecordId,
    policy_sha256: Sha256Digest,
    index: crate::ioc::AllowanceIndex,
}
impl ToolIocIndex {
    pub fn prepare(
        policy: &OriginPolicy,
        subject: &RecordId,
        now: i64,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Self, ToolError> {
        subject.require_kind(RecordKind::Subject)?;
        let allowances = policy
            .ioc_exceptions
            .iter()
            .filter(|exception| {
                exception.subject_id == *subject && exception.policy_sha256 == policy.policy_sha256
            })
            .map(|exception| &exception.allowance);
        let index =
            crate::ioc::index_allowances_checked(allowances, now, check).map_err(ToolError)?;
        Ok(Self {
            subject_id: subject.clone(),
            policy_sha256: policy.policy_sha256.clone(),
            index,
        })
    }
    fn structural(policy: &OriginPolicy, subject: &RecordId) -> Result<Self, ToolError> {
        subject.require_kind(RecordKind::Subject)?;
        let allowances = policy
            .ioc_exceptions
            .iter()
            .filter(|exception| {
                exception.subject_id == *subject && exception.policy_sha256 == policy.policy_sha256
            })
            .map(|exception| &exception.allowance);
        let index = crate::ioc::index_allowances_structural(allowances).map_err(ToolError)?;
        Ok(Self {
            subject_id: subject.clone(),
            policy_sha256: policy.policy_sha256.clone(),
            index,
        })
    }
    pub fn allows(&self, finding: &Finding) -> bool {
        ioc_index_allows(&self.index, finding)
    }
}
fn ioc_index_allows(index: &crate::ioc::AllowanceIndex, finding: &Finding) -> bool {
    if finding.kind != FindingKind::Ioc || finding.identity != finding.detail_sha256.as_str() {
        return false;
    }
    let Ok(source_id) = crate::ioc::Source::from(&finding.package).id() else {
        return false;
    };
    !index.errors.contains_key(&source_id)
        && index
            .allowed
            .contains(&(source_id, finding.detail_sha256.clone()))
}
