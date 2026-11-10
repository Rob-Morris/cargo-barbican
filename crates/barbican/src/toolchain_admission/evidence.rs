use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Authentication,
    Publication,
    ReleaseNotes,
    SecurityAnnouncements,
    SourceIdentity,
    Advisories,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceId {
    pub kind: SourceKind,
    /// `distribution`, or the exact selected `package/target` pair.
    pub scope: String,
}

pub fn required_sources(subject: &Subject) -> BTreeSet<SourceId> {
    let mut sources = BTreeSet::new();
    for kind in [
        SourceKind::Authentication,
        SourceKind::Publication,
        SourceKind::ReleaseNotes,
        SourceKind::SecurityAnnouncements,
    ] {
        sources.insert(SourceId {
            kind,
            scope: "distribution".into(),
        });
    }
    for archive in &subject.record().archives {
        for kind in [SourceKind::SourceIdentity, SourceKind::Advisories] {
            sources.insert(SourceId {
                kind,
                scope: format!("{}/{}", archive.package, archive.target),
            });
        }
    }
    sources
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectionStatus {
    Completed,
    Missing,
    Failed,
    Inapplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Covered,
    ResidualUnknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingChange {
    New,
    PreExisting,
    Resolved,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    Known,
    Unknown,
    NotApplicable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub source: SourceId,
    pub change: FindingChange,
    pub exposure: Exposure,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservation {
    pub source: SourceId,
    pub location: String,
    pub provenance: String,
    pub revision: String,
    pub content_sha256: Sha256Digest,
    pub snapshot: RecordReference,
    pub status: CollectionStatus,
    pub coverage: Coverage,
    pub coverage_rationale: String,
    /// Successful retrieval/verification time, never the time of a cache read.
    pub checked_at: i64,
    pub expires_at: Option<i64>,
}
impl SourceObservation {
    pub fn content_id(&self) -> Result<Sha256Digest> {
        record_id("rust-toolchain-source-v1", &SourceContent::from(self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationFacts {
    pub subject_id: Sha256Digest,
    pub authenticated_manifest_day: String,
    /// Official corroborated days for these exact bytes, not the old version label.
    pub corroborated_days: Vec<String>,
    pub source: SourceId,
    pub source_content_sha256: Sha256Digest,
}
impl PublicationFacts {
    pub fn maturity_start(&self, subject: &Subject, now: i64) -> Result<i64> {
        require(
            &self.subject_id == subject.id(),
            "publication belongs to another subject",
        )?;
        require(
            self.authenticated_manifest_day == subject.record().publication_date,
            "publication manifest date mismatch",
        )?;
        require(
            !self.corroborated_days.is_empty() && self.corroborated_days.len() <= 16,
            "required corroborated publication dates missing or excessive",
        )?;
        let manifest = crate::parse_iso_date(&self.authenticated_manifest_day)
            .map_err(|e| AdmissionError(e.to_string()))?;
        let mut latest = manifest;
        for raw in &self.corroborated_days {
            let day = crate::parse_iso_date(raw).map_err(|e| AdmissionError(e.to_string()))?;
            require(
                day >= manifest,
                "publication precedes authenticated manifest date",
            )?;
            latest = latest.max(day);
        }
        let start = latest
            .next_day()
            .ok_or_else(|| AdmissionError("publication date overflow".into()))?
            .midnight()
            .assume_utc()
            .unix_timestamp();
        // A publication on today's UTC day is possible, but no complete maturity day exists yet.
        require(
            latest.midnight().assume_utc().unix_timestamp() <= now,
            "future publication date",
        )?;
        Ok(start)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub schema_version: u32,
    pub subject_id: Sha256Digest,
    pub publication: PublicationFacts,
    pub observations: Vec<SourceObservation>,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_sources: Vec<ComponentEvidence>,
}

impl EvidenceRecord {
    /// Refresh times are deliberately absent from this identity. Source expiry and
    /// coverage remain binding facts: a changed conclusion needs a new assessment.
    pub fn content_id(&self, subject: &Subject) -> Result<Sha256Digest> {
        require(
            matches!(self.schema_version, 1 | 2),
            "unsupported toolchain evidence schema",
        )?;
        let selected = subject.record();
        if self.schema_version == 1 {
            let packages: BTreeSet<_> = selected
                .archives
                .iter()
                .map(|a| a.package.as_str())
                .collect();
            require(
                self.component_sources.is_empty(),
                "component matrix requires evidence schema 2",
            )?;
            require(
                selected.profile == "minimal"
                    && selected.host == "aarch64-apple-darwin"
                    && ["rustc", "cargo", "rust-std"]
                        .iter()
                        .all(|p| packages.contains(p))
                    && selected.archives.iter().all(|a| {
                        a.target == selected.host
                            && [
                                "rustc",
                                "cargo",
                                "rust-std",
                                "clippy-preview",
                                "rustfmt-preview",
                            ]
                            .contains(&a.package.as_str())
                    }),
                "this selection requires a new component source matrix and explicit review; legacy generic evidence cannot authorise default/docs or wider native scope",
            )?;
        } else {
            require(
                self.component_sources.len() == selected.archives.len(),
                "required component source matrix is incomplete",
            )?;
            let mut seen = BTreeSet::new();
            for row in &self.component_sources {
                row.validate()?;
                require(
                    selected.archives.contains(&row.archive)
                        && seen.insert((&row.archive.package, &row.archive.target)),
                    "component evidence archive identity mismatch or duplicate",
                )?;
            }
        }
        require(
            &self.subject_id == subject.id(),
            "evidence subject mismatch",
        )?;
        require(
            self.observations.len() <= 256,
            "evidence source count limit",
        )?;
        let mut sources = BTreeMap::new();
        for observation in &self.observations {
            observation.snapshot.validate()?;
            require(
                observation.snapshot.sha256 == observation.content_sha256,
                "source snapshot content identity mismatch",
            )?;
            for value in [
                &observation.location,
                &observation.provenance,
                &observation.revision,
                &observation.coverage_rationale,
            ] {
                text(value)?;
            }
            timestamp(observation.checked_at)?;
            if let Some(expiry) = observation.expires_at {
                timestamp(expiry)?;
                require(
                    expiry > observation.checked_at,
                    "source expired at check time",
                )?;
            }
            require(
                observation.status == CollectionStatus::Completed,
                "required source collection did not complete",
            )?;
            require(
                observation.coverage != Coverage::NotApplicable
                    || observation.source.kind == SourceKind::Advisories,
                "mandatory evidence source cannot be inapplicable",
            )?;
            require(
                sources
                    .insert(observation.source.clone(), SourceContent::from(observation))
                    .is_none(),
                "duplicate source identity",
            )?;
        }
        require(
            sources.keys().cloned().collect::<BTreeSet<_>>() == required_sources(subject),
            "required source floor mismatch",
        )?;
        for archive in &subject.record().archives {
            let scope = format!("{}/{}", archive.package, archive.target);
            let identity = &sources[&SourceId {
                kind: SourceKind::SourceIdentity,
                scope: scope.clone(),
            }];
            let advisories = &sources[&SourceId {
                kind: SourceKind::Advisories,
                scope,
            }];
            if self.schema_version == 2 {
                require(
                    identity.coverage == Coverage::ResidualUnknown
                        && advisories.coverage == Coverage::ResidualUnknown,
                    "component source inventory does not establish complete binary/advisory coverage",
                )?;
            }
            require(
                identity.coverage == Coverage::Covered
                    || advisories.coverage == Coverage::ResidualUnknown,
                "advisory coverage requires established component source identity",
            )?;
        }
        let publication_source = SourceId {
            kind: SourceKind::Publication,
            scope: "distribution".into(),
        };
        require(
            self.publication.source == publication_source,
            "wrong publication source identity",
        )?;
        require(
            sources
                .get(&publication_source)
                .is_some_and(|s| s.content_sha256 == &self.publication.source_content_sha256),
            "publication source content mismatch",
        )?;
        let mut publication = self.publication.clone();
        publication.corroborated_days.sort();
        publication.corroborated_days.dedup();
        require(self.findings.len() <= 4096, "finding count limit")?;
        let mut findings = BTreeMap::new();
        for finding in &self.findings {
            text(&finding.id)?;
            text(&finding.rationale)?;
            require(
                sources.contains_key(&finding.source),
                "finding source was not collected",
            )?;
            require(
                findings.insert(finding.id.clone(), finding).is_none(),
                "duplicate finding identity",
            )?;
        }
        record_id(
            "rust-toolchain-evidence-v1",
            &EvidenceContent {
                schema_version: self.schema_version,
                subject_id: &self.subject_id,
                publication,
                sources: sources.into_values().collect(),
                findings: findings.into_values().collect(),
                component_sources: &self.component_sources,
            },
        )
    }
    pub fn residual_unknowns(&self) -> BTreeSet<SourceId> {
        self.observations
            .iter()
            .filter(|s| s.coverage == Coverage::ResidualUnknown)
            .map(|s| s.source.clone())
            .collect()
    }
    pub fn verify_snapshots(&self, snapshots: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        for observation in &self.observations {
            observation.snapshot.verify(
                snapshots
                    .get(&observation.snapshot.path)
                    .ok_or_else(|| AdmissionError("required source snapshot missing".into()))?,
            )?;
        }
        for row in &self.component_sources {
            let scope = format!("{}/{}", row.archive.package, row.archive.target);
            let observation = self
                .observations
                .iter()
                .find(|o| o.source.kind == SourceKind::SourceIdentity && o.source.scope == scope)
                .ok_or_else(|| AdmissionError("component source observation missing".into()))?;
            let bytes = snapshots
                .get(&observation.snapshot.path)
                .ok_or_else(|| AdmissionError("component source snapshot missing".into()))?;
            let snapshot: ComponentSourceSnapshot = parse_record(bytes)?;
            require(
                &snapshot.component == row,
                "component matrix differs from source snapshot",
            )?;
            snapshot.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EvidenceContent<'a> {
    schema_version: u32,
    subject_id: &'a Sha256Digest,
    publication: PublicationFacts,
    sources: Vec<SourceContent<'a>>,
    findings: Vec<&'a Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    component_sources: &'a Vec<ComponentEvidence>,
}
#[derive(Serialize)]
struct SourceContent<'a> {
    source: &'a SourceId,
    location: &'a str,
    provenance: &'a str,
    revision: &'a str,
    content_sha256: &'a Sha256Digest,
    snapshot: &'a RecordReference,
    coverage: Coverage,
    coverage_rationale: &'a str,
    expires_at: Option<i64>,
}
impl<'a> From<&'a SourceObservation> for SourceContent<'a> {
    fn from(s: &'a SourceObservation) -> Self {
        Self {
            source: &s.source,
            location: &s.location,
            provenance: &s.provenance,
            revision: &s.revision,
            content_sha256: &s.content_sha256,
            snapshot: &s.snapshot,
            coverage: s.coverage,
            coverage_rationale: &s.coverage_rationale,
            expires_at: s.expires_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordReference {
    pub path: String,
    pub sha256: Sha256Digest,
}
impl RecordReference {
    pub fn validate(&self) -> Result<()> {
        text(&self.path)?;
        require(
            !self.path.contains('\\')
                && !self.path.contains(':')
                && !self.path.starts_with('/')
                && self
                    .path
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != ".."),
            "unsafe portable record path",
        )
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        require(
            bytes.len() <= MAX_RECORD_BYTES && digest_bytes(bytes) == self.sha256,
            "record digest or byte limit mismatch",
        )
    }
    pub fn verify_completed(&self, bytes: &[u8]) -> Result<()> {
        self.verify(bytes)?;
        let text = std::str::from_utf8(bytes).map_err(|e| AdmissionError(e.to_string()))?;
        require(
            crate::classify_review_record(Some(text)).is_satisfied(),
            "review prose is incomplete",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAssessment {
    pub schema_version: u32,
    pub subject_id: Sha256Digest,
    pub evidence_id: Sha256Digest,
    pub policy_id: Sha256Digest,
    pub review: RecordReference,
    pub assessed_at: i64,
    pub assessed_unknowns: BTreeSet<SourceId>,
    pub assessed_findings: BTreeSet<String>,
}
impl HumanAssessment {
    pub fn id(&self) -> Result<Sha256Digest> {
        version(self.schema_version)?;
        self.review.validate()?;
        timestamp(self.assessed_at)?;
        record_id("rust-toolchain-assessment-v1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalAcceptance {
    pub schema_version: u32,
    pub subject_id: Sha256Digest,
    pub assessment_id: Sha256Digest,
    pub accepted_at: i64,
}
impl PersonalAcceptance {
    pub fn id(&self) -> Result<Sha256Digest> {
        version(self.schema_version)?;
        timestamp(self.accepted_at)?;
        record_id("rust-toolchain-personal-acceptance-v1", self)
    }
}
