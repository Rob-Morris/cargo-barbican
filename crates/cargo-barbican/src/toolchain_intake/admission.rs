use super::{
    acceptance::AcceptanceRecord,
    repo::{self, RepoContext},
    review::ReconstructedReview,
    store::PrivateStore,
    trust,
};
use barbican::Sha256Digest;
use barbican::toolchain_admission::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(super) type Result<T> = std::result::Result<T, String>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownSources {
    schema_version: u32,
    subject_id: Sha256Digest,
    checks: Vec<(SourceId, i64, Sha256Digest)>,
    conflicts: Vec<(SourceId, i64)>,
    adverse: bool,
}

pub(super) fn knowledge(data: &PrivateStore, subject: &Subject) -> Result<CurrentKnowledge> {
    let mut knowledge = CurrentKnowledge::default();
    let path = format!("knowledge/{}.json", subject.id());
    if let Some(captured) = data.read_optional(Path::new(&path), MAX_RECORD_BYTES as u64)? {
        let record: KnownSources = parse_record(captured.bytes()).map_err(|e| e.to_string())?;
        if record.schema_version != 1 || record.subject_id != *subject.id() {
            return Err("durable source knowledge identity mismatch".into());
        }
        for (source, time, content) in record.checks {
            if time < 0
                || time > i64::from(u32::MAX)
                || knowledge
                    .source_checks
                    .insert(source.clone(), time)
                    .is_some()
            {
                return Err("duplicate or invalid durable source observation".into());
            }
            knowledge.source_contents.insert(source, content);
        }
        let mut conflict_sources = std::collections::BTreeSet::new();
        for (source, at) in &record.conflicts {
            if !conflict_sources.insert(source) || knowledge.source_checks.get(source) != Some(at) {
                return Err("duplicate or unpaired durable source conflict".into());
            }
        }
        if record.adverse || !record.conflicts.is_empty() {
            knowledge.adverse_subjects.insert(record.subject_id);
        }
    }
    Ok(knowledge)
}
pub(super) fn retain_knowledge(
    data: &PrivateStore,
    review: &ReconstructedReview,
    now: i64,
) -> Result<()> {
    let path = format!("knowledge/{}.json", review.subject.id());
    let captured = data.read_optional(Path::new(&path), MAX_RECORD_BYTES as u64)?;
    let previous: Option<KnownSources> = captured
        .as_ref()
        .map(|file| parse_record(file.bytes()).map_err(|e| e.to_string()))
        .transpose()?;
    let knowledge = knowledge(data, &review.subject)?;
    let mut checks = knowledge.source_checks;
    let mut contents = knowledge.source_contents;
    let mut conflicts: std::collections::BTreeMap<_, _> = previous
        .as_ref()
        .map(|record| record.conflicts.iter().cloned().collect())
        .unwrap_or_default();
    let mut conflict = false;
    for observation in &review.record.evidence.observations {
        if observation.checked_at < 0 || observation.checked_at > now {
            return Err("future or invalid successful source check cannot be retained".into());
        }
        let content = observation.content_id().map_err(|e| e.to_string())?;
        if let Some(known) = checks.get(&observation.source) {
            if observation.checked_at < *known {
                return Err(
                    "backward source observation cannot replace newer durable knowledge".into(),
                );
            }
            if observation.checked_at == *known
                && contents.get(&observation.source) != Some(&content)
            {
                conflicts.insert(observation.source.clone(), *known);
                conflict = true;
                continue;
            }
        }
        if conflicts
            .get(&observation.source)
            .is_some_and(|at| observation.checked_at > *at)
        {
            conflicts.remove(&observation.source);
        }
        checks.insert(observation.source.clone(), observation.checked_at);
        contents.insert(observation.source.clone(), content);
    }
    let adverse = previous.as_ref().is_some_and(|record| record.adverse)
        || review
            .record
            .evidence
            .findings
            .iter()
            .any(|f| f.exposure == Exposure::Known && f.change != FindingChange::Resolved);
    let record = KnownSources {
        schema_version: 1,
        subject_id: review.subject.id().clone(),
        checks: checks
            .into_iter()
            .map(|(source, time)| {
                let content = contents
                    .get(&source)
                    .expect("paired retained source identity")
                    .clone();
                (source, time, content)
            })
            .collect(),
        conflicts: conflicts.into_iter().collect(),
        adverse,
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    match captured {
        Some(captured) => data.replace(&captured, &bytes)?,
        None => data.publish(Path::new(&path), &bytes)?,
    }
    if conflict {
        return Err("different source facts were observed at the same clock time; conflict retained and cached/continuing use blocked; perform a later successful refresh and assess its exact evidence".into());
    }
    Ok(())
}

pub(super) fn consumer_id(repo: &RepoContext) -> Result<Sha256Digest> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(&repo.root).map_err(|e| e.to_string())?;
    Ok(digest_bytes(
        &serde_json::to_vec(&(repo.root.to_string_lossy(), metadata.dev(), metadata.ino()))
            .map_err(|e| e.to_string())?,
    ))
}

pub(super) fn publish_repository(
    data: &PrivateStore,
    review: &ReconstructedReview,
    accepted: &AcceptanceRecord,
    repo: &RepoContext,
    freshness: FreshnessRequest,
    now: i64,
) -> Result<ReviewedToolchainAdmission> {
    repo.recheck()?;
    let scope=repo.config.toolchain.admission_scope.as_deref().ok_or("personal acceptance retained; repository admission requires explicit [toolchain].admission_scope in barbican.toml")?;
    let policy = super::review::policy(Some(repo), None);
    if policy.id().map_err(|e| e.to_string())?
        != review.record.policy.id().map_err(|e| e.to_string())?
    {
        return Err("personal acceptance retained; current repository policy differs from completed review; collect and complete a review with --repo".into());
    }
    let portable = PortableReview {
        schema_version: 1,
        subject: review.subject.record().clone(),
        evidence: review.record.evidence.clone(),
        policy: policy.clone(),
        assessment: accepted.assessment.clone(),
    };
    portable
        .validate(&review.subject)
        .map_err(|e| e.to_string())?;
    let evidence_bytes = serde_json::to_vec_pretty(&portable).map_err(|e| e.to_string())?;
    let admission = ReviewedToolchainAdmission {
        schema_version: 1,
        subject_id: review.subject.id().clone(),
        policy_id: policy.id().map_err(|e| e.to_string())?,
        assessment_id: accepted.assessment.id().map_err(|e| e.to_string())?,
        scope: scope.into(),
        review_record: accepted.assessment.review.path.clone(),
        review_record_sha256: accepted.assessment.review.sha256.clone(),
        evidence_record: format!(
            "docs/dependency-reviews/toolchains/{}/evidence.json",
            accepted.review_id
        ),
        evidence_record_sha256: digest_bytes(&evidence_bytes),
        review_by: None,
        age_exception: None,
    };
    let context_id = consumer_id(repo)?;
    let knowledge = knowledge(data, &review.subject)?;
    let existing =
        repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?.unwrap_or_default();
    let existing_text = std::str::from_utf8(&existing).map_err(|e| e.to_string())?;
    let targets =
        barbican::parse_reviewed_targets_toml(existing_text).map_err(|e| e.to_string())?;
    for previous in targets.rust_toolchains() {
        if previous.subject_id == admission.subject_id {
            let previous_evidence =
                repo::read_optional(&repo.root, Path::new(&previous.evidence_record))?
                    .ok_or("existing portable evidence missing")?;
            let previous_prose =
                repo::read_optional(&repo.root, Path::new(&previous.review_record))?
                    .ok_or("existing completed prose missing")?;
            if previous_prose != accepted.prose {
                return Err(
                    "existing repository prose conflicts with explicit personal acceptance".into(),
                );
            }
            for observation in &review.record.evidence.observations {
                let bytes = repo::read_optional(&repo.root, Path::new(&observation.snapshot.path))?
                    .ok_or("portable source snapshot missing")?;
                observation
                    .snapshot
                    .verify(&bytes)
                    .map_err(|e| e.to_string())?;
            }
            let exception = previous
                .age_exception
                .as_ref()
                .map(|exception| {
                    repo::read_optional(&repo.root, Path::new(&exception.review.path))
                        .and_then(|bytes| bytes.ok_or("age-exception prose missing".into()))
                })
                .transpose()?;
            evaluate_eligibility(EligibilityInput {
                purpose: EligibilityPurpose::RepositoryAdmission,
                subject: &review.subject,
                evidence: &review.record.evidence,
                source_snapshots: &review.source_snapshots,
                policy: &policy,
                assessment: &accepted.assessment,
                review_bytes: &accepted.prose,
                personal: Some(PersonalApproval {
                    acceptance: &accepted.acceptance,
                    assessment: &accepted.assessment,
                    review_bytes: &accepted.prose,
                }),
                repository: Some(RepositoryContext {
                    scope,
                    consumer_context_id: &context_id,
                    admission: previous,
                    evidence_bytes: &previous_evidence,
                    exception_review_bytes: exception.as_deref(),
                    continuing: None,
                }),
                installed: None,
                knowledge: &knowledge,
                freshness,
                now,
            })
            .map_err(|e| e.to_string())?;
            repo.recheck()?;
            return Ok(previous.clone());
        }
    }
    evaluate_eligibility(EligibilityInput {
        purpose: EligibilityPurpose::RepositoryAdmission,
        subject: &review.subject,
        evidence: &review.record.evidence,
        source_snapshots: &review.source_snapshots,
        policy: &policy,
        assessment: &accepted.assessment,
        review_bytes: &accepted.prose,
        personal: Some(PersonalApproval {
            acceptance: &accepted.acceptance,
            assessment: &accepted.assessment,
            review_bytes: &accepted.prose,
        }),
        repository: Some(RepositoryContext {
            scope,
            consumer_context_id: &context_id,
            admission: &admission,
            evidence_bytes: &evidence_bytes,
            exception_review_bytes: None,
            continuing: None,
        }),
        installed: None,
        knowledge: &knowledge,
        freshness: freshness.clone(),
        now,
    })
    .map_err(|e| e.to_string())?;
    let fragment = render_admission_fragment(&admission).map_err(|e| e.to_string())?;
    let mut policy_text = existing_text.to_owned();
    policy_text.push_str("\n\n");
    policy_text.push_str(&fragment);
    barbican::parse_reviewed_targets_toml(&policy_text).map_err(|e| e.to_string())?;
    for (path, bytes) in &review.source_snapshots {
        repo.publish_supporting(Path::new(path), bytes)?;
    }
    repo.publish_supporting(Path::new(&admission.review_record), &accepted.prose)?;
    repo.publish_supporting(Path::new(&admission.evidence_record), &evidence_bytes)?;
    for (name, relative) in [
        ("manifest.toml", "manifest.toml"),
        ("manifest.asc", "manifest.asc"),
        ("certificate.pgp", "certificate.pgp"),
    ] {
        let source = data.read(
            &Path::new(&review.record.snapshot_root).join(relative),
            MAX_RECORD_BYTES as u64,
        )?;
        repo.publish_supporting(
            Path::new(&format!(
                "docs/dependency-reviews/toolchains/{}/{name}",
                accepted.review_id
            )),
            source.bytes(),
        )?;
    }
    repo.publish_policy(policy_text.as_bytes())?;
    Ok(admission)
}

pub(super) struct AcceptedContext<'a> {
    pub data: &'a PrivateStore,
    pub review: ReconstructedReview,
    pub accepted: AcceptanceRecord,
    pub repository: Option<RepoContext>,
    pub admission: Option<ReviewedToolchainAdmission>,
    evidence_bytes: Vec<u8>,
    repo_assessment: Option<HumanAssessment>,
    exception_review: Option<Vec<u8>>,
    continuing: Option<ContinuingUseBinding>,
    pub freshness: FreshnessRequest,
    current_policy: EffectivePolicy,
}
impl<'a> AcceptedContext<'a> {
    pub fn load(
        data: &'a PrivateStore,
        id: Sha256Digest,
        repository: Option<RepoContext>,
        current_policy: EffectivePolicy,
        freshness: FreshnessRequest,
        now: i64,
    ) -> Result<Self> {
        let seed = trust::bundled_seed()?;
        let review = if matches!(freshness, FreshnessRequest::Online { .. }) {
            super::review::refresh(data, &id, &seed, now)?
        } else {
            super::review::load(data, &id, &seed, now)?
        };
        super::review::require_current_policy(&review.record.policy, &current_policy)?;
        let accepted = super::acceptance::load(data, &id)?;
        let mut admission = None;
        let mut evidence_bytes = Vec::new();
        let mut repo_assessment = None;
        let mut exception_review = None;
        let mut continuing = None;
        if let Some(repo) = &repository {
            repo.recheck()?;
            let bytes = repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?
                .ok_or("repository admission policy is missing")?;
            let targets = barbican::parse_reviewed_targets_toml(
                std::str::from_utf8(&bytes).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let matches: Vec<_> = targets
                .rust_toolchains()
                .iter()
                .filter(|entry| entry.subject_id == *review.subject.id())
                .collect();
            let [matched] = matches.as_slice() else {
                return Err(
                    "repository must declare exactly one admission for this exact subject".into(),
                );
            };
            evidence_bytes = repo::read_optional(&repo.root, Path::new(&matched.evidence_record))?
                .ok_or("portable repository evidence is missing")?;
            let portable: PortableReview =
                parse_record(&evidence_bytes).map_err(|e| e.to_string())?;
            portable
                .validate(&review.subject)
                .map_err(|e| e.to_string())?;
            repo_assessment = Some(portable.assessment);
            let prose = repo::read_optional(&repo.root, Path::new(&matched.review_record))?
                .ok_or("completed repository prose is missing")?;
            if prose != accepted.prose {
                return Err("repository review prose differs from personal acceptance".into());
            }
            for observation in &review.record.evidence.observations {
                let bytes = repo::read_optional(&repo.root, Path::new(&observation.snapshot.path))?
                    .ok_or("portable required source snapshot is missing")?;
                observation
                    .snapshot
                    .verify(&bytes)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(exception) = &matched.age_exception {
                exception_review = Some(
                    repo::read_optional(&repo.root, Path::new(&exception.review.path))?
                        .ok_or("repository age-exception prose is missing")?,
                );
            }
            let context_id = consumer_id(repo)?;
            if let Some(record) = data.read_optional(
                Path::new(&format!(
                    "continuing/{context_id}/{}.json",
                    review.subject.id()
                )),
                MAX_RECORD_BYTES as u64,
            )? {
                continuing = Some(parse_record(record.bytes()).map_err(|e| e.to_string())?);
            }
            admission = Some((*matched).clone());
        }
        Ok(Self {
            data,
            review,
            accepted,
            repository,
            admission,
            evidence_bytes,
            repo_assessment,
            exception_review,
            continuing,
            freshness,
            current_policy,
        })
    }

    pub fn recheck_before_effects(
        &self,
        purpose: EligibilityPurpose,
        installed: Option<&InstalledCorrespondence>,
        now: i64,
    ) -> Result<Eligibility> {
        let (current, snapshots) =
            super::review::recheck(self.data, &self.review, &trust::bundled_seed()?, now)?;
        let policy = match self.repository.as_ref() {
            Some(repo) => super::review::policy(Some(repo), None),
            None => self.current_policy.clone(),
        };
        if policy.id().map_err(|e| e.to_string())?
            != self.review.record.policy.id().map_err(|e| e.to_string())?
        {
            return Err(
                "current policy differs from completed review; obtain current-context assessment"
                    .into(),
            );
        }
        let context_id = self.repository.as_ref().map(consumer_id).transpose()?;
        let repository = match (&self.repository, &self.admission, &context_id) {
            (Some(repo), Some(admission), Some(context_id)) => {
                repo.recheck()?;
                if repo::read_optional(&repo.root, Path::new(&admission.evidence_record))?
                    .as_deref()
                    != Some(self.evidence_bytes.as_slice())
                    || repo::read_optional(&repo.root, Path::new(&admission.review_record))?
                        .as_deref()
                        != Some(self.accepted.prose.as_slice())
                {
                    return Err("repository review evidence changed during operation".into());
                }
                Some(RepositoryContext {
                    scope: repo
                        .config
                        .toolchain
                        .admission_scope
                        .as_deref()
                        .ok_or("current repository admission_scope missing")?,
                    consumer_context_id: context_id,
                    admission,
                    evidence_bytes: &self.evidence_bytes,
                    exception_review_bytes: self.exception_review.as_deref(),
                    continuing: self.continuing.as_ref(),
                })
            }
            (None, None, None) => None,
            _ => return Err("incomplete repository admission context".into()),
        };
        let knowledge = knowledge(self.data, &self.review.subject)?;
        evaluate_eligibility(EligibilityInput {
            purpose,
            subject: &self.review.subject,
            evidence: &current.evidence,
            source_snapshots: &snapshots,
            policy: &policy,
            assessment: self
                .repo_assessment
                .as_ref()
                .unwrap_or(&self.accepted.assessment),
            review_bytes: &self.accepted.prose,
            personal: Some(PersonalApproval {
                acceptance: &self.accepted.acceptance,
                assessment: &self.accepted.assessment,
                review_bytes: &self.accepted.prose,
            }),
            repository,
            installed,
            knowledge: &knowledge,
            freshness: self.freshness.clone(),
            now,
        })
        .map_err(|e| e.to_string())
    }

    pub fn installed(
        &self,
        rustup_home: &Path,
    ) -> Result<(
        super::installation::InstalledCorrespondence,
        InstalledCorrespondence,
    )> {
        let manifest = &self.review.manifest_bytes;
        let actual = super::installation::verify_selected(
            &self.review.subject,
            &self.review.selection,
            manifest,
            &self.review.inventories,
            rustup_home,
        )?;
        let correspondence = self.correspondence(&actual)?;
        Ok((actual, correspondence))
    }

    fn correspondence(
        &self,
        actual: &super::installation::InstalledCorrespondence,
    ) -> Result<InstalledCorrespondence> {
        let installation_id = digest_bytes(
            &serde_json::to_vec(&(
                actual.slot.to_string_lossy(),
                actual.root_device,
                actual.root_inode,
                &actual.subject_id,
                &actual.mapping_sha256,
            ))
            .map_err(|e| e.to_string())?,
        );
        Ok(InstalledCorrespondence {
            subject_id: self.review.subject.id().clone(),
            mapping_sha256: self.review.subject.record().mapping_sha256.clone(),
            installation_id,
        })
    }

    pub fn remember_installation(&self, installed: &InstalledCorrespondence) -> Result<()> {
        if let (Some(repo), Some(admission)) = (&self.repository, &self.admission) {
            let context_id = consumer_id(repo)?;
            let record = ContinuingUseBinding {
                schema_version: 1,
                subject_id: self.review.subject.id().clone(),
                admission_id: admission.id().map_err(|e| e.to_string())?,
                consumer_context_id: context_id.clone(),
                installation_id: installed.installation_id.clone(),
            };
            let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
            let path = format!("continuing/{context_id}/{}.json", self.review.subject.id());
            match self
                .data
                .read_optional(Path::new(&path), MAX_RECORD_BYTES as u64)?
            {
                Some(captured) => self.data.replace(&captured, &bytes)?,
                None => self.data.publish(Path::new(&path), &bytes)?,
            }
        }
        Ok(())
    }
}

impl AcceptedContext<'_> {
    pub fn adopt(
        &self,
        rustup_home: &Path,
        now: i64,
    ) -> Result<(
        super::installation::InstalledCorrespondence,
        super::operation::OperationEvidence,
    )> {
        let (actual, installed) = self.installed(rustup_home)?;
        let eligible =
            self.recheck_before_effects(EligibilityPurpose::FirstAdoption, Some(&installed), now)?;
        let operation = super::operation::OperationEvidence::new("adopt", &eligible, now);
        operation.retain(self.data)?;
        self.remember_installation(&installed)?;
        Ok((actual, operation))
    }
    pub fn install(
        &self,
        rustup_home: &Path,
        rustup_executable: &Path,
        initial_default: bool,
        cancelled: &std::sync::atomic::AtomicBool,
        now: i64,
    ) -> Result<(
        super::installation::InstallOutcome,
        super::operation::OperationEvidence,
    )> {
        let eligible = self.recheck_before_effects(EligibilityPurpose::Installation, None, now)?;
        let operation = super::operation::OperationEvidence::new("install", &eligible, now);
        operation.retain(self.data)?;
        let inputs = super::installation::SelectedInputs {
            subject: &self.review.subject,
            selection: &self.review.selection,
            manifest: &self.review.manifest_bytes,
            inventories: &self.review.inventories,
        };
        let outcome = super::installation::install_selected(
            &inputs,
            &self.review.archives,
            rustup_home,
            rustup_executable,
            initial_default,
            cancelled,
            || {
                self.recheck_before_effects(
                    EligibilityPurpose::Installation,
                    None,
                    barbican::OffsetDateTime::now_utc().unix_timestamp(),
                )
                .map(|_| ())
            },
        )?;
        let installed = self.correspondence(&outcome.correspondence)?;
        self.remember_installation(&installed)?;
        Ok((outcome, operation))
    }
    pub fn activate(
        &self,
        rustup_home: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
        _now: i64,
    ) -> Result<(
        super::installation::ActivationOutcome,
        super::operation::OperationEvidence,
    )> {
        let repo = self
            .repository
            .as_ref()
            .ok_or("activation requires explicit current repository context")?;
        let mut operation = None;
        let inputs = super::installation::SelectedInputs {
            subject: &self.review.subject,
            selection: &self.review.selection,
            manifest: &self.review.manifest_bytes,
            inventories: &self.review.inventories,
        };
        let outcome = super::installation::activate_selected(
            &inputs,
            rustup_home,
            &repo.root,
            cancelled,
            |actual| {
                let installed = self.correspondence(actual)?;
                let now = barbican::OffsetDateTime::now_utc().unix_timestamp();
                let eligible = self.recheck_before_effects(
                    EligibilityPurpose::Activation,
                    Some(&installed),
                    now,
                )?;
                let evaluated =
                    super::operation::OperationEvidence::new("activate", &eligible, now);
                evaluated.retain(self.data)?;
                operation = Some(evaluated);
                Ok(())
            },
        )?;
        Ok((
            outcome,
            operation.ok_or("activation did not evaluate current eligibility")?,
        ))
    }
    pub fn continuing_check(&self, rustup_home: &Path, now: i64) -> Result<()> {
        let (_, installed) = self.installed(rustup_home)?;
        self.recheck_before_effects(EligibilityPurpose::ContinuingUse, Some(&installed), now)
            .map(|_| ())
    }
}
