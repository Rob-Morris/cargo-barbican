use super::{
    repo::RepoContext,
    sources::Sources,
    store::PrivateStore,
    trust::{Material, Trust, VERIFICATION_POLICY},
};
use barbican::Sha256Digest;
use barbican::rust_distribution::{
    ArchiveIdentity, ArchiveInventory, Encoding, MAX_COMPRESSED_BYTES, Manifest, Profile,
    Selection, SelectionRequest, inspect_archive,
};
use barbican::toolchain_admission::{
    AuthenticationIdentity, EffectivePolicy, EvidenceRecord, MAX_RECORD_BYTES, Subject,
    SubjectRecord, digest_bytes, parse_record,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) type Result<T> = std::result::Result<T, String>;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewRecord {
    pub schema_version: u32,
    pub subject: SubjectRecord,
    pub evidence: EvidenceRecord,
    pub policy: EffectivePolicy,
    pub snapshot_root: String,
    pub created_at: i64,
}
impl ReviewRecord {
    pub fn id(&self, subject: &Subject) -> Result<Sha256Digest> {
        self.subject
            .validate_against(subject)
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&(
            "toolchain-review-v1",
            subject.id(),
            self.evidence
                .content_id(subject)
                .map_err(|e| e.to_string())?,
            self.policy.id().map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
        Ok(digest_bytes(&bytes))
    }
}

pub(super) struct ReconstructedReview {
    pub record: ReviewRecord,
    pub subject: Subject,
    pub selection: Selection,
    pub inventories: Vec<ArchiveInventory>,
    pub manifest_bytes: Vec<u8>,
    pub archives: Vec<(ArchiveIdentity, PathBuf)>,
    pub source_snapshots: BTreeMap<String, Vec<u8>>,
}

pub(super) fn collect_inputs(
    release: &str,
    request: &SelectionRequest,
    data: &PrivateStore,
    cache: &PrivateStore,
    trust: &Trust<'_>,
    sources: &Sources,
    now: i64,
) -> Result<(Subject, Selection, Vec<ArchiveInventory>, String, u32)> {
    let snapshot_root = format!(
        "snapshots/{}-{}-{}",
        now,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let manifest_url = format!("https://static.rust-lang.org/dist/channel-rust-{release}.toml");
    // Validate exact stable syntax before using the candidate in a URL.
    let channel = release
        .parse::<barbican::ExactRustToolchainChannel>()
        .map_err(|e| e.to_string())?;
    if channel.as_str() != release
        || release.split('.').count() != 3
        || !release.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Err("toolchain review requires an exact stable X.Y.Z release".into());
    }
    let manifest_bytes = sources.fetch(&manifest_url)?;
    let signature = sources.fetch(&format!("{manifest_url}.asc"))?;
    let certificate = sources.fetch(super::trust::OFFICIAL_KEY_URL)?;
    let signer = trust.verify(&certificate, &signature, &manifest_bytes, now)?;
    let manifest = Manifest::parse(&manifest_bytes, release).map_err(|e| e.to_string())?;
    let selection = manifest.select(request).map_err(|e| e.to_string())?;
    for (name, bytes) in [
        ("manifest.toml", &manifest_bytes),
        ("manifest.asc", &signature),
        ("certificate.pgp", &certificate),
    ] {
        data.publish(Path::new(&format!("{snapshot_root}/{name}")), bytes)?;
    }
    let mut inventories = Vec::new();
    let mut selection_bytes = 0u64;
    for archive in &selection.archives {
        let relative = PathBuf::from(format!("archives/{}", archive.sha256));
        let durable_path = data.root().join(&relative);
        if !durable_path.try_exists().map_err(|e| e.to_string())? {
            let cache_path = cache.root().join(&relative);
            if !cache_path.try_exists().map_err(|e| e.to_string())? {
                sources.archive(&archive.url, cache, &relative)?;
            }
            let cached = cache.open_snapshot(&relative, MAX_COMPRESSED_BYTES)?;
            data.publish_stream(&relative, cached, MAX_COMPRESSED_BYTES)?;
        }
        let input = data.open_snapshot(&relative, MAX_COMPRESSED_BYTES)?;
        add_inventory(
            &mut inventories,
            &mut selection_bytes,
            inspect_archive(input, archive).map_err(|e| e.to_string())?,
        )?;
    }
    let authentication = AuthenticationIdentity {
        manifest_sha256: manifest.sha256(),
        signature_sha256: digest_bytes(&signature),
        certificate_sha256: digest_bytes(&certificate),
        primary_fingerprint: signer.primary,
        signing_fingerprint: signer.component,
        verification_policy_sha256: digest_bytes(VERIFICATION_POLICY.as_bytes()),
    };
    let subject = Subject::reconstruct(&manifest, request, authentication, inventories.clone())
        .map_err(|e| e.to_string())?;
    Ok((
        subject,
        selection,
        inventories,
        snapshot_root,
        signer.signature_created_at,
    ))
}

pub(super) fn load(
    data: &PrivateStore,
    id: &Sha256Digest,
    seed: &Material,
    now: i64,
) -> Result<ReconstructedReview> {
    let captured = data.read(Path::new(&format!("reviews/{id}.json")), 8 * 1024 * 1024)?;
    let record: ReviewRecord = parse_record(captured.bytes()).map_err(|e| e.to_string())?;
    if record.schema_version != 1 || record.created_at > now {
        return Err("unsupported review schema or future review clock".into());
    }
    let prefix = Path::new(&record.snapshot_root);
    let manifest = data.read(&prefix.join("manifest.toml"), 8 * 1024 * 1024)?;
    let signature = data.read(&prefix.join("manifest.asc"), 256 * 1024)?;
    let certificate = data.read(&prefix.join("certificate.pgp"), 1024 * 1024)?;
    let trust = Trust::load(data, seed, now)?;
    let signer = trust.verify(
        certificate.bytes(),
        signature.bytes(),
        manifest.bytes(),
        now,
    )?;
    let manifest_parsed =
        Manifest::parse(manifest.bytes(), &record.subject.release).map_err(|e| e.to_string())?;
    let request = SelectionRequest {
        host: record.subject.host.clone(),
        profile: match record.subject.profile.as_str() {
            "minimal" => Profile::Minimal,
            "default" => Profile::Default,
            _ => return Err("unsupported stored profile".into()),
        },
        components: record.subject.requested_components.clone(),
        targets: record.subject.requested_targets.clone(),
        encoding: match record.subject.archives.first().map(|a| a.encoding.as_str()) {
            Some("xz") => Encoding::Xz,
            Some("gzip") => Encoding::Gzip,
            _ => return Err("missing or unsupported stored encoding".into()),
        },
    };
    let selection = manifest_parsed
        .select(&request)
        .map_err(|e| e.to_string())?;
    let mut inventories = Vec::new();
    let mut selection_bytes = 0u64;
    let mut archives = Vec::new();
    for archive in &selection.archives {
        let relative = Path::new("archives").join(archive.sha256.as_str());
        add_inventory(
            &mut inventories,
            &mut selection_bytes,
            inspect_archive(
                data.open_snapshot(&relative, MAX_COMPRESSED_BYTES)?,
                archive,
            )
            .map_err(|e| e.to_string())?,
        )?;
        archives.push((archive.clone(), data.root().join(relative)));
    }
    let authentication = AuthenticationIdentity {
        manifest_sha256: manifest_parsed.sha256(),
        signature_sha256: digest_bytes(signature.bytes()),
        certificate_sha256: digest_bytes(certificate.bytes()),
        primary_fingerprint: signer.primary,
        signing_fingerprint: signer.component,
        verification_policy_sha256: digest_bytes(VERIFICATION_POLICY.as_bytes()),
    };
    let subject = Subject::reconstruct(
        &manifest_parsed,
        &request,
        authentication,
        inventories.clone(),
    )
    .map_err(|e| e.to_string())?;
    if record.id(&subject)? != *id {
        return Err("review content identity mismatch".into());
    }
    let mut source_snapshots = BTreeMap::new();
    for observation in &record.evidence.observations {
        let bytes = data
            .read(&prefix.join(&observation.snapshot.path), 8 * 1024 * 1024)?
            .bytes()
            .to_vec();
        observation
            .snapshot
            .verify(&bytes)
            .map_err(|e| e.to_string())?;
        source_snapshots.insert(observation.snapshot.path.clone(), bytes);
    }
    record
        .evidence
        .verify_snapshots(&source_snapshots)
        .map_err(|e| e.to_string())?;
    data.check_capture(&captured)?;
    Ok(ReconstructedReview {
        manifest_bytes: manifest.bytes().to_vec(),
        record,
        subject,
        selection,
        inventories,
        archives,
        source_snapshots,
    })
}

pub(super) fn policy(repo: Option<&RepoContext>, minimum_days: Option<u64>) -> EffectivePolicy {
    EffectivePolicy {
        schema_version: 1,
        minimum_days: minimum_days
            .unwrap_or_else(|| repo.map(|r| r.config.release_age.minimum_days).unwrap_or(7)),
        override_reason: minimum_days.map(|_| "explicit --min-age-days for this operation".into()),
    }
}

pub(super) fn create(
    release: &str,
    request: &SelectionRequest,
    policy: EffectivePolicy,
    data: &PrivateStore,
    cache: &PrivateStore,
    seed: &Material,
    now: i64,
) -> Result<(Sha256Digest, ReconstructedReview)> {
    policy.id().map_err(|e| e.to_string())?;
    let sources = Sources::new();
    let trust = Trust::load(data, seed, now)?;
    let (subject, selection, inventories, snapshot_root, signed_at) =
        collect_inputs(release, request, data, cache, &trust, &sources, now)?;
    let manifest_bytes = data.read(
        Path::new(&format!("{snapshot_root}/manifest.toml")),
        8 * 1024 * 1024,
    )?;
    let manifest = Manifest::parse(manifest_bytes.bytes(), release).map_err(|e| e.to_string())?;
    let collected = super::collection::collect(&sources, &subject, &manifest, signed_at, now)?;
    super::collection::persist(data, &snapshot_root, &collected)?;
    let record = ReviewRecord {
        schema_version: 1,
        subject: subject.record().clone(),
        evidence: collected.evidence,
        policy,
        snapshot_root,
        created_at: now,
    };
    let id = record.id(&subject)?;
    let path = format!("reviews/{id}.json");
    let bytes = serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?;
    match data.read_optional(Path::new(&path), 8 * 1024 * 1024)? {
        Some(captured) => data.replace(&captured, &bytes)?,
        None => data.publish(Path::new(&path), &bytes)?,
    }
    let archives = selection
        .archives
        .iter()
        .map(|archive| {
            (
                archive.clone(),
                data.root().join("archives").join(archive.sha256.as_str()),
            )
        })
        .collect();
    let reconstructed = ReconstructedReview {
        manifest_bytes: manifest_bytes.bytes().to_vec(),
        record,
        subject,
        selection,
        inventories,
        archives,
        source_snapshots: collected.snapshots,
    };
    super::admission::retain_knowledge(data, &reconstructed, now)?;
    let template = super::acceptance::template(&reconstructed, &id)?;
    let template_path = format!("reviews/{id}.md");
    if data
        .read_optional(Path::new(&template_path), 8 * 1024 * 1024)?
        .is_none()
    {
        data.publish(Path::new(&template_path), template.as_bytes())?;
    }
    Ok((id, reconstructed))
}

pub(super) fn refresh(
    data: &PrivateStore,
    id: &Sha256Digest,
    seed: &Material,
    now: i64,
) -> Result<ReconstructedReview> {
    let mut review = load(data, id, seed, now)?;
    let sources = Sources::new();
    let url = format!(
        "https://static.rust-lang.org/dist/channel-rust-{}.toml",
        review.subject.record().release
    );
    let manifest = sources.fetch(&url)?;
    let signature = sources.fetch(&format!("{url}.asc"))?;
    let certificate = sources.fetch(super::trust::OFFICIAL_KEY_URL)?;
    let trust = Trust::load(data, seed, now)?;
    let signer = trust.verify(&certificate, &signature, &manifest, now)?;
    let expected = &review.subject.record().authentication;
    if digest_bytes(&manifest) != expected.manifest_sha256
        || digest_bytes(&signature) != expected.signature_sha256
        || digest_bytes(&certificate) != expected.certificate_sha256
    {
        return Err("official authenticated distribution inputs changed; run a new toolchain review before acceptance or installation".into());
    }
    let parsed =
        Manifest::parse(&manifest, &review.subject.record().release).map_err(|e| e.to_string())?;
    let collected = super::collection::collect(
        &sources,
        &review.subject,
        &parsed,
        signer.signature_created_at,
        now,
    )?;
    for (path, bytes) in &collected.snapshots {
        let path = Path::new(&review.record.snapshot_root).join(path);
        match data.read_optional(&path, 8 * 1024 * 1024)? {
            Some(existing) if existing.bytes() == bytes => {}
            Some(_) => {
                return Err("source content-address collision or local snapshot corruption".into());
            }
            None => data.publish(&path, bytes)?,
        }
    }
    review.record.evidence = collected.evidence;
    review.source_snapshots = collected.snapshots;
    super::admission::retain_knowledge(data, &review, now)?;
    let refreshed_id = review.record.id(&review.subject)?;
    let path = format!("reviews/{refreshed_id}.json");
    let bytes = serde_json::to_vec_pretty(&review.record).map_err(|e| e.to_string())?;
    match data.read_optional(Path::new(&path), 8 * 1024 * 1024)? {
        Some(existing) => data.replace(&existing, &bytes)?,
        None => data.publish(Path::new(&path), &bytes)?,
    }
    if refreshed_id != *id {
        let template = super::acceptance::template(&review, &refreshed_id)?;
        let path = format!("reviews/{refreshed_id}.md");
        if data
            .read_optional(Path::new(&path), 8 * 1024 * 1024)?
            .is_none()
        {
            data.publish(Path::new(&path), template.as_bytes())?;
        }
        return Err(format!(
            "required source facts changed; new review {refreshed_id} is retained and requires completed human assessment; prior approval was not renewed"
        ));
    }
    Ok(review)
}

pub(super) fn import_portable(
    data: &PrivateStore,
    cache: &PrivateStore,
    repo: &RepoContext,
    id: &Sha256Digest,
    cached: bool,
    now: i64,
) -> Result<()> {
    let policy_bytes = super::repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?
        .ok_or("portable admission policy is missing")?;
    let targets = barbican::parse_reviewed_targets_toml(
        std::str::from_utf8(&policy_bytes).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let evidence_path = format!("docs/dependency-reviews/toolchains/{id}/evidence.json");
    let admissions: Vec<_> = targets
        .rust_toolchains()
        .iter()
        .filter(|admission| admission.evidence_record == evidence_path)
        .collect();
    let [admission] = admissions.as_slice() else {
        return Err(
            "explicit local import requires one matching reviewed repository evidence reference"
                .into(),
        );
    };
    let bytes = super::repo::read_optional(&repo.root, Path::new(&evidence_path))?
        .ok_or("portable evidence is missing")?;
    admission
        .evidence()
        .verify(&bytes)
        .map_err(|e| e.to_string())?;
    let portable: barbican::toolchain_admission::PortableReview =
        parse_record(&bytes).map_err(|e| e.to_string())?;
    let request = SelectionRequest {
        host: portable.subject.host.clone(),
        profile: match portable.subject.profile.as_str() {
            "minimal" => Profile::Minimal,
            "default" => Profile::Default,
            _ => return Err("unsupported portable profile".into()),
        },
        components: portable.subject.requested_components.clone(),
        targets: portable.subject.requested_targets.clone(),
        encoding: match portable
            .subject
            .archives
            .first()
            .map(|a| a.encoding.as_str())
        {
            Some("xz") => Encoding::Xz,
            Some("gzip") => Encoding::Gzip,
            _ => return Err("unsupported portable encoding".into()),
        },
    };
    if !cached {
        let (actual, _) = create(
            &portable.subject.release,
            &request,
            portable.policy,
            data,
            cache,
            &super::trust::bundled_seed()?,
            now,
        )?;
        if actual != *id {
            return Err(format!(
                "current verified evidence differs from portable review {id}; newly collected review {actual} requires completion"
            ));
        }
        repo.recheck()?;
        return Ok(());
    }
    let snapshot_root = format!(
        "snapshots/import-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let portable_root = format!("docs/dependency-reviews/toolchains/{id}");
    let mut inputs = BTreeMap::new();
    for name in ["manifest.toml", "manifest.asc", "certificate.pgp"] {
        let bytes=super::repo::read_optional(&repo.root,&Path::new(&portable_root).join(name))?.ok_or("cached import requires checked-in original manifest/signature/certificate evidence")?;
        data.publish(&Path::new(&snapshot_root).join(name), &bytes)?;
        inputs.insert(name, bytes);
    }
    let seed = super::trust::bundled_seed()?;
    let trust = Trust::load(data, &seed, now)?;
    let signer = trust.verify(
        &inputs["certificate.pgp"],
        &inputs["manifest.asc"],
        &inputs["manifest.toml"],
        now,
    )?;
    let manifest = Manifest::parse(&inputs["manifest.toml"], &portable.subject.release)
        .map_err(|e| e.to_string())?;
    let selected = manifest.select(&request).map_err(|e| e.to_string())?;
    let mut inventories = Vec::new();
    let mut selection_bytes = 0u64;
    for archive in &selected.archives {
        let cached = cache
            .open_snapshot(
                Path::new(&format!("archives/{}", archive.sha256)),
                MAX_COMPRESSED_BYTES,
            )
            .map_err(|e| {
                format!("cached import lacks intact immutable archive; run online review: {e}")
            })?;
        let path = Path::new("archives").join(archive.sha256.as_str());
        if !data
            .root()
            .join(&path)
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            data.publish_stream(&path, cached, MAX_COMPRESSED_BYTES)?;
        }
        add_inventory(
            &mut inventories,
            &mut selection_bytes,
            inspect_archive(data.open_snapshot(&path, MAX_COMPRESSED_BYTES)?, archive)
                .map_err(|e| e.to_string())?,
        )?;
    }
    let authentication = AuthenticationIdentity {
        manifest_sha256: manifest.sha256(),
        signature_sha256: digest_bytes(&inputs["manifest.asc"]),
        certificate_sha256: digest_bytes(&inputs["certificate.pgp"]),
        primary_fingerprint: signer.primary,
        signing_fingerprint: signer.component,
        verification_policy_sha256: digest_bytes(super::trust::VERIFICATION_POLICY.as_bytes()),
    };
    let subject = Subject::reconstruct(&manifest, &request, authentication, inventories)
        .map_err(|e| e.to_string())?;
    portable.validate(&subject).map_err(|e| e.to_string())?;
    if admission.subject_id != *subject.id() {
        return Err("portable admission belongs to another reconstructed subject".into());
    }
    for source in &portable.evidence.observations {
        let bytes = super::repo::read_optional(&repo.root, Path::new(&source.snapshot.path))?
            .ok_or("portable required source snapshot missing")?;
        source.snapshot.verify(&bytes).map_err(|e| e.to_string())?;
        let path = Path::new(&snapshot_root).join(&source.snapshot.path);
        if data
            .read_optional(&path, MAX_RECORD_BYTES as u64)?
            .is_none()
        {
            data.publish(&path, &bytes)?;
        }
    }
    let record = ReviewRecord {
        schema_version: 1,
        subject: portable.subject,
        evidence: portable.evidence,
        policy: portable.policy,
        snapshot_root,
        created_at: now,
    };
    if record.id(&subject)? != *id {
        return Err("portable review ID does not match independently reconstructed inputs".into());
    }
    repo.recheck()?;
    data.publish(
        Path::new(&format!("reviews/{id}.json")),
        &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )
}

/// Rehash retained bytes against the already reconstructed in-memory mapping;
/// mutable stored inventories never supply expected installation authority.
pub(super) fn recheck(
    data: &PrivateStore,
    review: &ReconstructedReview,
    seed: &Material,
    now: i64,
) -> Result<(ReviewRecord, BTreeMap<String, Vec<u8>>)> {
    let id = review.record.id(&review.subject)?;
    let captured = data.read(
        Path::new(&format!("reviews/{id}.json")),
        MAX_RECORD_BYTES as u64,
    )?;
    let record: ReviewRecord = parse_record(captured.bytes()).map_err(|e| e.to_string())?;
    if record.schema_version != 1
        || record.created_at > now
        || record.id(&review.subject)? != id
        || record.snapshot_root != review.record.snapshot_root
    {
        return Err("review identity or private snapshot changed during operation".into());
    }
    let prefix = Path::new(&record.snapshot_root);
    let manifest = data.read(&prefix.join("manifest.toml"), MAX_RECORD_BYTES as u64)?;
    let signature = data.read(&prefix.join("manifest.asc"), 256 * 1024)?;
    let certificate = data.read(&prefix.join("certificate.pgp"), 1024 * 1024)?;
    let expected = &review.subject.record().authentication;
    if manifest.bytes() != review.manifest_bytes
        || digest_bytes(signature.bytes()) != expected.signature_sha256
        || digest_bytes(certificate.bytes()) != expected.certificate_sha256
    {
        return Err("authenticated private distribution bytes changed during operation".into());
    }
    Trust::load(data, seed, now)?.verify(
        certificate.bytes(),
        signature.bytes(),
        manifest.bytes(),
        now,
    )?;
    for archive in &review.selection.archives {
        let input = data.open_snapshot(
            &Path::new("archives").join(archive.sha256.as_str()),
            MAX_COMPRESSED_BYTES,
        )?;
        if barbican::toolchain_admission::digest_reader(input, MAX_COMPRESSED_BYTES)
            .map_err(|e| e.to_string())?
            .0
            != archive.sha256
        {
            return Err("private archive bytes changed during operation".into());
        }
    }
    let mut snapshots = BTreeMap::new();
    for observation in &record.evidence.observations {
        let bytes = data
            .read(
                &prefix.join(&observation.snapshot.path),
                MAX_RECORD_BYTES as u64,
            )?
            .bytes()
            .to_vec();
        observation
            .snapshot
            .verify(&bytes)
            .map_err(|e| e.to_string())?;
        snapshots.insert(observation.snapshot.path.clone(), bytes);
    }
    record
        .evidence
        .verify_snapshots(&snapshots)
        .map_err(|e| e.to_string())?;
    data.check_capture(&captured)?;
    Ok((record, snapshots))
}

fn add_inventory(
    inventories: &mut Vec<ArchiveInventory>,
    total: &mut u64,
    inventory: ArchiveInventory,
) -> Result<()> {
    *total = total
        .checked_add(inventory.expanded_bytes)
        .filter(|n| *n <= barbican::rust_distribution::MAX_SELECTION_BYTES)
        .ok_or("selected archives exceed the aggregate expanded-byte limit")?;
    inventories.push(inventory);
    Ok(())
}

pub(super) fn invocation_policy(
    repo: Option<&RepoContext>,
    minimum_days: Option<u64>,
) -> Result<barbican::toolchain_admission::EffectivePolicy> {
    if repo.is_some() && minimum_days.is_some() {
        return Err("--min-age-days applies only to standalone toolchain operations; use checked-in release_age.minimum_days or an exact scoped repository age exception".into());
    }
    Ok(policy(repo, minimum_days))
}
pub(super) fn require_current_policy(
    reviewed: &barbican::toolchain_admission::EffectivePolicy,
    current: &barbican::toolchain_admission::EffectivePolicy,
) -> Result<()> {
    if reviewed.id().map_err(|e| e.to_string())? != current.id().map_err(|e| e.to_string())? {
        return Err("current operation policy differs from completed review; explicitly repeat the reviewed standalone --min-age-days override or complete a review under the current policy".into());
    }
    Ok(())
}
