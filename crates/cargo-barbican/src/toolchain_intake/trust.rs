use super::store::{CapturedFile, PrivateStore};
use super::verifier::{
    self, AdverseKnowledge, ApprovedCertificate, RevocationObservation, VerifiedSigner,
};
use barbican::Sha256Digest;
use barbican::toolchain_admission::{digest_bytes, parse_record};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(super) type Result<T> = std::result::Result<T, String>;
const BASELINE: &str = "trust/baseline.json";
const ADVERSE: &str = "trust/adverse.json";
const LIMIT: u64 = 8 * 1024 * 1024;
pub(super) const OFFICIAL_KEY_URL: &str = "https://static.rust-lang.org/rust-key.gpg.ascii";
pub(super) const VERIFICATION_POLICY: &str = "rust-official-manifest-v1:public-rsa:current-clock:sha256-384-512:exact-approved-legacy-structure:retained-adverse";
const PURPOSE: &str = "official-exact-stable-rust-distribution-manifest";

pub(super) fn bundled_seed() -> Result<Material> {
    let certificate = include_bytes!("rust-release-key.asc").to_vec();
    if digest_bytes(&certificate).as_str()
        != "e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b"
    {
        return Err(
            "bundled public seed content changed without updating its reviewed identity".into(),
        );
    }
    Ok(Material {
        certificate,
        fingerprint: "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE".into(),
        purpose: PURPOSE.into(),
        source: OFFICIAL_KEY_URL.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Material {
    pub certificate: Vec<u8>,
    pub fingerprint: String,
    pub purpose: String,
    pub source: String,
}
impl Material {
    pub fn id(&self) -> Result<Sha256Digest> {
        encode(self).map(|bytes| digest_bytes(&bytes))
    }
    fn validate(&self, now: i64) -> Result<ApprovedCertificate> {
        if self.purpose != PURPOSE || self.source.is_empty() || self.source.len() > 4096 {
            return Err("unsupported trust purpose or provenance".into());
        }
        let approved = ApprovedCertificate::from_reviewed_bytes(
            self.certificate.as_slice(),
            &self.fingerprint,
        )?;
        approved.validate_current(clock(now)?)?;
        Ok(approved)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Baseline {
    pub schema_version: u32,
    pub material: Material,
    pub approved_at: i64,
    pub checked_at: i64,
    pub approval_source: String,
    pub bundled_seed_id: Sha256Digest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proposal {
    pub schema_version: u32,
    pub base_id: Sha256Digest,
    pub material: Material,
    pub observed_at: i64,
    pub bundled_seed_id: Option<Sha256Digest>,
}
impl Proposal {
    pub fn id(&self) -> Result<Sha256Digest> {
        encode(&(
            self.schema_version,
            &self.base_id,
            &self.material,
            &self.bundled_seed_id,
        ))
        .map(|bytes| digest_bytes(&bytes))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdverseRecord {
    schema_version: u32,
    observations: Vec<RevocationObservation>,
}

pub(super) struct Trust<'a> {
    store: &'a PrivateStore,
    captured: CapturedFile,
    pub baseline: Baseline,
    pub pending_bundle_proposal: Option<Sha256Digest>,
}
#[derive(Debug)]
pub(super) enum Refresh {
    Unchanged,
    Proposed(Sha256Digest),
}

impl<'a> Trust<'a> {
    pub fn load(store: &'a PrivateStore, seed: &Material, now: i64) -> Result<Self> {
        ApprovedCertificate::from_reviewed_bytes(seed.certificate.as_slice(), &seed.fingerprint)?;
        let captured = match store.read_optional(Path::new(BASELINE), LIMIT)? {
            Some(captured) => captured,
            None => {
                seed.validate(now)?;
                let baseline = Baseline {
                    schema_version: 1,
                    material: seed.clone(),
                    approved_at: now,
                    checked_at: now,
                    approval_source: "reviewed bundled public seed".into(),
                    bundled_seed_id: seed.id()?,
                };
                store.publish(Path::new(BASELINE), &encode(&baseline)?)?;
                store.read(Path::new(BASELINE), LIMIT)?
            }
        };
        let baseline: Baseline = parse(captured.bytes())?;
        version(baseline.schema_version)?;
        clock(baseline.approved_at)?;
        clock(baseline.checked_at)?;
        if baseline.approved_at > now || baseline.checked_at > now {
            return Err("trust baseline clock is ahead of the current clock".into());
        }
        ApprovedCertificate::from_reviewed_bytes(
            baseline.material.certificate.as_slice(),
            &baseline.material.fingerprint,
        )?;
        let mut trust = Self {
            store,
            captured,
            baseline,
            pending_bundle_proposal: None,
        };
        trust.adverse()?;
        // Bundle changes follow the same explicit proposal route as fetched changes.
        if seed.id()? != trust.baseline.bundled_seed_id
            && let Refresh::Proposed(id) = trust.stage_inner(seed.clone(), now, Some(seed.id()?))?
        {
            trust.pending_bundle_proposal = Some(id);
        }
        Ok(trust)
    }

    pub fn observations(&self) -> Result<Vec<RevocationObservation>> {
        Ok(self.adverse()?.observations().to_vec())
    }
    pub fn proposal(&self, id: &Sha256Digest) -> Result<Proposal> {
        let captured = self
            .store
            .read(Path::new(&format!("trust/proposals/{id}.json")), LIMIT)?;
        let proposal: Proposal = parse(captured.bytes())?;
        if proposal.id()? != *id {
            return Err("proposal content identity mismatch".into());
        }
        Ok(proposal)
    }

    pub fn recheck(&self) -> Result<()> {
        self.store.check_capture(&self.captured)
    }

    fn adverse(&self) -> Result<AdverseKnowledge> {
        let Some(captured) = self.store.read_optional(Path::new(ADVERSE), LIMIT)? else {
            return Ok(AdverseKnowledge::default());
        };
        let record: AdverseRecord = parse(captured.bytes())?;
        version(record.schema_version)?;
        if record.observations.len() > 4096 {
            return Err("adverse knowledge record exceeds observation limit".into());
        }
        for observation in &record.observations {
            for fingerprint in [&observation.primary, &observation.component] {
                if fingerprint.len() != 40
                    || !fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
                {
                    return Err("invalid adverse observation identity".into());
                }
            }
        }
        Ok(AdverseKnowledge::from_observations(record.observations))
    }

    fn persist_adverse(&self, knowledge: &AdverseKnowledge) -> Result<()> {
        let before = self.store.read_optional(Path::new(ADVERSE), LIMIT)?;
        let mut merged = match &before {
            Some(captured) => {
                let record: AdverseRecord = parse(captured.bytes())?;
                version(record.schema_version)?;
                record.observations
            }
            None => Vec::new(),
        };
        let original = merged.clone();
        for observation in knowledge.observations() {
            if !merged.contains(observation) {
                merged.push(observation.clone());
            }
        }
        if merged == original {
            return Ok(());
        }
        let bytes = encode(&AdverseRecord {
            schema_version: 1,
            observations: merged,
        })?;
        match before {
            Some(captured) => self.store.replace(&captured, &bytes),
            None => self.store.publish(Path::new(ADVERSE), &bytes),
        }
        .map_err(|error| {
            format!("cannot persist authenticated adverse knowledge; operation blocked: {error}")
        })
    }

    fn refuse_adverse(&self, knowledge: &AdverseKnowledge) -> Result<()> {
        if knowledge
            .observations()
            .iter()
            .any(|observation| observation.primary == self.baseline.material.fingerprint)
        {
            return Err(
                "retained authenticated adverse revocation knowledge blocks this trust identity"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn verify(
        &self,
        observed: &[u8],
        signature: &[u8],
        document: &[u8],
        now: i64,
    ) -> Result<VerifiedSigner> {
        self.recheck()?;
        let approved = self.baseline.material.validate(now)?;
        let mut adverse = self.adverse()?;
        let result = verifier::verify(
            &approved,
            observed,
            signature,
            document,
            clock(now)?,
            &mut adverse,
        );
        self.persist_adverse(&adverse)?;
        self.recheck()?;
        result
    }

    pub fn stage(&self, material: Material, now: i64) -> Result<Refresh> {
        self.stage_inner(material, now, None)
    }

    fn stage_inner(
        &self,
        material: Material,
        now: i64,
        bundled_seed_id: Option<Sha256Digest>,
    ) -> Result<Refresh> {
        self.recheck()?;
        let approved = ApprovedCertificate::from_reviewed_bytes(
            self.baseline.material.certificate.as_slice(),
            &self.baseline.material.fingerprint,
        )?;
        let mut adverse = self.adverse()?;
        // Even material rejected for approval may contain authenticated revocation.
        let observed = approved.observe(material.certificate.as_slice(), clock(now)?, &mut adverse);
        self.persist_adverse(&adverse)?;
        self.refuse_adverse(&adverse)?;
        if material.fingerprint == self.baseline.material.fingerprint {
            observed?;
        }
        material.validate(now)?;
        if material == self.baseline.material && bundled_seed_id.is_none() {
            let mut baseline = self.baseline.clone();
            baseline.checked_at = now;
            self.store.replace(&self.captured, &encode(&baseline)?)?;
            return Ok(Refresh::Unchanged);
        }
        let proposal = Proposal {
            schema_version: 1,
            base_id: self.baseline.material.id()?,
            material,
            observed_at: now,
            bundled_seed_id,
        };
        let id = proposal.id()?;
        let path = format!("trust/proposals/{id}.json");
        let bytes = encode(&proposal)?;
        match self.store.read_optional(Path::new(&path), LIMIT)? {
            Some(existing) => {
                let existing: Proposal = parse(existing.bytes())?;
                if existing.id()? != id {
                    return Err("trust proposal content conflict".into());
                }
            }
            None => self.store.publish(Path::new(&path), &bytes)?,
        }
        self.recheck()?;
        Ok(Refresh::Proposed(id))
    }

    pub fn approve(&self, id: &Sha256Digest, now: i64) -> Result<()> {
        self.recheck()?;
        let captured = self
            .store
            .read(Path::new(&format!("trust/proposals/{id}.json")), LIMIT)?;
        let proposal: Proposal = parse(captured.bytes())?;
        version(proposal.schema_version)?;
        if proposal.id()? != *id
            || proposal.base_id != self.baseline.material.id()?
            || proposal.observed_at > now
        {
            return Err(
                "trust proposal identity/base/clock conflict; refresh and inspect a new proposal"
                    .into(),
            );
        }
        proposal.material.validate(now)?;
        let adverse = self.adverse()?;
        if adverse
            .observations()
            .iter()
            .any(|observation| observation.primary == proposal.material.fingerprint)
        {
            return Err("proposed identity has retained adverse revocation knowledge".into());
        }
        self.store.check_capture(&captured)?;
        let baseline = Baseline {
            schema_version: 1,
            material: proposal.material,
            approved_at: now,
            checked_at: proposal.observed_at,
            approval_source: format!("explicit proposal {id}"),
            bundled_seed_id: proposal
                .bundled_seed_id
                .unwrap_or_else(|| self.baseline.bundled_seed_id.clone()),
        };
        self.store.replace(&self.captured, &encode(&baseline)?)
    }
}

fn clock(now: i64) -> Result<u32> {
    u32::try_from(now).map_err(|_| "clock outside supported verification range".into())
}
fn version(version: u32) -> Result<()> {
    if version != 1 {
        Err("unsupported trust record schema".into())
    } else {
        Ok(())
    }
}
fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(record).map_err(|e| e.to_string())
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    parse_record(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: i64 = 1_793_750_400;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "barbican-trust-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/toolchain-intake/verifier")
                .join(name),
        )
        .unwrap()
    }
    fn seed() -> Material {
        Material {
            certificate: fixture("valid.asc"),
            fingerprint: String::from_utf8(fixture("primary-fingerprint.txt"))
                .unwrap()
                .trim()
                .into(),
            purpose: PURPOSE.into(),
            source: OFFICIAL_KEY_URL.into(),
        }
    }
    #[test]
    fn unchanged_refresh_preserves_approval_and_material_change_requires_exact_proposal() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0, &[]).unwrap();
        let original = seed();
        let trust = Trust::load(&store, &original, NOW).unwrap();
        assert!(matches!(
            trust.stage(original.clone(), NOW + 1).unwrap(),
            Refresh::Unchanged
        ));
        let trust = Trust::load(&store, &original, NOW + 1).unwrap();
        assert_eq!(trust.baseline.approved_at, NOW);
        assert_eq!(trust.baseline.checked_at, NOW + 1);
        let mut changed = original.clone();
        changed.source = "explicit reviewed public file".into();
        let Refresh::Proposed(id) = trust.stage(changed.clone(), NOW + 2).unwrap() else {
            panic!("must propose");
        };
        assert_eq!(trust.baseline.material, original);
        trust.approve(&id, NOW + 3).unwrap();
        assert!(trust.approve(&id, NOW + 3).is_err());
        let trust = Trust::load(&store, &original, NOW + 3).unwrap();
        assert_eq!(trust.baseline.material, changed);
        assert_eq!(trust.baseline.approved_at, NOW + 3);
    }
    #[test]
    fn adverse_observation_persists_before_refusal_and_survives_later_omission() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0, &[]).unwrap();
        let original = seed();
        let trust = Trust::load(&store, &original, NOW).unwrap();
        assert!(
            trust
                .verify(
                    &fixture("valid-plus-revocation.bin"),
                    &fixture("strong.asc"),
                    &fixture("payload.txt"),
                    NOW
                )
                .is_err()
        );
        let adverse = store.read(Path::new(ADVERSE), LIMIT).unwrap();
        let record: AdverseRecord = parse(adverse.bytes()).unwrap();
        assert!(!record.observations.is_empty());
        let trust = Trust::load(&store, &original, NOW).unwrap();
        assert!(
            trust
                .verify(
                    &original.certificate,
                    &fixture("strong.asc"),
                    &fixture("payload.txt"),
                    NOW
                )
                .is_err()
        );
        assert!(trust.stage(original, NOW).is_err());
    }
    #[test]
    fn material_bundle_update_stages_until_explicit_approval() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0, &[]).unwrap();
        let original = seed();
        Trust::load(&store, &original, NOW).unwrap();
        let mut update = original.clone();
        update.source = "reviewed bundled provenance update".into();
        let trust = Trust::load(&store, &update, NOW + 1).unwrap();
        assert_eq!(trust.baseline.material, original);
        let Refresh::Proposed(id) = trust
            .stage_inner(update.clone(), NOW + 1, Some(update.id().unwrap()))
            .unwrap()
        else {
            panic!("must propose");
        };
        trust.approve(&id, NOW + 2).unwrap();
        let trust = Trust::load(&store, &update, NOW + 2).unwrap();
        assert_eq!(trust.baseline.material, update);
        assert_eq!(trust.baseline.bundled_seed_id, update.id().unwrap());
    }
}
