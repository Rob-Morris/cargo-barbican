//! Bounded public-only verification; callers supply an explicitly approved baseline.
//! No trust publication, clock acquisition, network or installation occurs here.
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use pgp::{
    composed::SignedPublicKey,
    crypto::hash::HashAlgorithm,
    packet::{Packet, Signature, SignatureType, SubpacketData},
    ser::Serialize as _,
    types::{KeyDetails, Timestamp},
};
use rpgpie::{
    certificate::{Certificate, Checked},
    detached,
};

#[path = "verifier/input.rs"]
mod input;
#[cfg(test)]
#[path = "verifier/tests.rs"]
mod tests;

pub(super) type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RevocationStatus {
    Admissible,
    Indeterminate(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevocationObservation {
    pub primary: String,
    pub component: String,
    pub status: RevocationStatus,
}

/// Append-only authenticated knowledge; the trust owner persists before reporting.
#[derive(Debug, Default)]
pub(super) struct AdverseKnowledge(Vec<RevocationObservation>);

impl AdverseKnowledge {
    pub fn observations(&self) -> &[RevocationObservation] {
        &self.0
    }

    pub fn from_observations(observations: Vec<RevocationObservation>) -> Self {
        Self(observations)
    }

    fn retain(&mut self, observation: RevocationObservation) {
        if !self.0.contains(&observation) {
            self.0.push(observation);
        }
    }
}

pub(super) struct ApprovedCertificate {
    packets: Vec<Packet>,
    key: SignedPublicKey,
    fingerprint: String,
}

impl ApprovedCertificate {
    /// This validates supplied authority; it does not approve a new certificate.
    pub fn from_reviewed_bytes(bytes: &[u8], full_fingerprint: &str) -> Result<Self> {
        if full_fingerprint.len() != 40 || !full_fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("expected full v4 primary fingerprint".into());
        }
        let packets = input::packets(bytes, true)?;
        let key = input::certificate(&packets)?;
        let fingerprint = format!("{}", key.fingerprint()).to_ascii_uppercase();
        if fingerprint != full_fingerprint.to_ascii_uppercase() {
            return Err("wrong full primary identity".into());
        }
        Ok(Self {
            packets,
            key,
            fingerprint,
        })
    }

    pub fn validate_current(&self, now: u32) -> Result<()> {
        structural_policy(&self.key, Timestamp::from_secs(now))?;
        let checked = Checked::from(Certificate::from(self.key.clone()));
        if checked
            .valid_signing_capable_component_keys_at(Timestamp::from_secs(now))
            .is_empty()
        {
            return Err("certificate has no currently eligible signing component".into());
        }
        Ok(())
    }

    pub fn observe(&self, observed: &[u8], now: u32, adverse: &mut AdverseKnowledge) -> Result<()> {
        let packets = input::packets(observed, true)?;
        let Some(Packet::PublicKey(primary)) = packets.first() else {
            return Err("missing primary key".into());
        };
        if primary.to_bytes().map_err(|e| e.to_string())?
            != self.key.primary_key.to_bytes().map_err(|e| e.to_string())?
        {
            return Err("wrong full primary identity".into());
        }
        observe_revocations(&packets, self, Timestamp::from_secs(now), adverse);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedSigner {
    pub primary: String,
    pub component: String,
    pub signature_created_at: u32,
}

pub(super) fn verify(
    approved: &ApprovedCertificate,
    observed: &[u8],
    signature: &[u8],
    document: &[u8],
    now: u32,
    adverse: &mut AdverseKnowledge,
) -> Result<VerifiedSigner> {
    let observed_packets = input::packets(observed, true)?;
    let Some(Packet::PublicKey(primary)) = observed_packets.first() else {
        return Err("missing primary key".into());
    };
    if primary.to_bytes().map_err(|e| e.to_string())?
        != approved
            .key
            .primary_key
            .to_bytes()
            .map_err(|e| e.to_string())?
    {
        return Err("wrong full primary identity".into());
    }
    let now = Timestamp::from_secs(now);
    observe_revocations(&observed_packets, approved, now, adverse);
    if adverse
        .0
        .iter()
        .any(|event| event.primary == approved.fingerprint)
    {
        return Err("retained authenticated adverse revocation observation".into());
    }
    let key = input::certificate(&observed_packets)?;
    if observed_packets != approved.packets {
        return Err("unapproved certificate material".into());
    }
    structural_policy(&key, now)?;
    let sigs = input::packets(signature, false)?;
    let [Packet::Signature(sig)] = sigs.as_slice() else {
        return Err("exactly one detached signature required".into());
    };
    if sig.typ() != Some(SignatureType::Binary) {
        return Err("binary signature required".into());
    }
    signature_policy(sig, now, key.primary_key.created_at(), false)?;
    if document.len() > 8 * 1024 * 1024 {
        return Err("document size limit".into());
    }
    let cert = Certificate::from(key);
    let checked = Checked::from(cert.clone());
    let current = checked.valid_signing_capable_component_keys_at(now);
    let identities: Vec<_> = current
        .iter()
        .map(|k| k.as_componentkey().fingerprint())
        .collect();
    let certs = [cert];
    let signatures = [sig.clone()];
    let verified =
        detached::verify(Cursor::new(document), &signatures, &certs).map_err(|e| e.to_string())?;
    let signer = verified
        .iter()
        .find(|v| identities.contains(&v.component))
        .ok_or("signature absent or no current signing key")?;
    Ok(VerifiedSigner {
        primary: approved.fingerprint.clone(),
        component: format!("{}", signer.component).to_ascii_uppercase(),
        signature_created_at: sig.created().ok_or("missing signature time")?.as_secs(),
    })
}

fn strong_hash(hash: HashAlgorithm) -> bool {
    matches!(
        hash,
        HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
    )
}

fn signature_policy(
    sig: &Signature,
    now: Timestamp,
    not_before: Timestamp,
    structural: bool,
) -> Result<()> {
    let config = sig.config().ok_or("unsupported signature version")?;
    if !(strong_hash(config.hash_alg) || structural && config.hash_alg == HashAlgorithm::Sha1) {
        return Err("current signature hash policy".into());
    }
    let mut created = 0;
    let mut expiry = 0;
    for sub in &config.hashed_subpackets {
        if matches!(sub.data, SubpacketData::SignatureCreationTime(_)) {
            created += 1;
        }
        if matches!(sub.data, SubpacketData::SignatureExpirationTime(_)) {
            expiry += 1;
        }
        if sub.is_critical
            && !matches!(
                sub.data,
                SubpacketData::IssuerFingerprint(_)
                    | SubpacketData::SignatureCreationTime(_)
                    | SubpacketData::SignatureExpirationTime(_)
            )
        {
            return Err("unsupported critical signature extension".into());
        }
    }
    if created != 1 || expiry > 1 {
        return Err("ambiguous signature time".into());
    }
    if config.unhashed_subpackets.iter().any(|s| s.is_critical) {
        return Err("unhashed critical signature extension".into());
    }
    let created = sig.created().ok_or("missing signature time")?;
    if created < not_before {
        return Err("signature predates key".into());
    }
    if created > now {
        return Err("future signature".into());
    }
    if let Some(duration) = sig.signature_expiration_time()
        && duration.as_secs() != 0
    {
        let expires = created
            .as_secs()
            .checked_add(duration.as_secs())
            .ok_or("signature expiry overflow")?;
        if expires <= now.as_secs() {
            return Err("expired signature".into());
        }
    }
    Ok(())
}

fn structural_policy(key: &SignedPublicKey, now: Timestamp) -> Result<()> {
    // Exact approved packets are the sole legacy exception; no claimed historical date grants it.
    for sig in key
        .details
        .direct_signatures
        .iter()
        .chain(key.details.users.iter().flat_map(|u| &u.signatures))
    {
        structural_signature(sig, now, key.primary_key.created_at())?;
    }
    for subkey in &key.public_subkeys {
        for binding in &subkey.signatures {
            structural_signature(binding, now, subkey.key.created_at())?;
            if let Some(back) = binding.embedded_signature() {
                // rpgpie checks hashed embedded signatures only; rPGP also returns unhashed ones.
                back.verify_primary_key_binding(&subkey.key, &key.primary_key)
                    .map_err(|e| e.to_string())?;
                signature_policy(back, now, subkey.key.created_at(), true)?;
            }
        }
    }
    Ok(())
}

fn structural_signature(sig: &Signature, now: Timestamp, created: Timestamp) -> Result<()> {
    signature_policy(sig, now, created, true)?;
    if let Some(duration) = sig.key_expiration_time() {
        // Upstream represents primary expiry as u32; refuse unrepresentable input before Checked.
        created
            .as_secs()
            .checked_add(duration.as_secs())
            .ok_or("key expiry overflow")?;
    }
    Ok(())
}

fn observe_revocations(
    packets: &[Packet],
    approved: &ApprovedCertificate,
    now: Timestamp,
    adverse: &mut AdverseKnowledge,
) {
    let primary = &approved.key.primary_key;
    let mut subkey = None;
    for packet in packets {
        let (sig, component, created, authenticated) = match packet {
            Packet::PublicSubkey(key) => {
                subkey = Some(key);
                continue;
            }
            Packet::Signature(sig) if sig.typ() == Some(SignatureType::KeyRevocation) => (
                sig,
                approved.fingerprint.clone(),
                primary.created_at(),
                sig.verify_key(primary).is_ok(),
            ),
            Packet::Signature(sig) if sig.typ() == Some(SignatureType::SubkeyRevocation) => {
                let Some(key) = subkey else {
                    continue;
                };
                (
                    sig,
                    format!("{}", key.fingerprint()).to_ascii_uppercase(),
                    key.created_at(),
                    sig.verify_subkey_binding(primary, key).is_ok(),
                )
            }
            _ => continue,
        };
        if !authenticated {
            continue;
        }
        let status = match signature_policy(sig, now, created, false) {
            Ok(()) => RevocationStatus::Admissible,
            Err(reason) => RevocationStatus::Indeterminate(reason),
        };
        adverse.retain(RevocationObservation {
            primary: approved.fingerprint.clone(),
            component,
            status,
        });
    }
}
