use super::*;
use pgp::ser::Serialize;

const NOW: u32 = 1_793_750_400;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/toolchain-intake/verifier")
            .join(name),
    )
    .unwrap()
}
fn approved(name: &str, fp: &str) -> ApprovedCertificate {
    ApprovedCertificate::from_reviewed_bytes(&fixture(name), fp).unwrap()
}
fn fp(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap().trim().to_owned()
}
fn run(cert: &str, signature: &str, fingerprint: &str, now: u32) -> Result<VerifiedSigner> {
    verify(
        &approved(cert, fingerprint),
        &fixture(cert),
        &fixture(signature),
        &fixture("payload.txt"),
        now,
        &mut AdverseKnowledge::default(),
    )
}

#[test]
fn authentic_rust_manifest_and_current_subkey_verify() {
    let anchor = approved("rust-key.asc", "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE");
    let verified = verify(
        &anchor,
        &fixture("rust-key.asc"),
        &fixture("rust-manifest.asc"),
        &fixture("rust-manifest.toml"),
        NOW,
        &mut AdverseKnowledge::default(),
    )
    .unwrap();
    assert_eq!(verified.primary, anchor.fingerprint);
    assert!(
        run(
            "valid.asc",
            "strong.asc",
            &fp("primary-fingerprint.txt"),
            NOW
        )
        .is_ok()
    );
}

#[test]
fn exact_primary_and_selected_subkey_expiry_boundaries() {
    for (cert, sig, fingerprint) in [
        (
            "expired-primary.asc",
            "expired-primary-signature.asc",
            fp("expired-primary-fingerprint.txt"),
        ),
        (
            "expired-subkey.asc",
            "strong.asc",
            fp("primary-fingerprint.txt"),
        ),
    ] {
        let anchor = approved(cert, &fingerprint);
        let key = &anchor.key;
        let expiry = if cert == "expired-primary.asc" {
            key.primary_key.created_at().as_secs()
                + key
                    .details
                    .users
                    .iter()
                    .flat_map(|u| &u.signatures)
                    .find_map(|s| s.key_expiration_time())
                    .unwrap()
                    .as_secs()
        } else {
            let sub = &key.public_subkeys[0];
            sub.key.created_at().as_secs()
                + sub
                    .signatures
                    .iter()
                    .find_map(|s| s.key_expiration_time())
                    .unwrap()
                    .as_secs()
        };
        assert!(
            run(cert, sig, &fingerprint, expiry - 1).is_ok(),
            "{cert} before expiry"
        );
        for now in [expiry, expiry + 1] {
            assert!(
                run(cert, sig, &fingerprint, now)
                    .unwrap_err()
                    .contains("no current signing key"),
                "{cert} at {now}"
            );
        }
    }
}

#[test]
fn original_refusal_controls() {
    let fingerprint = fp("primary-fingerprint.txt");
    let anchor = approved("valid.asc", &fingerprint);
    for sig in [
        "tampered-signature.bin",
        "empty.bin",
        "weak-backdated.asc",
        "duplicate-signatures.bin",
        "truncated-header.bin",
        "large-declared.bin",
        "truncated-body.bin",
        "many-signatures.bin",
        "oversize.bin",
        "secret-tag.bin",
        "compressed-tag.bin",
    ] {
        assert!(
            verify(
                &anchor,
                &fixture("valid.asc"),
                &fixture(sig),
                &fixture("payload.txt"),
                NOW,
                &mut AdverseKnowledge::default()
            )
            .is_err(),
            "{sig}"
        );
    }
    assert!(
        verify(
            &anchor,
            &fixture("valid.asc"),
            &fixture("strong.asc"),
            &fixture("tampered.txt"),
            NOW,
            &mut AdverseKnowledge::default()
        )
        .is_err()
    );
    assert!(
        ApprovedCertificate::from_reviewed_bytes(&fixture("valid.asc"), &"0".repeat(40)).is_err()
    );
    assert!(
        verify(
            &anchor,
            &fixture("extra-armour.asc"),
            &fixture("strong.asc"),
            &fixture("payload.txt"),
            NOW,
            &mut AdverseKnowledge::default()
        )
        .unwrap_err()
        .contains("trailing armour")
    );
    assert!(
        verify(
            &anchor,
            &fixture("new-binding.asc"),
            &fixture("strong.asc"),
            &fixture("payload.txt"),
            NOW,
            &mut AdverseKnowledge::default()
        )
        .unwrap_err()
        .contains("unapproved")
    );
    for cert in [
        "expired-subkey.asc",
        "wrong-purpose.asc",
        "corrupt-cross-signature.bin",
        "remove-cross-signature.bin",
        "future-cross-signature.bin",
    ] {
        assert!(
            run(cert, "strong.asc", &fingerprint, NOW).is_err(),
            "{cert}"
        );
    }
    assert!(
        run(
            "expired-primary.asc",
            "expired-primary-signature.asc",
            &fp("expired-primary-fingerprint.txt"),
            NOW
        )
        .is_err()
    );
    for sig in [
        "strong.asc",
        "expired-document.asc",
        "future-document.asc",
        "critical-document.asc",
        "critical-policy-uri.asc",
    ] {
        assert!(
            run(
                "document-cert.asc",
                sig,
                &fp("document-fingerprint.txt"),
                NOW
            )
            .is_err(),
            "{sig}"
        );
    }
}

#[test]
fn adverse_observations_precede_proposal_refusal_and_cannot_be_erased() {
    let anchor = approved("valid.asc", &fp("primary-fingerprint.txt"));
    for cert in ["revoked-newer-uid.asc", "valid-plus-revocation.bin"] {
        let mut known = AdverseKnowledge::default();
        assert!(
            verify(
                &anchor,
                &fixture(cert),
                &fixture("strong.asc"),
                &fixture("payload.txt"),
                NOW,
                &mut known
            )
            .unwrap_err()
            .contains("adverse")
        );
        assert!(!known.observations().is_empty());
        let before = known.observations().to_vec();
        assert!(
            verify(
                &anchor,
                &fixture("valid.asc"),
                &fixture("strong.asc"),
                &fixture("payload.txt"),
                NOW,
                &mut known
            )
            .unwrap_err()
            .contains("adverse")
        );
        assert_eq!(before, known.observations());
    }
    let anchor = approved(
        "subkey-before-revocation.asc",
        &fp("document-fingerprint.txt"),
    );
    let mut known = AdverseKnowledge::default();
    assert!(
        verify(
            &anchor,
            &fixture("revoked-subkey.asc"),
            &fixture("subkey-before-revocation-signature.asc"),
            &fixture("payload.txt"),
            NOW,
            &mut known
        )
        .unwrap_err()
        .contains("adverse")
    );
    assert_ne!(
        known.observations()[0].primary,
        known.observations()[0].component
    );
}

#[test]
fn genuinely_authenticated_future_cross_signature_reaches_time_guard() {
    let original = approved(
        "future-cross-original.asc",
        &fp("future-cross-fingerprint.txt"),
    );
    let future = approved(
        "future-cross-authored.asc",
        &fp("future-cross-fingerprint.txt"),
    );
    let back = future.key.public_subkeys[0]
        .signatures
        .iter()
        .find_map(|s| s.embedded_signature())
        .unwrap();
    back.verify_primary_key_binding(
        &original.key.public_subkeys[0].key,
        &original.key.primary_key,
    )
    .unwrap();
    assert!(
        back.created().unwrap().as_secs() > NOW,
        "fixture must actually be future and cryptographically valid"
    );
    let mut packets = original.packets.clone();
    for packet in &mut packets {
        if let Packet::Signature(binding) = packet
            && binding.typ() == Some(SignatureType::SubkeyBinding)
        {
            let mut config = binding.config().unwrap().clone();
            for sub in &mut config.unhashed_subpackets {
                if let SubpacketData::EmbeddedSignature(value) = &mut sub.data {
                    **value = back.clone();
                }
            }
            *binding = Signature::from_config(
                config,
                binding.signed_hash_value().unwrap(),
                binding.signature().unwrap().clone(),
            )
            .unwrap();
        }
    }
    let mut bytes = Vec::new();
    for packet in packets {
        packet.to_writer(&mut bytes).unwrap();
    }
    let anchor = ApprovedCertificate::from_reviewed_bytes(&bytes, &original.fingerprint).unwrap();
    anchor.key.public_subkeys[0].signatures[0]
        .verify_subkey_binding(&anchor.key.primary_key, &anchor.key.public_subkeys[0].key)
        .unwrap();
    assert_eq!(
        structural_policy(&anchor.key, Timestamp::from_secs(NOW)).unwrap_err(),
        "future signature"
    );
    assert!(
        verify(
            &anchor,
            &bytes,
            &fixture("future-cross-document.asc"),
            &fixture("future-cross-payload.txt"),
            NOW,
            &mut AdverseKnowledge::default()
        )
        .unwrap_err()
        .contains("future signature")
    );
}

#[test]
fn authenticated_revocation_classification_is_bounded_and_invalid_packets_have_no_authority() {
    let anchor = approved(
        "future-cross-original.asc",
        &fp("future-cross-fingerprint.txt"),
    );
    for (name, reason) in [
        ("current", None),
        ("future", Some("future signature")),
        ("obsolete", Some("current signature hash policy")),
        ("critical", Some("unsupported critical signature extension")),
        ("expired", Some("expired signature")),
    ] {
        let bytes = fixture(&format!("revocation-{name}.bin"));
        let observed = input::certificate(&input::packets(&bytes, true).unwrap()).unwrap();
        observed.details.revocation_signatures[0]
            .verify_key(&anchor.key.primary_key)
            .unwrap();
        let mut known = AdverseKnowledge::default();
        let error = verify(
            &anchor,
            &bytes,
            &fixture("future-cross-document.asc"),
            &fixture("future-cross-payload.txt"),
            NOW,
            &mut known,
        )
        .unwrap_err();
        assert!(error.contains("adverse"), "{name}: {error}");
        assert_eq!(known.observations().len(), 1);
        assert_eq!(
            known.observations()[0].status,
            match reason {
                None => RevocationStatus::Admissible,
                Some(s) => RevocationStatus::Indeterminate(s.into()),
            }
        );
        let before = known.observations().to_vec();
        assert!(
            verify(
                &anchor,
                &fixture("future-cross-original.asc"),
                &fixture("future-cross-document.asc"),
                &fixture("future-cross-payload.txt"),
                NOW,
                &mut known
            )
            .unwrap_err()
            .contains("adverse")
        );
        assert_eq!(before, known.observations());
    }
    let mut packets = input::packets(&fixture("revocation-current.bin"), true).unwrap();
    if let Packet::Signature(sig) = &mut packets[1] {
        let mut config = sig.config().unwrap().clone();
        for sub in &mut config.hashed_subpackets {
            if let SubpacketData::SignatureCreationTime(time) = &mut sub.data {
                *time = Timestamp::from_secs(time.as_secs() + 1);
            }
        }
        *sig = Signature::from_config(
            config,
            sig.signed_hash_value().unwrap(),
            sig.signature().unwrap().clone(),
        )
        .unwrap();
    }
    let mut bytes = Vec::new();
    for packet in packets {
        packet.to_writer(&mut bytes).unwrap();
    }
    let mut known = AdverseKnowledge::default();
    assert!(
        verify(
            &anchor,
            &bytes,
            &fixture("future-cross-document.asc"),
            &fixture("future-cross-payload.txt"),
            NOW,
            &mut known
        )
        .unwrap_err()
        .contains("unapproved")
    );
    assert!(known.observations().is_empty());
    assert!(
        verify(
            &anchor,
            &fixture("future-cross-original.asc"),
            &fixture("future-cross-document.asc"),
            &fixture("future-cross-payload.txt"),
            NOW,
            &mut known
        )
        .is_ok()
    );
}

#[test]
fn adverse_packets_survive_rejected_benign_composed_projection() {
    let anchor = approved(
        "future-cross-original.asc",
        &fp("future-cross-fingerprint.txt"),
    );
    let mut packets = input::packets(&fixture("revocation-current.bin"), true).unwrap();
    // An unbound extra subkey is dropped by the composed parser. It cannot hide the earlier revocation.
    let sub = packets
        .iter()
        .find(|p| matches!(p, Packet::PublicSubkey(_)))
        .unwrap()
        .clone();
    packets.push(sub);
    let mut bytes = Vec::new();
    for packet in packets {
        packet.to_writer(&mut bytes).unwrap();
    }
    assert!(input::certificate(&input::packets(&bytes, true).unwrap()).is_err());
    let mut known = AdverseKnowledge::default();
    assert!(
        verify(&anchor, &bytes, &[], &[], NOW, &mut known)
            .unwrap_err()
            .contains("adverse")
    );
    assert_eq!(known.observations().len(), 1);
}
