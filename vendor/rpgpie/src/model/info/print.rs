// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Printing functionality for the `info` data structures

use pgp::packet::SubpacketType;

use crate::{
    model::info::{CertInfo, SigInfo, SubpacketInfo, subpacket::typ_to_name},
    signature,
};

pub(crate) fn print_cert_info(ci: &CertInfo, verbose: bool, ordered: bool) {
    println!(
        "🔐 {} v{} {}",
        ci.primary.algorithm, ci.primary.version, ci.primary.fingerprint
    );
    println!("  ⏱️ Created {}", ci.primary.created);

    if !ci.primary.revocations.is_empty() {
        println!("    Revocation signatures:");
        print_sig_infos(&ci.primary.revocations, verbose, ordered);
    }

    if !ci.primary.signatures.is_empty() {
        println!("    Direct signatures:");
        print_sig_infos(&ci.primary.signatures, verbose, ordered);
    }

    println!();

    for sk in &ci.subkeys {
        println!("  🔑 {} v{} {}", sk.algorithm, sk.version, sk.fingerprint);
        println!("    ⏱️ Created {}", sk.created);

        if !sk.revocations.is_empty() {
            // TODO: is this ever happening?
            println!("    subkey revocation signatures:");
            print_sig_infos(&sk.revocations, verbose, ordered);
        }

        print_sig_infos(&sk.signatures, verbose, ordered);

        println!();
    }

    for uid in &ci.users {
        println!("  🪪 ID {:?}", uid.id);
        print_sig_infos(&uid.signatures, verbose, ordered);

        println!();
    }

    for ua in &ci.user_attributes {
        println!("  🪪 ATTR [{:?}]", ua.id);
        print_sig_infos(&ua.signatures, verbose, ordered);

        println!();
    }
}

fn print_sig_infos(sigs: &[SigInfo], verbose: bool, ordered: bool) {
    let mut sigs = sigs.to_vec();
    if ordered {
        // TODO: show self-sigs first?

        sigs.sort_by_key(|si| std::cmp::Reverse(si.created));
    }

    sigs.iter().for_each(|s| print_sig_info(s, verbose))
}

pub(crate) fn print_sig_info(s: &SigInfo, verbose: bool) {
    // TODO:
    // - better model self-sig-ness / cryptographically check self-sig status?
    // - show self-sig as a special output format, distinct from third-party sigs (📝 ?)
    // - what should be shown for third-party sigs if multiple issure/fp subpackets are found?

    // Summary of subpackets, if "verbose" is off (empty if verbose is on)
    let summary = if !verbose {
        let issuer = s
            .hashed
            .iter()
            .chain(&s.unhashed)
            .find(|spi| spi.typ == SubpacketType::IssuerKeyId);
        let issuer_fp = s
            .hashed
            .iter()
            .chain(&s.unhashed)
            .find(|spi| spi.typ == SubpacketType::IssuerFingerprint);

        let issued_by = match (issuer, issuer_fp, &s.legacy_issuer) {
            (Some(keyid), _, _) => &keyid.value,
            (None, Some(fp), _) => &fp.value,
            (_, _, Some(legacy)) => legacy,
            (None, None, None) => "??",
        };

        format!(" {}, by {issued_by}", s.created)
    } else {
        "".to_string()
    };

    let sig_icon = match signature::is_revocation_type(s.typ) {
        false => "🖋",
        true => "🚫",
    };

    println!(
        "    {sig_icon} {:?}{summary} [{}, {}, v{}]",
        s.typ, s.public_key_algo, s.hash_algo, s.version
    );

    if verbose {
        print_subpackets(&s.hashed);

        if !s.unhashed.is_empty() {
            println!("      Unhashed subpackets:");
            print_subpackets(&s.unhashed);
        }

        println!();
    }
}

fn print_subpackets(subpackets: &[SubpacketInfo]) {
    for sp in subpackets {
        let crit = match sp.critical {
            true => "!",
            false => " ",
        };

        println!("       {crit}{}: {}", typ_to_name(sp.typ), sp.value);
    }
}
