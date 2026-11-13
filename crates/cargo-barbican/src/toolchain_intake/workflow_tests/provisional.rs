use super::*;
use crate::toolchain_intake::{collection, review, sources::Sources};

const REV: &str = "5555555555555555555555555555555555555555";
fn corpus() -> BTreeMap<String, String> {
    ["first", "second"].into_iter().map(|slug| (
        format!("crates/example/RUSTSEC-0000-0000.{slug}.md"),
        "```toml\n[advisory]\nid='RUSTSEC-0000-0000'\npackage='example'\ndate='2026-01-01'\naliases=['CVE-2026-12345']\n[versions]\npatched=[]\n```\n\n# Authored provisional source fixture\n".into(),
    )).collect()
}
fn lock() -> String {
    format!(
        "version=4\n[[package]]\nname='example'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{}'\n",
        "a".repeat(64)
    )
}
fn findings(f: &Fixture, corpus: &BTreeMap<String, String>) -> Vec<Finding> {
    let lock = parse_source_package_inventory(&lock()).unwrap();
    collection::findings_from_corpus(
        corpus,
        REV,
        &f.review.subject,
        &[lock.clone(), lock.clone(), lock],
        f.now,
    )
    .unwrap()
}
fn complete(review: &ReconstructedReview, now: i64) -> (Vec<u8>, HumanAssessment) {
    let id = review.record.id(&review.subject).unwrap();
    let prose = acceptance::template(review, &id).unwrap()
        .replace("PENDING — complete this review before acceptance.\n", "")
        .replace("Decision: PENDING", "Decision: ACCEPT")
        .replace("Rationale: PENDING — review every source snapshot and finding, explain accepted residual uncertainty and relevant applicability. Set Decision: ACCEPT and remove all PENDING markers only after human review.", "Rationale: Reviewed all exact source records and their individual applicability; accepted the stated unknown reachability for this authored test.")
        .into_bytes();
    let assessment = acceptance::assess(review, &id, &prose, now).unwrap();
    (prose, assessment)
}
fn republish(f: &mut Fixture) {
    (f.prose, f.assessment) = complete(&f.review, f.now);
    let id = f.id();
    let portable = PortableReview {
        schema_version: 1,
        subject: f.review.subject.record().clone(),
        evidence: f.review.record.evidence.clone(),
        policy: f.review.record.policy.clone(),
        assessment: f.assessment.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&portable).unwrap();
    f.admission.assessment_id = f.assessment.id().unwrap();
    f.admission.review_record = f.assessment.review.path.clone();
    f.admission.review_record_sha256 = f.assessment.review.sha256.clone();
    f.admission.evidence_record = format!("docs/dependency-reviews/toolchains/{id}/evidence.json");
    f.admission.evidence_record_sha256 = digest_bytes(&bytes);
    let repo = f.root.join("repo");
    write(
        &repo,
        "reviewed-targets.toml",
        render_admission_fragment(&f.admission).unwrap().as_bytes(),
    );
    write(&repo, &f.admission.evidence_record, &bytes);
    write(&repo, &f.admission.review_record, &f.prose);
    for (path, bytes) in &f.review.source_snapshots {
        write(&repo, path, bytes);
    }
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/toolchain-intake/workflow");
    for (name, original) in [
        ("manifest.toml", "channel-rust-1.99.1.toml"),
        ("manifest.asc", "channel-rust-1.99.1.toml.asc"),
        ("certificate.pgp", "fixture-public-key.asc"),
    ] {
        write(
            &repo,
            &format!("docs/dependency-reviews/toolchains/{id}/{name}"),
            &fs::read(source.join(original)).unwrap(),
        );
    }
}

#[test]
fn provisional_findings_survive_collection_template_and_exact_assessment() {
    let mut f = Fixture::prepared(true);
    let corpus = corpus();
    let rows = findings(&f, &corpus);
    assert_eq!(rows.len(), 6); // Two independent issues in each of three components.
    let mut lock = parse_source_package_inventory(&lock()).unwrap();
    lock.push(lock[0].clone());
    assert_eq!(
        rows,
        collection::findings_from_corpus(
            &corpus,
            REV,
            &f.review.subject,
            &[lock.clone(), lock.clone(), lock],
            f.now
        )
        .unwrap()
    );
    f.review.record.evidence.findings = rows;
    let template = acceptance::template(&f.review, &f.id()).unwrap();
    assert_eq!(
        template
            .lines()
            .filter(|l| l.starts_with("Assessed-Finding: "))
            .count(),
        6
    );
    for path in corpus.keys() {
        assert!(template.contains(path));
    }
    assert!(template.contains(REV));
    assert!(template.contains("Provisional RustSec record RUSTSEC-0000-0000"));
    assert!(!template.contains("rustsec.org/advisories/RUSTSEC-0000-0000"));
    assert_eq!(
        template
            .lines()
            .filter(|l| l.starts_with("Rationale: "))
            .count(),
        1
    );
    let (prose, assessment) = complete(&f.review, f.now);
    assert_eq!(assessment.assessed_findings.len(), 6);
    let first = &f.review.record.evidence.findings[0].id;
    let missing = String::from_utf8(prose.clone())
        .unwrap()
        .replace(&format!("Assessed-Finding: {first}\n"), "");
    assert!(
        acceptance::assess(&f.review, &f.id(), missing.as_bytes(), f.now)
            .unwrap_err()
            .contains("every exact finding")
    );
    let data = f.data("unknown-positive");
    acceptance::publish_personal(
        &data,
        &f.id(),
        &f.review,
        assessment,
        prose,
        FreshnessRequest::Online {
            operation_started_at: f.now,
        },
        &CurrentKnowledge::default(),
        None,
        f.now,
    )
    .unwrap();
    f.review.record.evidence.findings[0].exposure = Exposure::Known;
    let (prose, assessment) = complete(&f.review, f.now);
    assert!(
        acceptance::publish_personal(
            &data,
            &f.id(),
            &f.review,
            assessment,
            prose,
            FreshnessRequest::Online {
                operation_started_at: f.now
            },
            &CurrentKnowledge::default(),
            None,
            f.now
        )
        .unwrap_err()
        .contains("known applicable adverse")
    );
    let assigned = BTreeMap::from([(
        "crates/example/RUSTSEC-2026-0001.md".into(),
        corpus
            .values()
            .next()
            .unwrap()
            .replace("RUSTSEC-0000-0000", "RUSTSEC-2026-0001"),
    )]);
    assert_eq!(
        findings(&f, &assigned)
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        [
            "RUSTSEC-2026-0001/vulnerability/example@1.0.0/cargo/aarch64-apple-darwin",
            "RUSTSEC-2026-0001/vulnerability/example@1.0.0/rust-std/aarch64-apple-darwin",
            "RUSTSEC-2026-0001/vulnerability/example@1.0.0/rustc/aarch64-apple-darwin",
        ]
    );
}

fn archive(corpus: &BTreeMap<String, String>) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut append = |name: &str, body: &[u8], kind| {
        let mut header = tar::Header::new_ustar();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(kind);
        header.set_cksum();
        tar.append_data(&mut header, name, body).unwrap();
    };
    append(
        "pax_global_header",
        format!("52 comment={REV}\n").as_bytes(),
        tar::EntryType::new(b'g'),
    );
    for (path, body) in corpus {
        append(
            &format!("advisory-db-{REV}/{path}"),
            body.as_bytes(),
            tar::EntryType::Regular,
        );
    }
    let input = tar.into_inner().unwrap();
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    out.extend(miniz_oxide::deflate::compress_to_vec(&input, 6));
    let mut crc = !0u32;
    for &b in &input {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    out.extend((!crc).to_le_bytes());
    out.extend((input.len() as u32).to_le_bytes());
    out
}

// Authored source responses exercise the real collector and authenticated archive path.
// The instance has no network fallback for missing fixture URLs.
fn sources(corpus: &BTreeMap<String, String>) -> Sources {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/toolchain-intake/workflow");
    let mut responses = BTreeMap::new();
    for (url, file) in [
        (
            "https://static.rust-lang.org/dist/channel-rust-1.99.1.toml",
            "channel-rust-1.99.1.toml",
        ),
        (
            "https://static.rust-lang.org/dist/channel-rust-1.99.1.toml.asc",
            "channel-rust-1.99.1.toml.asc",
        ),
        (
            super::super::trust::OFFICIAL_KEY_URL,
            "fixture-public-key.asc",
        ),
    ] {
        responses.insert(url.into(), fs::read(root.join(file)).unwrap());
    }
    for package in ["cargo", "rustc", "rust-std"] {
        let name = format!("{package}-1.99.1-aarch64-apple-darwin.tar.xz");
        responses.insert(
            format!("https://static.rust-lang.org/dist/2026-10-15/{name}"),
            fs::read(root.join(name)).unwrap(),
        );
    }
    let rust = "1".repeat(40);
    let root_tree = "2".repeat(40);
    let src_tree = "3".repeat(40);
    let tools_tree = "4".repeat(40);
    let cargo = "6".repeat(40);
    responses.insert(
        format!("https://api.github.com/repos/rust-lang/rust/git/commits/{rust}"),
        format!(r#"{{"sha":"{rust}","tree":{{"sha":"{root_tree}"}}}}"#).into_bytes(),
    );
    for (tree, entries) in [
        (
            &root_tree,
            vec![
                ("src", "tree", &src_tree),
                ("compiler", "tree", &tools_tree),
                ("library", "tree", &tools_tree),
            ],
        ),
        (
            &src_tree,
            vec![
                ("tools", "tree", &tools_tree),
                ("llvm-project", "commit", &cargo),
                ("librustdoc", "tree", &tools_tree),
            ],
        ),
        (&tools_tree, vec![("cargo", "commit", &cargo)]),
    ] {
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(path, kind, sha)| serde_json::json!({"path":path,"type":kind,"sha":sha}))
            .collect();
        responses.insert(
            format!("https://api.github.com/repos/rust-lang/rust/git/trees/{tree}"),
            serde_json::to_vec(&serde_json::json!({"sha":tree,"tree":entries})).unwrap(),
        );
    }
    let mut packages = lock();
    for (package, version) in [
        ("rustc-main", "0.0.0"),
        ("rustdoc", "0.0.0"),
        ("std", "0.0.0"),
        ("cargo", "0.100.0"),
    ] {
        packages.push_str(&format!(
            "[[package]]\nname='{package}'\nversion='{version}'\n"
        ));
    }
    for (repo, revision, path) in [
        ("rust", &rust, "Cargo.lock"),
        ("rust", &rust, "library/Cargo.lock"),
        ("cargo", &cargo, "Cargo.lock"),
    ] {
        responses.insert(
            format!("https://raw.githubusercontent.com/rust-lang/{repo}/{revision}/{path}"),
            packages.as_bytes().to_vec(),
        );
    }
    for (repo, revision, path, package, version) in [
        (
            "rust",
            &rust,
            "compiler/rustc/Cargo.toml",
            "rustc-main",
            "0.0.0",
        ),
        (
            "rust",
            &rust,
            "src/librustdoc/Cargo.toml",
            "rustdoc",
            "0.0.0",
        ),
        ("rust", &rust, "library/std/Cargo.toml", "std", "0.0.0"),
        ("cargo", &cargo, "Cargo.toml", "cargo", "0.100.0"),
    ] {
        responses.insert(
            format!("https://raw.githubusercontent.com/rust-lang/{repo}/{revision}/{path}"),
            format!("[package]\nname='{package}'\nversion='{version}'\n").into_bytes(),
        );
    }
    for (url, body) in [
        (
            "https://llvm.org/docs/Security.html",
            "Authored LLVM security scope".into(),
        ),
        (
            "https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/",
            "Rust 1.99.1 authored release announcement".into(),
        ),
        (
            "https://blog.rust-lang.org/",
            "Authored announcement index".into(),
        ),
        (
            "https://rust-lang.org/policies/security/",
            format!(
                "Security policy Scope {}",
                "authored test scope ".repeat(100)
            ),
        ),
        (
            "https://api.github.com/repos/rust-lang/cargo/security-advisories",
            "[]".into(),
        ),
        (
            "https://api.github.com/repos/RustSec/advisory-db/commits/HEAD",
            format!(r#"{{"sha":"{REV}"}}"#),
        ),
    ] {
        responses.insert(url.into(), body.into_bytes());
    }
    responses.insert(
        format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{REV}"),
        archive(corpus),
    );
    Sources::fixture(responses)
}

#[test]
fn provisional_body_path_and_assignment_changes_require_new_review_and_portable_assessment() {
    for change in ["body", "path", "assigned"] {
        let mut f = Fixture::prepared(true);
        let data = f.data("author");
        let cache = f.data("cache");
        let corpus = corpus();
        let request = SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Xz,
        };
        let (id, collected) = review::create_with_sources(
            "1.99.1",
            &request,
            f.review.record.policy.clone(),
            &data,
            &cache,
            &fixture_material(),
            f.now,
            &sources(&corpus),
        )
        .unwrap();
        f.review = collected;
        republish(&mut f);
        let imported = f.data("online-import");
        review::import_portable_with_sources(
            &imported,
            &cache,
            &f.repo(),
            &id,
            false,
            f.now,
            &sources(&corpus),
            &fixture_material(),
        )
        .unwrap();
        let loaded = review::load(&imported, &id, &fixture_material(), f.now).unwrap();
        assert_eq!(
            loaded.record.evidence.findings,
            f.review.record.evidence.findings
        );
        acceptance::portable_assessment(&f.repo(), &loaded, &id, &f.prose)
            .unwrap()
            .unwrap();
        let mut changed = corpus.clone();
        let path = changed.keys().next().unwrap().clone();
        let body = changed.remove(&path).unwrap();
        match change {
            "body" => {
                changed.insert(path, format!("{body}\nMaterial source correction.\n"));
            }
            "path" => {
                changed.insert(path.replace("first", "renamed"), body);
            }
            _ => {
                changed.insert(
                    "crates/example/RUSTSEC-2026-0001.md".into(),
                    body.replace("RUSTSEC-0000-0000", "RUSTSEC-2026-0001"),
                );
            }
        }
        let error = review::refresh_with_sources(
            &data,
            &id,
            &fixture_material(),
            f.now + 1,
            &sources(&changed),
        )
        .err()
        .unwrap();
        assert!(
            error.contains("prior approval was not renewed"),
            "{change}: {error}"
        );
        let imported = f.data("changed-import");
        let error = review::import_portable_with_sources(
            &imported,
            &cache,
            &f.repo(),
            &id,
            false,
            f.now + 1,
            &sources(&changed),
            &fixture_material(),
        )
        .unwrap_err();
        assert!(error.contains("requires completion"), "{change}: {error}");
        let (_, current) = review::create_with_sources(
            "1.99.1",
            &request,
            f.review.record.policy.clone(),
            &f.data("new-review"),
            &cache,
            &fixture_material(),
            f.now + 1,
            &sources(&changed),
        )
        .unwrap();
        let current_id = current.record.id(&current.subject).unwrap();
        assert!(acceptance::assess(&current, &current_id, &f.prose, f.now + 1).is_err());
        assert!(
            acceptance::publish_personal(
                &f.data("old-acceptance"),
                &current_id,
                &current,
                f.assessment.clone(),
                f.prose.clone(),
                FreshnessRequest::Online {
                    operation_started_at: f.now + 1
                },
                &CurrentKnowledge::default(),
                None,
                f.now + 1
            )
            .is_err()
        );
    }
}

#[test]
fn historical_placeholder_cached_import_and_continuing_use_retain_exact_authority() {
    let mut f = Fixture::prepared(true);
    let historical_id = "RUSTSEC-0000-0000/vulnerability/example@1.0.0/cargo/aarch64-apple-darwin";
    f.review.record.evidence.findings.push(Finding {
        id: historical_id.into(), source: SourceId { kind:SourceKind::Advisories, scope:"cargo/aarch64-apple-darwin".into() },
        change:FindingChange::Unknown, exposure:Exposure::Unknown, rationale:"Historical bare-placeholder source inclusion with unknown compiled reachability".into(),
    });
    for source in &mut f.review.record.evidence.observations {
        source.expires_at = Some(f.now + 100_000);
    }
    f.admission.age_exception = None;
    republish(&mut f);
    let before = fs::read(f.root.join("repo").join(&f.admission.evidence_record)).unwrap();
    let data = f.data("legacy-import");
    let cache = f.data("legacy-cache");
    let fixture_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/toolchain-intake/workflow");
    for archive in &f.review.selection.archives {
        cache
            .publish(
                Path::new(&format!("archives/{}", archive.sha256)),
                &fs::read(fixture_path.join(format!(
                    "{}-1.99.1-aarch64-apple-darwin.tar.xz",
                    archive.package
                )))
                .unwrap(),
            )
            .unwrap();
    }
    let id = f.id();
    review::import_portable_with_sources(
        &data,
        &cache,
        &f.repo(),
        &id,
        true,
        f.now + 60,
        &Sources::fixture(BTreeMap::new()),
        &fixture_material(),
    )
    .unwrap();
    let loaded = review::load(&data, &id, &fixture_material(), f.now + 60).unwrap();
    assert_eq!(loaded.record.evidence, f.review.record.evidence);
    assert_eq!(loaded.record.evidence.schema_version, 1);
    assert_eq!(loaded.record.evidence.findings[0].id, historical_id);
    let assessment = acceptance::portable_assessment(&f.repo(), &loaded, &id, &f.prose)
        .unwrap()
        .unwrap();
    let (accepted, _) = acceptance::publish_personal(
        &data,
        &id,
        &loaded,
        assessment,
        f.prose.clone(),
        FreshnessRequest::Cached {
            reason: "explicit historical fixture import".into(),
        },
        &CurrentKnowledge::default(),
        Some(&f.repo()),
        f.now + 60,
    )
    .unwrap();
    assert_eq!(accepted.assessment, f.assessment);
    assert_eq!(
        fs::read(f.root.join("repo").join(&f.admission.evidence_record)).unwrap(),
        before
    );
    let installed = InstalledCorrespondence {
        subject_id: f.review.subject.id().clone(),
        mapping_sha256: f.review.subject.record().mapping_sha256.clone(),
        installation_id: digest_bytes(b"authored domain correspondence; no native execution"),
    };
    let context_id = admission::consumer_id(&f.repo()).unwrap();
    let binding = ContinuingUseBinding {
        schema_version: 1,
        subject_id: f.review.subject.id().clone(),
        admission_id: f.admission.id().unwrap(),
        consumer_context_id: context_id.clone(),
        installation_id: installed.installation_id.clone(),
    };
    data.publish(
        Path::new(&format!(
            "continuing/{context_id}/{}.json",
            f.review.subject.id()
        )),
        &serde_json::to_vec(&binding).unwrap(),
    )
    .unwrap();
    let later = f.now + 86_401;
    let context = admission::AcceptedContext::load(
        &data,
        id.clone(),
        Some(f.repo()),
        f.review.record.policy.clone(),
        FreshnessRequest::Local,
        later,
    )
    .unwrap();
    context
        .recheck_before_effects(EligibilityPurpose::ContinuingUse, Some(&installed), later)
        .unwrap();
    assert!(
        context
            .recheck_before_effects(
                EligibilityPurpose::ContinuingUse,
                Some(&installed),
                f.now + 100_000
            )
            .unwrap_err()
            .contains("source evidence expired")
    );
    assert!(
        acceptance::publish_personal(
            &data,
            &id,
            &loaded,
            f.assessment.clone(),
            f.prose.clone(),
            FreshnessRequest::Cached {
                reason: "expired source".into()
            },
            &CurrentKnowledge::default(),
            Some(&f.repo()),
            f.now + 100_000
        )
        .unwrap_err()
        .contains("source evidence expired")
    );
    let mut wrong_installation = installed.clone();
    wrong_installation.installation_id = digest_bytes(b"another installation");
    assert!(
        context
            .recheck_before_effects(
                EligibilityPurpose::ContinuingUse,
                Some(&wrong_installation),
                later
            )
            .unwrap_err()
            .contains("binding")
    );
    let other_root = f.root.join("another-repo");
    copy_approved_fixture(&f.root.join("repo"), &other_root);
    let other_context = admission::AcceptedContext::load(
        &data,
        id.clone(),
        Some(RepoContext::capture(&other_root).unwrap()),
        f.review.record.policy.clone(),
        FreshnessRequest::Local,
        later,
    )
    .unwrap();
    assert!(
        other_context
            .recheck_before_effects(EligibilityPurpose::ContinuingUse, Some(&installed), later)
            .unwrap_err()
            .contains("binding")
    );
    assert!(
        acceptance::publish_personal(
            &data,
            &id,
            &loaded,
            f.assessment.clone(),
            f.prose.clone(),
            FreshnessRequest::Cached {
                reason: "too old".into()
            },
            &CurrentKnowledge::default(),
            Some(&f.repo()),
            later
        )
        .unwrap_err()
        .contains("freshness")
    );
    let mut newer = review::load(&data, &id, &fixture_material(), f.now + 60).unwrap();
    for source in &mut newer.record.evidence.observations {
        source.checked_at = f.now + 1;
    }
    admission::retain_knowledge(&data, &newer, f.now + 60).unwrap();
    let knowledge = admission::knowledge(&data, &loaded.subject).unwrap();
    assert!(
        acceptance::publish_personal(
            &data,
            &id,
            &loaded,
            f.assessment.clone(),
            f.prose.clone(),
            FreshnessRequest::Cached {
                reason: "cannot roll back newer facts".into()
            },
            &knowledge,
            Some(&f.repo()),
            f.now + 60
        )
        .unwrap_err()
        .contains("newer local knowledge")
    );
    assert!(
        context
            .recheck_before_effects(EligibilityPurpose::ContinuingUse, Some(&installed), later)
            .unwrap_err()
            .contains("newer local knowledge")
    );
    newer.record.evidence.observations[0].coverage_rationale =
        "Conflicting successfully retained source fact".into();
    assert!(
        admission::retain_knowledge(&data, &newer, f.now + 60)
            .unwrap_err()
            .contains("conflict")
    );
    let knowledge = admission::knowledge(&data, &loaded.subject).unwrap();
    assert!(
        acceptance::publish_personal(
            &data,
            &id,
            &loaded,
            f.assessment.clone(),
            f.prose.clone(),
            FreshnessRequest::Cached {
                reason: "conflict cannot be bypassed".into()
            },
            &knowledge,
            Some(&f.repo()),
            f.now + 60
        )
        .is_err()
    );
    // Online import recollects even when the historical portable shape is valid.
    let online = f.data("legacy-online");
    let bare = BTreeMap::from([(
        "crates/example/RUSTSEC-0000-0000.md".into(),
        corpus().values().next().unwrap().clone(),
    )]);
    let error = review::import_portable_with_sources(
        &online,
        &cache,
        &f.repo(),
        &id,
        false,
        f.now + 60,
        &sources(&bare),
        &fixture_material(),
    )
    .unwrap_err();
    assert!(error.contains("requires completion"), "{error}");
    let fresh = findings(&f, &bare);
    assert!(
        fresh
            .iter()
            .all(|finding| finding.id.starts_with("rustsec-provisional:"))
    );
}
