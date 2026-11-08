use super::{sources::Sources, store::PrivateStore};
use barbican::rust_distribution::Manifest;
use barbican::toolchain_admission::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) type Result<T> = std::result::Result<T, String>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    location: String,
    sha256: barbican::Sha256Digest,
    body: String,
}

pub(super) struct CollectedSources {
    pub evidence: EvidenceRecord,
    pub snapshots: BTreeMap<String, Vec<u8>>,
}
struct Collector<'a> {
    sources: &'a Sources,
    subject: &'a Subject,
    now: i64,
    observations: Vec<SourceObservation>,
    snapshots: BTreeMap<String, Vec<u8>>,
}
impl Collector<'_> {
    fn document(&self, url: &str) -> Result<Document> {
        let bytes = self.sources.fetch(url)?;
        let sha256 = digest_bytes(&bytes);
        Ok(Document {
            location: url.into(),
            sha256,
            body: String::from_utf8(bytes).map_err(|e| e.to_string())?,
        })
    }
    fn observe(
        &mut self,
        kind: SourceKind,
        scope: &str,
        location: &str,
        revision: &str,
        bytes: Vec<u8>,
        coverage: Coverage,
        rationale: &str,
    ) -> RecordReference {
        let sha256 = digest_bytes(&bytes);
        let reference = RecordReference {
            path: format!(
                "docs/dependency-reviews/toolchains/{}/sources/{sha256}",
                self.subject.id()
            ),
            sha256: sha256.clone(),
        };
        self.snapshots.insert(reference.path.clone(), bytes);
        self.observations.push(SourceObservation{source:SourceId{kind,scope:scope.into()},location:location.into(),provenance:"Official supplier/source-maintainer HTTPS publication; no binary-source correspondence or universal vulnerability coverage inferred".into(),revision:revision.into(),content_sha256:sha256,snapshot:reference.clone(),status:CollectionStatus::Completed,coverage,coverage_rationale:rationale.into(),checked_at:self.now,expires_at:None});
        reference
    }
}
fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(record).map_err(|e| e.to_string())
}
fn full_commit(value: &str) -> Result<String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("source identity is not a canonical full Git commit".into());
    }
    Ok(value.into())
}
fn tree_entry(
    sources: &Sources,
    revision: &str,
    name: &str,
    kind: &str,
    documents: &mut Vec<Document>,
) -> Result<String> {
    let url = format!("https://api.github.com/repos/rust-lang/rust/git/trees/{revision}");
    let bytes = sources.fetch(&url)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value.get("truncated").and_then(Value::as_bool) == Some(true)
        || value.get("sha").and_then(Value::as_str) != Some(revision)
    {
        return Err("incomplete or mismatched official source tree".into());
    }
    let entries = value
        .get("tree")
        .and_then(Value::as_array)
        .ok_or("missing official source tree entries")?;
    let found: Vec<_> = entries
        .iter()
        .filter(|entry| entry.get("path").and_then(Value::as_str) == Some(name))
        .collect();
    let [entry] = found.as_slice() else {
        return Err("missing or ambiguous official source tree entry".into());
    };
    if entry.get("type").and_then(Value::as_str) != Some(kind) {
        return Err("unexpected official source tree entry type".into());
    }
    let sha = full_commit(
        entry
            .get("sha")
            .and_then(Value::as_str)
            .ok_or("source tree entry missing commit")?,
    )?;
    documents.push(Document {
        location: url,
        sha256: digest_bytes(&bytes),
        body: String::from_utf8(bytes).map_err(|e| e.to_string())?,
    });
    Ok(sha)
}

pub(super) fn collect(
    sources: &Sources,
    subject: &Subject,
    manifest: &Manifest,
    signed_at: u32,
    now: i64,
) -> Result<CollectedSources> {
    let mut collector = Collector {
        sources,
        subject,
        now,
        observations: Vec::new(),
        snapshots: BTreeMap::new(),
    };
    let record = subject.record();
    let rust_metadata = manifest
        .package_source_metadata("rustc")
        .ok_or("signed manifest lacks Rust source identity")?;
    let rust_commit = full_commit(
        rust_metadata
            .git_commit_hash
            .ok_or("signed manifest lacks Rust source commit")?,
    )?;
    let mut identity_documents = Vec::new();
    let commit_url =
        format!("https://api.github.com/repos/rust-lang/rust/git/commits/{rust_commit}");
    let commit_bytes = sources.fetch(&commit_url)?;
    let commit: Value =
        serde_json::from_slice(&commit_bytes).map_err(|e| format!("{commit_url}: {e}"))?;
    if commit.get("sha").and_then(Value::as_str) != Some(rust_commit.as_str()) {
        return Err("official Rust commit response does not match signed source identity".into());
    }
    let root_tree = full_commit(
        commit
            .get("tree")
            .and_then(|v| v.get("sha"))
            .and_then(Value::as_str)
            .ok_or("official Rust commit lacks root tree identity")?,
    )?;
    identity_documents.push(Document {
        location: commit_url,
        sha256: digest_bytes(&commit_bytes),
        body: String::from_utf8(commit_bytes).map_err(|e| e.to_string())?,
    });
    let src_tree = tree_entry(sources, &root_tree, "src", "tree", &mut identity_documents)?;
    let tools_tree = tree_entry(sources, &src_tree, "tools", "tree", &mut identity_documents)?;
    let cargo_commit = tree_entry(
        sources,
        &tools_tree,
        "cargo",
        "commit",
        &mut identity_documents,
    )?;
    let llvm_commit = tree_entry(
        sources,
        &src_tree,
        "llvm-project",
        "commit",
        &mut identity_documents,
    )?;
    let cargo_metadata = manifest
        .package_source_metadata("cargo")
        .ok_or("signed manifest lacks Cargo package identity")?;
    // Cargo's advertised git_commit_hash names the Rust tree; the gitlink names Cargo.
    if cargo_metadata.git_commit_hash != Some(rust_commit.as_str()) {
        return Err("unsupported Cargo/Rust source identity relationship".into());
    }
    let cargo_version = cargo_metadata
        .version
        .split_whitespace()
        .next()
        .ok_or("missing Cargo package version")?;
    let mut locks = Vec::new();
    for (repository, revision, path) in [
        ("rust", rust_commit.as_str(), "Cargo.lock"),
        ("rust", rust_commit.as_str(), "library/Cargo.lock"),
        ("cargo", cargo_commit.as_str(), "Cargo.lock"),
    ] {
        let document = collector.document(&format!(
            "https://raw.githubusercontent.com/rust-lang/{repository}/{revision}/{path}"
        ))?;
        let lock = parse_source_package_inventory(&document.body)
            .map_err(|e| format!("source package inventory {}: {e}", document.location))?;
        locks.push(lock);
        identity_documents.push(document);
    }
    let cargo_manifest = collector.document(&format!(
        "https://raw.githubusercontent.com/rust-lang/cargo/{cargo_commit}/Cargo.toml"
    ))?;
    // The exact package identity is independently parsed from the source lockfile.
    if !locks[2].iter().any(|package| {
        package.name == "cargo" && package.version == cargo_version && package.source.is_none()
    }) {
        return Err(
            "Cargo source package version does not match signed distribution metadata".into(),
        );
    }
    identity_documents.push(cargo_manifest);
    identity_documents.push(collector.document("https://llvm.org/docs/Security.html")?);
    let identity_bytes = encode(&(
        &rust_commit,
        &cargo_commit,
        cargo_version,
        &llvm_commit,
        &identity_documents,
    ))?;

    let day = &record.publication_date;
    let date = barbican::parse_iso_date(day).map_err(|e| e.to_string())?;
    let url = format!(
        "https://blog.rust-lang.org/{:04}/{:02}/{:02}/Rust-{}/",
        date.year(),
        u8::from(date.month()),
        date.day(),
        record.release
    );
    let release = collector.document(&url)?;
    if !release.body.contains(&format!("Rust {}", record.release)) {
        return Err("official publication does not identify the exact release".into());
    }
    let publication=collector.observe(SourceKind::Publication,"distribution",&url,day,release.body.as_bytes().to_vec(),Coverage::Covered,"Exact official release announcement retrieved at the manifest publication-day URL; original signed-manifest and signature day also bound conservatively.");
    collector.observe(SourceKind::ReleaseNotes,"distribution",&url,day,release.body.into_bytes(),Coverage::ResidualUnknown,"Official release notes are retained for explicit human compatibility/security review; notes are not universal vulnerability coverage.");
    let security_policy = collector.document("https://rust-lang.org/policies/security/")?;
    if security_policy.body.len() < 1000
        || !security_policy.body.contains("Security policy")
        || !security_policy.body.contains("Scope")
    {
        return Err(
            "official security policy body is missing its expected substantive content".into(),
        );
    }
    let cargo_advisories = collector.sources.cargo_advisories()?;
    let security = vec![
        collector.document("https://blog.rust-lang.org/")?,
        security_policy,
        Document {
            location: "https://api.github.com/repos/rust-lang/cargo/security-advisories".into(),
            sha256: digest_bytes(&cargo_advisories),
            body: String::from_utf8(cargo_advisories).map_err(|e| e.to_string())?,
        },
    ];
    collector.observe(SourceKind::SecurityAnnouncements,"distribution","https://blog.rust-lang.org/","current official announcement index and Cargo advisories",encode(&security)?,Coverage::ResidualUnknown,"Current official announcement index, Rust security scope and published Cargo advisories are retained. Exact affected-range/applicability and historical completeness require explicit human assessment; source inclusion is not execution reachability.");
    collector.observe(SourceKind::Authentication,"distribution","https://static.rust-lang.org/","qualified current public-only verification",encode(&record.authentication)?,Coverage::Covered,"Original exact manifest, detached signature and approved certificate identities verified; current nonrevocation cannot be proved and retained authenticated adverse knowledge blocks.");
    for archive in &record.archives {
        collector.observe(SourceKind::SourceIdentity,&format!("{}/{}",archive.package,archive.target),"https://github.com/rust-lang/rust",&rust_commit,identity_bytes.clone(),Coverage::ResidualUnknown,"Exact Rust commit, independent Cargo/LLVM gitlinks, separate Rust/std/Cargo lockfiles and Cargo package identity retained. Optional/dev/host/native inclusion and binary/source correspondence are not established.");
    }
    let findings = collect_advisories(&mut collector, &locks)?;
    let signature_day = barbican::OffsetDateTime::from_unix_timestamp(i64::from(signed_at))
        .map_err(|e| e.to_string())?
        .date()
        .to_string();
    let evidence = EvidenceRecord {
        schema_version: 1,
        subject_id: subject.id().clone(),
        publication: PublicationFacts {
            subject_id: subject.id().clone(),
            authenticated_manifest_day: day.clone(),
            corroborated_days: vec![day.clone(), signature_day.max(day.clone())],
            source: SourceId {
                kind: SourceKind::Publication,
                scope: "distribution".into(),
            },
            source_content_sha256: publication.sha256,
        },
        observations: collector.observations,
        findings,
    };
    evidence.content_id(subject).map_err(|e| e.to_string())?;
    evidence
        .publication
        .maturity_start(subject, now)
        .map_err(|e| e.to_string())?;
    Ok(CollectedSources {
        evidence,
        snapshots: collector.snapshots,
    })
}

pub(super) fn persist(data: &PrivateStore, root: &str, collected: &CollectedSources) -> Result<()> {
    for (path, bytes) in &collected.snapshots {
        data.publish(&Path::new(root).join(path), bytes)?;
    }
    Ok(())
}

fn collect_advisories(
    collector: &mut Collector<'_>,
    locks: &[Vec<SourcePackage>],
) -> Result<Vec<Finding>> {
    let head_url = "https://api.github.com/repos/RustSec/advisory-db/commits/HEAD";
    let head = collector.sources.fetch(head_url)?;
    let head: Value = serde_json::from_slice(&head).map_err(|e| e.to_string())?;
    let revision = full_commit(
        head.get("sha")
            .and_then(Value::as_str)
            .ok_or("RustSec HEAD response lacks exact commit")?,
    )?;
    let url = format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}");
    let bytes = collector.sources.fetch(&url)?;
    let corpus = read_advisory_archive(&bytes, &revision).map_err(|e| e.to_string())?;
    let advisories: Vec<_> = corpus
        .iter()
        .map(|(path, body)| {
            parse_source_advisory(path, body)
                .map_err(|e| format!("RustSec advisory source {path}: {e}"))
        })
        .collect::<std::result::Result<_, _>>()?;
    let mut findings = Vec::new();
    let selected_archives = collector.subject.record().archives.clone();
    for archive in &selected_archives {
        let scope = format!("{}/{}", archive.package, archive.target);
        let lock = match archive.package.as_str() {
            "cargo" => &locks[2],
            "rust-std" => &locks[1],
            _ => &locks[0],
        };
        for advisory in &advisories {
            let versions: Vec<&str> = match advisory.corpus {
                AdvisoryCorpus::Crates => lock
                    .iter()
                    .filter(|package| package.name == advisory.package && package.is_crates_io())
                    .map(|package| package.version.as_str())
                    .collect(),
                AdvisoryCorpus::Rust => {
                    if !matches!(advisory.package.as_str(), "std" | "rustdoc" | "cargo") {
                        return Err(
                            "unsupported RustSec Rust-corpus package/version semantics".into()
                        );
                    }
                    if (advisory.package == "std" && archive.package != "rust-std")
                        || (advisory.package == "rustdoc" && archive.package != "rustc")
                        || (advisory.package == "cargo" && archive.package != "cargo")
                    {
                        continue;
                    }
                    vec![collector.subject.record().release.as_str()]
                }
            };
            for version in versions {
                if advisory
                    .version_status(version, collector.now)
                    .map_err(|e| {
                        format!(
                            "advisory {} package {} exact source version {version}: {e}",
                            advisory.id, advisory.package
                        )
                    })?
                    != SourceVersionStatus::Affected
                {
                    continue;
                }
                let maintenance = advisory.informational.as_deref().unwrap_or("vulnerability");
                findings.push(Finding{id:format!("{}/{maintenance}/{}@{version}/{scope}",advisory.id,advisory.package),source:SourceId{kind:SourceKind::Advisories,scope:scope.clone()},change:FindingChange::Unknown,exposure:Exposure::Unknown,rationale:format!("{maintenance}: source corpus contains {}@{version} in the affected stable-version range. Initial admission has no accepted baseline. RustSec architecture {:?}, OS {:?}, function constraints {:?}; selected-host compiled inclusion and reachability are unproved and require explicit assessment. RustSec rust/std, rust/rustdoc and rust/cargo use distribution Rust release versions; GitHub Cargo package advisories use Cargo package 0.x versions, distinct from displayed Cargo 1.x versions.",advisory.package,advisory.affected_arch,advisory.affected_os,advisory.affected_functions)});
            }
        }
        collector.observe(SourceKind::Advisories,&scope,&url,&revision,bytes.clone(),Coverage::ResidualUnknown,"Complete bounded exact-commit RustSec crates/Rust corpus inspected against separate represented source locks; source matches retained as findings. Optional/dev/host/build inclusion, native LLVM coverage and binary reachability remain unknown; official security announcements are separate evidence.");
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings.dedup_by(|a, b| a.id == b.id);
    Ok(findings)
}
