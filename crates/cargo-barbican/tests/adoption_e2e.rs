#![cfg(unix)]

mod adoption_support;
use adoption_support::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

#[test]
#[ignore = "required real scanner/network proof: run sh scripts/verify-adoption.sh"]
fn existing_family_extension_keeps_shared_review_and_independent_gates_authoritative() {
    assert_eq!(
        std::env::var("BARBICAN_TEST_ADOPTION_DENY_VERSION").as_deref(),
        Ok("0.19.6")
    );
    let f = Fixture::new();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"));
    fs::create_dir_all(f.path("cargo-home")).unwrap();
    symlink(
        cargo_home.join("registry").canonicalize().unwrap(),
        f.path("cargo-home/registry"),
    )
    .unwrap();
    f.write("Cargo.toml", "[package]\nname='family-consumer'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nsemver='=1.0.28'\nserde='=1.0.228'\nserde_core='=1.0.228'\n");
    f.write(
        "src/lib.rs",
        "#[test] fn works(){assert!(semver::Version::parse(\"1.0.28\").is_ok());}\n",
    );
    f.write("build.rs", "fn main(){std::fs::write(std::env::var_os(\"BARBICAN_FAMILY_SENTINEL\").unwrap(),b\"executed\").unwrap();}\n");
    f.init(&[]);
    let sentinel = f.path("family-executed");
    let run = |args: &[&str]| {
        f.ok(f
            .barbican(args)
            .env("CARGO_NET_OFFLINE", "false")
            .env("BARBICAN_FAMILY_SENTINEL", &sentinel))
    };
    run(&["resolve"]);
    run(&["pin", "add", "semver"]);
    let policy = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(f.path("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    let family = &policy.rust_families()[0];
    let record = family.review_record();
    let semver_target = &family.resolved()["semver"];
    let old_review = include_str!("../../../docs/dependency-reviews/2026-07-01-semver-1.0.28.md");
    f.write(record, old_review);
    let mut source = fs::read_to_string(f.path("reviewed-targets.toml")).unwrap();
    source.push_str(&format!("\n[[rust.families]]\nname='shared-sibling'\nreview_record={}\n[rust.families.resolved]\nsemver={{version='1.0.28',checksum_sha256='{}'}}\n", serde_json::to_string(record).unwrap(), semver_target.checksum_sha256().unwrap()));
    f.write("reviewed-targets.toml", &source);
    run(&["pin", "list"]);
    run(&["pin", "show", "--", family.name()]);
    let selection = format!("--family={}", family.name());
    let added = run(&["pin", "add", &selection, "serde"]);
    assert!(rendered(&added).contains("shared-sibling"));
    run(&["pin", "add", &selection, "serde_core"]);
    let pending = fs::read_to_string(f.path(record)).unwrap();
    let title_end = old_review.find('\n').unwrap() + 1;
    assert!(pending.starts_with(&old_review[..title_end]));
    assert!(pending.contains(&old_review[title_end..]));
    assert_eq!(
        pending
            .matches(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
            .count(),
        1
    );
    for args in [
        vec!["pin", "check"],
        vec!["gatehouse", "policy-check"],
        vec!["gatehouse", "pre-release"],
    ] {
        let output = f.run(
            f.barbican(&args)
                .env("CARGO_NET_OFFLINE", "false")
                .env("BARBICAN_FAMILY_SENTINEL", &sentinel),
        );
        assert!(!output.status.success(), "{}", rendered(&output));
        assert!(!sentinel.exists(), "PENDING must stop workspace execution");
    }
    let lock = fs::read(f.path("Cargo.lock")).unwrap();
    let policy_before = fs::read(f.path("reviewed-targets.toml")).unwrap();
    assert!(rendered(&run(&["pin", "add", &selection, "serde"])).contains("no changes"));
    assert_eq!(fs::read_to_string(f.path(record)).unwrap(), pending);
    assert_eq!(
        fs::read(f.path("reviewed-targets.toml")).unwrap(),
        policy_before
    );
    let inspections = ["serde@1.0.228", "serde_core@1.0.228"].map(|spec| {
        let output = f.run(
            f.barbican(&["inspect", spec])
                .env("CARGO_NET_OFFLINE", "false"),
        );
        let evidence = rendered(&output);
        // These inherited reviewed artefacts have build scripts containing
        // process-execution IOCs; inspect must keep reporting those findings.
        assert_eq!(output.status.code(), Some(1), "{evidence}");
        assert!(
            evidence.contains("classification: policy-violating"),
            "{evidence}"
        );
        assert!(evidence.contains("inspection failures: none"), "{evidence}");
        assert!(evidence.contains("checksum: ok"), "{evidence}");
        evidence
    });
    run(&["audit"]);
    // Only these inherited, pinned registry artefacts and the authored sentinel
    // fixture are accepted here; no general automatic review completion exists.
    let completed = pending
        .lines()
        .filter(|line| !line.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n\nFixture acceptance: inherited reviewed semver/serde sources, fresh inspect/audit, authored build sentinel only. The known build-script process IOCs remain policy-violating inspection evidence; this controlled test accepts these exact existing reviewed artefacts deliberately.\n"
        + &inspections.join("\n");
    f.write(record, &completed);
    run(&["gatehouse", "policy-check"]);
    assert!(!sentinel.exists());
    // Admission completeness, source policy and toolchain preflight retain their
    // existing owners after the shared amendment is deliberately reviewed.
    f.write("reviewed-targets.toml", &source);
    let floor = f.run(
        f.barbican(&["gatehouse", "pre-release"])
            .env("BARBICAN_FAMILY_SENTINEL", &sentinel),
    );
    assert!(!floor.status.success());
    assert!(rendered(&floor).contains("FAIL (inventory)"));
    assert!(!sentinel.exists());
    f.write(
        "reviewed-targets.toml",
        &String::from_utf8(policy_before.clone()).unwrap(),
    );
    f.write(".cargo/config.toml", "[source.crates-io]\nreplace-with='review-test'\n[source.review-test]\nregistry='https://example.invalid/index'\n");
    let source_override = f.run(
        f.barbican(&["verify"])
            .env("BARBICAN_FAMILY_SENTINEL", &sentinel),
    );
    assert!(!source_override.status.success());
    assert!(rendered(&source_override).contains("source"));
    assert!(!sentinel.exists());
    fs::remove_file(f.path(".cargo/config.toml")).unwrap();
    let toolchain = f.run(
        f.barbican(&["verify"])
            .env("RUSTC", "/unaccepted-rustc-control")
            .env("BARBICAN_FAMILY_SENTINEL", &sentinel),
    );
    assert!(!toolchain.status.success());
    assert!(rendered(&toolchain).contains("RUSTC"));
    assert!(!sentinel.exists());
    // Completing shared evidence does not waive an independent checksum failure.
    let parsed =
        barbican::parse_reviewed_targets_toml(&String::from_utf8(policy_before.clone()).unwrap())
            .unwrap();
    let serde_checksum = parsed.rust_families()[0].resolved()["serde"]
        .checksum_sha256()
        .unwrap()
        .as_str();
    f.write(
        "reviewed-targets.toml",
        &String::from_utf8(policy_before.clone())
            .unwrap()
            .replace(serde_checksum, &"a".repeat(64)),
    );
    let failed = f.run(
        f.barbican(&["verify"])
            .env("BARBICAN_FAMILY_SENTINEL", &sentinel),
    );
    assert!(!failed.status.success());
    assert!(!sentinel.exists());
    f.write(
        "reviewed-targets.toml",
        &String::from_utf8(policy_before).unwrap(),
    );
    run(&["gatehouse", "pre-release"]);
    assert!(sentinel.exists());
    assert_eq!(fs::read(f.path("Cargo.lock")).unwrap(), lock);
    println!(
        "family acceptance: generated legacy family -> explicit extension, shared PENDING/no-op, real scanner policy/full gates, independent checksum negative and deliberate build/test positive"
    );
}

#[test]
#[ignore = "required real scanner/network proof: run sh scripts/verify-adoption.sh"]
fn adoption_fixture_runs_real_scanner_before_explicit_execution() {
    assert_eq!(
        std::env::var("BARBICAN_TEST_ADOPTION_DENY_VERSION").as_deref(),
        Ok("0.19.6"),
        "use the required runner; absence is not a skip"
    );
    let f = Fixture::new();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"));
    fs::create_dir_all(f.path("cargo-home")).unwrap();
    symlink(
        cargo_home.join("registry").canonicalize().unwrap(),
        f.path("cargo-home/registry"),
    )
    .unwrap();
    f.write("Cargo.toml", "[package]\nname = \"adoption-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\nmembers = [\"dep\"]\nresolver = \"3\"\n[dependencies]\nsemver = \"=1.0.28\"\ninternal-fixture = { path = \"dep\", version = \"=0.1.0\" }\n");
    f.write("src/lib.rs", "#[test]\nfn approved_graph_works() { assert!(semver::Version::parse(\"1.0.28\").is_ok()); internal_fixture::approved(); }\n");
    f.write(
        "dep/Cargo.toml",
        "[package]\nname = \"internal-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    f.write("dep/src/lib.rs", "pub fn approved() {}\n");
    f.write("dep/build.rs", "fn main() { std::fs::write(std::env::var_os(\"BARBICAN_ADOPTION_SENTINEL\").unwrap(), b\"explicit execution reached\").unwrap(); }\n");
    let sentinel = f.path("execution-sentinel");
    f.init(&["--pre-commit-hook"]);
    let run = |args: &[&str]| {
        let mut command = f.barbican(args);
        command.env("CARGO_NET_OFFLINE", "false");
        command.env("BARBICAN_ADOPTION_SENTINEL", &sentinel);
        f.ok(&mut command)
    };
    assert!(!f.path("Cargo.lock").exists());
    run(&["resolve"]);
    let locked = fs::read(f.path("Cargo.lock")).unwrap();
    run(&["inventory"]);
    run(&["pin", "add", "semver"]);
    let policy = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(f.path("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    let family = &policy.rust_families()[0];
    let spec = &family.resolved()["semver"];
    assert_eq!(spec.version(), "1.0.28");
    assert_eq!(
        spec.checksum_sha256().unwrap().as_str(),
        "8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd"
    );
    let pending = f.run(&mut f.barbican(&["pin", "check"]));
    assert!(!pending.status.success());
    assert!(rendered(&pending).contains("PENDING"));
    let premature = f.run(
        f.barbican(&["gatehouse", "pre-release"])
            .env("CARGO_NET_OFFLINE", "false")
            .env("BARBICAN_ADOPTION_SENTINEL", &sentinel),
    );
    assert!(!premature.status.success());
    assert!(
        !sentinel.exists(),
        "policy setup/rejection must not build the workspace dependency"
    );

    let age = run(&["age", "semver@1.0.28"]);
    let inspection = run(&["inspect", "semver@1.0.28"]);
    let audit = run(&["audit"]);
    assert!(
        !sentinel.exists(),
        "independent evidence must not build this consumer"
    );
    // This exact registry artefact and controlled in-workspace sentinel are a
    // reviewed test fixture, not an automatic review-completion mechanism.
    let prior_review = include_str!("../../../docs/dependency-reviews/2026-07-01-semver-1.0.28.md");
    let completed = format!(
        "{prior_review}\n\n## Adoption fixture review\n\nExact semver 1.0.28/checksum matches the inherited reviewed artefact above; no registry bytes were changed. This test rechecks age, registry inspection and real configured cargo-deny advisory/source/bans outcomes before policy acceptance. The controlled in-workspace internal-fixture has no external dependencies; its only build.rs action writes the test-owned sentinel. That execution is deliberately approved only at the final pre-release gate. Tool installation/version trust is separate; the required runner checks cargo-deny 0.19.6.\n\n### Fresh age evidence\n\n```text\n{}\n```\n\n### Fresh inspection evidence\n\n```text\n{}\n```\n\n### Fresh audit evidence\n\n```text\n{}\n```\n",
        rendered(&age),
        rendered(&inspection),
        rendered(&audit)
    );
    assert!(!completed.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER));
    f.write(family.review_record(), &completed);
    run(&["gatehouse", "policy-check"]);
    assert!(!sentinel.exists(), "policy-check must not run build.rs");
    assert_eq!(fs::read(f.path("Cargo.lock")).unwrap(), locked);

    // Prove cold frozen-metadata failure without silently fetching at hook time.
    fs::rename(
        f.path("cargo-home/registry"),
        f.path("cargo-home/registry.saved"),
    )
    .unwrap();
    let cold = f.run(&mut f.barbican(&["inventory", "--enforce"]));
    assert!(!cold.status.success());
    assert!(rendered(&cold).contains("NOT COLLECTED"));
    if f.path("cargo-home/registry").exists() {
        assert!(
            fs::symlink_metadata(f.path("cargo-home/registry"))
                .unwrap()
                .is_dir()
        );
        fs::remove_dir_all(f.path("cargo-home/registry")).unwrap();
    }
    fs::rename(
        f.path("cargo-home/registry.saved"),
        f.path("cargo-home/registry"),
    )
    .unwrap();
    assert!(!sentinel.exists());

    let output = run(&["gatehouse", "pre-release"]);
    assert!(rendered(&output).contains("Gatehouse pre-release: PASS"));
    assert_eq!(fs::read(&sentinel).unwrap(), b"explicit execution reached");
    println!(
        "adoption acceptance: real cargo-deny 0.19.6, first resolve, PENDING refusal, independent age/inspect/audit, policy-check without execution, cold-cache failure, approved pre-release build/test sentinel"
    );
}
