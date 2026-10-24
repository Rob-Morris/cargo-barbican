#![cfg(unix)]

mod adoption_support;
use adoption_support::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

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
