#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TOOLCHAIN: &str = "1.95.0";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    cleanup_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "barbican-real-nextest-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("unique fixture directory should create");
        let fixture = Self {
            cleanup_root: root.clone(),
            root,
        };
        fixture.write(
            "rust-toolchain.toml",
            &format!("[toolchain]\nchannel = \"{TOOLCHAIN}\"\n"),
        );
        fixture.write(
            "docs/dependency-reviews/fixture.md",
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../docs/dependency-reviews/2026-07-01-semver-1.0.28.md"),
            )
            .unwrap(),
        );
        fixture.write("reviewed-targets.toml", "[[rust.families]]\nname = \"fixture\"\nreview_record = \"docs/dependency-reviews/fixture.md\"\n[rust.families.resolved]\nsemver = { version = \"1.0.28\", checksum_sha256 = \"8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd\" }\n");
        let version = std::env::var("BARBICAN_TEST_NEXTEST_VERSION")
            .expect("run sh scripts/verify-nextest.sh to supply the reviewed tool pin");
        fixture.write(
            "barbican.toml",
            &format!("[verify]\ntest_runner = \"nextest\"\nnextest_version = \"{version}\"\n"),
        );
        fs::create_dir(fixture.root.join("markers")).unwrap();
        fs::create_dir(fixture.root.join("cargo-home")).unwrap();
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").expect("Cargo home should be available"))
                    .join(".cargo")
            });
        symlink(
            cargo_home
                .join("registry")
                .canonicalize()
                .expect("the enclosing locked test build should populate the registry cache"),
            fixture.root.join("cargo-home/registry"),
        )
        .unwrap();
        fixture
    }

    fn write(&self, path: &str, contents: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn nest_workspace(&mut self) {
        let workspace = self.root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        for entry in fs::read_dir(&self.root).unwrap() {
            let entry = entry.unwrap();
            if entry.path() != workspace {
                fs::rename(entry.path(), workspace.join(entry.file_name())).unwrap();
            }
        }
        self.root = workspace;
    }

    fn package(&self, directory: &str, name: &str, extra_manifest: &str, source: &str) {
        let prefix = if directory.is_empty() {
            String::new()
        } else {
            format!("{directory}/")
        };
        self.write(&format!("{prefix}Cargo.toml"), &format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nsemver = \"=1.0.28\"\n{extra_manifest}"
        ));
        self.write(&format!("{prefix}src/lib.rs"), source);
    }

    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command.current_dir(&self.root);
        for name in [
            "CARGO",
            "CARGO_MANIFEST_DIR",
            "CARGO_ALIAS_NEXTEST",
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTDOC",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTDOC",
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "NEXTEST_PROFILE",
            "NEXTEST_RETRIES",
        ] {
            command.env_remove(name);
        }
        command.env("CARGO_HOME", self.root.join("cargo-home"));
        command.env("CARGO_TARGET_DIR", self.root.join("target"));
        command.env("CARGO_NET_OFFLINE", "true");
        command.env("CARGO_TERM_COLOR", "never");
        command.env("BARBICAN_TEST_MARKERS", self.root.join("markers"));
        command
    }

    fn lock(&self) {
        let output = self
            .command("cargo")
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", rendered(&output));
    }

    fn verify_command(&self) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_cargo-barbican"));
        command.arg("verify");
        command
    }

    fn verify(&self) -> Output {
        self.verify_command().output().unwrap()
    }

    fn marker(&self, name: &str) -> PathBuf {
        self.root.join("markers").join(name)
    }

    fn hostile_executable(&self) -> PathBuf {
        self.write(
            "hostile-tool",
            "#!/bin/sh\nprintf used > \"$BARBICAN_TEST_MARKERS/hostile-tool\"\nexit 99\n",
        );
        let path = self.root.join("hostile-tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn redirect_path(&self) -> std::ffi::OsString {
        self.write(
            "bin/cargo-redirect",
            "#!/bin/sh\nprintf used > \"$BARBICAN_TEST_MARKERS/redirect\"\nprintf 'cargo-nextest %s (alias probe)\\n' \"$BARBICAN_TEST_NEXTEST_VERSION\"\n",
        );
        fs::set_permissions(
            self.root.join("bin/cargo-redirect"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        std::env::join_paths(paths).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.cleanup_root);
    }
}

fn rendered(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn passed(output: &Output) {
    assert!(output.status.success(), "{}", rendered(output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Verify: PASS"),
        "{}",
        rendered(output)
    );
}

fn failed(output: &Output) {
    assert_eq!(output.status.code(), Some(1), "{}", rendered(output));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("Verify: PASS"),
        "{}",
        rendered(output)
    );
}

fn test_source(name: &str, marker: &str, fail: bool) -> String {
    format!(
        "#[test]\nfn {name}() {{ std::fs::write(std::path::Path::new(&std::env::var(\"BARBICAN_TEST_MARKERS\").unwrap()).join(\"{marker}\"), std::process::id().to_string()).unwrap(); {} }}\n",
        if fail {
            "panic!(\"deliberate unit failure\");"
        } else {
            ""
        }
    )
}

fn doc_source(marker: &str, fail: bool) -> String {
    format!(
        "/// ```\n/// std::fs::write(std::path::Path::new(&std::env::var(\"BARBICAN_TEST_MARKERS\").unwrap()).join(\"{marker}\"), \"executed\").unwrap();\n{}/// ```\npub fn documented() {{}}\n",
        if fail {
            "/// panic!(\"deliberate doctest failure\");\n"
        } else {
            ""
        }
    )
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_nextest_isolates_tests_runs_docs_and_overrides_hostile_cargo() {
    let fixture = Fixture::new();
    let source = format!(
        "{}{}{}#[test]\n#[ignore]\nfn ignored() {{ panic!(\"ignored tests must stay ignored\"); }}\n",
        test_source("one", "one", false),
        test_source("two", "two", false),
        doc_source("doc", false)
    );
    fixture.package("", "fixture", "", &source);
    fixture.lock();
    let output = fixture
        .verify_command()
        .env("CARGO", fixture.hostile_executable())
        .output()
        .unwrap();
    passed(&output);
    assert_ne!(
        fs::read_to_string(fixture.marker("one")).unwrap(),
        fs::read_to_string(fixture.marker("two")).unwrap()
    );
    assert!(fixture.marker("doc").exists());
    assert!(!fixture.marker("hostile-tool").exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK   cargo nextest run --locked"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK   cargo test --doc --locked"));
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_nextest_defeats_native_filters_profile_retry_and_fail_fast_controls() {
    for per_test in [false, true] {
        let fixture = Fixture::new();
        fixture.package("", "fixture", "", &format!("{}\n{}\n{}", r#"#[test]
fn retried_failure() {
    use std::io::Write;
    let path = std::path::Path::new(&std::env::var("BARBICAN_TEST_MARKERS").unwrap()).join("attempts");
    writeln!(std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap(), "attempt").unwrap();
    panic!("deliberate failure");
}"#, test_source("later_test", "later-test", false), doc_source("must-not-run", false)));
        fixture.write(".config/nextest.toml", &format!("[profile.default]\nretries = 3\ndefault-filter = \"none()\"\nfail-fast = false\ntest-threads = 1\n[profile.alternate]\ndefault-filter = \"none()\"\nrun-extra-args = [\"--invalid-alternate-profile-argument\"]\n[[profile.default.overrides]]\nfilter = \"test(retried_failure)\"\npriority = 100\n{}", if per_test { "retries = 2\n" } else { "" }));
        fixture.lock();
        let output = fixture
            .verify_command()
            .env("NEXTEST_PROFILE", "alternate")
            .env("NEXTEST_RETRIES", "4")
            .output()
            .unwrap();
        failed(&output);
        assert_eq!(
            fs::read_to_string(fixture.marker("attempts")).unwrap(),
            "attempt\n",
            "{}",
            rendered(&output)
        );
        assert!(!fixture.marker("must-not-run").exists());
        assert!(
            !fixture.marker("later-test").exists(),
            "{}",
            rendered(&output)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("OK   cargo test --doc --locked")
        );
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_doctest_failure_blocks_verify() {
    let fixture = Fixture::new();
    fixture.package(
        "",
        "fixture",
        "",
        &format!(
            "{}{}",
            test_source("unit", "unit", false),
            doc_source("failed-doc", true)
        ),
    );
    fixture.lock();
    let output = fixture.verify();
    failed(&output);
    assert!(fixture.marker("unit").exists());
    assert!(fixture.marker("failed-doc").exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK   cargo nextest run --locked"));
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_empty_and_doctest_only_suites_pass() {
    for has_doc in [false, true] {
        let fixture = Fixture::new();
        fixture.package(
            "",
            "fixture",
            "",
            &if has_doc {
                doc_source("only-doc", false)
            } else {
                "pub fn empty() {}\n".to_owned()
            },
        );
        fixture.lock();
        let output = fixture.verify();
        passed(&output);
        assert_eq!(fixture.marker("only-doc").exists(), has_doc);
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_proc_macro_library_doctests_execute() {
    let fixture = Fixture::new();
    fixture.package(
        "",
        "fixture",
        "[lib]\nproc-macro = true\n",
        &doc_source("proc-macro-doc", false).replace(
            "pub fn documented() {}",
            "#[proc_macro]\npub fn identity(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }",
        ),
    );
    fixture.lock();
    let output = fixture.verify();
    passed(&output);
    assert!(fixture.marker("proc-macro-doc").exists());
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_binary_only_and_all_disabled_docs_skip_doctests() {
    for binary_only in [false, true] {
        let fixture = Fixture::new();
        if binary_only {
            fixture.write(
                "Cargo.toml",
                "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nsemver = \"=1.0.28\"\n",
            );
            fixture.write(
                "src/main.rs",
                &format!("fn main() {{}}\n{}", test_source("binary", "binary", false)),
            );
        } else {
            fixture.package(
                "",
                "fixture",
                "[lib]\ndoctest = false\n",
                &doc_source("excluded-doc", true),
            );
        }
        fixture.lock();
        let output = fixture.verify();
        passed(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains(
            "no doctest-enabled libraries in the default package scope; doctests skipped"
        ));
        assert!(!fixture.marker("excluded-doc").exists());
        if binary_only {
            assert!(fixture.marker("binary").exists());
        }
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_mixed_doctest_scope_fails_closed() {
    let fixture = Fixture::new();
    fixture.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"enabled\", \"disabled\"]\nresolver = \"3\"\n",
    );
    fixture.package("enabled", "fixture", "", &doc_source("enabled-doc", false));
    fixture.package(
        "disabled",
        "disabled",
        "[lib]\ndoctest = false\n",
        &doc_source("disabled-doc", true),
    );
    fixture.lock();
    let output = fixture.verify();
    failed(&output);
    let text = rendered(&output);
    assert!(
        text.contains("mixed") && text.contains("fixture") && text.contains("disabled"),
        "{text}"
    );
    assert!(!fixture.marker("enabled-doc").exists());
    assert!(!fixture.marker("disabled-doc").exists());
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_default_member_binary_keeps_library_doc_features_enabled() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", "[workspace]\nmembers = [\"library\", \"binary\"]\ndefault-members = [\"library\", \"binary\"]\nresolver = \"3\"\n");
    fixture.package(
        "library",
        "fixture",
        "[features]\nactivated = []\n",
        &format!(
            "#[cfg(feature = \"activated\")]\n{}",
            doc_source("feature-doc", true)
        ),
    );
    fixture.write("binary/Cargo.toml", "[package]\nname = \"binary\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nfixture = { path = \"../library\", features = [\"activated\"] }\n");
    fixture.write("binary/src/main.rs", "fn main() {}\n");
    fixture.lock();
    let output = fixture.verify();
    failed(&output);
    assert!(
        fixture.marker("feature-doc").exists(),
        "{}",
        rendered(&output)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK   cargo nextest run --locked"));
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_workspace_scope_preserves_explicit_and_implicit_default_members() {
    for root_package in [false, true] {
        let fixture = Fixture::new();
        if root_package {
            fixture.package(
                "",
                "fixture",
                "[workspace]\nmembers = [\"other\"]\nexclude = [\"excluded\"]\nresolver = \"3\"\n",
                &format!(
                    "{}{}",
                    test_source("selected", "selected-unit", false),
                    doc_source("selected-doc", false)
                ),
            );
        } else {
            fixture.write("Cargo.toml", "[workspace]\nmembers = [\"selected\", \"other\"]\ndefault-members = [\"selected\"]\nexclude = [\"excluded\"]\nresolver = \"3\"\n");
            fixture.package(
                "selected",
                "fixture",
                "",
                &format!(
                    "{}{}",
                    test_source("selected", "selected-unit", false),
                    doc_source("selected-doc", false)
                ),
            );
        }
        for directory in ["other", "excluded"] {
            fixture.package(
                directory,
                directory,
                "",
                &format!(
                    "{}{}",
                    test_source("unselected", "unselected-unit", true),
                    doc_source("unselected-doc", true)
                ),
            );
        }
        fixture.lock();
        let output = fixture.verify();
        passed(&output);
        assert!(fixture.marker("selected-unit").exists());
        assert!(fixture.marker("selected-doc").exists());
        assert!(!fixture.marker("unselected-unit").exists());
        assert!(!fixture.marker("unselected-doc").exists());
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_hostile_compiler_environment_and_config_fail_before_build() {
    for control in [
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "config-rustc",
        "config-rustdoc",
        "config-rustc-wrapper",
        "config-rustc-workspace-wrapper",
        "cargo-home-config",
    ] {
        let fixture = Fixture::new();
        fixture.package("", "fixture", "", "pub fn untouched() {}\n");
        fixture.write("build.rs", "fn main() { std::fs::write(std::path::Path::new(&std::env::var(\"BARBICAN_TEST_MARKERS\").unwrap()).join(\"build\"), \"built\").unwrap(); }\n");
        fixture.lock();
        let hostile = fixture.hostile_executable();
        let mut command = fixture.verify_command();
        if control == "cargo-home-config" {
            fixture.write(
                "cargo-home/config.toml",
                &format!(
                    "[build]\nrustc-wrapper = {}\n",
                    serde_json::to_string(hostile.to_str().unwrap()).unwrap()
                ),
            );
        } else if let Some(key) = control.strip_prefix("config-") {
            fixture.write(
                ".cargo/config.toml",
                &format!(
                    "[build]\n{key} = {}\n",
                    serde_json::to_string(hostile.to_str().unwrap()).unwrap()
                ),
            );
        } else {
            command.env(control, hostile);
        }
        let output = command.output().unwrap();
        failed(&output);
        assert!(
            rendered(&output).contains("controls Cargo's Rust toolchain executable selection"),
            "{}",
            rendered(&output)
        );
        assert!(!fixture.marker("build").exists());
        assert!(!fixture.marker("hostile-tool").exists());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("OK   cargo build --locked"));
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_custom_harness_protocol_runs_and_incompatible_discovery_blocks() {
    for compatible in [false, true] {
        let fixture = Fixture::new();
        fixture.package(
            "",
            "fixture",
            "[[test]]\nname = \"custom\"\nharness = false\n",
            "pub fn library() {}\n",
        );
        fixture.write("tests/custom.rs", if compatible { r#"fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--list") {
        assert!(args.windows(2).any(|pair| pair == ["--format", "terse"]));
        if !args.iter().any(|arg| arg == "--ignored") { println!("custom::works: test"); }
    } else {
        assert!(args.iter().any(|arg| arg == "custom::works"));
        assert!(args.iter().any(|arg| arg == "--exact"));
        assert!(args.iter().any(|arg| arg == "--nocapture"));
        std::fs::write(std::path::Path::new(&std::env::var("BARBICAN_TEST_MARKERS").unwrap()).join("custom"), "ran").unwrap();
    }
}
"# } else { "fn main() { if std::env::args().any(|arg| arg == \"--list\") { eprintln!(\"unsupported discovery\"); std::process::exit(19); } }\n" });
        fixture.lock();
        let output = fixture.verify();
        if compatible {
            passed(&output);
        } else {
            failed(&output);
        }
        assert_eq!(
            fixture.marker("custom").exists(),
            compatible,
            "{}",
            rendered(&output)
        );
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_nextest_version_mismatch_blocks_tests_after_build() {
    let fixture = Fixture::new();
    fixture.package(
        "",
        "fixture",
        "",
        &test_source("must_not_run", "must-not-run", false),
    );
    fixture.write(
        "barbican.toml",
        "[verify]\ntest_runner = \"nextest\"\nnextest_version = \"0.9.999\"\n",
    );
    fixture.lock();
    let output = fixture.verify();
    failed(&output);
    let text = rendered(&output);
    assert!(text.contains("OK   cargo build --locked"), "{text}");
    assert!(
        text.contains("0.9.999") && text.contains("cargo install --locked"),
        "{text}"
    );
    assert!(!fixture.marker("must-not-run").exists());
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_cargo_nextest_aliases_are_rejected_before_verify_and_gatehouse_execution() {
    for location in ["environment", "workspace", "ancestor", "cargo-home"] {
        let mut fixture = Fixture::new();
        if location == "ancestor" {
            fixture.nest_workspace();
        }
        fixture.package("", "fixture", "", "pub fn untouched() {}\n");
        fixture.write("build.rs", "fn main() { std::fs::write(std::path::Path::new(&std::env::var(\"BARBICAN_TEST_MARKERS\").unwrap()).join(\"build\"), \"built\").unwrap(); }\n");
        fixture.lock();
        match location {
            "workspace" => fixture.write(".cargo/config.toml", "[alias]\nnextest = \"redirect\"\n"),
            "ancestor" => {
                fixture.write("../.cargo/config.toml", "[alias]\nnextest = \"redirect\"\n")
            }
            "cargo-home" => fixture.write(
                "cargo-home/config.toml",
                "[alias]\nnextest = \"redirect\"\n",
            ),
            "environment" => {}
            _ => unreachable!(),
        }
        let path = fixture.redirect_path();
        let mut probe = fixture.command("cargo");
        probe.args(["nextest", "--version"]).env("PATH", &path);
        if location == "environment" {
            probe.env("CARGO_ALIAS_NEXTEST", "redirect");
        }
        let output = probe.output().unwrap();
        assert!(output.status.success(), "{location}: {}", rendered(&output));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!(
                "cargo-nextest {} (alias probe)",
                std::env::var("BARBICAN_TEST_NEXTEST_VERSION").unwrap()
            )),
            "{location}: {}",
            rendered(&output)
        );
        assert!(fixture.marker("redirect").exists());
        fs::remove_file(fixture.marker("redirect")).unwrap();

        for args in [&["verify"][..], &["gatehouse", "pre-release"][..]] {
            let mut command = fixture.command(env!("CARGO_BIN_EXE_cargo-barbican"));
            command.args(args).env("PATH", &path);
            if location == "environment" {
                command.env("CARGO_ALIAS_NEXTEST", "redirect");
            }
            let output = command.output().unwrap();
            failed(&output);
            assert!(
                rendered(&output).contains("can replace the pinned nextest delegate"),
                "{location} {args:?}: {}",
                rendered(&output)
            );
            assert!(!fixture.marker("redirect").exists(), "{location} {args:?}");
            assert!(!fixture.marker("build").exists(), "{location} {args:?}");
            assert!(!fixture.root.join("target").exists(), "{location} {args:?}");
            assert!(!String::from_utf8_lossy(&output.stdout).contains("Inventory:"));
        }

        fixture.write("barbican.toml", "[verify]\ntest_runner = \"cargo-test\"\n");
        let mut command = fixture.verify_command();
        command.env("PATH", &path);
        if location == "environment" {
            command.env("CARGO_ALIAS_NEXTEST", "redirect");
        }
        let output = command.output().unwrap();
        passed(&output);
        assert!(fixture.marker("build").exists());
        assert!(!fixture.marker("redirect").exists());
    }
}

#[test]
#[ignore = "requires the reviewed real nextest tool; run sh scripts/verify-nextest.sh"]
fn real_unrelated_aliases_and_forced_cargo_config_preserve_nextest_handoff() {
    let fixture = Fixture::new();
    fixture.package("", "fixture", "", &test_source("executed", "unit", false));
    fixture.lock();
    let hostile = fixture.hostile_executable();
    fixture.write(
        ".cargo/config.toml",
        &format!(
            "[alias]\nunrelated = \"redirect\"\n[env]\nCARGO = {{ value = {}, force = true }}\n",
            serde_json::to_string(hostile.to_str().unwrap()).unwrap()
        ),
    );
    let output = fixture
        .verify_command()
        .env("PATH", fixture.redirect_path())
        .env("CARGO_ALIAS_UNRELATED", "redirect")
        .output()
        .unwrap();
    passed(&output);
    assert!(fixture.marker("unit").exists());
    assert!(!fixture.marker("redirect").exists());
    assert!(!fixture.marker("hostile-tool").exists());
}
