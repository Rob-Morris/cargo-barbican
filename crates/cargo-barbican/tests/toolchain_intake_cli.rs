#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-barbican"));
    for name in [
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_HOME",
        "RUSTUP_DIST_SERVER",
        "RUSTUP_DIST_ROOT",
        "RUSTUP_OVERRIDE_HOST_TRIPLE",
        "RUSTUP_UPDATE_ROOT",
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
        "RUSTUP_FORCE_ARG0",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(name);
    }
    command
}
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-intake-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("home")).unwrap();
        for executable in ["cargo", "rustc", "rustdoc", "rustup"] {
            let path = root.join("bin").join(executable);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf candidate-executed >> '{}'\nexit 91\n",
                    root.join("candidate-marker").display()
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { root }
    }
    fn run(&self, cwd: &std::path::Path, args: &[&str]) -> Output {
        command()
            .current_dir(cwd)
            .env("HOME", self.root.join("home"))
            .env("CARGO_HOME", self.root.join("home/.cargo"))
            .env("PATH", self.root.join("bin"))
            .env(
                "CARGO_BARBICAN_CRATES_IO_BASE_URL",
                "invalid-unrelated-source",
            )
            .args([
                "--data-dir",
                self.root.join("data").to_str().unwrap(),
                "--cache-dir",
                self.root.join("cache").to_str().unwrap(),
            ])
            .args(args)
            .output()
            .unwrap()
    }
    fn no_candidate(&self) {
        assert!(
            !self.root.join("candidate-marker").exists(),
            "candidate or Cargo discovery executed before intake admission"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn direct_help_and_trust_show_need_neither_cargo_nor_workspace_nor_crates_client() {
    let fixture = Fixture::new();
    let help = fixture.run(&fixture.root, &["toolchain", "review", "--help"]);
    assert!(
        help.status.success(),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );
    assert!(String::from_utf8_lossy(&help.stdout).contains("cargo-barbican"));
    let show = fixture.run(
        &fixture.root,
        &["toolchain", "trust", "show", "--format", "json"],
    );
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(
        value["fingerprint"],
        "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
    );
    fixture.no_candidate();
}

#[test]
fn invalid_static_review_refuses_before_network_or_candidate() {
    let fixture = Fixture::new();
    let result = fixture.run(
        &fixture.root,
        &["toolchain", "review", "nightly", "--standalone"],
    );
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(!error.contains("invalid-unrelated-source"), "{error}");
    assert!(
        error.contains("exact") || error.contains("channel"),
        "{error}"
    );
    fixture.no_candidate();
}

#[test]
fn admission_ci_scaffolding_is_static_before_cargo_rustup_or_crates_client() {
    for mode in [
        "bootstrap",
        "missing-bootstrap",
        "malformed",
        "explicit-root",
        "ambiguous",
    ] {
        let fixture = Fixture::new();
        let repo = fixture.root.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(repo.join("nested")).unwrap();
        fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
        fs::write(
            repo.join("barbican.toml"),
            if mode == "malformed" {
                "[toolchain]\nrequire_admission='invalid'\n"
            } else {
                "[toolchain]\nrequire_admission=true\nadmission_scope='example'\n"
            },
        )
        .unwrap();
        fs::write(
            repo.join("rust-toolchain.toml"),
            "[toolchain]\nchannel='1.99.1'\nprofile='minimal'\n",
        )
        .unwrap();
        let config = repo.join("ci.json");
        fs::write(&config, serde_json::json!({"schema_version":1,"controller_tag":"barbican-ci-v1","provider_repository":"owner/tools","provider_revision":"a".repeat(40),"provider_script":"ci/provision.sh","approved_repository":"owner/repo","approved_revision":"b".repeat(40),"review_id":"c".repeat(64)}).to_string()).unwrap();
        let mut args = Vec::new();
        if mode == "explicit-root" {
            args.extend(["--repo", repo.to_str().unwrap()]);
        }
        args.extend(["policy", "init", "--ci", "github"]);
        if mode == "bootstrap" || mode == "explicit-root" {
            args.extend(["--ci-bootstrap", config.to_str().unwrap()]);
        }
        let cwd = if mode == "explicit-root" {
            fixture.root.clone()
        } else if mode == "ambiguous" {
            repo.join("nested")
        } else {
            repo.clone()
        };
        let output = fixture.run(&cwd, &args);
        let success = mode == "bootstrap" || mode == "explicit-root";
        assert_eq!(
            output.status.success(),
            success,
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("invalid-unrelated-source"),
            "{mode}"
        );
        assert_eq!(
            repo.join(".github/workflows/barbican-admission.yml")
                .exists(),
            success
        );
        assert!(!repo.join(".github/workflows/barbican.yml").exists());
        assert!(!fixture.root.join("data").exists());
        fixture.no_candidate();
    }
}

#[test]
fn opted_in_gate_refuses_missing_admission_before_cargo_discovery() {
    let fixture = Fixture::new();
    let repo = fixture.root.join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    fs::write(
        repo.join("barbican.toml"),
        "[toolchain]\nrequire_admission=true\nadmission_scope='example'\n",
    )
    .unwrap();
    fs::write(
        repo.join("rust-toolchain.toml"),
        "[toolchain]\nchannel='1.99.1'\nprofile='minimal'\n",
    )
    .unwrap();
    for args in [
        &["verify"][..],
        &["gatehouse", "policy-check"][..],
        &["gatehouse", "pre-release"][..],
        &["toolchain", "check"][..],
    ] {
        let output = command()
            .current_dir(&repo)
            .env("HOME", fixture.root.join("home"))
            .env("CARGO_HOME", fixture.root.join("home/.cargo"))
            .env("PATH", fixture.root.join("bin"))
            .args([
                "--data-dir",
                fixture.root.join("data").to_str().unwrap(),
                "--cache-dir",
                fixture.root.join("cache").to_str().unwrap(),
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reviewed-targets.toml"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.no_candidate();
    }
}

#[test]
fn explicit_nested_member_cannot_bypass_parent_governance() {
    let fixture = Fixture::new();
    let repo = fixture.root.join("repo");
    let member = repo.join("member");
    fs::create_dir_all(&member).unwrap();
    fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=['member']\n").unwrap();
    fs::write(
        repo.join("barbican.toml"),
        "[toolchain]\nrequire_admission=true\n",
    )
    .unwrap();
    fs::write(
        member.join("Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\n",
    )
    .unwrap();
    let output = command()
        .current_dir(&member)
        .env("HOME", fixture.root.join("home"))
        .env("CARGO_HOME", fixture.root.join("home/.cargo"))
        .env("PATH", fixture.root.join("bin"))
        .args(["--repo", member.to_str().unwrap(), "verify"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("nested"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.no_candidate();
}

#[test]
fn hostile_selection_controls_fail_before_any_delegate_with_explicit_storage() {
    for control in [
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
        "RUSTUP_DIST_SERVER",
        "RUSTUP_DIST_ROOT",
        "RUSTUP_OVERRIDE_HOST_TRIPLE",
        "RUSTC_WRAPPER",
        "CARGO_HOME",
        "HOME",
        "RUSTUP_HOME",
    ] {
        let fixture = Fixture::new();
        let repo = fixture.root.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
        fs::write(
            repo.join("barbican.toml"),
            "[toolchain]\nrequire_admission=true\n",
        )
        .unwrap();
        let output = command()
            .current_dir(&repo)
            .env("HOME", fixture.root.join("home"))
            .env("CARGO_HOME", fixture.root.join("home/.cargo"))
            .env("PATH", fixture.root.join("bin"))
            .env(control, "unaccepted-or-relative")
            .args([
                "--data-dir",
                fixture.root.join("data").to_str().unwrap(),
                "--cache-dir",
                fixture.root.join("cache").to_str().unwrap(),
                "verify",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(control),
            "{control}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.no_candidate();
    }
}

#[test]
fn explicit_target_root_config_and_exact_rustup_override_are_checked_before_cargo() {
    for case in ["env", "build", "directory", "host"] {
        let fixture = Fixture::new();
        let repo = fixture.root.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
        fs::write(
            repo.join("barbican.toml"),
            "[toolchain]\nrequire_admission=true\n",
        )
        .unwrap();
        fs::create_dir(repo.join(".cargo")).unwrap();
        match case {
            "env" => fs::write(
                repo.join(".cargo/config.toml"),
                "[env]\nRUSTUP_HOME={value='/unaccepted',force=true}\n",
            )
            .unwrap(),
            "build" => fs::write(
                repo.join(".cargo/config.toml"),
                "[build]\nrustc='unaccepted'\n",
            )
            .unwrap(),
            "host" => {
                fs::create_dir(fixture.root.join("home/.rustup")).unwrap();
                fs::write(
                    fixture.root.join("home/.rustup/settings.toml"),
                    "version='12'\ndefault_host_triple='unaccepted-host'\n",
                )
                .unwrap();
            }
            _ => {
                fs::create_dir(fixture.root.join("home/.rustup")).unwrap();
                fs::write(
                    fixture.root.join("home/.rustup/settings.toml"),
                    format!(
                        "version='12'\n[overrides]\n'{}'='unaccepted'\n",
                        repo.canonicalize().unwrap().display()
                    ),
                )
                .unwrap();
            }
        }
        let output = command()
            .current_dir(&fixture.root)
            .env("HOME", fixture.root.join("home"))
            .env("CARGO_HOME", fixture.root.join("home/.cargo"))
            .env("PATH", fixture.root.join("bin"))
            .args([
                "--repo",
                repo.to_str().unwrap(),
                "--data-dir",
                fixture.root.join("data").to_str().unwrap(),
                "--cache-dir",
                fixture.root.join("cache").to_str().unwrap(),
                "verify",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("configuration")
                || error.contains("directory override")
                || error.contains("default_host_triple"),
            "{case}: {error}"
        );
        fixture.no_candidate();
    }
}

#[test]
fn fully_qualified_pinned_export_passes_selection_guard_but_never_skips_admission() {
    let fixture = Fixture::new();
    let repo = fixture.root.join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    fs::write(
        repo.join("barbican.toml"),
        "[toolchain]\nrequire_admission=true\n",
    )
    .unwrap();
    fs::write(
        repo.join("rust-toolchain.toml"),
        "[toolchain]\nchannel='1.99.1'\nprofile='minimal'\n",
    )
    .unwrap();
    let host = if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    for value in [
        format!("1.99.1-{host}"),
        "1.99.1".into(),
        format!("1.99.0-{host}"),
        "/unaccepted/toolchain".into(),
    ] {
        let output = command()
            .current_dir(&repo)
            .env("HOME", fixture.root.join("home"))
            .env("CARGO_HOME", fixture.root.join("home/.cargo"))
            .env("PATH", fixture.root.join("bin"))
            .env("RUSTUP_TOOLCHAIN", &value)
            .args([
                "--data-dir",
                fixture.root.join("data").to_str().unwrap(),
                "--cache-dir",
                fixture.root.join("cache").to_str().unwrap(),
                "verify",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        if value == format!("1.99.1-{host}") {
            assert!(error.contains("reviewed-targets.toml"), "{error}");
        } else {
            assert!(error.contains("RUSTUP_TOOLCHAIN"), "{error}");
        }
        fixture.no_candidate();
    }
}

#[test]
fn repository_minimum_age_override_refuses_before_collection_or_native_dispatch() {
    let fixture = Fixture::new();
    let repo = fixture.root.join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    for command in [
        "review",
        "accept",
        "install",
        "adopt",
        "installation-check",
        "activate",
    ] {
        let mut args = vec![
            "--repo",
            repo.to_str().unwrap(),
            "toolchain",
            command,
            "1.99.1",
            "--min-age-days",
            "7",
        ];
        if command == "accept" {
            args.extend(["--record", "unused.md"]);
        }
        if command == "install" {
            args.extend(["--rustup-executable", "unused-rustup"]);
        }
        let output = fixture.run(&fixture.root, &args);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("applies only to standalone"),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.no_candidate();
    }
}
