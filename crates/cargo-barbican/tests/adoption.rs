#![cfg(unix)]

mod adoption_support;
use adoption_support::*;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

const HOOK: &str = ".barbican/hooks/pre-commit";
const RECORD: &str = "docs/dependency-reviews/record-template.md";
fn executable(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn git(f: &Fixture, args: &[&str]) -> Output {
    f.ok(f.command("git").args(args))
}
fn prepare_git(f: &Fixture, hooks: &str) {
    git(f, &["-c", "init.templateDir=", "init", "-q"]);
    git(f, &["config", "core.hooksPath", hooks]);
    git(f, &["config", "commit.gpgsign", "false"]);
    f.write("fake-bin/cargo", "#!/bin/sh\nprintf '%s|%s\\n' \"$PWD\" \"$*\" >> \"$BARBICAN_HOOK_LOG\"\nexit \"${BARBICAN_HOOK_FAIL:-0}\"\n");
    executable(&f.path("fake-bin/cargo"));
}
fn commit(f: &Fixture, fail: &str) -> Command {
    let mut command = f.command("git");
    command.args(["commit", "--allow-empty", "-qm", "fixture"]);
    command.env(
        "PATH",
        format!("{}:/usr/bin:/bin", f.path("fake-bin").display()),
    );
    command.env("BARBICAN_HOOK_LOG", f.path("hook.log"));
    command.env("BARBICAN_HOOK_FAIL", fail);
    command
}

#[test]
fn optional_copy_is_disabled_and_preserves_existing_content_modes_and_git_config() {
    let f = Fixture::new();
    f.init(&[]);
    assert!(!f.path(".barbican").exists());
    assert_eq!(
        fs::read_to_string(f.path(RECORD)).unwrap(),
        include_str!("../../../templates/dependency-reviews/record-template.md")
    );
    prepare_git(&f, "original-hooks");
    let output = f.init(&["--pre-commit-hook"]);
    assert!(rendered(&output).contains("pre-commit: created"));
    assert_eq!(
        fs::read_to_string(f.path(HOOK)).unwrap(),
        include_str!("../../../templates/hooks/pre-commit")
    );
    assert_eq!(
        fs::metadata(f.path(HOOK)).unwrap().permissions().mode() & 0o111,
        0
    );
    assert_eq!(
        String::from_utf8(git(&f, &["config", "--get", "core.hooksPath"]).stdout)
            .unwrap()
            .trim(),
        "original-hooks"
    );
    for path in [HOOK, RECORD, "docs/dependency-reviews/README.md"] {
        f.write(path, "consumer-owned\n");
        fs::set_permissions(f.path(path), fs::Permissions::from_mode(0o751)).unwrap();
    }
    let output = f.init(&["--pre-commit-hook"]);
    assert!(rendered(&output).contains("pre-commit: already present"));
    for path in [HOOK, RECORD, "docs/dependency-reviews/README.md"] {
        assert_eq!(
            fs::read_to_string(f.path(path)).unwrap(),
            "consumer-owned\n"
        );
        assert_eq!(
            fs::metadata(f.path(path)).unwrap().permissions().mode() & 0o777,
            0o751
        );
    }
}

#[test]
fn new_outputs_are_non_executable_under_permissive_umask() {
    let f = Fixture::new();
    f.ok(f.command("/bin/sh").args([
        "-c",
        "umask 000; exec \"$@\"",
        "adoption-umask",
        env!("CARGO_BIN_EXE_cargo-barbican"),
        "policy",
        "init",
        "--pre-commit-hook",
    ]));
    for path in [HOOK, RECORD] {
        assert_eq!(
            fs::metadata(f.path(path)).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}

#[test]
fn member_invocation_anchors_both_new_outputs_at_cargo_workspace_root() {
    let f = Fixture::new();
    f.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"member\"]\nresolver = \"3\"\n",
    );
    f.write(
        "member/Cargo.toml",
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
    );
    f.write("member/src/lib.rs", "");
    f.ok(f
        .barbican(&["policy", "init", "--pre-commit-hook"])
        .current_dir(f.path("member/src")));
    for path in [HOOK, RECORD] {
        assert!(f.path(path).is_file());
        assert!(!f.path("member").join(path).exists());
        assert!(!f.path("member/src").join(path).exists());
    }
}

#[test]
fn new_outputs_refuse_initial_wrong_types_and_unsafe_ancestors() {
    for path in [HOOK, RECORD] {
        for kind in [
            "directory",
            "symlink",
            "fifo",
            "ancestor-file",
            "ancestor-symlink",
        ] {
            let f = Fixture::new();
            let parent = Path::new(path).parent().unwrap();
            let first = Path::new(path).components().next().unwrap().as_os_str();
            if kind == "ancestor-file" {
                fs::write(f.root.join(first), "blocked").unwrap();
            } else if kind == "ancestor-symlink" {
                fs::create_dir(f.path("outside")).unwrap();
                symlink(f.path("outside"), f.root.join(first)).unwrap();
            } else {
                fs::create_dir_all(f.root.join(parent)).unwrap();
                match kind {
                    "directory" => fs::create_dir(f.path(path)).unwrap(),
                    "symlink" => {
                        f.write("untouched", "original");
                        symlink(f.path("untouched"), f.path(path)).unwrap();
                    }
                    "fifo" => {
                        f.ok(f.command("mkfifo").arg(f.path(path)));
                    }
                    _ => unreachable!(),
                }
            }
            let output = f.run(&mut f.barbican(&["policy", "init", "--pre-commit-hook"]));
            assert!(
                !output.status.success(),
                "{path}/{kind}: {}",
                rendered(&output)
            );
            assert!(
                rendered(&output).contains("blocked"),
                "{}",
                rendered(&output)
            );
            if kind == "symlink" {
                assert_eq!(fs::read_to_string(f.path("untouched")).unwrap(), "original");
            }
            if kind == "ancestor-symlink" {
                assert_eq!(fs::read_dir(f.path("outside")).unwrap().count(), 0);
            }
        }
    }
}

#[test]
fn native_git_ignores_disabled_copy_and_runs_explicitly_activated_hook() {
    let f = Fixture::new();
    prepare_git(&f, ".barbican/hooks");
    f.init(&["--pre-commit-hook"]);
    f.ok(&mut commit(&f, "0"));
    assert!(!f.path("hook.log").exists());
    executable(&f.path(HOOK));
    f.ok(&mut commit(&f, "0"));
    let log = fs::read_to_string(f.path("hook.log")).unwrap();
    assert_eq!(
        log,
        format!(
            "{}|barbican pin check\n{}|barbican inventory --enforce\n",
            f.root.display(),
            f.root.display()
        )
    );
}

#[test]
fn existing_hook_steps_survive_and_helper_failure_blocks_commit_and_later_steps() {
    let f = Fixture::new();
    prepare_git(&f, "existing-hooks");
    f.init(&["--pre-commit-hook"]);
    f.write("existing-hooks/pre-commit", "#!/bin/sh\nprintf before >> steps\nsh .barbican/hooks/pre-commit || exit $?\nprintf after >> steps\n");
    executable(&f.path("existing-hooks/pre-commit"));
    f.write(
        "existing-hooks/commit-msg",
        "#!/bin/sh\nprintf message >> steps\n",
    );
    executable(&f.path("existing-hooks/commit-msg"));
    f.ok(&mut commit(&f, "0"));
    assert_eq!(
        fs::read_to_string(f.path("steps")).unwrap(),
        "beforeaftermessage"
    );
    f.write("steps", "");
    f.write("hook.log", "");
    let output = f.run(&mut commit(&f, "7"));
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(f.path("steps")).unwrap(), "before");
    assert_eq!(
        fs::read_to_string(f.path("hook.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        fs::metadata(f.path(HOOK)).unwrap().permissions().mode() & 0o111,
        0
    );
}

#[test]
fn nested_wrapper_selects_cargo_root_and_preserves_parent_hook_cwd() {
    let f = Fixture::new();
    prepare_git(&f, "existing-hooks");
    f.write(
        "app/Cargo.toml",
        "[package]\nname = \"nested\"\nversion = \"0.1.0\"\n[workspace]\n",
    );
    f.write("app/src/lib.rs", "");
    f.write(
        "app/rust-toolchain.toml",
        &format!("[toolchain]\nchannel = \"{TOOLCHAIN}\"\n"),
    );
    f.ok(f
        .barbican(&["policy", "init", "--pre-commit-hook"])
        .current_dir(f.path("app")));
    f.write("existing-hooks/pre-commit", "#!/bin/sh\n(cd app && sh .barbican/hooks/pre-commit) || exit $?\nprintf '%s' \"$PWD\" > parent-cwd\n");
    executable(&f.path("existing-hooks/pre-commit"));
    f.ok(&mut commit(&f, "0"));
    let log = fs::read_to_string(f.path("hook.log")).unwrap();
    assert!(
        log.lines()
            .all(|line| line.starts_with(&format!("{}|", f.path("app").display())))
    );
    assert_eq!(log.lines().count(), 2);
    assert_eq!(
        fs::read_to_string(f.path("parent-cwd")).unwrap(),
        f.root.display().to_string()
    );
}

#[test]
fn gui_style_path_without_cargo_fails_visibly() {
    let f = Fixture::new();
    prepare_git(&f, ".barbican/hooks");
    f.init(&["--pre-commit-hook"]);
    executable(&f.path(HOOK));
    let output = f.run(commit(&f, "0").env("PATH", "/usr/bin:/bin"));
    assert!(!output.status.success());
    assert!(rendered(&output).contains("cargo"));
    assert!(!f.path("hook.log").exists());
}

fn manual_copy_script() -> &'static str {
    include_str!("../../../docs/user/ci.md")
        .split("```sh\n")
        .find(|block| block.starts_with("(\n  set -eu\n  hook_source="))
        .unwrap()
        .split("```")
        .next()
        .unwrap()
}

#[test]
fn reviewed_manual_copy_works_without_consumer_upstream_templates_and_stays_disabled() {
    let f = Fixture::new();
    f.write(
        "scratch/upstream/templates/hooks/pre-commit",
        include_str!("../../../templates/hooks/pre-commit"),
    );
    f.ok(f
        .command("/bin/sh")
        .args(["-c", manual_copy_script()])
        .env("barbican_source", f.path("scratch")));
    assert!(!f.path("templates").exists());
    assert!(!f.path("scratch").exists());
    assert_eq!(
        fs::read(f.path(HOOK)).unwrap(),
        include_bytes!("../../../templates/hooks/pre-commit")
    );
    assert_eq!(
        fs::metadata(f.path(HOOK)).unwrap().permissions().mode() & 0o111,
        0
    );
    let original = fs::read(f.path(HOOK)).unwrap();
    f.write("scratch/upstream/templates/hooks/pre-commit", "replacement");
    let output = f.run(
        f.command("/bin/sh")
            .args(["-c", manual_copy_script()])
            .env("barbican_source", f.path("scratch")),
    );
    assert!(!output.status.success());
    assert!(f.path("scratch").exists());
    assert_eq!(fs::read(f.path(HOOK)).unwrap(), original);
    fs::remove_file(f.path(HOOK)).unwrap();
    f.ok(f.command("mkfifo").arg(f.path(HOOK)));
    let output = f.run_with_timeout(
        f.command("/bin/sh")
            .args(["-c", manual_copy_script()])
            .env("barbican_source", f.path("scratch")),
        std::time::Duration::from_secs(5),
    );
    assert!(!output.status.success());
    assert!(
        fs::symlink_metadata(f.path(HOOK))
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn manual_copy_refuses_missing_or_empty_source_before_creating_destination() {
    for empty in [false, true] {
        let f = Fixture::new();
        fs::create_dir(f.path("scratch")).unwrap();
        if empty {
            f.write("scratch/upstream/templates/hooks/pre-commit", "");
        }
        let output = f.run(
            f.command("/bin/sh")
                .args(["-c", manual_copy_script()])
                .env("barbican_source", f.path("scratch")),
        );
        assert!(!output.status.success());
        assert!(!f.path(HOOK).exists());
        assert!(f.path("scratch").exists());
    }
}

#[test]
fn timed_out_proof_terminates_its_delegated_process_group() {
    let f = Fixture::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.run_with_timeout(
            f.command("/bin/sh")
                .args(["-c", "sleep 60 & printf '%s' \"$!\" > descendant.pid; wait"]),
            std::time::Duration::from_millis(500),
        )
    }));
    assert!(result.is_err());
    let descendant = fs::read_to_string(f.path("descendant.pid")).unwrap();
    // A killed child may briefly remain as a zombie while the OS reaps it.
    // Neither absent nor zombie processes can outlive the proof as work.
    let output = f.run(f.command("ps").args(["-o", "stat=", "-p", &descendant]));
    assert!(
        output.stderr.is_empty(),
        "process cleanup observation failed: {}",
        rendered(&output)
    );
    let status = String::from_utf8(output.stdout).unwrap();
    assert!(
        status.trim().is_empty() || status.trim().starts_with('Z'),
        "delegated process survived: {descendant} {status}"
    );
}

#[test]
fn copied_standalone_template_cannot_satisfy_the_reviewed_family_gate() {
    let f = Fixture::new();
    f.init(&[]);
    f.write("Cargo.toml", "[package]\nname = \"adoption-fixture\"\nversion = \"0.1.0\"\n[dependencies]\nsemver = \"=1.0.28\"\n");
    f.write("Cargo.lock", "version = 4\n[[package]]\nname = \"adoption-fixture\"\nversion = \"0.1.0\"\ndependencies = [\"semver\"]\n[[package]]\nname = \"semver\"\nversion = \"1.0.28\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd\"\n");
    f.write("reviewed-targets.toml", "[[rust.families]]\nname = \"reviewed-semver-fixture\"\nreview_record = \"docs/dependency-reviews/manual.md\"\n[rust.families.direct]\nsemver = \"=1.0.28\"\n[rust.families.resolved]\nsemver = { version = \"1.0.28\", checksum_sha256 = \"8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd\" }\n");
    fs::copy(f.path(RECORD), f.path("docs/dependency-reviews/manual.md")).unwrap();
    let pending = f.run(&mut f.barbican(&["pin", "check"]));
    assert!(!pending.status.success());
    assert!(rendered(&pending).contains("PENDING"));
    // Positive control cites the existing deliberate review of these exact
    // registry bytes, rather than merely stripping the template's marker.
    f.write(
        "docs/dependency-reviews/manual.md",
        include_str!("../../../docs/dependency-reviews/2026-07-01-semver-1.0.28.md"),
    );
    f.ok(&mut f.barbican(&["pin", "check"]));
}
