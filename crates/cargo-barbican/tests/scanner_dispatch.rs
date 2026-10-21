#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use cargo_barbican::{CommandRunner, RealCommandRunner, RunnerError};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-scanner-dispatch-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self { root };
        for directory in ["workspace/src", "scratch", "cargo-home", "bin", "records"] {
            fs::create_dir_all(fixture.root.join(directory)).unwrap();
        }
        for tool in [
            "cargo", "rustup", "rustc", "rustdoc", "cat", "cc", "as", "ld",
        ] {
            let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|path| path.join(tool))
                .find(|path| path.is_file())
                .unwrap();
            symlink(executable, fixture.root.join("bin").join(tool)).unwrap();
        }
        fixture.executable(
            "bin/cargo-scanner-marker",
            "#!/bin/sh\nprintf alias > \"$BARBICAN_SCANNER_FIXTURE/alias-hit\"\n",
        );
        fixture.write(
            "workspace/Cargo.toml",
            "[package]\nname = \"scanner-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        fixture.write("workspace/src/lib.rs", "pub fn fixture() {}\n");
        fixture.write("workspace/build.rs", "fn main() { std::fs::write(std::env::var(\"BARBICAN_SCANNER_FIXTURE\").unwrap() + \"/build-hit\", \"executed\").unwrap(); }\n");
        fixture.write(
            "workspace/Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"scanner-fixture\"\nversion = \"0.1.0\"\n",
        );
        fixture.write(
            "workspace/barbican.toml",
            "[delegates.advisories]\nlockfile_scanner = \"both\"\n",
        );
        fixture.write(
            "scratch/deny.toml",
            "[bans]\nmultiple-versions = \"deny\"\n",
        );
        fixture.write("deny.json", "{\"type\":\"summary\",\"fields\":{\"advisories\":{\"errors\":0},\"bans\":{\"errors\":0},\"sources\":{\"errors\":0}}}\n");
        fixture.write("audit.json", "{\"vulnerabilities\":{\"found\":false,\"count\":0,\"list\":[]},\"settings\":{\"ignore\":[]},\"warnings\":{}}\n");
        for scanner in ["deny", "audit"] {
            fixture.executable(&format!("bin/cargo-{scanner}"), &format!(r##"#!/bin/sh
if [ "$1" = --version ]; then printf 'cargo-{scanner} fixture\n'; exit 0; fi
record="$BARBICAN_SCANNER_FIXTURE/records/{scanner}"
printf '%s\n' "$PWD" > "$record.cwd"
printf '%s\n' "$@" > "$record.args"
printf '%s\n' "${{CARGO_MANIFEST_DIR-unset}}" "${{CARGO_PKG_NAME-unset}}" "${{OUT_DIR-unset}}" "${{CARGO_HOME-unset}}" "${{CARGO_NET_OFFLINE-unset}}" "${{CARGO_ALIAS_DENY-unset}}" > "$record.env"
case "${{BARBICAN_SCANNER_MODE-clean}}" in
  {scanner}-malformed) printf 'not-json\n' >&2; printf 'not-json\n'; exit 0 ;;
  {scanner}-failed) printf 'scanner failed\n' >&2; exit 42 ;;
esac
if [ '{scanner}' = deny ]; then cat "$BARBICAN_SCANNER_FIXTURE/deny.json" >&2
else cat "$BARBICAN_SCANNER_FIXTURE/audit.json"
fi
case "${{BARBICAN_SCANNER_MODE-clean}}" in
  {scanner}-report-failed) exit 42 ;;
  {scanner}-report-signal) kill -TERM $$ ;;
  {scanner}-report-unexplained) exit 1 ;;
esac
"##));
        }
        fixture
    }

    fn write(&self, path: &str, body: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn executable(&self, path: &str, body: &str) {
        self.write(path, body);
        fs::set_permissions(self.root.join(path), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn command(&self, executable: impl AsRef<OsStr>, directory: &str) -> Command {
        let mut command = Command::new(executable);
        command.current_dir(self.root.join(directory));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("CARGO_ALIAS_") {
                command.env_remove(name);
            }
        }
        command.env("PATH", self.root.join("bin"));
        command.env("CARGO_HOME", self.root.join("cargo-home"));
        command.env("CARGO_NET_OFFLINE", "true");
        command.env("CARGO_TARGET_DIR", self.root.join("target"));
        command.env("BARBICAN_SCANNER_FIXTURE", &self.root);
        command.env_remove("BARBICAN_SCANNER_MODE");
        command
    }

    fn alias(&self, source: &str) {
        let alias = "scanner-marker";
        let body = format!("[alias]\ndeny = {alias:?}\naudit = {alias:?}\n");
        let path = match source {
            "workspace" => "workspace/.cargo/config.toml",
            "legacy-workspace" => "workspace/.cargo/config",
            "ancestor" => ".cargo/config.toml",
            "cargo-home" => "cargo-home/config.toml",
            "scratch" => "scratch/.cargo/config.toml",
            "environment" => return,
            _ => unreachable!(),
        };
        self.write(path, &body);
    }

    fn aliases(&self, command: &mut Command, source: &str) {
        if source == "environment" {
            let alias = "scanner-marker";
            command
                .env("CARGO_ALIAS_DENY", alias)
                .env("CARGO_ALIAS_AUDIT", alias);
        }
    }

    fn assert_unchanged(&self) {
        assert!(!self.root.join("alias-hit").exists());
        assert!(!self.root.join("build-hit").exists());
        assert!(!self.root.join("target").exists());
        assert_eq!(
            fs::read_to_string(self.root.join("workspace/Cargo.lock")).unwrap(),
            "version = 4\n\n[[package]]\nname = \"scanner-fixture\"\nversion = \"0.1.0\"\n"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn success(output: Output) -> Output {
    assert!(output.status.success(), "{output:?}");
    output
}

#[test]
fn scanner_dispatch_bypasses_native_cargo_aliases() {
    for source in [
        "environment",
        "workspace",
        "legacy-workspace",
        "ancestor",
        "cargo-home",
        "scratch",
    ] {
        let fixture = Fixture::new();
        fixture.alias(source);
        for scanner in ["deny", "audit"] {
            let directory = if source == "scratch" {
                "scratch"
            } else {
                "workspace"
            };
            let mut probe = fixture.command("cargo", directory);
            fixture.aliases(&mut probe, source);
            success(probe.arg(scanner).output().unwrap());
            assert!(
                fixture.root.join("alias-hit").exists(),
                "positive control: {source}/{scanner}"
            );
            fs::remove_file(fixture.root.join("alias-hit")).unwrap();
        }
        for mode in ["clean", "deny-failed", "audit-failed"] {
            let mut child = fixture.command(std::env::current_exe().unwrap(), "workspace");
            fixture.aliases(&mut child, source);
            child.env("CARGO_MANIFEST_DIR", "/nested-build-metadata");
            child.env("CARGO_PKG_NAME", "outer-package");
            child.env("OUT_DIR", "/nested-output");
            child.env("BARBICAN_SCANNER_MODE", mode);
            success(
                child
                    .args(["--exact", "scanner_runner_child", "--ignored"])
                    .output()
                    .unwrap(),
            );
        }
        fixture.assert_unchanged();
    }
}

#[test]
#[ignore = "isolated subprocess helper, called by scanner_dispatch_bypasses_native_cargo_aliases"]
fn scanner_runner_child() {
    let root = PathBuf::from(std::env::var_os("BARBICAN_SCANNER_FIXTURE").unwrap());
    let workspace = root.join("workspace");
    let scratch = root.join("scratch");
    match std::env::var("BARBICAN_SCANNER_MODE").as_deref() {
        Ok("audit-failed") => {
            let audit = RealCommandRunner
                .cargo_audit_json(&scratch, &workspace.join("Cargo.lock"))
                .unwrap();
            assert_eq!(audit.exit_code, Some(42));
            assert!(matches!(
                RealCommandRunner.cargo_audit(&workspace),
                Err(RunnerError::Exited { code: Some(42), .. })
            ));
            return;
        }
        Ok("deny-failed") => {
            let deny = RealCommandRunner
                .cargo_deny_json(
                    &workspace,
                    &scratch.join("deny.toml"),
                    &[barbican::CargoDenyCheck::Bans],
                )
                .unwrap();
            assert_eq!(deny.exit_code, Some(42));
            return;
        }
        _ => {}
    }
    let deny = RealCommandRunner
        .cargo_deny_json(
            &workspace,
            &scratch.join("deny.toml"),
            &[
                barbican::CargoDenyCheck::Bans,
                barbican::CargoDenyCheck::Sources,
            ],
        )
        .unwrap();
    assert_eq!(deny.exit_code, Some(0));
    assert_eq!(
        deny.stderr,
        fs::read_to_string(root.join("deny.json")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(root.join("records/deny.args")).unwrap(),
        format!(
            "--locked\n-f\njson\ncheck\n-c\n{}\nbans\nsources\n",
            scratch.join("deny.toml").display()
        )
    );
    assert_eq!(
        fs::read_to_string(root.join("records/deny.cwd"))
            .unwrap()
            .trim(),
        workspace.canonicalize().unwrap().to_str().unwrap()
    );
    let audit = RealCommandRunner
        .cargo_audit_json(&scratch, &workspace.join("Cargo.lock"))
        .unwrap();
    assert_eq!(audit.exit_code, Some(0));
    assert_eq!(
        audit.stdout,
        fs::read_to_string(root.join("audit.json")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(root.join("records/audit.args")).unwrap(),
        format!(
            "audit\n--json\n-f\n{}\n-d\n{}\n",
            workspace.join("Cargo.lock").display(),
            root.join("cargo-home/advisory-db").display()
        )
    );
    assert_eq!(
        fs::read_to_string(root.join("records/audit.cwd"))
            .unwrap()
            .trim(),
        scratch.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        RealCommandRunner.cargo_audit(&workspace).unwrap(),
        audit.stdout
    );
    assert_eq!(
        fs::read_to_string(root.join("records/audit.args")).unwrap(),
        "audit\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("records/audit.cwd"))
            .unwrap()
            .trim(),
        workspace.canonicalize().unwrap().to_str().unwrap()
    );
    for scanner in ["deny", "audit"] {
        let environment = fs::read_to_string(root.join(format!("records/{scanner}.env"))).unwrap();
        let lines = environment.lines().collect::<Vec<_>>();
        assert_eq!(&lines[..3], &["unset", "unset", "unset"]);
        assert_eq!(Path::new(lines[3]), root.join("cargo-home"));
        assert_eq!(lines[4], "true");
        assert_eq!(
            lines[5],
            std::env::var("CARGO_ALIAS_DENY").unwrap_or_else(|_| "unset".to_owned())
        );
    }
}

#[test]
fn audit_native_scanner_success_and_failures_never_use_alias_fallback() {
    for mode in [
        "clean",
        "deny-malformed",
        "audit-malformed",
        "deny-failed",
        "audit-failed",
        "deny-report-failed",
        "audit-report-failed",
        "deny-report-signal",
        "audit-report-signal",
        "deny-report-unexplained",
        "audit-report-unexplained",
        "missing-deny",
        "missing-audit",
    ] {
        let fixture = Fixture::new();
        fixture.alias("cargo-home");
        if let Some(scanner) = mode.strip_prefix("missing-") {
            fs::remove_file(fixture.root.join(format!("bin/cargo-{scanner}"))).unwrap();
        }
        let mut command = fixture.command(env!("CARGO_BIN_EXE_cargo-barbican"), "workspace");
        command.args(["audit", "--format", "json"]);
        command.env("BARBICAN_SCANNER_MODE", mode);
        let output = command.output().unwrap();
        if mode == "clean" {
            assert!(output.status.success(), "{output:?}");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["schema_version"], 6);
        } else {
            assert_eq!(output.status.code(), Some(1), "{mode}: {output:?}");
            assert!(output.stdout.is_empty(), "{mode}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("FAIL "),
                "{mode}: {output:?}"
            );
        }
        fixture.assert_unchanged();
    }
}

impl Fixture {
    fn policy_workspace(&self) {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"));
        symlink(
            cargo_home.join("registry").canonicalize().unwrap(),
            self.root.join("cargo-home/registry"),
        )
        .unwrap();
        self.write(
            "workspace/rust-toolchain.toml",
            "[toolchain]\nchannel='1.95.0'\n",
        );
        self.write("workspace/Cargo.toml", "[package]\nname='scanner-fixture'\nversion='0.1.0'\nedition='2024'\n\n[workspace]\nmembers=['member']\n\n[dependencies]\nsemver='=1.0.28'\n");
        self.write(
            "workspace/member/Cargo.toml",
            "[package]\nname='member-fixture'\nversion='0.1.0'\nedition='2024'\n",
        );
        self.write("workspace/member/src/lib.rs", "pub fn member() {}\n");
        self.write("workspace/Cargo.lock", "version = 4\n\n[[package]]\nname = \"member-fixture\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"scanner-fixture\"\nversion = \"0.1.0\"\ndependencies = [\"semver\"]\n\n[[package]]\nname = \"semver\"\nversion = \"1.0.28\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd\"\n");
        self.write("workspace/reviewed-targets.toml", "[[rust.families]]\nname='semver'\nreview_record='review.md'\n[rust.families.direct]\nsemver='=1.0.28'\n[rust.families.resolved]\nsemver={version='1.0.28',checksum_sha256='8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd'}\n");
        self.write(
            "workspace/review.md",
            "# Completed review fixture: semver\n",
        );
    }

    fn policy_snapshot(&self) -> Vec<Option<Vec<u8>>> {
        [
            "Cargo.toml",
            "Cargo.lock",
            "reviewed-targets.toml",
            "review.md",
            "member/Cargo.toml",
            "barbican.toml",
            "rust-toolchain.toml",
        ]
        .iter()
        .map(|path| fs::read(self.root.join("workspace").join(path)).ok())
        .collect()
    }

    fn assert_policy_unchanged(&self, before: &[Option<Vec<u8>>]) {
        assert_eq!(self.policy_snapshot(), before);
        for marker in ["alias-hit", "build-hit", "target"] {
            assert!(!self.root.join(marker).exists(), "unexpected {marker}");
        }
    }
}

#[test]
fn policy_check_native_root_and_member_pass_without_workspace_execution() {
    for scanner in ["cargo-deny", "cargo-audit", "both"] {
        let fixture = Fixture::new();
        fixture.policy_workspace();
        fixture.alias("cargo-home");
        let mut control = fixture.command("cargo", "workspace");
        success(
            control
                .args(["check", "--locked", "--offline"])
                .output()
                .unwrap(),
        );
        assert!(
            fixture.root.join("build-hit").exists(),
            "build-script control must execute"
        );
        fs::remove_file(fixture.root.join("build-hit")).unwrap();
        fs::remove_dir_all(fixture.root.join("target")).unwrap();
        fixture.write("workspace/barbican.toml", &format!("[delegates.advisories]\nlockfile_scanner='{scanner}'\n[verify]\ntest_runner='nextest'\nnextest_version='0.9.146'\n"));
        let before = fixture.policy_snapshot();
        for directory in ["workspace", "workspace/member"] {
            let mut command = fixture.command(env!("CARGO_BIN_EXE_cargo-barbican"), directory);
            fixture.aliases(&mut command, "environment");
            let output = success(
                command
                    .args(["gatehouse", "policy-check"])
                    .output()
                    .unwrap(),
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                stdout.ends_with(
                    "Policy checks only; build/test not run.\nGatehouse policy-check: PASS\n"
                ),
                "{stdout}"
            );
            assert!(!stdout.contains("Verify: PASS"));
            assert!(!stdout.contains("OK   cargo"));
            fixture.assert_policy_unchanged(&before);
        }
    }
}

#[test]
fn policy_check_native_failures_never_execute_or_rewrite_workspace() {
    for failure in [
        "deny-malformed",
        "audit-failed",
        "deny-report-failed",
        "audit-report-failed",
        "deny-report-signal",
        "audit-report-signal",
        "deny-report-unexplained",
        "audit-report-unexplained",
        "missing-deny",
        "missing-policy",
        "empty-policy",
        "pending-review",
        "checksum",
        "missing-lock",
        "toolchain",
    ] {
        let fixture = Fixture::new();
        fixture.policy_workspace();
        fixture.alias("cargo-home");
        match failure {
            "missing-deny" => fs::remove_file(fixture.root.join("bin/cargo-deny")).unwrap(),
            "missing-policy" => {
                fs::remove_file(fixture.root.join("workspace/reviewed-targets.toml")).unwrap()
            }
            "empty-policy" => {
                fixture.write("workspace/reviewed-targets.toml", "[rust]\nfamilies=[]\n")
            }
            "pending-review" => fixture.write(
                "workspace/review.md",
                &format!("# Review\n{}\n", barbican::REVIEW_RECORD_SCAFFOLD_MARKER),
            ),
            "checksum" => {
                let path = fixture.root.join("workspace/reviewed-targets.toml");
                let text = fs::read_to_string(&path).unwrap().replace(
                    "8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd",
                    &"f".repeat(64),
                );
                fs::write(path, text).unwrap();
            }
            "missing-lock" => fs::remove_file(fixture.root.join("workspace/Cargo.lock")).unwrap(),
            "toolchain" => fixture.write(
                "workspace/rust-toolchain.toml",
                "[toolchain]\nchannel='stable'\n",
            ),
            _ => {}
        }
        let before = fixture.policy_snapshot();
        let mut command = fixture.command(env!("CARGO_BIN_EXE_cargo-barbican"), "workspace");
        fixture.aliases(&mut command, "environment");
        command.env("BARBICAN_SCANNER_MODE", failure);
        let output = command
            .args(["gatehouse", "policy-check"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{failure}: {output:?}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Gatehouse policy-check: PASS"));
        fixture.assert_policy_unchanged(&before);
    }
}
