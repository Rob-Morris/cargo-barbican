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
        for tool in ["cargo", "rustc", "rustdoc", "cat"] {
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
