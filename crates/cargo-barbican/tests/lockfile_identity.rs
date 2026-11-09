#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TOOLCHAIN: &str = "1.95.0";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    cargo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-lockfile-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("cargo-home")).unwrap();
        fs::create_dir(root.join("markers")).unwrap();
        let rustup = std::env::var_os("BARBICAN_TEST_RUSTUP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rustup"));
        let mut cargo = PathBuf::new();
        for tool in ["cargo", "rustc", "rustdoc"] {
            let output = Command::new(&rustup)
                .args(["which", "--toolchain", TOOLCHAIN, tool])
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", render(&output));
            let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
            symlink(&path, root.join("bin").join(tool)).unwrap();
            if tool == "cargo" {
                cargo = path;
            }
        }
        if rustup.is_absolute() {
            symlink(rustup, root.join("bin/rustup")).unwrap();
        }
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"));
        symlink(
            cargo_home.join("registry").canonicalize().unwrap(),
            root.join("cargo-home/registry"),
        )
        .unwrap();
        let fixture = Self {
            root,
            workspace,
            cargo,
        };
        fixture.write("Cargo.toml", "[package]\nname='lockfile-identity-fixture'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nsemver='=1.0.28'\n");
        fixture.write(
            "rust-toolchain.toml",
            &format!("[toolchain]\nchannel='{TOOLCHAIN}'\n"),
        );
        fixture.write("src/lib.rs", "#[test]\nfn test_marker() { std::fs::write(std::path::PathBuf::from(std::env::var_os(\"BARBICAN_IDENTITY_MARKERS\").unwrap()).join(\"test\"), b\"ran\").unwrap(); }\n");
        fixture.write("build.rs", "fn main() { std::fs::write(std::path::PathBuf::from(std::env::var_os(\"BARBICAN_IDENTITY_MARKERS\").unwrap()).join(\"build\"), b\"ran\").unwrap(); }\n");
        fixture.write("reviewed-targets.toml", "[[rust.families]]\nname='semver'\nreview_record='review.md'\n[rust.families.resolved]\nsemver={version='1.0.28',checksum_sha256='8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd'}\n");
        fixture.write("review.md", "Reviewed fixture dependency: exact semver from the enclosing repository's reviewed dependency set.\n");
        let output = fixture
            .command(&fixture.cargo)
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", render(&output));
        fixture.write(
            "alternate/Cargo.lock",
            "version = 4\n# Alternate lockfile must remain byte-for-byte intact.\n",
        );
        fs::set_permissions(
            fixture.workspace.join("Cargo.lock"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        fs::set_permissions(
            fixture.workspace.join("alternate/Cargo.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fixture
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.workspace.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command.current_dir(&self.workspace);
        for name in [
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTDOC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTDOC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_RESOLVER_LOCKFILE_PATH",
            "CARGO_ALIAS_NEXTEST",
            "CARGO_MANIFEST_DIR",
            "CARGO",
            "CARGO_BARBICAN_CRATES_IO_BASE_URL",
        ] {
            command.env_remove(name);
        }
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        command.env("PATH", std::env::join_paths(paths).unwrap());
        command.env("CARGO_HOME", self.root.join("cargo-home"));
        command.env("CARGO_TARGET_DIR", self.root.join("target"));
        command.env("CARGO_NET_OFFLINE", "true");
        command.env("CARGO_TERM_COLOR", "never");
        command.env("BARBICAN_IDENTITY_MARKERS", self.root.join("markers"));
        command
    }

    fn barbican(&self, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_cargo-barbican"))
            .args(args)
            .output()
            .unwrap()
    }

    fn lockfiles(&self) -> Vec<(Vec<u8>, u32)> {
        ["Cargo.lock", "alternate/Cargo.lock"]
            .into_iter()
            .map(|name| {
                let path = self.workspace.join(name);
                (
                    fs::read(&path).unwrap(),
                    fs::metadata(path).unwrap().permissions().mode(),
                )
            })
            .collect()
    }

    fn no_markers(&self) {
        assert_eq!(fs::read_dir(self.root.join("markers")).unwrap().count(), 0);
        assert!(!self.root.join("target").exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn render(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn ordinary_verification_executes_real_build_and_tests_with_the_default_lockfile() {
    let fixture = Fixture::new();
    let before = fixture.lockfiles();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_cargo-barbican"))
        .env(
            "CARGO_RESOLVER_LOCKFILE_PATH",
            fixture.workspace.join("alternate/Cargo.lock"),
        )
        .arg("verify")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", render(&output));
    assert!(render(&output).contains("Verify: PASS"));
    assert_eq!(
        fs::read(fixture.root.join("markers/build")).unwrap(),
        b"ran"
    );
    assert_eq!(fs::read(fixture.root.join("markers/test")).unwrap(), b"ran");
    assert_eq!(fixture.lockfiles(), before);
}

#[test]
fn unsupported_configurations_refuse_before_native_build_test_or_lockfile_writes() {
    let fixture = Fixture::new();
    let before = fixture.lockfiles();
    for (location, config) in [
        (
            "workspace",
            "[resolver]\nlockfile-path='alternate/Cargo.lock'\n",
        ),
        (
            "ancestor",
            "[resolver]\nlockfile-path='alternate/Cargo.lock'\n",
        ),
        ("home", "[resolver]\nlockfile-path='alternate/Cargo.lock'\n"),
        ("workspace", "[resolver]\nlockfile-path='Cargo.lock'\n"),
        (
            "workspace",
            "[env]\nCARGO_RESOLVER_LOCKFILE_PATH={value='alternate/Cargo.lock',force=true,relative=true}\n",
        ),
    ] {
        let path = match location {
            "ancestor" => fixture.root.join(".cargo/config.toml"),
            "home" => fixture.root.join("cargo-home/config.toml"),
            _ => fixture.workspace.join(".cargo/config.toml"),
        };
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, config).unwrap();
        for args in [
            vec!["verify"],
            vec!["resolve"],
            vec!["update", "semver@1.0.28"],
            vec!["update", "--dry-run", "semver@1.0.28"],
        ] {
            let output = fixture.barbican(&args);
            assert!(
                !output.status.success(),
                "{location} {args:?}: {}",
                render(&output)
            );
            assert!(
                render(&output).contains("default workspace Cargo.lock"),
                "{}",
                render(&output)
            );
            fixture.no_markers();
            assert_eq!(fixture.lockfiles(), before);
        }
        fixture.write(
            "barbican.toml",
            "[verify]\ntest_runner='nextest'\nnextest_version='0.9.146'\n",
        );
        let output = fixture.barbican(&["verify"]);
        assert!(!output.status.success(), "{}", render(&output));
        assert!(render(&output).contains("default workspace Cargo.lock"));
        fixture.no_markers();
        assert_eq!(fixture.lockfiles(), before);
        fs::remove_file(fixture.workspace.join("barbican.toml")).unwrap();
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn real_cargo_selection_keeps_legacy_filename_precedence() {
    let fixture = Fixture::new();
    fixture.write(".cargo/config", "[build]\njobs=1\n");
    fixture.write(
        ".cargo/config.toml",
        "[resolver]\nlockfile-path='alternate/Cargo.lock'\n",
    );
    let output = fixture.barbican(&["pin", "check"]);
    assert!(output.status.success(), "{}", render(&output));
    fixture.write(
        ".cargo/config",
        "[resolver]\nlockfile-path='alternate/Cargo.lock'\n",
    );
    fixture.write(".cargo/config.toml", "[build]\njobs=1\n");
    let before = fixture.lockfiles();
    let output = fixture.barbican(&["verify"]);
    assert!(!output.status.success(), "{}", render(&output));
    assert!(render(&output).contains("default workspace Cargo.lock"));
    fixture.no_markers();
    assert_eq!(fixture.lockfiles(), before);
}
