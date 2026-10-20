use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const URL: &str = "https://example.invalid/barbican-fixture.git";

struct Fixture {
    root: PathBuf,
    upstream: PathBuf,
    consumer: PathBuf,
    rev: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove task-owned Git fixture");
    }
}

impl Fixture {
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.consumer)
            .env("CARGO_HOME", self.root.join("cargo-home"))
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
            .env("CARGO_NET_RETRY", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "2")
            .env(
                "GIT_CONFIG_KEY_0",
                format!("url.file://{}.insteadOf", self.upstream.display()),
            )
            .env("GIT_CONFIG_VALUE_0", URL)
            .env("GIT_CONFIG_KEY_1", "protocol.file.allow")
            .env("GIT_CONFIG_VALUE_1", "always")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("BARBICAN_GIT_SENTINEL", self.root.join("executed"));
        command
    }

    fn cli(&self, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_cargo-barbican"))
            .args(args)
            .output()
            .unwrap()
    }

    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-git-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let upstream = root.join("upstream");
        let consumer = root.join("consumer");
        for package in ["wrapper", "native-sys"] {
            let dir = upstream.join(package);
            fs::create_dir_all(dir.join("src")).unwrap();
            fs::write(dir.join("src/lib.rs"), "pub fn harmless() {}\n").unwrap();
            let deps = if package == "wrapper" {
                "[dependencies]\nnative-sys={path=\"../native-sys\"}\n"
            } else {
                ""
            };
            fs::write(
                dir.join("Cargo.toml"),
                format!(
                    "[package]\nname=\"{package}\"\nversion=\"0.1.0\"\nedition=\"2024\"\n{deps}"
                ),
            )
            .unwrap();
        }
        fs::write(upstream.join("native-sys/build.rs"), "fn main(){if let Ok(path)=std::env::var(\"BARBICAN_GIT_SENTINEL\"){std::fs::write(path,\"executed\").unwrap();}}\n").unwrap();
        fs::write(
            upstream.join("Cargo.toml"),
            "[workspace]\nmembers=[\"wrapper\",\"native-sys\"]\nresolver=\"3\"\n",
        )
        .unwrap();
        for args in [
            vec!["init", "-b", "main"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                "harmless fixture",
            ],
        ] {
            let output = Command::new("git")
                .current_dir(&upstream)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let rev = String::from_utf8(
            Command::new("git")
                .current_dir(&upstream)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::create_dir_all(consumer.join("src")).unwrap();
        fs::write(consumer.join("src/lib.rs"), "pub fn consumer() {}\n").unwrap();
        fs::write(consumer.join("Cargo.toml"), format!("[package]\nname=\"consumer\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[dependencies]\nalias={{package=\"wrapper\",git=\"{URL}\",rev=\"{rev}\"}}\n")).unwrap();
        fs::write(
            consumer.join("rust-toolchain.toml"),
            "[toolchain]\nchannel=\"1.95.0\"\n",
        )
        .unwrap();
        fs::write(consumer.join("reviewed-targets.toml"), "[rust]\n").unwrap();
        let fixture = Self {
            root,
            upstream,
            consumer,
            rev,
        };
        let metadata = fixture
            .command("cargo")
            .args(["metadata", "--format-version", "1"])
            .output()
            .unwrap();
        assert!(
            metadata.status.success(),
            "{}",
            String::from_utf8_lossy(&metadata.stderr)
        );
        let packages: serde_json::Value = serde_json::from_slice(&metadata.stdout).unwrap();
        let expected = format!("git+{URL}?rev={}#{}", fixture.rev, fixture.rev);
        for name in ["wrapper", "native-sys"] {
            assert_eq!(
                packages["packages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|package| package["name"] == name)
                    .unwrap()["source"],
                expected
            );
        }
        fixture
    }

    fn complete_reviews(&self) {
        let records = self.consumer.join("docs/dependency-reviews");
        for entry in fs::read_dir(records).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|value| value.to_str()) == Some("md") {
                let text = fs::read_to_string(&path).unwrap();
                fs::write(
                    path,
                    text.lines()
                        .filter(|line| !line.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
                .unwrap();
            }
        }
    }
}

fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn real_cargo_graph_requires_explicit_child_review_before_execution() {
    let fixture = Fixture::new();
    assert_success(fixture.cli(&["pin", "add", "wrapper"]));
    assert!(!fixture.cli(&["pin", "check"]).status.success());
    fixture.complete_reviews();
    assert_success(fixture.cli(&["inventory", "--enforce"]));
    let verify = fixture.cli(&["verify"]);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("native-sys"));
    assert!(!fixture.root.join("executed").exists());
    assert_success(fixture.cli(&["pin", "add", "native-sys"]));
    fixture.complete_reviews();
    let inventory = assert_success(fixture.cli(&["inventory", "--enforce"]));
    assert!(inventory.contains("reviewed Git"));
    let pin_check = assert_success(fixture.cli(&["pin", "check"]));
    assert!(pin_check.contains(&format!(
        "direct spec ok for wrapper: {URL} rev {}",
        fixture.rev
    )));
    assert_success(fixture.cli(&["verify"]));
    assert!(fixture.root.join("executed").exists());
    fs::remove_file(fixture.root.join("executed")).unwrap();
    let manifest = fs::read_to_string(fixture.consumer.join("Cargo.toml"))
        .unwrap()
        .replace(&fixture.rev, &fixture.rev[..8]);
    fs::write(fixture.consumer.join("Cargo.toml"), manifest).unwrap();
    assert!(!fixture.cli(&["verify"]).status.success());
    assert!(!fixture.root.join("executed").exists());
}

#[test]
fn registry_shaped_update_refuses_git_without_mutation_including_dry_run() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.consumer.join("Cargo.lock")).unwrap();
    for args in [
        vec!["update", "wrapper@0.1.0"],
        vec!["update", "--dry-run", "wrapper@0.1.0"],
    ] {
        let output = fixture.cli(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("registry-only"));
        assert_eq!(
            fs::read(fixture.consumer.join("Cargo.lock")).unwrap(),
            original
        );
    }
    assert!(!fixture.root.join("executed").exists());
}

#[test]
fn source_credentials_never_appear_in_policy_errors() {
    let fixture = Fixture::new();
    let policy = "[[rust.families]]\nname=\"bad\"\nreview_record=\"docs/review.md\"\n[rust.families.resolved]\nwrapper={source=\"git\",version=\"0.1.0\",url=\"https://user:SECRET@example.org/repo\",rev=\"broken\", oops\n";
    fs::write(fixture.consumer.join("reviewed-targets.toml"), policy).unwrap();
    let output = fixture.cli(&["pin", "check"]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET"));
    let output = fixture.cli(&["inspect", "https://user:SECRET@example.org/repo"]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET"));
}
