use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
#[test]
fn real_dry_run_refuses_fifo_introduced_during_precheck_before_copy_reads_it() {
    use std::os::unix::fs::FileTypeExt as _;
    use std::process::Stdio;
    let f = Fixture::new("", false);
    f.generate();
    let lock = f.work.join("Cargo.lock");
    let action = Box::new(move || {
        fs::remove_file(&lock).unwrap();
        assert!(Command::new("mkfifo").arg(lock).status().unwrap().success());
    });
    let (url, server) = server(release_body(false, false), Some(action));
    let mut child = f
        .command(env!("CARGO_BIN_EXE_cargo-barbican"))
        .env(cargo_barbican::CRATES_IO_BASE_URL_ENV, url)
        .args(["update", "--dry-run", "not-in-this-graph@1.0.0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            server.join().unwrap();
            panic!("dry-run read the unsafe source FIFO instead of refusing it before copying");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(server.join().unwrap().contains("not-in-this-graph/1.0.0"));
    let error = failure(&output);
    assert!(error.contains("regular file"), "{error}");
    assert!(
        fs::symlink_metadata(f.work.join("Cargo.lock"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn real_shallow_clone_reports_unavailable_history_without_substituting_head() {
    let f = Fixture::new("", false);
    f.generate();
    success(&f.git(&["init", "-b", "main"]));
    f.commit();
    fs::write(f.work.join("README.md"), "second commit").unwrap();
    f.commit();
    let clone = f.root.join("shallow");
    success(&f.git(&[
        "clone",
        "--depth",
        "1",
        &format!("file://{}", f.root.display()),
        clone.to_str().unwrap(),
    ]));
    let output = f
        .command(env!("CARGO_BIN_EXE_cargo-barbican"))
        .current_dir(clone)
        .args(["age-lock", "--base-ref", "HEAD~1"])
        .output()
        .unwrap();
    let error = failure(&output);
    assert!(
        error.contains("unable to resolve")
            && error.contains("HEAD~1")
            && error.contains("--base-lockfile"),
        "{error}"
    );
}

const CHECKSUM: &str = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682";

struct Fixture {
    root: PathBuf,
    work: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Fixture {
    fn new(nested: &str, virtual_workspace: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-bootstrap-real-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let work = root.join(nested);
        fs::create_dir_all(&work).unwrap();
        let package = if virtual_workspace {
            work.join("member")
        } else {
            work.clone()
        };
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(package.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        fs::write(package.join("build.rs"), r#"fn main() { if let Ok(path) = std::env::var("BARBICAN_BOOTSTRAP_SENTINEL") { std::fs::write(path, "executed").unwrap(); } }"#).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname='bootstrap-consumer'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        if virtual_workspace {
            fs::write(
                work.join("Cargo.toml"),
                "[workspace]\nmembers=['member']\nresolver='3'\n",
            )
            .unwrap();
        } else {
            let manifest = fs::read_to_string(work.join("Cargo.toml")).unwrap();
            fs::write(work.join("Cargo.toml"), manifest + "[workspace]\n").unwrap();
        }
        Self { root, work }
    }
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("GIT_") {
                command.env_remove(name);
            }
        }
        command
            .current_dir(&self.work)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("BARBICAN_BOOTSTRAP_SENTINEL", self.root.join("executed"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        command
    }
    fn cli(&self, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_cargo-barbican"))
            .args(args)
            .output()
            .unwrap()
    }
    fn generate(&self) {
        success(
            &self
                .command("cargo")
                .args(["generate-lockfile", "--offline"])
                .output()
                .unwrap(),
        );
    }
    fn registry(&self, version: &str) {
        let manifest = fs::read_to_string(self.work.join("Cargo.toml")).unwrap();
        fs::write(
            self.work.join("Cargo.toml"),
            format!("{manifest}[dependencies]\nitoa='={version}'\n"),
        )
        .unwrap();
    }
    fn git(&self, args: &[&str]) -> Output {
        self.command("git")
            .current_dir(&self.root)
            .args(args)
            .output()
            .unwrap()
    }
    fn commit(&self) {
        success(&self.git(&["add", "."]));
        success(&self.git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "fixture baseline",
        ]));
    }
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn failure(output: &Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}
fn release_body(fresh: bool, yanked: bool) -> String {
    let now = barbican::OffsetDateTime::now_utc();
    let date = if fresh {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        )
    } else {
        "2019-01-01T00:00:00Z".to_owned()
    };
    format!(
        r#"{{"version":{{"num":"1.0.18","created_at":"{date}","checksum":"{CHECKSUM}","yanked":{yanked}}}}}"#
    )
}
fn server(
    body: String,
    action: Option<Box<dyn FnOnce() + Send>>,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 2048];
                    while !request.windows(4).any(|x| x == b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&buffer[..count]);
                    }
                    if let Some(action) = action {
                        action();
                    }
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                    return String::from_utf8(request).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "command never made the expected release request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    (url, handle)
}
fn registry_cli(
    f: &Fixture,
    args: &[&str],
    body: String,
    action: Option<Box<dyn FnOnce() + Send>>,
) -> Output {
    let (url, handle) = server(body, action);
    let result = f
        .command(env!("CARGO_BIN_EXE_cargo-barbican"))
        .env(cargo_barbican::CRATES_IO_BASE_URL_ENV, url)
        .args(args)
        .output()
        .unwrap();
    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /api/v1/crates/"), "{request}");
    result
}

#[test]
fn real_first_graph_works_from_package_virtual_root_and_member_without_build_execution() {
    for (virtual_workspace, member) in [(false, false), (true, false), (true, true)] {
        let f = Fixture::new("", virtual_workspace);
        let mut command = f.command(env!("CARGO_BIN_EXE_cargo-barbican"));
        if member {
            command.current_dir(f.work.join("member"));
        }
        let output = command.arg("resolve").output().unwrap();
        success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("Initial resolution"));
        assert!(f.work.join("Cargo.lock").is_file());
        assert!(!f.root.join("executed").exists());
        success(
            &f.command("cargo")
                .args(["build", "--locked", "--offline"])
                .output()
                .unwrap(),
        );
        assert_eq!(
            fs::read_to_string(f.root.join("executed")).unwrap(),
            "executed"
        );
    }
}

#[test]
fn real_cargo_first_registry_graph_obeys_age_yank_and_http_failure_and_restores_absence() {
    for outcome in ["old", "fresh", "yanked", "malformed"] {
        let f = Fixture::new("", false);
        f.registry("1.0.18");
        let body = if outcome == "malformed" {
            "malformed JSON".to_owned()
        } else {
            release_body(outcome == "fresh", outcome == "yanked")
        };
        let output = registry_cli(&f, &["resolve"], body, None);
        if outcome == "old" {
            success(&output);
            assert!(
                fs::read_to_string(f.work.join("Cargo.lock"))
                    .unwrap()
                    .contains(CHECKSUM)
            );
        } else {
            failure(&output);
            assert!(!f.work.join("Cargo.lock").exists());
        }
        assert!(!f.root.join("executed").exists());
    }
}

#[cfg(unix)]
#[test]
fn real_cargo_rejection_restores_existing_bytes_and_original_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = Fixture::new("", false);
    f.registry("1.0.18");
    let original = "# exact original\r\nversion = 4\r\n";
    fs::write(f.work.join("Cargo.lock"), original).unwrap();
    fs::set_permissions(f.work.join("Cargo.lock"), fs::Permissions::from_mode(0o640)).unwrap();
    failure(&registry_cli(
        &f,
        &["resolve"],
        release_body(true, false),
        None,
    ));
    assert_eq!(
        fs::read(f.work.join("Cargo.lock")).unwrap(),
        original.as_bytes()
    );
    assert_eq!(
        fs::metadata(f.work.join("Cargo.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[cfg(unix)]
#[test]
fn real_http_hand_off_detects_external_edits_and_symlink_replacement_without_clobbering() {
    for replace in [false, true] {
        let f = Fixture::new("", false);
        f.registry("1.0.18");
        let path = f.work.join("Cargo.lock");
        let outside = f.root.join("outside");
        fs::write(&outside, "outside original").unwrap();
        let action = Box::new(move || {
            if replace {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(&outside, &path).unwrap();
            } else {
                fs::write(&path, "external lockfile edit").unwrap();
            }
        });
        let error = failure(&registry_cli(
            &f,
            &["resolve"],
            release_body(false, false),
            Some(action),
        ));
        assert!(
            error.contains("left intact") || error.contains("regular file"),
            "{error}"
        );
        if replace {
            assert!(
                fs::symlink_metadata(f.work.join("Cargo.lock"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(
                fs::read_to_string(f.root.join("outside")).unwrap(),
                "outside original"
            );
        } else {
            assert_eq!(
                fs::read_to_string(f.work.join("Cargo.lock")).unwrap(),
                "external lockfile edit"
            );
        }
    }
}

#[test]
fn real_update_restores_pre_metadata_graph_after_package_selection_failure() {
    let f = Fixture::new("", false);
    f.registry("1.0.17");
    f.generate();
    let original = fs::read(f.work.join("Cargo.lock")).unwrap();
    let manifest = fs::read_to_string(f.work.join("Cargo.toml"))
        .unwrap()
        .replace("1.0.17", "1.0.18");
    fs::write(f.work.join("Cargo.toml"), manifest).unwrap();
    let output = registry_cli(
        &f,
        &["update", "not-in-this-graph@1.0.0"],
        release_body(false, false),
        None,
    );
    let error = failure(&output);
    assert!(error.contains("not-in-this-graph"), "{error}");
    assert_eq!(fs::read(f.work.join("Cargo.lock")).unwrap(), original);
    assert!(!f.root.join("executed").exists());
}

#[test]
fn real_nested_git_baselines_use_workspace_objects_for_default_custom_absolute_and_member_paths() {
    for (nested, format) in [("rust space-é", "sha1"), ("rust\nline", "sha256")] {
        let f = Fixture::new(nested, true);
        f.generate();
        fs::create_dir_all(f.work.join("locks")).unwrap();
        fs::copy(f.work.join("Cargo.lock"), f.work.join("locks/custom.lock")).unwrap();
        fs::write(f.root.join("Cargo.lock"), "wrong root lockfile").unwrap();
        fs::write(f.root.join("Cargo.toml"), "wrong root manifest").unwrap();
        success(&f.git(&["init", "-b", "main", &format!("--object-format={format}")]));
        f.commit();
        success(&f.cli(&["age-lock"]));
        success(&f.cli(&["age-lock", "--lockfile", "locks/../locks/custom.lock"]));
        success(&f.cli(&[
            "age-lock",
            "--lockfile",
            f.work.join("Cargo.lock").to_str().unwrap(),
        ]));
        success(&f.cli(&["assess"]));
        let output = f
            .command(env!("CARGO_BIN_EXE_cargo-barbican"))
            .current_dir(f.work.join("member"))
            .arg("age-lock")
            .output()
            .unwrap();
        success(&output);
        fs::create_dir_all(f.work.join("new/src")).unwrap();
        fs::write(f.work.join("new/src/lib.rs"), "").unwrap();
        fs::write(f.work.join("new/Cargo.toml"), "[package]\nname='new-member'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nlocal={path='../member',package='bootstrap-consumer'}\n").unwrap();
        fs::write(
            f.work.join("Cargo.toml"),
            "[workspace]\nmembers=['member','new']\nresolver='3'\n",
        )
        .unwrap();
        let output = f.cli(&["assess"]);
        assert_eq!(output.status.code(), Some(1));
        let out = String::from_utf8_lossy(&output.stdout);
        assert!(
            out.contains("new direct dependencies") && out.contains("new/Cargo.toml"),
            "stdout:{out}\nstderr:{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("unable to read"));
    }
}

#[test]
fn real_unavailable_baselines_fail_actionably_without_guessing_an_empty_history() {
    for git in [false, true] {
        let f = Fixture::new("", false);
        f.generate();
        if git {
            success(&f.git(&["init", "-b", "main"]));
        }
        for command in ["age-lock", "assess", "review"] {
            let error = failure(&f.cli(&[command]));
            assert!(error.contains("unable to resolve Git baseline"), "{error}");
            assert!(
                error.contains(if command == "age-lock" {
                    "--base-lockfile"
                } else {
                    "--base-dir"
                }),
                "{error}"
            );
            if command == "review" {
                assert!(!error.contains("--base-ref"), "{error}");
            }
        }
    }
}

#[test]
fn real_git_missing_blob_and_malformed_blob_stay_distinct_from_resolution_failure() {
    let f = Fixture::new("", false);
    success(&f.git(&["init", "-b", "main"]));
    f.commit();
    f.generate();
    let valid = fs::read(f.work.join("Cargo.lock")).unwrap();
    let missing = failure(&f.cli(&["age-lock"]));
    assert!(
        missing.contains("unable to read") && !missing.contains("unable to resolve"),
        "{missing}"
    );
    fs::write(f.work.join("Cargo.lock"), "malformed historical lock").unwrap();
    f.commit();
    fs::write(f.work.join("Cargo.lock"), valid).unwrap();
    let malformed = failure(&f.cli(&["age-lock"]));
    assert!(
        !malformed.contains("unable to resolve") && !malformed.contains("unable to read"),
        "{malformed}"
    );
    let hostile = failure(&f.cli(&["age-lock", "--base-ref=--not-a-ref"]));
    assert!(
        hostile.contains("--not-a-ref") && hostile.contains("unable to resolve"),
        "{hostile}"
    );
}

#[test]
fn real_filesystem_baselines_keep_absolute_current_paths_inside_the_requested_baseline_without_git()
{
    let f = Fixture::new("rust", false);
    f.generate();
    fs::create_dir(f.work.join("before")).unwrap();
    fs::copy(f.work.join("Cargo.toml"), f.work.join("before/Cargo.toml")).unwrap();
    fs::write(f.work.join("before/Cargo.lock"), "malformed baseline").unwrap();
    for current in [
        Path::new("Cargo.lock").to_owned(),
        f.work.join("Cargo.lock"),
    ] {
        let error = failure(&f.cli(&[
            "assess",
            "--base-dir",
            "before",
            "--lockfile",
            current.to_str().unwrap(),
        ]));
        assert!(
            error.contains("before") && !error.contains("Git baseline"),
            "{error}"
        );
    }
    fs::write(f.root.join("outside.lock"), "version = 4\n").unwrap();
    let error = failure(&f.cli(&[
        "assess",
        "--base-dir",
        "before",
        "--lockfile",
        f.root.join("outside.lock").to_str().unwrap(),
    ]));
    assert!(error.contains("outside the workspace"), "{error}");
    success(&f.cli(&[
        "age-lock",
        "--base-lockfile",
        f.root.join("outside.lock").to_str().unwrap(),
    ]));
    fs::create_dir(f.work.join("review-before")).unwrap();
    fs::copy(
        f.work.join("Cargo.toml"),
        f.work.join("review-before/Cargo.toml"),
    )
    .unwrap();
    success(&f.cli(&["review", "--base-dir", "review-before"]));
}
