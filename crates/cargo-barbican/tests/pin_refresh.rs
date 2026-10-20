use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const CHECKSUM: &str = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682";
const OLD_CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-refresh-real-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"),"pub fn checked() -> usize { let mut buffer=itoa::Buffer::new(); buffer.format(42).len() }\n#[test] fn works(){ assert_eq!(checked(),2); }\n").unwrap();
        fs::write(root.join("build.rs"),"fn main(){if let Ok(path)=std::env::var(\"BARBICAN_REFRESH_SENTINEL\"){std::fs::write(path,\"executed\").unwrap();}}").unwrap();
        fs::write(root.join("Cargo.toml"),"[package]\nname='refresh-consumer'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nitoa='=1.0.18'\n").unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel='1.95.0'\n",
        )
        .unwrap();
        fs::write(root.join("review.md"), "# Completed old review\n").unwrap();
        fs::write(root.join("reviewed-targets.toml"),format!("[[rust.families]]\nname='itoa'\nreview_record='review.md'\n[rust.families.direct]\nitoa='=1.0.17'\n[rust.families.resolved]\nitoa={{version='1.0.17',checksum_sha256='{OLD_CHECKSUM}'}}\n")).unwrap();
        let fixture = Self { root };
        let generated = fixture
            .command("cargo")
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert_success(&generated);
        let locked = fs::read_to_string(fixture.root.join("Cargo.lock")).unwrap();
        assert!(locked.contains(CHECKSUM));
        fs::create_dir_all(fixture.root.join("before")).unwrap();
        fs::write(
            fixture.root.join("before/Cargo.toml"),
            fs::read_to_string(fixture.root.join("Cargo.toml"))
                .unwrap()
                .replace("1.0.18", "1.0.17"),
        )
        .unwrap();
        fs::write(
            fixture.root.join("before/Cargo.lock"),
            locked
                .replace("1.0.18", "1.0.17")
                .replace(CHECKSUM, OLD_CHECKSUM),
        )
        .unwrap();
        fixture
    }
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.root)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("BARBICAN_REFRESH_SENTINEL", self.root.join("executed"))
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
    fn before_commit(&self) -> String {
        let manifest = fs::read(self.root.join("Cargo.toml")).unwrap();
        let lock = fs::read(self.root.join("Cargo.lock")).unwrap();
        fs::copy(
            self.root.join("before/Cargo.toml"),
            self.root.join("Cargo.toml"),
        )
        .unwrap();
        fs::copy(
            self.root.join("before/Cargo.lock"),
            self.root.join("Cargo.lock"),
        )
        .unwrap();
        for args in [
            vec!["init", "-b", "main"],
            vec!["add", "Cargo.toml", "Cargo.lock"],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                "pre-move baseline",
            ],
        ] {
            assert_success(&self.command("git").args(args).output().unwrap());
        }
        let output = self
            .command("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert_success(&output);
        fs::write(self.root.join("Cargo.toml"), manifest).unwrap();
        fs::write(self.root.join("Cargo.lock"), lock).unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn release_server() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 2048];
                    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&buffer[..count]);
                    }
                    let body = format!(
                        r#"{{"version":{{"num":"1.0.18","created_at":"2019-01-01T00:00:00Z","checksum":"{CHECKSUM}","yanked":false}}}}"#
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                    return String::from_utf8(request).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "no real release request observed"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    (url, handle)
}

#[test]
fn real_refresh_blocks_cargo_execution_until_explicit_review_completion() {
    let fixture = Fixture::new();
    assert!(!fixture.cli(&["verify"]).status.success());
    assert!(!fixture.root.join("executed").exists());
    let output = fixture.cli(&["pin", "refresh", "itoa"]);
    assert_success(&output);
    let pending = fixture.cli(&["verify"]);
    assert!(!pending.status.success());
    assert!(String::from_utf8_lossy(&pending.stdout).contains("unreviewed scaffold"));
    assert!(!fixture.root.join("executed").exists());
    let record = fs::read_to_string(fixture.root.join("review.md")).unwrap();
    fs::write(
        fixture.root.join("review.md"),
        record
            .lines()
            .filter(|line| !line.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    assert_success(&fixture.cli(&["verify"]));
    assert_eq!(
        fs::read_to_string(fixture.root.join("executed")).unwrap(),
        "executed"
    );
}

#[test]
fn real_repin_uses_directory_and_immutable_git_baselines_without_execution() {
    for git in [false, true] {
        let fixture = Fixture::new();
        let selector = if git {
            fixture.before_commit()
        } else {
            fixture.root.join("before").display().to_string()
        };
        let (url, server) = release_server();
        let output = fixture
            .command(env!("CARGO_BIN_EXE_cargo-barbican"))
            .env(cargo_barbican::CRATES_IO_BASE_URL_ENV, &url)
            .args([
                "gatehouse",
                "re-pin",
                if git { "--base-ref" } else { "--base-dir" },
                &selector,
            ])
            .output()
            .unwrap();
        assert_success(&output);
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /api/v1/crates/itoa/1.0.18 ")
        );
        assert!(!fixture.root.join("executed").exists());
        assert!(!fixture.cli(&["pin", "check"]).status.success());
    }
}
