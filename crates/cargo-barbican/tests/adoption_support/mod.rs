use std::cell::Cell;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const TOOLCHAIN: &str = "1.95.0";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Fixture {
    pub root: PathBuf,
    command_sequence: Cell<usize>,
}

impl Fixture {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "barbican-adoption-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self {
            root: root.canonicalize().unwrap(),
            command_sequence: Cell::new(0),
        };
        fixture.write(
            "Cargo.toml",
            "[package]\nname = \"adoption-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        fixture.write("src/lib.rs", "pub fn fixture() {}\n");
        fixture.write(
            "rust-toolchain.toml",
            &format!("[toolchain]\nchannel = \"{TOOLCHAIN}\"\nprofile = \"minimal\"\n"),
        );
        fixture
    }

    pub fn write(&self, path: &str, text: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    pub fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command.current_dir(&self.root);
        for name in [
            "CARGO",
            "CARGO_MANIFEST_DIR",
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTDOC",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTDOC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
        ] {
            command.env_remove(name);
        }
        command.env("CARGO_HOME", self.root.join("cargo-home"));
        command.env("CARGO_TARGET_DIR", self.root.join("target"));
        command.env("CARGO_NET_OFFLINE", "true");
        command.env("CARGO_TERM_COLOR", "never");
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_CONFIG_GLOBAL", "/dev/null");
        command.env("GIT_AUTHOR_NAME", "Barbican fixture");
        command.env("GIT_AUTHOR_EMAIL", "fixture@example.invalid");
        command.env("GIT_COMMITTER_NAME", "Barbican fixture");
        command.env("GIT_COMMITTER_EMAIL", "fixture@example.invalid");
        command.env("GIT_TERMINAL_PROMPT", "0");
        command
    }

    pub fn barbican(&self, args: &[&str]) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_cargo-barbican"));
        command.args(args);
        command
    }

    pub fn run(&self, command: &mut Command) -> Output {
        self.run_with_timeout(command, Duration::from_secs(300))
    }

    pub fn run_with_timeout(&self, command: &mut Command, timeout: Duration) -> Output {
        let number = self.command_sequence.get();
        self.command_sequence.set(number + 1);
        let stdout = self.root.join(format!("command-{number}.stdout"));
        let stderr = self.root.join(format!("command-{number}.stderr"));
        command.stdout(Stdio::from(fs::File::create(&stdout).unwrap()));
        command.stderr(Stdio::from(fs::File::create(&stderr).unwrap()));
        command.process_group(0);
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{command:?}: {error}"));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let group = format!("-{}", child.id());
                let killed = Command::new("/bin/kill")
                    .args(["-KILL", "--", &group])
                    .status()
                    .unwrap();
                assert!(
                    killed.success(),
                    "failed to terminate owned proof process group {group}"
                );
                child.wait().unwrap();
                panic!(
                    "timed out: {command:?}\n{}",
                    fs::read_to_string(&stderr).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    pub fn ok(&self, command: &mut Command) -> Output {
        let output = self.run(command);
        assert!(
            output.status.success(),
            "{command:?}\n{}",
            rendered(&output)
        );
        output
    }

    pub fn init(&self, extra: &[&str]) -> Output {
        let mut command = self.barbican(&["policy", "init"]);
        command.args(extra);
        self.ok(&mut command)
    }

    pub fn path(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
pub fn rendered(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
