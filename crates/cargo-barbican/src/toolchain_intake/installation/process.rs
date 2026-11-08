use super::files::{Result, error};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);
static HANDLERS_REGISTERED: AtomicBool = AtomicBool::new(false);

pub(crate) struct NativeCancellation {
    flag: Arc<AtomicBool>,
}
impl NativeCancellation {
    pub fn install() -> Result<Self> {
        if HANDLERS_REGISTERED.swap(true, Ordering::SeqCst) {
            return Err("native cancellation supports one CLI operation per process".into());
        }
        let flag = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signal_hook::flag::register(signal, flag.clone()).map_err(error)?;
        }
        // Unregister does not restore default handlers: retain actions through CLI shutdown.
        Ok(Self { flag })
    }
    pub fn flag(&self) -> &AtomicBool {
        &self.flag
    }
}

struct OwnedChild {
    child: Child,
    finished: bool,
}
impl OwnedChild {
    fn stop(&mut self) -> Result<()> {
        let group = format!("-{}", self.child.id());
        let term = signal("-TERM", &group);
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until {
            match self.child.try_wait() {
                Ok(None) => (),
                _ => break,
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let kill = signal("-KILL", &group);
        if kill.is_err() {
            let _ = self.child.kill();
        }
        self.child.wait().map_err(error)?;
        self.finished = true;
        term?;
        kill?;
        let observation = Command::new("/bin/kill")
            .args(["-0", "--", &group])
            .env_clear()
            .env("LC_ALL", "C")
            .output()
            .map_err(error)?;
        if observation.status.success()
            || !String::from_utf8_lossy(&observation.stderr)
                .to_ascii_lowercase()
                .contains("no such process")
        {
            return Err(
                "child reaped; descendant stop is uncertain; no further phase dispatched".into(),
            );
        }
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.stop();
        }
    }
}
fn signal(kind: &str, group: &str) -> Result<()> {
    let output = Command::new("/bin/kill")
        .args([kind, "--", group])
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(error)?;
    if !output.status.success()
        && !String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("no such process")
    {
        return Err("unable to signal owned process group; cancellation uncertain".into());
    }
    Ok(())
}

pub(super) struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) fn run(
    command: &mut Command,
    scratch: &Path,
    cancelled: &AtomicBool,
    timeout: Duration,
) -> Result<ProcessOutput> {
    if cancelled.load(Ordering::SeqCst) {
        return Err("cancelled before native dispatch".into());
    }
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let stdout_path = scratch.join(format!("native-{sequence}.stdout"));
    let stderr_path = scratch.join(format!("native-{sequence}.stderr"));
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stdout_path)
        .map_err(error)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stderr_path)
        .map_err(error)?;
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    let mut owned = OwnedChild {
        child: command.spawn().map_err(error)?,
        finished: false,
    };
    let start = Instant::now();
    let result = loop {
        let reason = if cancelled.load(Ordering::SeqCst) {
            Some("cancelled")
        } else if start.elapsed() >= timeout {
            Some("native operation time limit")
        } else if fs::metadata(&stdout_path).map_err(error)?.len() > OUTPUT_LIMIT
            || fs::metadata(&stderr_path).map_err(error)?.len() > OUTPUT_LIMIT
        {
            Some("native output size limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            let stopped = owned.stop();
            break Err(match stopped {
                Ok(()) => {
                    format!("{reason}; owned child stopped and reaped; installed data retained")
                }
                Err(e) => format!("{reason}; {e}"),
            });
        }
        if let Some(status) = owned.child.try_wait().map_err(error)? {
            owned.finished = true;
            break Ok(ProcessOutput {
                status,
                stdout: read_output(&stdout_path)?,
                stderr: read_output(&stderr_path)?,
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = fs::remove_file(stdout_path);
    let _ = fs::remove_file(stderr_path);
    result
}

fn read_output(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(error)?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err("native output size limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn cancellation_kills_and_reaps_owned_group_before_late_effect() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "barbican-owned-child-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let other = flag.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            other.store(true, Ordering::SeqCst);
        });
        let mut command = Command::new("/bin/sh");
        command.current_dir(&root).args([
            "-c",
            "trap '' TERM; (trap '' TERM; sleep 1; echo late > late-effect) & wait",
        ]);
        let result = run(&mut command, &root, &flag, Duration::from_secs(5));
        worker.join().unwrap();
        assert!(result.is_err());
        let message = result.err().unwrap();
        assert!(message.contains("cancelled"), "{message}");
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            !root.join("late-effect").exists(),
            "abandoned child produced late effect: {message}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_detector_rejects_deliberate_abandonment() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "barbican-abandon-control-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut broken = Command::new("/bin/sh")
            .current_dir(&root)
            .args(["-c", "sleep 0.1; echo late > late-effect"])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            root.join("late-effect").exists(),
            "negative detector must observe abandoned effect"
        );
        broken.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_signal_child() {
        let Some(root) = std::env::var_os("BARBICAN_SIGNAL_FIXTURE") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let cancellation = NativeCancellation::install().unwrap();
        assert!(NativeCancellation::install().is_err());
        let mut command = Command::new("/bin/sh");
        command.current_dir(&root).args(["-c","trap '' TERM; echo ready > worker-ready; (trap '' TERM; sleep 1; echo late > late-effect) & wait"]);
        let message = run(
            &mut command,
            &root,
            cancellation.flag(),
            Duration::from_secs(10),
        )
        .err()
        .expect("real signal must cancel owned operation");
        assert!(message.contains("cancelled"), "{message}");
        assert!(!root.join("late-effect").exists());
        fs::write(root.join("child-stopped"), message).unwrap();
    }

    #[test]
    fn real_sigint_sigterm_and_repeat_signals_do_not_abandon_children() {
        for signal in ["-INT", "-TERM"] {
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "barbican-real-signal-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "toolchain_intake::installation::process::tests::actual_signal_child",
                    "--nocapture",
                ])
                .env("BARBICAN_SIGNAL_FIXTURE", &root)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !root.join("worker-ready").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !root.join("worker-ready").exists() {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "signal fixture did not start: {:?} {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            for _ in 0..2 {
                assert!(
                    Command::new("/bin/kill")
                        .args([signal, &child.id().to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            std::thread::sleep(Duration::from_millis(1100));
            assert!(root.join("child-stopped").is_file());
            assert!(!root.join("late-effect").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }
}
