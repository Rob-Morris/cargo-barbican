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

pub(crate) fn check_cancelled(cancelled: &AtomicBool, phase: &str) -> Result<()> {
    if cancelled.load(Ordering::SeqCst) {
        Err(format!("cancelled {phase}"))
    } else {
        Ok(())
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

    const LATE_CHILD: &str = r#"
trap '' TERM
(
    trap '' TERM
    echo ready > worker-ready
    remaining=500
    until [ -f release-worker ]; do
        [ "$remaining" -gt 0 ] || exit 1
        remaining=$((remaining - 1))
        sleep 0.02
    done
    echo late > late-effect
) &
wait "$!"
"#;

    fn wait_until(timeout: Duration, ready: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while !ready() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    fn wait_for_marker(path: &Path, timeout: Duration) -> bool {
        wait_until(timeout, || path.is_file())
    }

    fn assert_no_late_effect(root: &Path) {
        fs::write(root.join("release-worker"), []).unwrap();
        assert!(
            !wait_for_marker(&root.join("late-effect"), Duration::from_secs(1)),
            "abandoned child produced a late effect"
        );
    }

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
        let ready_marker = root.join("worker-ready");
        let worker = std::thread::spawn(move || {
            let ready = wait_for_marker(&ready_marker, Duration::from_secs(5));
            other.store(true, Ordering::SeqCst);
            ready
        });
        let mut command = Command::new("/bin/sh");
        command.current_dir(&root).args(["-c", LATE_CHILD]);
        let result = run(&mut command, &root, &flag, Duration::from_secs(5));
        assert!(
            worker.join().unwrap(),
            "descendant did not report readiness"
        );
        assert!(result.is_err());
        let message = result.err().unwrap();
        assert!(message.contains("cancelled"), "{message}");
        assert_no_late_effect(&root);
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
            .args(["-c", LATE_CHILD])
            .spawn()
            .unwrap();
        assert!(wait_for_marker(
            &root.join("worker-ready"),
            Duration::from_secs(5)
        ));
        fs::write(root.join("release-worker"), []).unwrap();
        assert!(broken.wait().unwrap().success());
        assert!(
            root.join("late-effect").exists(),
            "negative detector must observe abandoned effect"
        );
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
        command.current_dir(&root).args(["-c", LATE_CHILD]);
        let message = run(
            &mut command,
            &root,
            cancellation.flag(),
            Duration::from_secs(10),
        )
        .err()
        .expect("real signal must cancel owned operation");
        assert!(message.contains("cancelled"), "{message}");
        cancellation.flag().store(false, Ordering::SeqCst);
        fs::write(root.join("child-stopped"), message).unwrap();
        assert!(
            wait_until(Duration::from_secs(10), || {
                cancellation.flag().load(Ordering::SeqCst)
            }),
            "follow-up signal was not observed"
        );
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
            for marker in ["worker-ready", "child-stopped"] {
                if !wait_for_marker(&root.join(marker), Duration::from_secs(10)) {
                    let _ = child.kill();
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "signal fixture did not report {marker}: {:?} {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
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
            assert_no_late_effect(&root);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
