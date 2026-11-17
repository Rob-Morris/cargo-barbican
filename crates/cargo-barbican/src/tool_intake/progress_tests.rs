use super::*;
use std::sync::mpsc::{RecvTimeoutError, Sender};
const TIMEOUT: Duration = Duration::from_secs(10);

struct PausedSink {
    entered: Sender<String>,
    permit: Receiver<()>,
}
impl Write for PausedSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered
            .send(String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(io::Error::other)?;
        self.permit.recv().map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(in crate::tool_intake) struct Blocked {
    entered: Receiver<String>,
    permit: Sender<()>,
}
impl Blocked {
    pub(in crate::tool_intake) fn release_and_expect_exit(self) {
        self.permit.send(()).unwrap();
        assert_eq!(
            self.entered.recv_timeout(TIMEOUT),
            Err(RecvTimeoutError::Disconnected)
        );
    }
}
pub(in crate::tool_intake) fn blocked_progress() -> (Scope, Blocked) {
    let (entered, lines) = mpsc::channel();
    let (permit, ack) = mpsc::channel();
    let scope = Scope::start(
        PausedSink {
            entered,
            permit: ack,
        },
        false,
        Phase::Install,
    );
    let first = lines.recv_timeout(TIMEOUT).unwrap();
    assert!(first.ends_with("Preparing tool install context\n"));
    (
        scope,
        Blocked {
            entered: lines,
            permit,
        },
    )
}
fn snapshot(phase: Phase) -> Snapshot {
    Snapshot {
        phase,
        counts: None,
    }
}
#[test]
fn cadence_counts_and_line_limits_use_only_explicit_monotonic_samples() {
    for terminal in [false, true] {
        let mut lines = Lines {
            last: None,
            emitted: 0,
            terminal,
        };
        let counts = |n| Snapshot {
            phase: Phase::Inspection,
            counts: Some((n, 8)),
        };
        assert_eq!(
            lines.next(counts(0), Duration::ZERO).unwrap(),
            "Tool progress [0s] Recording source inspection results (0/8)\n"
        );
        assert_eq!(lines.next(counts(4), Duration::from_secs(9)), None);
        assert_eq!(
            lines.next(counts(8), CADENCE),
            terminal.then(
                || "Tool progress [10s] Recording source inspection results (8/8)\n".to_string()
            )
        );
        assert!(lines.next(snapshot(Phase::Policy), CADENCE).is_some());
        let mut phase = Phase::Graph;
        while lines.emitted < lines.cap() - 1 {
            assert!(lines.next(snapshot(phase), CADENCE).is_some());
            phase = if phase == Phase::Graph {
                Phase::Source
            } else {
                Phase::Graph
            };
        }
        assert_eq!(
            lines.next(snapshot(phase), CADENCE).unwrap(),
            "Tool progress [10s] Progress line limit reached\n"
        );
        assert_eq!(lines.emitted, if terminal { 256 } else { 32 });
        assert_eq!(lines.next(snapshot(Phase::Native), CADENCE * 2), None);
    }
}
#[test]
fn blocked_sink_coalesces_to_latest_counts_and_stops_without_joining() {
    let (scope, blocked) = blocked_progress();
    let (updated, finished) = mpsc::channel();
    let handle = scope.handle.clone();
    thread::spawn(move || {
        handle.phase(Phase::Source);
        for i in 0..=4096 {
            handle.inspected(i, 4096);
        }
        updated.send(()).unwrap();
    });
    finished.recv_timeout(TIMEOUT).unwrap();
    blocked.permit.send(()).unwrap();
    let line = blocked.entered.recv_timeout(TIMEOUT).unwrap();
    assert!(
        line.ends_with("Recording source inspection results (4096/4096)\n"),
        "{line}"
    );
    scope.handle.phase(Phase::Outputs);
    let (dropped, done) = mpsc::channel();
    thread::spawn(move || {
        drop(scope);
        let _ = dropped.send(());
    });
    done.recv_timeout(TIMEOUT).unwrap();
    blocked.release_and_expect_exit();
}
#[test]
fn stop_after_formatting_discards_unclaimed_line() {
    let (scope, blocked) = blocked_progress();
    let shared = scope.handle.worker.as_ref().unwrap().0.clone();
    let mut lines = Lines {
        last: None,
        emitted: 0,
        terminal: false,
    };
    let pending = lines
        .next(snapshot(Phase::Outputs), Duration::ZERO)
        .unwrap();
    drop(scope);
    let mut output = Vec::new();
    assert!(!write_claimed(&shared, &mut output, &pending));
    assert!(output.is_empty());
    blocked.release_and_expect_exit();
}
#[test]
fn closed_progress_sink_exits_and_later_updates_are_harmless() {
    let (sink, reader) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    let scope = Scope::start(sink, false, Phase::Review);
    let shared = &scope.handle.worker.as_ref().unwrap().0;
    let deadline = Instant::now() + TIMEOUT;
    while !shared.stopped.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "closed sink did not stop");
        thread::yield_now();
    }
    scope.handle.phase(Phase::Graph);
    assert_eq!(shared.latest.lock().unwrap().phase, Phase::Review);
}

#[test]
fn setup_error_yields_disabled_scope() {
    let scope = Scope::from_stderr(
        Err(io::Error::other("fixture descriptor unavailable")),
        Phase::Review,
    );
    scope.handle.phase(Phase::Evaluators);
    assert!(scope.handle.worker.is_none());
}

#[test]
fn stdio_transport_writes_live_while_global_stderr_lock_is_held() {
    use std::io::{BufRead, Read};
    use std::process::{Command, Stdio};
    const CHILD: &str = "BARBICAN_TEST_PROGRESS_STDERR_LOCK";
    if std::env::var_os(CHILD).is_some() {
        let _locked = io::stderr().lock();
        let _scope = Target::Stderr.start(Phase::Review);
        io::stdin().read_exact(&mut [0u8; 1]).unwrap();
        return;
    }
    let mut child=Command::new(std::env::current_exe().unwrap())
        .args(["--exact","tool_intake::progress::tests::stdio_transport_writes_live_while_global_stderr_lock_is_held"])
        .env(CHILD,"1").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        io::BufReader::new(stderr).read_line(&mut line).unwrap();
        let _ = tx.send(line);
    });
    let observed = rx.recv_timeout(TIMEOUT);
    if observed.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let line = observed.expect("progress waited for the global stderr lock");
    assert!(child.try_wait().unwrap().is_none());
    child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        line.starts_with("Tool progress [") && line.ends_with("Preparing tool review context\n"),
        "{line}"
    );
}
