//! Best-effort stderr diagnostics for one CLI tool review or install.
use std::{
    fs::File,
    io::{self, IsTerminal, Write},
    os::fd::{AsFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) enum Target {
    Disabled,
    Stderr,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Phase {
    Review,
    Install,
    Evaluators,
    Source,
    Cached,
    Refresh,
    Graph,
    Inspection,
    Policy,
    ReviewRecords,
    Preflight,
    Advisory,
    Deny,
    Audit,
    Native,
    Outputs,
    RetainedEffects,
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Review => "Preparing tool review context",
            Self::Install => "Preparing tool install context",
            Self::Evaluators => "Checking trusted evaluators",
            Self::Source => "Collecting verified source inputs",
            Self::Cached => "Restoring cached source inputs",
            Self::Refresh => "Refreshing current install evidence",
            Self::Graph => "Resolving native install graph",
            Self::Inspection => "Recording source inspection results",
            Self::Policy => "Checking source and policy evidence",
            Self::ReviewRecords => "Recording review evidence",
            Self::Preflight => "Checking install authority and destination",
            Self::Advisory => "Refreshing advisory data",
            Self::Deny => "Running cargo-deny",
            Self::Audit => "Running cargo-audit",
            Self::Native => "Native Cargo installation",
            Self::RetainedEffects => "Checking retained installation effects",
            Self::Outputs => "Checking installed outputs and current authority",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) phase: Phase,
    pub(super) counts: Option<(usize, usize)>,
}

struct Shared {
    latest: Mutex<Snapshot>,
    stopped: AtomicBool,
}
#[derive(Default, Clone)]
pub(super) struct Handle {
    worker: Option<(Arc<Shared>, SyncSender<()>)>,
    #[cfg(test)]
    recorded: Option<Arc<Mutex<Vec<Snapshot>>>>,
}

impl Handle {
    #[cfg(test)]
    pub(super) fn recording() -> (Self, Arc<Mutex<Vec<Snapshot>>>) {
        let phases = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                worker: None,
                recorded: Some(phases.clone()),
            },
            phases,
        )
    }
    pub(super) fn phase(&self, phase: Phase) {
        self.update(Snapshot {
            phase,
            counts: None,
        });
    }
    pub(super) fn inspected(&self, completed: usize, total: usize) {
        self.update(Snapshot {
            phase: Phase::Inspection,
            counts: Some((completed, total)),
        });
    }
    fn update(&self, snapshot: Snapshot) {
        #[cfg(test)]
        if let Some(history) = &self.recorded {
            history.lock().unwrap().push(snapshot);
        }
        if let Some((shared, wake)) = &self.worker {
            if shared.stopped.load(Ordering::Acquire) {
                return;
            }
            *shared.latest.lock().unwrap() = snapshot;
            let _ = wake.try_send(());
        }
    }
}
#[derive(Default)]
pub(super) struct Scope {
    pub(super) handle: Handle,
}
impl Target {
    pub(super) fn start(self, phase: Phase) -> Scope {
        if matches!(self, Self::Disabled) {
            return Scope::default();
        }
        Scope::from_stderr(io::stderr().as_fd().try_clone_to_owned(), phase)
    }
}
impl Scope {
    fn from_stderr(duplicate: io::Result<OwnedFd>, phase: Phase) -> Self {
        let Ok(fd) = duplicate else {
            return Self::default();
        };
        let stderr = File::from(fd);
        let terminal = stderr.is_terminal();
        Self::start(stderr, terminal, phase)
    }
    pub(super) fn start(sink: impl Write + Send + 'static, terminal: bool, phase: Phase) -> Self {
        let started = Instant::now();
        let shared = Arc::new(Shared {
            latest: Mutex::new(Snapshot {
                phase,
                counts: None,
            }),
            stopped: AtomicBool::new(false),
        });
        let (wake, rx) = mpsc::sync_channel(1);
        let worker = shared.clone();
        if thread::Builder::new()
            .name("tool-progress".into())
            .spawn(move || {
                render(sink, terminal, started, &worker, rx);
                worker.stopped.store(true, Ordering::Release);
            })
            .is_err()
        {
            return Self::default();
        }
        Self {
            handle: Handle {
                worker: Some((shared, wake)),
                #[cfg(test)]
                recorded: None,
            },
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some((shared, wake)) = &self.handle.worker {
            // Serialise stop with claiming the next snapshot, never with writing it.
            let _claim = shared.latest.lock().unwrap();
            shared.stopped.store(true, Ordering::Release);
            let _ = wake.try_send(());
        }
    }
}
const CADENCE: Duration = Duration::from_secs(10);

struct Lines {
    last: Option<(Phase, Duration)>,
    emitted: usize,
    terminal: bool,
}
impl Lines {
    fn cap(&self) -> usize {
        if self.terminal { 256 } else { 32 }
    }
    fn next(&mut self, snapshot: Snapshot, elapsed: Duration) -> Option<String> {
        if self.emitted >= self.cap()
            || self.last.is_some_and(|(phase, time)| {
                phase == snapshot.phase && (!self.terminal || elapsed - time < CADENCE)
            })
        {
            return None;
        }
        self.last = Some((snapshot.phase, elapsed));
        self.emitted += 1;
        let label = if self.emitted == self.cap() {
            "Progress line limit reached"
        } else {
            snapshot.phase.label()
        };
        let counts = if self.emitted < self.cap() {
            snapshot
                .counts
                .map(|(n, total)| format!(" ({n}/{total})"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Some(format!(
            "Tool progress [{}s] {label}{counts}\n",
            elapsed.as_secs()
        ))
    }
}
fn render(
    mut sink: impl Write,
    terminal: bool,
    started: Instant,
    shared: &Shared,
    rx: Receiver<()>,
) {
    let mut lines = Lines {
        last: None,
        emitted: 0,
        terminal,
    };
    loop {
        let snapshot = {
            let latest = shared.latest.lock().unwrap();
            if shared.stopped.load(Ordering::Acquire) {
                return;
            }
            *latest
        };
        if let Some(line) = lines.next(snapshot, started.elapsed())
            && (!write_claimed(shared, &mut sink, &line) || lines.emitted == lines.cap())
        {
            return;
        }
        if terminal {
            let remaining = CADENCE.saturating_sub(started.elapsed() - lines.last.unwrap().1);
            if rx.recv_timeout(remaining) == Err(mpsc::RecvTimeoutError::Disconnected) {
                return;
            }
        } else if rx.recv().is_err() {
            return;
        }
    }
}

fn write_claimed(shared: &Shared, sink: &mut impl Write, line: &str) -> bool {
    {
        let _claim = shared.latest.lock().unwrap();
        if shared.stopped.load(Ordering::Acquire) {
            return false;
        }
    }
    sink.write_all(line.as_bytes()).is_ok()
}

#[cfg(test)]
#[path = "progress_tests.rs"]
pub(super) mod tests;
