use barbican::cargo_tool::{
    COLLECTION_DEADLINE_SECONDS, MAX_CAPTURE_BYTES, MAX_FILE_BYTES, MAX_FILES, MAX_SOURCE_BYTES,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub(crate) const STREAM_LIMIT: u64 = 8 * 1024 * 1024;
pub(crate) const FILE_LIMIT: u64 = MAX_FILE_BYTES;
pub(crate) type Result<T> = std::result::Result<T, String>;

pub(crate) struct Budget {
    pub cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
    captured: AtomicU64,
    materialised: AtomicU64,
    files: AtomicU64,
    entry_limit: u64,
}
impl Budget {
    pub fn new(register_signals: bool) -> Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        if register_signals {
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signal_hook::flag::register(signal, cancelled.clone()).map_err(err)?;
            }
        }
        Ok(Self {
            cancelled,
            deadline: Some(
                Instant::now() + Duration::from_secs(COLLECTION_DEADLINE_SECONDS as u64),
            ),
            captured: AtomicU64::new(0),
            materialised: AtomicU64::new(0),
            files: AtomicU64::new(0),
            entry_limit: MAX_FILES as u64,
        })
    }
    pub fn native(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            deadline: None,
            captured: AtomicU64::new(0),
            materialised: AtomicU64::new(0),
            files: AtomicU64::new(0),
            entry_limit: MAX_FILES as u64,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err("tool operation cancelled".into());
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err("tool evidence collection exceeded its 30-minute deadline".into());
        }
        Ok(())
    }
    fn charge(counter: &AtomicU64, amount: u64, maximum: u64, label: &str) -> Result<()> {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                old.checked_add(amount).filter(|new| *new <= maximum)
            })
            .map_err(|_| format!("tool {label} exceeds operation limit"))?;
        Ok(())
    }
    pub fn materialise(&self, bytes: u64) -> Result<()> {
        self.check()?;
        if bytes > FILE_LIMIT {
            return Err("source file exceeds 128 MiB".into());
        }
        Self::charge(&self.files, 1, self.entry_limit, "source entry count")?;
        Self::charge(&self.materialised, bytes, MAX_SOURCE_BYTES, "source bytes")
    }
    #[cfg(test)]
    pub fn with_entry_limit(limit: u64) -> Result<Self> {
        let mut budget = Self::new(false)?;
        budget.entry_limit = limit;
        Ok(budget)
    }
    #[cfg(test)]
    pub fn expire_for_test(&mut self) {
        self.deadline = Some(Instant::now() - Duration::from_secs(1));
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Executable {
    pub path: PathBuf,
    pub sha256: barbican::Sha256Digest,
    identity: (u64, u64, u32, u64),
}
impl Executable {
    pub fn capture(path: &Path, budget: &Budget) -> Result<Self> {
        if !path.is_absolute() {
            return Err("trusted evaluator must be an absolute executable path".into());
        }
        let path = fs::canonicalize(path).map_err(err)?;
        protected_ancestors(&path)?;
        let metadata = fs::symlink_metadata(&path).map_err(err)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.len() > FILE_LIMIT
        {
            return Err("trusted evaluator must be a bounded protected regular executable".into());
        }
        let bytes = read_bounded(&path, FILE_LIMIT, budget)?;
        Ok(Self {
            path,
            sha256: barbican::cargo_tool::sha256(&bytes),
            identity: identity(&metadata),
        })
    }
    pub fn recheck(&self, budget: &Budget) -> Result<()> {
        protected_ancestors(&self.path)?;
        let metadata = fs::symlink_metadata(&self.path).map_err(err)?;
        if !metadata.is_file()
            || identity(&metadata) != self.identity
            || barbican::cargo_tool::sha256(&read_bounded(&self.path, FILE_LIMIT, budget)?)
                != self.sha256
        {
            return Err("trusted evaluator changed during operation".into());
        }
        Ok(())
    }
}
fn identity(metadata: &fs::Metadata) -> (u64, u64, u32, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len(),
    )
}
fn protected_ancestors(path: &Path) -> Result<()> {
    let uid = crate::private_store::effective_owner()?;
    let mut child: Option<std::fs::Metadata> = None;
    for part in path.ancestors() {
        let metadata = fs::symlink_metadata(part).map_err(err)?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.is_dir()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o1000 != 0
                    && child
                        .as_ref()
                        .is_some_and(|child| child.uid() == uid && child.mode() & 0o022 == 0)))
        {
            return Err(
                "trusted evaluator path has unsupported ownership, links or writable permissions"
                    .into(),
            );
        }
        child = Some(metadata);
    }
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, limit: u64, budget: &Budget) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(err)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("input is not a bounded regular file".into());
    }
    let mut file = File::open(path).map_err(err)?;
    if identity(&file.metadata().map_err(err)?) != identity(&metadata) {
        return Err("input changed while opening".into());
    }
    let mut bytes = Vec::new();
    let mut chunk = [0; 64 * 1024];
    loop {
        budget.check()?;
        let count = file.read(&mut chunk).map_err(err)?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > limit {
            return Err("input exceeded size limit".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if identity(&fs::symlink_metadata(path).map_err(err)?) != identity(&metadata) {
        return Err("input changed while reading".into());
    }
    Ok(bytes)
}

pub(crate) fn absolute_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME unavailable")?;
    if !home.is_absolute() {
        return Err("HOME must be absolute".into());
    }
    Ok(home)
}
pub(crate) fn base_environment(
    home: &Path,
    cargo_home: &Path,
    rustc: &Path,
) -> BTreeMap<OsString, OsString> {
    [
        ("HOME", home.as_os_str().to_owned()),
        ("CARGO_HOME", cargo_home.as_os_str().to_owned()),
        ("RUSTC", rustc.as_os_str().to_owned()),
        ("PATH", OsString::from("/usr/bin:/bin")),
        ("LC_ALL", OsString::from("C")),
        ("CARGO_TERM_COLOR", OsString::from("never")),
        ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
        ("GIT_CONFIG_GLOBAL", OsString::from("/dev/null")),
        ("GIT_TERMINAL_PROMPT", OsString::from("0")),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect()
}
pub(crate) struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
pub(crate) fn run<S: AsRef<OsStr>>(
    executable: &Executable,
    args: &[S],
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    budget: &Budget,
) -> Result<ProcessOutput> {
    executable.recheck(budget)?;
    budget.check()?;
    for ancestor in cwd.ancestors() {
        for name in [".cargo/config", ".cargo/config.toml"] {
            match fs::symlink_metadata(ancestor.join(name)) {
                Ok(_) => {
                    return Err(
                        "controlled child cwd has an unqualified Cargo configuration ancestor"
                            .into(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }
    let mut child = Command::new(&executable.path)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(err)?;
    let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("child stderr unavailable")?;
    let (sender, receiver) = mpsc::sync_channel(4);
    let readers: Vec<_> = [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)]
        .into_iter()
        .enumerate()
        .map(|(stream, mut reader)| {
            let sender = sender.clone();
            std::thread::spawn(move || {
                let mut buffer = [0; 16 * 1024];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            let _ = sender.send((stream, Ok(Vec::new())));
                            break;
                        }
                        Ok(count) => {
                            if sender.send((stream, Ok(buffer[..count].to_vec()))).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send((stream, Err(error.to_string())));
                            break;
                        }
                    }
                }
            })
        })
        .collect();
    drop(sender);
    let mut streams = [Vec::new(), Vec::new()];
    let mut closed = 0;
    let result = (|| {
        while closed < 2 {
            budget.check()?;
            match receiver.recv_timeout(Duration::from_millis(20)) {
                Ok((_, Err(error))) => return Err(error),
                Ok((_, Ok(bytes))) if bytes.is_empty() => closed += 1,
                Ok((stream, Ok(bytes))) => {
                    if streams[stream].len() as u64 + bytes.len() as u64 > STREAM_LIMIT {
                        return Err("subprocess stream exceeds 8 MiB".into());
                    }
                    Budget::charge(
                        &budget.captured,
                        bytes.len() as u64,
                        MAX_CAPTURE_BYTES,
                        "subprocess capture",
                    )?;
                    streams[stream].extend(bytes);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("subprocess capture truncated".into());
                }
            }
        }
        loop {
            budget.check()?;
            if let Some(status) = child.try_wait().map_err(err)? {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &group])
            .env_clear()
            .status();
        let _ = child.kill();
    }
    drop(receiver);
    let waited = child.wait().map_err(err);
    // An escaped accepted-build descendant may retain a pipe after the owned
    // child is reaped; cancellation must still permit CLI shutdown.
    for reader in readers {
        if result.is_ok() || reader.is_finished() {
            reader.join().map_err(|_| "subprocess reader panicked")?;
        }
    }
    let status = result?;
    waited?;
    let [stdout, stderr] = streams;
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}
pub(crate) fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(crate) fn run_git_bounded<S: AsRef<OsStr>>(
    git: &Executable,
    args: &[S],
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
    budget: &Budget,
) -> Result<ProcessOutput> {
    git.recheck(budget)?;
    let shell = Executable::capture(Path::new("/bin/sh"), budget)?;
    let mut bounded: Vec<OsString> = vec![
        "-c".into(),
        "ulimit -f 131072 || exit 125; exec \"$@\"".into(),
        "barbican-bounded-git".into(),
        git.path.as_os_str().to_owned(),
    ];
    bounded.extend(args.iter().map(|arg| arg.as_ref().to_owned()));
    run(&shell, &bounded, cwd, environment, budget)
}
