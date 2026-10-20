use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use barbican::{Date, PinRefreshChange, PinRefreshPlan, ReviewedTargets, compose_refresh_record};

use super::super::lockfile_ops::write_file_atomically;
use super::super::scaffold_fs::{ScaffoldState, confined_scaffold_state};
use super::super::{CommandError, load_effective_cargo_configs, workspace_manifest_paths};
use crate::command_runner::{CommandRunner, cargo_home_from_environment};

pub(super) fn error(detail: impl Into<String>) -> CommandError {
    CommandError::PinRefresh(detail.into())
}

#[derive(Clone)]
struct FileIdentity {
    canonical: PathBuf,
    permissions: fs::Permissions,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}
impl FileIdentity {
    fn at(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(io::Error::other("expected a regular file"));
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Ok(Self {
            canonical: fs::canonicalize(path)?,
            permissions: metadata.permissions(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }
    fn aliases(&self, other: &Self) -> bool {
        #[cfg(unix)]
        if self.device == other.device && self.inode == other.inode {
            return true;
        }
        self.canonical == other.canonical
    }
}

pub(super) struct Input {
    path: PathBuf,
    text: Option<String>,
    identity: Option<FileIdentity>,
}
impl Input {
    fn read(path: PathBuf) -> Result<Self, CommandError> {
        let text = match fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(source) if source.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(error(format!(
                    "unable to read {}: {source}",
                    path.display()
                )));
            }
        };
        let identity = if text.is_some() {
            Some(
                FileIdentity::at(&path)
                    .map_err(|source| error(format!("{}: {source}", path.display())))?,
            )
        } else {
            None
        };
        Ok(Self {
            path,
            text,
            identity,
        })
    }
    fn check(&self) -> Result<(), CommandError> {
        let current = Self::read(self.path.clone())?;
        let same_identity = match (&self.identity, &current.identity) {
            (None, None) => true,
            (Some(previous), Some(current)) => {
                previous.aliases(current) && previous.permissions == current.permissions
            }
            _ => false,
        };
        if current.text != self.text || !same_identity {
            return Err(error(format!(
                "input changed during refresh: {}; inspect the diff before retrying",
                self.path.display()
            )));
        }
        Ok(())
    }
}

pub(super) struct Inputs {
    root: PathBuf,
    manifest_paths: BTreeMap<PathBuf, Vec<PathBuf>>,
    files: BTreeMap<PathBuf, Input>,
    cargo_home: PathBuf,
    configs: Vec<(String, String)>,
}
impl Inputs {
    pub fn capture<R: CommandRunner + ?Sized>(
        root: &Path,
        runner: &R,
    ) -> Result<Self, CommandError> {
        let root = fs::canonicalize(root).map_err(CommandError::Io)?;
        let cargo_home = cargo_home_from_environment(|name| runner.environment_variable(name))
            .ok_or(CommandError::CargoHomeUnresolved)?;
        let mut inputs = Self {
            manifest_paths: BTreeMap::new(),
            root,
            files: BTreeMap::new(),
            cargo_home,
            configs: Vec::new(),
        };
        let root = inputs.root.clone();
        for path in [
            "Cargo.lock",
            "reviewed-targets.toml",
            "barbican.toml",
            "deny.toml",
            "rust-toolchain.toml",
            "rust-toolchain",
            ".cargo/audit.toml",
            ".cargo/config",
            ".cargo/config.toml",
        ] {
            inputs.add_confined(&root, Path::new(path))?;
        }
        inputs.add_manifests(&root)?;
        inputs.configs = inputs.read_configs()?;
        for (path, _) in inputs.configs.clone() {
            let absolute = inputs.root.join(path);
            inputs
                .files
                .insert(absolute.clone(), Input::read(absolute)?);
        }
        Ok(inputs)
    }
    pub fn add_baseline(&mut self, baseline: &Path) -> Result<(), CommandError> {
        let baseline = fs::canonicalize(baseline).map_err(CommandError::Io)?;
        self.add_confined(&baseline, Path::new("Cargo.lock"))?;
        self.add_manifests(&baseline)
    }
    fn add_manifests(&mut self, root: &Path) -> Result<(), CommandError> {
        let paths = workspace_manifest_paths(root)?;
        for path in &paths {
            self.add_confined(root, path)?;
        }
        self.manifest_paths.entry(root.to_owned()).or_insert(paths);
        Ok(())
    }
    fn add_confined(&mut self, root: &Path, relative: &Path) -> Result<(), CommandError> {
        match confined_scaffold_state(root, relative)? {
            ScaffoldState::Missing | ScaffoldState::RegularFile => {}
            _ => {
                return Err(error(format!(
                    "unsafe input path: {}",
                    root.join(relative).display()
                )));
            }
        }
        let path = root.join(relative);
        if !self.files.contains_key(&path) {
            self.files.insert(path.clone(), Input::read(path)?);
        }
        Ok(())
    }
    fn read_configs(&self) -> Result<Vec<(String, String)>, CommandError> {
        Ok(load_effective_cargo_configs(&self.root, &self.cargo_home)?
            .into_iter()
            .map(|config| (config.display_path, config.text))
            .collect())
    }
    pub fn text(&self, root: &Path, relative: &str) -> Result<&str, CommandError> {
        let path = root.join(relative);
        self.files
            .get(&path)
            .and_then(|input| input.text.as_deref())
            .ok_or_else(|| error(format!("required input is missing: {}", path.display())))
    }
    pub fn manifests(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .filter_map(|(path, input)| {
                let relative = path.strip_prefix(&self.root).ok()?;
                (path.file_name()? == "Cargo.toml")
                    .then(|| Some((relative.to_str()?.to_owned(), input.text.clone()?)))?
            })
            .collect()
    }
    pub fn check(&self) -> Result<(), CommandError> {
        for input in self.files.values() {
            for root in self.manifest_paths.keys() {
                if let Ok(relative) = input.path.strip_prefix(root)
                    && !matches!(
                        confined_scaffold_state(root, relative)?,
                        ScaffoldState::Missing | ScaffoldState::RegularFile
                    )
                {
                    return Err(error(format!(
                        "input became unsafe: {}",
                        input.path.display()
                    )));
                }
            }
            input.check()?;
        }
        for (root, paths) in &self.manifest_paths {
            if workspace_manifest_paths(root)? != *paths {
                return Err(error(format!(
                    "workspace manifest inventory changed during refresh: {}; inspect the diff before retrying",
                    root.display()
                )));
            }
        }
        if self.read_configs()? != self.configs {
            return Err(error(
                "effective Cargo configuration changed during refresh",
            ));
        }
        Ok(())
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}

struct Record {
    path: PathBuf,
    original: Input,
    updated: String,
    families: Vec<String>,
}

pub(super) struct Prepared {
    pub inputs: Inputs,
    records: Vec<Record>,
    policy: String,
}
impl Prepared {
    pub fn new(
        inputs: Inputs,
        policy: &ReviewedTargets,
        plan: &PinRefreshPlan,
        date: Date,
    ) -> Result<Self, CommandError> {
        let root = &inputs.root;
        let policy_path = root.join("reviewed-targets.toml");
        if fs::metadata(&policy_path)
            .map_err(CommandError::Io)?
            .permissions()
            .readonly()
        {
            return Err(error("reviewed-targets.toml is read-only"));
        }
        let original = inputs.text(root, "reviewed-targets.toml")?;
        let updated_policy = plan
            .edit_policy(original)
            .map_err(|source| error(source.to_string()))?;
        let mut grouped = BTreeMap::<PathBuf, Vec<&PinRefreshChange>>::new();
        for change in plan.changes() {
            grouped
                .entry(record_path(root, change.record())?)
                .or_default()
                .push(change);
        }
        let mut family_records = BTreeMap::<PathBuf, (Vec<String>, Option<FileIdentity>)>::new();
        for family in policy.rust_families() {
            let path = record_path(root, family.review_record())?;
            let (families, _) = family_records
                .entry(path.clone())
                .or_insert_with(|| (Vec::new(), FileIdentity::at(&path).ok()));
            families.push(family.name().to_owned());
        }
        let mut records: Vec<Record> = Vec::new();
        for (path, changes) in grouped {
            let relative = path.strip_prefix(root).expect("record path confined");
            if !matches!(
                confined_scaffold_state(root, relative)?,
                ScaffoldState::RegularFile
            ) {
                return Err(error(format!(
                    "record must be an existing confined regular file: {}",
                    relative.display()
                )));
            }
            let original = Input::read(path.clone())?;
            let identity = original
                .identity
                .as_ref()
                .expect("regular record has identity");
            for input in inputs.files.values() {
                if input.path == path
                    || input
                        .identity
                        .as_ref()
                        .is_some_and(|other| identity.aliases(other))
                {
                    return Err(error(format!(
                        "record collides with protected input: {}",
                        input.path.display()
                    )));
                }
            }
            if records.iter().any(|record| {
                record
                    .original
                    .identity
                    .as_ref()
                    .is_some_and(|other| identity.aliases(other))
            }) {
                return Err(error("distinct review record paths alias the same file"));
            }
            let text = original.text.as_deref().expect("regular record has text");
            if text.trim().is_empty()
                || fs::metadata(&path)
                    .map_err(CommandError::Io)?
                    .permissions()
                    .readonly()
            {
                return Err(error(format!(
                    "record is empty or read-only: {}",
                    relative.display()
                )));
            }
            let mut families = Vec::new();
            for (other, (names, other_identity)) in &family_records {
                if *other == path {
                    families.extend_from_slice(names);
                } else if other_identity
                    .as_ref()
                    .is_some_and(|other| identity.aliases(other))
                {
                    return Err(error(
                        "different family record paths alias one file; use a single unambiguous record path",
                    ));
                }
            }
            let updated = compose_refresh_record(text, &changes, &families, date);
            records.push(Record {
                path,
                original,
                updated,
                families,
            });
        }
        inputs.check()?;
        Ok(Self {
            inputs,
            records,
            policy: updated_policy,
        })
    }
    pub fn apply(&self) -> Result<(), CommandError> {
        self.apply_with(write_file_atomically)
    }
    fn apply_with(
        &self,
        mut writer: impl FnMut(&Path, &str) -> io::Result<()>,
    ) -> Result<(), CommandError> {
        self.inputs.check()?;
        for record in &self.records {
            record.original.check()?;
            ensure_record_path(&self.inputs.root, &record.path)?;
        }
        let mut persisted = Vec::new();
        for record in &self.records {
            record
                .original
                .check()
                .and_then(|()| ensure_record_path(&self.inputs.root, &record.path))
                .map_err(|source| retained_error(&source.to_string(), &persisted))?;
            if let Err(source) = writer(&record.path, &record.updated) {
                return Err(write_error(&record.path, &persisted, &source));
            }
            persisted.push(record.path.display().to_string());
        }
        self.inputs
            .check()
            .map_err(|source| retained_error(&source.to_string(), &persisted))?;
        for record in &self.records {
            ensure_record_path(&self.inputs.root, &record.path)
                .map_err(|source| retained_error(&source.to_string(), &persisted))?;
            if fs::read_to_string(&record.path)
                .map_err(|source| retained_error(&source.to_string(), &persisted))?
                != record.updated
            {
                return Err(retained_error(
                    &format!("prepared PENDING record changed: {}", record.path.display()),
                    &persisted,
                ));
            }
        }
        let path = self.inputs.root.join("reviewed-targets.toml");
        writer(&path, &self.policy).map_err(|source| write_error(&path, &persisted, &source))
    }
    pub fn reopened(&self) -> impl Iterator<Item = (&Path, &[String])> {
        self.records
            .iter()
            .map(|record| (record.path.as_path(), record.families.as_slice()))
    }
}

fn write_error(path: &Path, persisted: &[String], source: &io::Error) -> CommandError {
    retained_error(
        &format!("write failed at {}: {source}", path.display()),
        persisted,
    )
}

fn retained_error(detail: &str, persisted: &[String]) -> CommandError {
    error(format!(
        "{detail}; PENDING retained at {persisted:?}; policy publication not confirmed. Inspect the diff and cargo barbican pin check before retrying; never remove markers to recover an I/O failure"
    ))
}

fn ensure_record_path(root: &Path, path: &Path) -> Result<(), CommandError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| error("record escaped workspace"))?;
    if !matches!(
        confined_scaffold_state(root, relative)?,
        ScaffoldState::RegularFile
    ) {
        return Err(error(format!(
            "record became unsafe: {}",
            relative.display()
        )));
    }
    Ok(())
}

fn record_path(root: &Path, path: &str) -> Result<PathBuf, CommandError> {
    let mut relative = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name)
                if !name
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(".git")) =>
            {
                relative.push(name);
            }
            Component::CurDir => {}
            _ => {
                return Err(error(
                    "record path escapes the workspace or enters Git administration",
                ));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(error("record path is empty"));
    }
    Ok(root.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::RealCommandRunner;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "barbican-refresh-files-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname='fixture'\nversion='0.1.0'\n",
            )
            .unwrap();
            let old = "a".repeat(64);
            let new = "b".repeat(64);
            let mut policy = String::new();
            let mut lock = String::from("version=4\n");
            for name in ["demo", "aux"] {
                policy.push_str(&format!("[[rust.families]]\nname='{name}'\nreview_record='{name}.md'\n[rust.families.resolved]\n{name}={{version='1.0.0',checksum_sha256='{old}'}}\n"));
                lock.push_str(&format!("[[package]]\nname='{name}'\nversion='1.1.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{new}'\n"));
                fs::write(
                    root.join(format!("{name}.md")),
                    "# Original completed review\n",
                )
                .unwrap();
            }
            fs::write(root.join("reviewed-targets.toml"), policy).unwrap();
            fs::write(root.join("Cargo.lock"), lock).unwrap();
            Self(root)
        }
        fn prepared(&self) -> Prepared {
            let inputs = Inputs::capture(&self.0, &RealCommandRunner).unwrap();
            let context = super::super::Context::load(&inputs).unwrap();
            let plan = context.plan(&["demo".into(), "aux".into()]).unwrap();
            Prepared::new(
                inputs,
                &context.policy,
                &plan,
                barbican::parse_iso_date("2026-10-20").unwrap(),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn partial_record_or_final_policy_failure_retains_pending_but_never_a_subset_of_pins() {
        for failure in [1, 2] {
            let fixture = Fixture::new();
            let prepared = fixture.prepared();
            let policy = fs::read(fixture.0.join("reviewed-targets.toml")).unwrap();
            let mut writes = 0;
            let result = prepared.apply_with(|path, text| {
                let index = writes;
                writes += 1;
                if index == failure {
                    Err(io::Error::other("injected I/O failure"))
                } else {
                    write_file_atomically(path, text)
                }
            });
            assert!(result.unwrap_err().to_string().contains("PENDING retained"));
            assert_eq!(
                fs::read(fixture.0.join("reviewed-targets.toml")).unwrap(),
                policy
            );
            for (index, record) in prepared.records.iter().enumerate() {
                let text = fs::read_to_string(&record.path).unwrap();
                assert_eq!(
                    text.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER),
                    index < failure
                );
            }
            let retry = fixture.prepared();
            retry.apply().unwrap();
            for record in &retry.records {
                assert_eq!(
                    fs::read_to_string(&record.path)
                        .unwrap()
                        .matches(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn missing_or_corrupted_pending_content_prevents_policy_publication() {
        for corrupted in [false, true] {
            let fixture = Fixture::new();
            let prepared = fixture.prepared();
            let policy_path = fixture.0.join("reviewed-targets.toml");
            let original = fs::read(&policy_path).unwrap();
            let mut count = 0;
            let result = prepared.apply_with(|path, text| {
                assert_ne!(path, policy_path);
                count += 1;
                if count == 1 {
                    if corrupted {
                        return write_file_atomically(
                            path,
                            "# Corrupt replacement without PENDING\n",
                        );
                    }
                    return Ok(());
                }
                write_file_atomically(path, text)
            });
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("PENDING record changed")
                    && error.contains("policy publication not confirmed")
            );
            assert_eq!(count, 2);
            assert_eq!(fs::read(&policy_path).unwrap(), original);
            assert!(
                fs::read_to_string(&prepared.records[1].path)
                    .unwrap()
                    .contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
            );
        }
    }

    #[test]
    fn stale_inputs_abort_before_records_or_after_records_without_publishing_policy() {
        for after_record in [false, true] {
            let fixture = Fixture::new();
            let prepared = fixture.prepared();
            let policy = fs::read(fixture.0.join("reviewed-targets.toml")).unwrap();
            if !after_record {
                fs::write(fixture.0.join("Cargo.lock"), "version=4\n").unwrap();
            }
            let mut count = 0;
            let result = prepared.apply_with(|path, text| {
                count += 1;
                write_file_atomically(path, text)?;
                if count == 1 {
                    fs::write(fixture.0.join("Cargo.lock"), "version=4\n")?;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(
                fs::read(fixture.0.join("reviewed-targets.toml")).unwrap(),
                policy
            );
            assert_eq!(count, if after_record { 2 } else { 0 });
        }
    }

    #[test]
    fn new_workspace_manifests_abort_before_policy_publication_in_both_roots() {
        for baseline in [false, true] {
            for after_record in [false, true] {
                let fixture = Fixture::new();
                let mut prepared = fixture.prepared();
                let manifest_root = if baseline {
                    let root = fixture.0.join("baseline");
                    fs::create_dir(&root).unwrap();
                    fs::copy(fixture.0.join("Cargo.toml"), root.join("Cargo.toml")).unwrap();
                    fs::copy(fixture.0.join("Cargo.lock"), root.join("Cargo.lock")).unwrap();
                    prepared.inputs.add_baseline(&root).unwrap();
                    root
                } else {
                    fixture.0.clone()
                };
                let add_manifest = || {
                    let member = manifest_root.join("crates/new-member");
                    fs::create_dir_all(&member).unwrap();
                    fs::write(
                        member.join("Cargo.toml"),
                        "[package]\nname='new-member'\nversion='0.1.0'\n",
                    )
                    .unwrap();
                };
                let policy = fs::read(fixture.0.join("reviewed-targets.toml")).unwrap();
                if !after_record {
                    add_manifest();
                }
                let mut count = 0;
                let result = prepared.apply_with(|path, text| {
                    count += 1;
                    write_file_atomically(path, text)?;
                    if count == 1 {
                        add_manifest();
                    }
                    Ok(())
                });
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("manifest inventory changed")
                );
                assert_eq!(
                    fs::read(fixture.0.join("reviewed-targets.toml")).unwrap(),
                    policy
                );
                assert_eq!(count, if after_record { 2 } else { 0 });
                if after_record {
                    for record in &prepared.records {
                        assert!(
                            fs::read_to_string(&record.path)
                                .unwrap()
                                .contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn git_administration_records_are_refused_for_every_case_variant() {
        for git_dir in [".git", ".GIT", ".Git"] {
            let fixture = Fixture::new();
            fs::create_dir(fixture.0.join(".git")).unwrap();
            let config = fixture.0.join(".git/config");
            let original = "[core]\nrepositoryformatversion = 0\n";
            fs::write(&config, original).unwrap();
            let policy_path = fixture.0.join("reviewed-targets.toml");
            let policy = fs::read_to_string(&policy_path)
                .unwrap()
                .replace("demo.md", &format!("{git_dir}/config"));
            fs::write(&policy_path, &policy).unwrap();
            let inputs = Inputs::capture(&fixture.0, &RealCommandRunner).unwrap();
            let context = super::super::Context::load(&inputs).unwrap();
            let plan = context.plan(&["demo".into()]).unwrap();
            let error = Prepared::new(
                inputs,
                &context.policy,
                &plan,
                barbican::parse_iso_date("2026-10-21").unwrap(),
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("Git administration"));
            assert_eq!(fs::read_to_string(&config).unwrap(), original);
            assert_eq!(fs::read_to_string(&policy_path).unwrap(), policy);
            assert!(
                !fs::read_to_string(fixture.0.join("demo.md"))
                    .unwrap()
                    .contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
            );
        }
    }

    #[test]
    fn changed_record_and_new_input_symlink_are_refused_before_any_output_write() {
        let fixture = Fixture::new();
        let prepared = fixture.prepared();
        fs::write(
            &prepared.records[0].path,
            "# Another writer changed the record",
        )
        .unwrap();
        let mut count = 0;
        assert!(
            prepared
                .apply_with(|_, _| {
                    count += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(count, 0);
        #[cfg(unix)]
        {
            let fixture = Fixture::new();
            let prepared = fixture.prepared();
            fs::rename(fixture.0.join("Cargo.lock"), fixture.0.join("old.lock")).unwrap();
            std::os::unix::fs::symlink(fixture.0.join("old.lock"), fixture.0.join("Cargo.lock"))
                .unwrap();
            let mut count = 0;
            assert!(
                prepared
                    .apply_with(|_, _| {
                        count += 1;
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(count, 0);
        }
    }
}
