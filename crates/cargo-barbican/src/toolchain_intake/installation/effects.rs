use super::super::operation::ComponentAddition;
use super::*;
use barbican::rust_distribution::{
    ArchiveIdentity, Encoding, Manifest, check_rustup_default_assignment,
    check_rustup_default_restoration, replace_channel, rustup_configured_components,
    rustup_default,
};
use barbican::toolchain_admission::digest_bytes;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct SelectedInputs<'a> {
    pub subject: &'a Subject,
    pub selection: &'a Selection,
    pub manifest: &'a [u8],
    pub inventories: &'a [ArchiveInventory],
}
impl SelectedInputs<'_> {
    fn verify(&self, home: &Path, cancelled: &AtomicBool) -> Result<InstalledCorrespondence> {
        verify_selected_with_cancellation(
            self.subject,
            self.selection,
            self.manifest,
            self.inventories,
            home,
            cancelled,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum InstallMode {
    Install { allow_initial_default: bool },
    AddComponents,
}

pub(crate) struct InstallOutcome {
    pub correspondence: InstalledCorrespondence,
    pub already_present: bool,
    pub initial_default_assigned: bool,
}
pub(crate) struct ActivationOutcome {
    pub pin: PathBuf,
    pub changed: bool,
}

struct Scratch {
    path: PathBuf,
    identity: Identity,
}
impl Scratch {
    fn new() -> Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir()).map_err(error)?;
        files::ancestors(&base)?;
        let path = base.join(format!(
            "barbican-toolchain-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).map_err(error)?;
        let identity = Identity::of(&fs::symlink_metadata(&path).map_err(error)?);
        Ok(Self { path, identity })
    }
    fn require_native_creation_modes(&self) -> Result<()> {
        let directory = self.path.join("permission-directory");
        DirBuilder::new()
            .mode(0o777)
            .create(&directory)
            .map_err(error)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(self.path.join("permission-file"))
            .map_err(error)?;
        let file_mode = file.metadata().map_err(error)?.mode() & 0o7777;
        let directory_mode = fs::symlink_metadata(&directory).map_err(error)?.mode() & 0o7777;
        if file_mode != 0o644 || directory_mode != 0o755 {
            return Err("native installation requires effective file/directory creation modes 0644/0755; retry this command in a shell with command-local umask 022, for example (umask 022; cargo-barbican toolchain install ...); no native process started".into());
        }
        Ok(())
    }

    fn directory(&self, name: &str) -> Result<PathBuf> {
        let path = self.path.join(name);
        DirBuilder::new().mode(0o700).create(&path).map_err(error)?;
        Ok(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.path.join(name))
            .map_err(error)?;
        file.write_all(bytes).map_err(error)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(error)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .ok()
            .is_some_and(|m| Identity::of(&m) == self.identity)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn file_url(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or("nonUTF8 mirror path")?;
    let mut url = String::from("file://");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            url.push(byte as char);
        } else {
            url.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(url)
}

fn native_command(executable: &Path, home: &Path, scratch: &Scratch) -> Result<Command> {
    let mut command = Command::new(executable);
    command
        .arg0("rustup")
        .env_clear()
        .current_dir(&scratch.path)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", &scratch.path)
        .env("TMPDIR", &scratch.path)
        .env("CARGO_HOME", scratch.path.join("cargo"))
        .env("RUSTUP_HOME", home)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env(
            "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
            scratch.path.join("fallback.toml"),
        )
        .env("RUSTUP_DIST_SERVER", file_url(&scratch.path)?)
        .env(
            "RUSTUP_UPDATE_ROOT",
            file_url(&scratch.path.join("no-update"))?,
        );
    Ok(command)
}

fn evaluator(executable: &Path) -> Result<&'static str> {
    compiled_host()?;
    files::ancestors(executable.parent().ok_or("Rustup path has no parent")?)?;
    let metadata = fs::symlink_metadata(executable).map_err(error)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(
            "Rustup evaluator must be a real protected executable, not a wrapper or link".into(),
        );
    }
    let file = File::open(executable).map_err(error)?;
    if Identity::of(&file.metadata().map_err(error)?) != Identity::of(&metadata) {
        return Err("Rustup evaluator changed".into());
    }
    let (sha, _) = digest_reader(file, 100 * 1024 * 1024).map_err(error)?;
    qualified_rustup_version(sha.as_str()).ok_or_else(|| format!(
        "unqualified native Rustup build; required aarch64-apple-darwin reviewed SHA256 {QUALIFIED_RUSTUP_SHA256} (1.29.0) or {OFFICIAL_RUSTUP_SHA256} (1.29.3); no automatic evaluator fetch or diagnostic fallback"
    ))
}

fn prepare_mirror(
    inputs: &SelectedInputs<'_>,
    archives: &[(ArchiveIdentity, PathBuf)],
    scratch: &Scratch,
) -> Result<()> {
    if digest_bytes(inputs.manifest) != inputs.selection.manifest_sha256 {
        return Err("original manifest changed before handoff".into());
    }
    let manifest =
        Manifest::parse(inputs.manifest, &inputs.selection.release).map_err(|e| e.to_string())?;
    if archives.len() != inputs.selection.archives.len() {
        return Err("incomplete selected archive snapshots".into());
    }
    scratch.directory("dist")?;
    scratch.directory(&format!("dist/{}", inputs.selection.date))?;
    scratch.write(
        &format!("dist/channel-rust-{}.toml", inputs.selection.release),
        inputs.manifest,
    )?;
    scratch.write(
        &format!("dist/channel-rust-{}.toml.sha256", inputs.selection.release),
        format!("{}\n", inputs.selection.manifest_sha256).as_bytes(),
    )?;
    let mut seen = BTreeSet::new();
    for (identity, path) in archives {
        if !inputs.selection.archives.contains(identity)
            || !seen.insert((&identity.package, &identity.target))
        {
            return Err("archive snapshots differ from accepted selection".into());
        }
        let encoding = manifest
            .archive_encodings(&identity.package, &identity.target)
            .ok_or("selected archive format metadata is missing")?;
        if encoding.zstd_advertised
            || (encoding.xz && identity.encoding != Encoding::Xz)
            || (!encoding.xz && identity.encoding != Encoding::Gzip)
        {
            return Err("selected archive is not the qualified Rustup preferred encoding; review the preferred bytes".into());
        }
        let relative = identity
            .url
            .strip_prefix("https://static.rust-lang.org/dist/")
            .ok_or("nonofficial archive URL cannot enter selected-only mirror")?;
        if relative.split('/').count() != 2
            || !relative.starts_with(&format!("{}/", inputs.selection.date))
        {
            return Err("unsupported archive mirror path".into());
        }
        let metadata = fs::symlink_metadata(path).map_err(error)?;
        files::ancestors(path.parent().ok_or("snapshot has no parent")?)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != scratch.identity.uid {
            return Err("archive snapshot is not an independent owned regular file".into());
        }
        let mut source = File::open(path).map_err(error)?;
        if Identity::of(&source.metadata().map_err(error)?) != Identity::of(&metadata) {
            return Err("archive snapshot changed while opening".into());
        }
        let destination = scratch.path.join("dist").join(relative);
        let mut target = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&destination)
            .map_err(error)?;
        std::io::copy(
            &mut (&mut source).take(barbican::rust_distribution::MAX_COMPRESSED_BYTES + 1),
            &mut target,
        )
        .map_err(error)?;
        target
            .set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(error)?;
        let (actual, _) = digest_reader(
            File::open(destination).map_err(error)?,
            barbican::rust_distribution::MAX_COMPRESSED_BYTES,
        )
        .map_err(error)?;
        if actual != identity.sha256 {
            return Err("selected archive bytes changed before native handoff".into());
        }
    }
    Ok(())
}

fn recheck_mirror(inputs: &SelectedInputs<'_>, scratch: &Scratch) -> Result<()> {
    let manifest = fs::read(scratch.path.join(format!(
        "dist/channel-rust-{}.toml",
        inputs.selection.release
    )))
    .map_err(error)?;
    if manifest != inputs.manifest {
        return Err("private original manifest changed before handoff".into());
    }
    for identity in &inputs.selection.archives {
        let relative = identity
            .url
            .strip_prefix("https://static.rust-lang.org/dist/")
            .ok_or("nonofficial archive URL")?;
        let path = scratch.path.join("dist").join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(error)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o400 {
            return Err("private archive snapshot changed".into());
        }
        let (digest, _) = digest_reader(
            File::open(path).map_err(error)?,
            barbican::rust_distribution::MAX_COMPRESSED_BYTES,
        )
        .map_err(error)?;
        if digest != identity.sha256 {
            return Err("private archive snapshot bytes changed before handoff".into());
        }
    }
    Ok(())
}

pub(crate) fn install_selected(
    inputs: &SelectedInputs<'_>,
    archives: &[(ArchiveIdentity, PathBuf)],
    rustup_home: &Path,
    executable: &Path,
    mode: InstallMode,
    cancelled: &AtomicBool,
    mut recheck: impl FnMut(Option<&ComponentAddition>) -> Result<()>,
) -> Result<InstallOutcome> {
    let adding = matches!(mode, InstallMode::AddComponents);
    let allow_initial_default = matches!(
        mode,
        InstallMode::Install {
            allow_initial_default: true
        }
    );
    if cancelled.load(Ordering::SeqCst) {
        return Err("cancelled before installation".into());
    }
    recheck(None)?;
    let expected =
        ExpectedInstallation::derive(inputs.selection, inputs.manifest, inputs.inventories)?;
    let uid = super::super::store::effective_owner()?;
    for name in [
        "RUSTUP_DIST_SERVER",
        "RUSTUP_UPDATE_ROOT",
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
    ] {
        if std::env::var_os(name).is_some() {
            return Err(format!(
                "unsupported ambient native source/settings control {name}"
            ));
        }
    }
    match fs::symlink_metadata("/etc/rustup/settings.toml") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("system fallback Rustup settings require explicit qualification".into()),
    }
    if let Err(e) = fs::symlink_metadata(rustup_home) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(error(e));
        }
        if adding {
            return Err("add-components requires an existing occupied toolchain slot".into());
        }
        if !allow_initial_default {
            return Err("Rustup home/default absent; explicit initial-default intent is required before installation".into());
        }
        files::ancestors(rustup_home.parent().ok_or("Rustup home has no parent")?)?;
        DirBuilder::new()
            .mode(0o700)
            .create(rustup_home)
            .map_err(error)?;
    }
    let home = Directory::capture(rustup_home, uid)?;
    let slot = rustup_home.join("toolchains").join(format!(
        "{}-{}",
        inputs.selection.release, inputs.selection.host
    ));
    match fs::symlink_metadata(&slot) {
        Ok(_) if adding => (),
        Ok(_) => {
            let correspondence = (|| {
                let correspondence = inputs.verify(rustup_home, cancelled)?;
                recheck(None)?;
                check_cancelled(cancelled, "before existing installation success")?;
                Ok(correspondence)
            })().map_err(|reason: String| format!("{reason}; existing installed data retained at {}; default and repository pin unchanged", slot.display()))?;
            return Ok(InstallOutcome {
                correspondence,
                already_present: true,
                initial_default_assigned: false,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && adding => {
            return Err("add-components requires an existing occupied toolchain slot".into());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(error(e)),
    }
    let base = if adding {
        let config = CapturedFile::capture(
            &slot.join("lib/rustlib/multirust-config.toml"),
            uid,
            8 * 1024 * 1024,
        )?;
        let claims = rustup_configured_components(
            inputs.manifest,
            &inputs.selection.host,
            config
                .bytes
                .as_deref()
                .ok_or("add-components requires an existing occupied toolchain slot")?,
        )
        .map_err(|e| e.to_string())?;
        let mut selection = inputs.selection.clone();
        selection
            .archives
            .retain(|a| claims.contains_key(&(a.package.clone(), a.target.clone())));
        if selection.archives.len() != claims.len() {
            return Err(
                "add-components requires an installed subset of the final accepted selection"
                    .into(),
            );
        }
        if selection.archives.len() == inputs.selection.archives.len() {
            let correspondence = inputs.verify(rustup_home, cancelled)?;
            recheck(Some(&ComponentAddition {
                installed_components: claims.keys().cloned().collect(),
                added_components: vec![],
            }))?;
            check_cancelled(cancelled, "before complete additive installation success")?;
            return Ok(InstallOutcome {
                correspondence,
                already_present: true,
                initial_default_assigned: false,
            });
        }
        let inventories: Vec<_> = inputs
            .inventories
            .iter()
            .filter(|i| selection.archives.contains(&i.identity))
            .cloned()
            .collect();
        let base = ExpectedInstallation::derive(&selection, inputs.manifest, &inventories)?;
        base.verify(&slot, uid, cancelled)?;
        let identities = base.preserved_identities(&slot)?;
        config.recheck()?;
        recheck(Some(&ComponentAddition {
            installed_components: selection
                .archives
                .iter()
                .map(|a| (a.package.clone(), a.target.clone()))
                .collect(),
            added_components: inputs
                .selection
                .archives
                .iter()
                .filter(|a| !selection.archives.contains(a))
                .map(|a| (a.package.clone(), a.target.clone()))
                .collect(),
        }))?;
        Some((selection, inventories, identities, claims))
    } else {
        None
    };
    let settings = CapturedFile::capture(&rustup_home.join("settings.toml"), uid, 2 * 1024 * 1024)?;
    let no_default = !adding
        && rustup_default(settings.bytes.as_deref())
            .map_err(|e| e.to_string())?
            .is_none();
    if no_default && !allow_initial_default {
        return Err("Rustup has no effective default; installation would assign this toolchain after its probe; explicit initial-default intent is required".into());
    }
    let mut native_directories = Vec::new();
    for name in ["toolchains", "downloads", "tmp", "update-hashes"] {
        let path = rustup_home.join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new().mode(0o755).create(&path).map_err(error)?
            }
            Err(e) => return Err(error(e)),
            Ok(_) => (),
        }
        native_directories.push(Directory::capture(&path, uid)?);
    }
    let update_hash = CapturedFile::capture(
        &rustup_home.join("update-hashes").join(format!(
            "{}-{}",
            inputs.selection.release, inputs.selection.host
        )),
        uid,
        1024,
    )?;
    let scratch = Scratch::new()?;
    scratch.require_native_creation_modes()?;
    let evaluator_version = evaluator(executable)?;
    scratch.directory("cargo")?;
    scratch.directory("identity-home")?;
    scratch.write("fallback.toml", b"version = '12'\n")?;
    prepare_mirror(inputs, archives, &scratch)?;
    let mut identity = native_command(executable, &scratch.path.join("identity-home"), &scratch)?;
    identity.arg("--help");
    let output = process::run(
        &mut identity,
        &scratch.path,
        cancelled,
        Duration::from_secs(10),
    )?;
    if !output.status.success()
        || !output
            .stdout
            .starts_with(format!("rustup {evaluator_version} ").as_bytes())
    {
        return Err("qualified Rustup isolated help identity failed".into());
    }
    recheck_mirror(inputs, &scratch)?;
    if evaluator(executable)? != evaluator_version {
        return Err("qualified Rustup build changed during operation".into());
    }
    recheck(None)?;
    home.recheck()?;
    settings.recheck()?;
    update_hash.recheck()?;
    for directory in &native_directories {
        directory.recheck()?;
    }
    for identity in &inputs.selection.archives {
        for name in [
            identity.sha256.to_string(),
            format!("{}.partial", identity.sha256),
        ] {
            match fs::symlink_metadata(rustup_home.join("downloads").join(name)) {
                Ok(m) if !m.is_file() || m.nlink() != 1 || m.uid() != uid => {
                    return Err("unsafe native selected archive cache file".into());
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(error(e)),
            }
        }
    }
    if let Some((selection, inventories, identities, _)) = &base {
        let base = ExpectedInstallation::derive(selection, inputs.manifest, inventories)?;
        base.verify(&slot, uid, cancelled)?;
        base.recheck_preserved_identities(&slot, identities)?;
    } else {
        match fs::symlink_metadata(&slot) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => {
                return Err(
                    "target slot appeared or became unreadable before native handoff".into(),
                );
            }
        }
    }
    let mut command = native_command(executable, rustup_home, &scratch)?;
    if let Some((selection, _, _, _)) = &base {
        command.args([
            "component",
            "add",
            "--toolchain",
            &format!("{}-{}", inputs.selection.release, inputs.selection.host),
        ]);
        for archive in &inputs.selection.archives {
            if !selection.archives.contains(archive) {
                command.arg(&archive.package);
            }
        }
    } else {
        command.args([
            "toolchain",
            "install",
            &format!("{}-{}", inputs.selection.release, inputs.selection.host),
            "--profile",
            &inputs.subject.record().profile,
            "--no-self-update",
        ]);
        for component in &inputs.subject.record().requested_components {
            command.args(["--component", component]);
        }
        for target in &inputs.subject.record().requested_targets {
            command.args(["--target", target]);
        }
    }
    let execution = process::run(
        &mut command,
        &scratch.path,
        cancelled,
        Duration::from_secs(1800),
    );
    let native_returned = execution.is_ok();
    let observed_settings =
        CapturedFile::capture(&rustup_home.join("settings.toml"), uid, 2 * 1024 * 1024);
    let assigned = format!("{}-{}", inputs.selection.release, inputs.selection.host);
    let owned_assignment = no_default
        && observed_settings
            .as_ref()
            .ok()
            .and_then(|s| s.bytes.as_deref())
            .is_some_and(|bytes| {
                check_rustup_default_assignment(settings.bytes.as_deref(), bytes, &assigned).is_ok()
            });
    let result = (|| {
        let output = execution?;
        if !output.status.success() {
            return Err(format!(
                "Rustup exited {:?}; native diagnostic: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n')
                    .take(4000)
                    .collect::<String>()
            ));
        }
        if cancelled.load(Ordering::SeqCst) {
            return Err("cancelled after native installation".into());
        }
        home.recheck()?;
        if no_default && !owned_assignment {
            return Err("initial default assignment differs from captured intent".into());
        }
        if !no_default {
            settings.recheck()?;
        }
        recheck(None)?;
        let checked_files = expected.verify(&slot, uid, cancelled)?;
        if let Some((selection, inventories, identities, claims)) = &base {
            ExpectedInstallation::derive(selection, inputs.manifest, inventories)?
                .recheck_preserved_identities(&slot, identities)?;
            update_hash.recheck()?;
            let config = CapturedFile::capture(
                &slot.join("lib/rustlib/multirust-config.toml"),
                uid,
                8 * 1024 * 1024,
            )?;
            let final_claims = rustup_configured_components(
                inputs.manifest,
                &inputs.selection.host,
                config
                    .bytes
                    .as_deref()
                    .ok_or("installed config disappeared")?,
            )
            .map_err(|e| e.to_string())?;
            if claims
                .iter()
                .any(|(component, extension)| final_claims.get(component) != Some(extension))
            {
                return Err("component addition changed existing component metadata".into());
            }
        }
        check_cancelled(cancelled, "before installed verification success")?;
        correspondence(inputs.subject, slot.clone(), checked_files)
    })();
    match result {
        Ok(correspondence) => Ok(InstallOutcome {
            correspondence,
            already_present: false,
            initial_default_assigned: owned_assignment,
        }),
        Err(reason) => {
            let default_state = if owned_assignment && native_returned {
                let captured = observed_settings.map_err(|e| {
                    format!(
                        "{reason}; default ownership uncertain: {e}; installed data retained at {}",
                        slot.display()
                    )
                })?;
                match (|| -> Result<()> {
                    captured.recheck()?;
                    if evaluator(executable)? != evaluator_version {
                        return Err("qualified Rustup build changed before recovery".into());
                    }
                    let mut unset = native_command(executable, rustup_home, &scratch)?;
                    unset.args(["default", "none"]);
                    let recovery = AtomicBool::new(false);
                    let output = process::run(
                        &mut unset,
                        &scratch.path,
                        &recovery,
                        Duration::from_secs(10),
                    )?;
                    if !output.status.success() {
                        return Err("native unset failed".into());
                    }
                    let restored = CapturedFile::capture(
                        &rustup_home.join("settings.toml"),
                        uid,
                        2 * 1024 * 1024,
                    )?;
                    if rustup_default(restored.bytes.as_deref())
                        .map_err(|e| e.to_string())?
                        .is_some()
                    {
                        return Err("default remained set".into());
                    }
                    check_rustup_default_restoration(
                        settings.bytes.as_deref(),
                        restored
                            .bytes
                            .as_deref()
                            .ok_or("restored settings disappeared")?,
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(())
                })() {
                    Ok(()) => "owned initial default unset".to_owned(),
                    Err(e) => format!("initial default restoration uncertain/conflicted: {e}"),
                }
            } else if owned_assignment {
                "initial default retained after interrupted/uncertain native completion; no recovery delegate dispatched".into()
            } else if no_default {
                if matches!(
                    observed_settings
                        .as_ref()
                        .map(|s| rustup_default(s.bytes.as_deref())),
                    Ok(Ok(None))
                ) {
                    "default remains unset".into()
                } else {
                    "initial default ownership unestablished; left untouched".into()
                }
            } else {
                "pre-existing default left untouched; inspect settings if externally changed".into()
            };
            let slot_state = match fs::symlink_metadata(&slot) {
                Ok(_) => format!("installed data retained at {}", slot.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => format!(
                    "selected slot absent; native cache/temp data may remain in {}",
                    rustup_home.display()
                ),
                Err(_) => format!("selected slot state uncertain at {}", slot.display()),
            };
            Err(format!(
                "{reason}; {default_state}; {slot_state}; repository pin unchanged"
            ))
        }
    }
}

pub(crate) fn activate_selected(
    inputs: &SelectedInputs<'_>,
    rustup_home: &Path,
    repo_root: &Path,
    cancelled: &AtomicBool,
    mut recheck: impl FnMut(&InstalledCorrespondence) -> Result<()>,
) -> Result<ActivationOutcome> {
    if cancelled.load(Ordering::SeqCst) {
        return Err("cancelled before activation".into());
    }
    let uid = super::super::store::effective_owner()?;
    let repo = Directory::capture(repo_root, uid)?;
    let pin = repo_root.join("rust-toolchain.toml");
    let old = CapturedFile::capture(&pin, uid, 2 * 1024 * 1024)?;
    if old.bytes.is_some() && fs::symlink_metadata(&pin).map_err(error)?.mode() & 0o200 == 0 {
        return Err("canonical toolchain pin is read-only".into());
    }
    let legacy = CapturedFile::capture(&repo_root.join("rust-toolchain"), uid, 2 * 1024 * 1024)?;
    if legacy.bytes.is_some() {
        return Err("legacy rust-toolchain shadows canonical intent".into());
    }
    let mut proposed = match old.bytes.as_deref() {
        Some(bytes) => replace_channel(
            std::str::from_utf8(bytes).map_err(|_| "toolchain pin is not UTF8")?,
            &inputs.selection.release,
        )
        .map_err(|e| e.to_string())?,
        None => format!(
            "[toolchain]\nchannel = \"{}\"\nprofile = \"{}\"\n",
            inputs.selection.release,
            inputs.subject.record().profile
        ),
    };
    if old.bytes.is_none() {
        for (key, values) in [
            ("components", &inputs.subject.record().requested_components),
            ("targets", &inputs.subject.record().requested_targets),
        ] {
            if !values.is_empty() {
                proposed.push_str(&format!(
                    "{key} = {}\n",
                    serde_json::to_string(values).map_err(|e| e.to_string())?
                ));
            }
        }
    }
    let encoding = inputs
        .selection
        .archives
        .first()
        .ok_or("accepted selection is empty")?
        .encoding;
    let (_, request) = barbican::rust_distribution::parse_repository_selection(
        &proposed,
        &inputs.selection.host,
        encoding,
    )
    .map_err(|e| e.to_string())?;
    let manifest =
        Manifest::parse(inputs.manifest, &inputs.selection.release).map_err(|e| e.to_string())?;
    let proposed_selection = manifest.select(&request).map_err(|e| e.to_string())?;
    if proposed_selection
        .archives
        .iter()
        .any(|archive| !inputs.selection.archives.contains(archive))
    {
        return Err("proposed repository pin requires archives outside the accepted selection; review the complete proposed profile/components/targets before activation".into());
    }
    require_qualified_selection(&proposed_selection)?;
    let actual = inputs.verify(rustup_home, cancelled)?;
    recheck(&actual)?;
    if cancelled.load(Ordering::SeqCst) {
        return Err(
            "cancelled before pin publication; installed data retained; pin unchanged".into(),
        );
    }
    repo.recheck()?;
    legacy.recheck()?;
    old.recheck()?;
    let changed = old.bytes.as_deref() != Some(proposed.as_bytes());
    if changed {
        old.publish(proposed.as_bytes(), cancelled)?;
    }
    Ok(ActivationOutcome { pin, changed })
}
