use super::*;
use barbican::rust_distribution::{
    ArchiveIdentity, Encoding, Manifest, Profile, SelectionRequest, inspect_archive,
};
use barbican::toolchain_admission::{AuthenticationIdentity, digest_bytes};
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture_evaluator(selected: Option<std::ffi::OsString>) -> Result<PathBuf> {
    let setup = "set BARBICAN_TEST_RUSTUP to the absolute path of the reviewed Rustup 1.29.0 executable; see docs/contributor/process.md";
    let path = PathBuf::from(selected.ok_or_else(|| format!("{setup}; no native tests skipped"))?);
    if !path.is_absolute() {
        return Err(format!(
            "{setup}; selected path is not absolute: {}",
            path.display()
        ));
    }
    let file =
        File::open(&path).map_err(|e| format!("{setup}; cannot read {}: {e}", path.display()))?;
    let (actual, _) = digest_reader(file, 100 * 1024 * 1024).map_err(error)?;
    if actual.as_str() != QUALIFIED_RUSTUP_SHA256 {
        return Err(format!(
            "{setup}; {} has SHA256 {actual}, required {QUALIFIED_RUSTUP_SHA256}",
            path.display()
        ));
    }
    Ok(path)
}

#[test]
fn fixture_evaluator_requires_an_explicit_matching_path() {
    assert!(
        fixture_evaluator(None)
            .unwrap_err()
            .contains("BARBICAN_TEST_RUSTUP")
    );
    assert!(
        fixture_evaluator(Some("rustup".into()))
            .unwrap_err()
            .contains("not absolute")
    );
    let fixture = Fixture::new();
    let selected = fixture.root.join("selected-rustup");
    assert!(
        fixture_evaluator(Some(selected.clone().into_os_string()))
            .unwrap_err()
            .contains("cannot read")
    );
    fs::write(&selected, b"unqualified authored evaluator").unwrap();
    assert!(
        fixture_evaluator(Some(selected.clone().into_os_string()))
            .unwrap_err()
            .contains("required")
    );
    fs::copy(Fixture::evaluator(), &selected).unwrap();
    assert_eq!(
        fixture_evaluator(Some(selected.clone().into_os_string())).unwrap(),
        selected
    );
}

fn isolated(name: &str) -> bool {
    if std::env::var_os("BARBICAN_NATIVE_FIXTURE_CHILD").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("BARBICAN_NATIVE_FIXTURE_CHILD", "1")
        .env_remove("RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS")
        .env_remove("RUSTUP_DIST_SERVER")
        .env_remove("RUSTUP_UPDATE_ROOT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}
struct Fixture {
    root: PathBuf,
    manifest: Vec<u8>,
    selection: Selection,
    inventories: Vec<ArchiveInventory>,
    subject: Subject,
    archives: Vec<(ArchiveIdentity, PathBuf)>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn xz() -> Self {
        let mut fixture = Self::new();
        let originals = fixture.archives.clone();
        let mut text = String::from_utf8(fixture.manifest.clone()).unwrap();
        for (identity, old_path) in originals {
            let bytes: &[u8] = match identity.package.as_str() {
                "rustc" => include_bytes!("fixtures/rustc.tar.xz"),
                "cargo" => include_bytes!("fixtures/cargo.tar.xz"),
                "rust-std" => include_bytes!("fixtures/rust-std.tar.xz"),
                _ => unreachable!(),
            };
            let xz_url = identity.url.replace(".tar.gz", ".tar.xz");
            text = text.replace(
                &format!("url='{}'\nhash='{}'", identity.url, identity.sha256),
                &format!(
                    "url='{}'\nhash='{}'\nxz_url='{xz_url}'\nxz_hash='{}'",
                    identity.url,
                    identity.sha256,
                    digest_bytes(bytes)
                ),
            );
            fs::write(old_path.with_extension("xz"), bytes).unwrap();
        }
        fixture.manifest = text.into_bytes();
        let manifest = Manifest::parse(&fixture.manifest, "1.99.99").unwrap();
        let request = SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Xz,
        };
        fixture.selection = manifest.select(&request).unwrap();
        fixture.archives = fixture
            .selection
            .archives
            .iter()
            .map(|a| {
                (
                    a.clone(),
                    fixture.root.join(a.url.rsplit('/').next().unwrap()),
                )
            })
            .collect();
        fixture.inventories = fixture
            .archives
            .iter()
            .map(|(a, p)| inspect_archive(File::open(p).unwrap(), a).unwrap())
            .collect();
        let mut auth = fixture.subject.record().authentication.clone();
        auth.manifest_sha256 = manifest.sha256();
        fixture.subject =
            Subject::reconstruct(&manifest, &request, auth, fixture.inventories.clone()).unwrap();
        fixture
    }
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "barbican-native-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let host = "aarch64-apple-darwin";
        let release = "1.99.99";
        let mut manifest = format!(
            "manifest-version='2'\ndate='2026-10-15'\n[profiles]\nminimal=['rustc','cargo','rust-std']\ndefault=['rustc','cargo','rust-std']\n[pkg.rust]\nversion='{release} (authored fixture)'\n[pkg.rust.target.{host}]\navailable=true\ncomponents=[{{pkg='rustc',target='{host}'}},{{pkg='cargo',target='{host}'}},{{pkg='rust-std',target='{host}'}}]\n"
        );
        for package in ["rustc", "cargo", "rust-std"] {
            let package_root = format!("{package}-{release}-{host}");
            let component = if package == "rust-std" {
                format!("{package}-{host}")
            } else {
                package.to_owned()
            };
            let (destination,body,mode)=match package {
                "rustc"=>("bin/rustc".to_owned(),format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'rustc {release} (authored fixture)\\n'\n",root.join("candidate-probes").display()).into_bytes(),0o700),
                "cargo"=>("bin/cargo".to_owned(),b"#!/bin/sh\nprintf 'authored cargo fixture\\n'\n".to_vec(),0o755),
                _=>(format!("lib/rustlib/{host}/lib/libstd-fixture.rlib"),b"accepted authored nonexecutable standard library fixture".to_vec(),0o600),
            };
            let mut tar = tar::Builder::new(Vec::new());
            append(&mut tar, &package_root, &[], 0o755, true);
            append(
                &mut tar,
                &format!("{package_root}/{component}"),
                &[],
                0o755,
                true,
            );
            append(
                &mut tar,
                &format!("{package_root}/components"),
                format!("{component}\n").as_bytes(),
                0o644,
                false,
            );
            append(
                &mut tar,
                &format!("{package_root}/rust-installer-version"),
                b"3\n",
                0o644,
                false,
            );
            append(
                &mut tar,
                &format!("{package_root}/{component}/manifest.in"),
                format!("file:{destination}\n").as_bytes(),
                0o644,
                false,
            );
            let mut parent = PathBuf::new();
            let parts: Vec<_> = destination.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                parent.push(part);
                append(
                    &mut tar,
                    &format!("{package_root}/{component}/{}", parent.display()),
                    &[],
                    0o755,
                    true,
                );
            }
            append(
                &mut tar,
                &format!("{package_root}/{component}/{destination}"),
                &body,
                mode,
                false,
            );
            let bytes = gzip(&tar.into_inner().unwrap());
            let filename = format!("{package_root}.tar.gz");
            fs::write(root.join(&filename), &bytes).unwrap();
            manifest.push_str(&format!("[pkg.{package}]\nversion='{release} (authored fixture)'\n[pkg.{package}.target.{host}]\navailable=true\nurl='https://static.rust-lang.org/dist/2026-10-15/{filename}'\nhash='{}'\n",digest_bytes(&bytes)));
        }
        let manifest = manifest.into_bytes();
        let parsed = Manifest::parse(&manifest, release).unwrap();
        let request = SelectionRequest {
            host: host.into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Gzip,
        };
        let selection = parsed.select(&request).unwrap();
        let archives: Vec<_> = selection
            .archives
            .iter()
            .map(|a| (a.clone(), root.join(a.url.rsplit('/').next().unwrap())))
            .collect();
        let inventories: Vec<_> = archives
            .iter()
            .map(|(a, p)| inspect_archive(File::open(p).unwrap(), a).unwrap())
            .collect();
        let auth = AuthenticationIdentity {
            manifest_sha256: parsed.sha256(),
            signature_sha256: digest_bytes(b"authored acceptance fixture"),
            certificate_sha256: digest_bytes(b"authored key fixture"),
            primary_fingerprint: "A".repeat(40),
            signing_fingerprint: "B".repeat(40),
            verification_policy_sha256: digest_bytes(b"fixture policy"),
        };
        let subject = Subject::reconstruct(&parsed, &request, auth, inventories.clone()).unwrap();
        Self {
            root,
            manifest,
            selection,
            inventories,
            subject,
            archives,
        }
    }
    fn inputs(&self) -> SelectedInputs<'_> {
        SelectedInputs {
            subject: &self.subject,
            selection: &self.selection,
            manifest: &self.manifest,
            inventories: &self.inventories,
        }
    }
    fn home(&self) -> PathBuf {
        self.root.join("rustup")
    }
    fn evaluator() -> PathBuf {
        fixture_evaluator(std::env::var_os("BARBICAN_TEST_RUSTUP"))
            .unwrap_or_else(|e| panic!("native fixture evaluator: {e}"))
    }
    fn install(&self) -> Result<InstallOutcome> {
        let mut calls = 0;
        install_selected(
            &self.inputs(),
            &self.archives,
            &self.home(),
            &Self::evaluator(),
            true,
            &AtomicBool::new(false),
            || {
                calls += 1;
                if calls <= 2 && self.root.join("candidate-probes").exists() {
                    return Err("candidate ran before synthetic acceptance/input recheck".into());
                }
                Ok(())
            },
        )
    }
}

#[test]
fn native_xz_selected_mirror_probe_and_mapping() {
    if !isolated(
        "toolchain_intake::installation::tests::native_xz_selected_mirror_probe_and_mapping",
    ) {
        return;
    }
    let fixture = Fixture::xz();
    let installed = fixture.install().expect("qualified XZ handoff");
    assert!(!installed.already_present);
    let probes = fs::read_to_string(fixture.root.join("candidate-probes")).unwrap();
    assert!(probes.contains("--version"));
    assert_eq!(
        fs::read(
            installed
                .correspondence
                .slot
                .join("lib/rustlib/aarch64-apple-darwin/lib/libstd-fixture.rlib")
        )
        .unwrap(),
        b"accepted authored XZ standard library fixture"
    );
    verify_selected(
        &fixture.subject,
        &fixture.selection,
        &fixture.manifest,
        &fixture.inventories,
        &fixture.home(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
}
fn append(
    builder: &mut tar::Builder<Vec<u8>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
    directory: bool,
) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(mode);
    header.set_size(bytes.len() as u64);
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_cksum();
    builder
        .append_data(&mut header, path, Cursor::new(bytes))
        .unwrap();
}
fn gzip(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    out.extend(miniz_oxide::deflate::compress_to_vec(input, 6));
    let mut crc = !0u32;
    for &b in input {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    out.extend((!crc).to_le_bytes());
    out.extend((input.len() as u32).to_le_bytes());
    out
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_accepted_handoff_static_scope_and_activation() {
    if !isolated(
        "toolchain_intake::installation::tests::native_accepted_handoff_static_scope_and_activation",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let installed = fixture.install().unwrap_or_else(|error| {
        panic!(
            "{error}; settings {:?}",
            fs::read_to_string(fixture.home().join("settings.toml"))
        )
    });
    assert!(installed.initial_default_assigned);
    assert!(
        fs::read_to_string(fixture.root.join("candidate-probes"))
            .unwrap()
            .contains("--version")
    );
    let slot = &installed.correspondence.slot;
    assert_eq!(
        fs::metadata(slot.join("bin/rustc")).unwrap().mode() & 0o777,
        0o755
    );
    let probes = fs::read(fixture.root.join("candidate-probes")).unwrap();
    verify_selected(
        &fixture.subject,
        &fixture.selection,
        &fixture.manifest,
        &fixture.inventories,
        &fixture.home(),
    )
    .unwrap();
    assert_eq!(
        fs::read(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
    for relative in [
        "bin/cargo",
        "lib/rustlib/components",
        "lib/rustlib/manifest-rustc-aarch64-apple-darwin",
        "lib/rustlib/multirust-config.toml",
        "lib/rustlib/multirust-channel-manifest.toml",
        "lib/rustlib/rust-installer-version",
    ] {
        let path = slot.join(relative);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(
            verify_selected(
                &fixture.subject,
                &fixture.selection,
                &fixture.manifest,
                &fixture.inventories,
                &fixture.home()
            )
            .is_err(),
            "tamper {relative}"
        );
        fs::write(&path, original).unwrap();
    }
    let cargo = slot.join("bin/cargo");
    let body = fs::read(&cargo).unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        verify_selected(
            &fixture.subject,
            &fixture.selection,
            &fixture.manifest,
            &fixture.inventories,
            &fixture.home()
        )
        .is_err()
    );
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let linked = fixture.root.join("linked-cargo");
    fs::hard_link(&cargo, &linked).unwrap();
    assert!(
        verify_selected(
            &fixture.subject,
            &fixture.selection,
            &fixture.manifest,
            &fixture.inventories,
            &fixture.home()
        )
        .is_err()
    );
    fs::remove_file(linked).unwrap();
    assert_eq!(fs::read(cargo).unwrap(), body);
    let repo = fixture.root.join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(
        repo.join("rust-toolchain.toml"),
        b"# preserve\n[toolchain]\nchannel = '1.95.0' # old\nprofile='minimal'\n",
    )
    .unwrap();
    let activated = activate_selected(
        &fixture.inputs(),
        &fixture.home(),
        &repo,
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap();
    assert!(activated.changed);
    assert!(
        fs::read_to_string(activated.pin)
            .unwrap()
            .contains("channel = \"1.99.99\" # old")
    );
    assert_eq!(
        fs::read(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
    let outside = b"[toolchain]\nchannel='1.95.0' # external\n";
    let conflict = activate_selected(
        &fixture.inputs(),
        &fixture.home(),
        &repo,
        &AtomicBool::new(false),
        |_| {
            fs::write(repo.join("rust-toolchain.toml"), outside).unwrap();
            Ok(())
        },
    );
    assert!(conflict.is_err());
    assert_eq!(fs::read(repo.join("rust-toolchain.toml")).unwrap(), outside);
    fs::write(slot.join("unreviewed-extra"), b"unexpected").unwrap();
    assert!(
        verify_selected(
            &fixture.subject,
            &fixture.selection,
            &fixture.manifest,
            &fixture.inventories,
            &fixture.home()
        )
        .unwrap_err()
        .contains("unexpected installed path")
    );
    assert!(fixture.install().is_err());
    assert_eq!(
        fs::read(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_existing_default_and_unrelated_state_are_preserved() {
    if !isolated(
        "toolchain_intake::installation::tests::native_existing_default_and_unrelated_state_are_preserved",
    ) {
        return;
    }
    let fixture = Fixture::new();
    fs::create_dir(fixture.home()).unwrap();
    let settings=b"version='12'\ndefault_toolchain='1.88.99-aarch64-apple-darwin'\nprofile='complete'\n[overrides]\n'/unrelated'='stable'\n";
    fs::write(fixture.home().join("settings.toml"), settings).unwrap();
    fs::create_dir_all(fixture.home().join("toolchains/unrelated")).unwrap();
    fs::write(
        fixture.home().join("toolchains/unrelated/marker"),
        b"retain unrelated",
    )
    .unwrap();
    let installed = fixture.install().unwrap();
    assert!(!installed.initial_default_assigned);
    assert!(!installed.already_present);
    assert_eq!(
        fs::read(fixture.home().join("settings.toml")).unwrap(),
        settings
    );
    assert_eq!(
        fs::read(fixture.home().join("toolchains/unrelated/marker")).unwrap(),
        b"retain unrelated"
    );
    let probes = fs::read(fixture.root.join("candidate-probes")).unwrap();
    let second = install_selected(
        &fixture.inputs(),
        &fixture.archives,
        &fixture.home(),
        &Fixture::evaluator(),
        false,
        &AtomicBool::new(false),
        || Ok(()),
    )
    .unwrap();
    assert!(second.already_present);
    assert_eq!(
        fs::read(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_preacceptance_corrupt_archive_default_and_path_refusals() {
    if !isolated(
        "toolchain_intake::installation::tests::native_preacceptance_corrupt_archive_default_and_path_refusals",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let err = install_selected(
        &fixture.inputs(),
        &fixture.archives,
        &fixture.home(),
        &Fixture::evaluator(),
        false,
        &AtomicBool::new(false),
        || Ok(()),
    )
    .err()
    .unwrap();
    assert!(err.contains("initial-default"), "{err}");
    assert!(!fixture.root.join("candidate-probes").exists());
    fs::write(&fixture.archives[0].1, b"corrupt").unwrap();
    assert!(
        fixture
            .install()
            .err()
            .unwrap()
            .contains("archive bytes changed")
    );
    assert!(!fixture.root.join("candidate-probes").exists());
    let fixture = Fixture::new();
    fs::create_dir(fixture.home()).unwrap();
    symlink(&fixture.root, fixture.home().join("toolchains")).unwrap();
    assert!(fixture.install().is_err());
    assert!(!fixture.root.join("candidate-probes").exists());
    for format in ["xz", "zst"] {
        let mut fixture = Fixture::new();
        fixture.manifest.extend_from_slice(format!("{format}_url='https://static.rust-lang.org/dist/2026-10-15/rust-std-1.99.99-aarch64-apple-darwin.tar.{format}'\n{format}_hash='{}'\n","0".repeat(64)).as_bytes());
        let manifest = Manifest::parse(&fixture.manifest, "1.99.99").unwrap();
        let request = SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Gzip,
        };
        fixture.selection = manifest.select(&request).unwrap();
        let mut auth = fixture.subject.record().authentication.clone();
        auth.manifest_sha256 = manifest.sha256();
        fixture.subject =
            Subject::reconstruct(&manifest, &request, auth, fixture.inventories.clone()).unwrap();
        let error = fixture
            .install()
            .err()
            .expect("unaccepted preferred encoding must refuse");
        assert!(error.contains("preferred encoding"), "{error}");
        assert!(!fixture.root.join("candidate-probes").exists());
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_owned_initial_default_restoration_and_external_conflict() {
    if !isolated(
        "toolchain_intake::installation::tests::native_owned_initial_default_restoration_and_external_conflict",
    ) {
        return;
    }
    for external in [false, true] {
        let fixture = Fixture::new();
        let mut calls = 0;
        let result = install_selected(
            &fixture.inputs(),
            &fixture.archives,
            &fixture.home(),
            &Fixture::evaluator(),
            true,
            &AtomicBool::new(false),
            || {
                calls += 1;
                if calls == 3 {
                    if external {
                        fs::write(
                            fixture.home().join("settings.toml"),
                            b"version='12'\ndefault_toolchain='external-choice'\n",
                        )
                        .unwrap();
                    }
                    return Err("repository admission changed after native install".into());
                }
                Ok(())
            },
        );
        let message = result.err().expect("post-install policy drift must fail");
        let settings = fs::read(fixture.home().join("settings.toml")).unwrap();
        let default = barbican::rust_distribution::rustup_default(Some(&settings)).unwrap();
        if external {
            assert_eq!(default.as_deref(), Some("external-choice"));
            assert!(message.contains("uncertain/conflicted"), "{message}");
        } else {
            assert!(default.is_none(), "{message}");
            assert!(message.contains("owned initial default unset"), "{message}");
        }
        assert!(
            fixture
                .home()
                .join("toolchains/1.99.99-aarch64-apple-darwin/bin/rustc")
                .is_file()
        );
        assert!(message.contains("installed data retained"));
    }
}

#[test]
#[ignore = "data-only evidence: requires retained authentic archives and explicit existing slot"]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authentic_existing_installation_static_only() {
    let manifest_path = PathBuf::from(
        std::env::var_os("BARBICAN_AUTHENTIC_MANIFEST").expect("explicit original manifest"),
    );
    let archives = PathBuf::from(
        std::env::var_os("BARBICAN_AUTHENTIC_ARCHIVES")
            .expect("explicit retained archive directory"),
    );
    let slot = PathBuf::from(
        std::env::var_os("BARBICAN_AUTHENTIC_SLOT")
            .expect("explicit read-only existing toolchain slot"),
    );
    let bytes = fs::read(manifest_path).unwrap();
    let manifest = Manifest::parse(&bytes, "1.99.1").unwrap();
    let selection = manifest
        .select(&SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile: Profile::Minimal,
            components: vec!["clippy".into(), "rustfmt".into()],
            targets: vec![],
            encoding: Encoding::Xz,
        })
        .unwrap();
    let inventories: Vec<_> = selection
        .archives
        .iter()
        .map(|identity| {
            let path = archives.join(identity.url.rsplit('/').next().unwrap());
            inspect_archive(File::open(path).unwrap(), identity).unwrap()
        })
        .collect();
    let expected = ExpectedInstallation::derive(&selection, &bytes, &inventories).unwrap();
    let count = expected
        .verify(
            &slot,
            super::super::store::effective_owner().unwrap(),
            &AtomicBool::new(false),
        )
        .unwrap();
    println!(
        "authentic static installed correspondence: {count} files; original manifest {}; no candidate execution or adoption",
        manifest.sha256()
    );
}

#[test]
fn activation_refuses_preserved_wider_pin_without_changing_bytes_or_permissions() {
    if !isolated(
        "toolchain_intake::installation::tests::activation_refuses_preserved_wider_pin_without_changing_bytes_or_permissions",
    ) {
        return;
    }
    let mut fixture = Fixture::new();
    let host = "aarch64-apple-darwin";
    let text = String::from_utf8(fixture.manifest.clone())
        .unwrap()
        .replace(
            "[pkg.rustc]",
            &format!("extensions=[{{pkg='clippy-preview',target='{host}'}}]\n[pkg.rustc]"),
        )
        .replace(
            "default=['rustc','cargo','rust-std']",
            "default=['rustc','cargo','rust-std','clippy-preview']",
        );
    fixture.manifest=format!("{text}\n[pkg.clippy-preview]\nversion='1.99.99'\n[pkg.clippy-preview.target.{host}]\navailable=true\nurl='https://static.rust-lang.org/dist/2026-10-15/clippy-1.99.99-{host}.tar.gz'\nhash='{}'\n[renames.clippy]\nto='clippy-preview'\n","0".repeat(64)).into_bytes();
    let manifest = Manifest::parse(&fixture.manifest, "1.99.99").unwrap();
    let request = SelectionRequest {
        host: host.into(),
        profile: Profile::Minimal,
        components: vec![],
        targets: vec![],
        encoding: Encoding::Gzip,
    };
    fixture.selection = manifest.select(&request).unwrap();
    let mut authentication = fixture.subject.record().authentication.clone();
    authentication.manifest_sha256 = manifest.sha256();
    fixture.subject = Subject::reconstruct(
        &manifest,
        &request,
        authentication,
        fixture.inventories.clone(),
    )
    .unwrap();
    fixture.install().unwrap();
    let probes = fs::read(fixture.root.join("candidate-probes")).unwrap();
    let repo = fixture.root.join("repo");
    fs::create_dir(&repo).unwrap();
    let pin = repo.join("rust-toolchain.toml");
    for declaration in [
        "profile='default'",
        "profile='minimal'\ncomponents=['clippy']",
    ] {
        let original = format!("# keep\n[toolchain]\nchannel='1.95.0'\n{declaration}\n");
        fs::write(&pin, &original).unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
        let error = activate_selected(
            &fixture.inputs(),
            &fixture.home(),
            &repo,
            &AtomicBool::new(false),
            |_| Ok(()),
        )
        .err()
        .expect("wider pin must refuse");
        assert!(error.contains("outside the accepted selection"), "{error}");
        assert_eq!(fs::read(&pin).unwrap(), original.as_bytes());
        assert_eq!(fs::metadata(&pin).unwrap().mode() & 0o777, 0o600);
    }
    fs::write(&pin, "[toolchain]\nchannel='1.95.0'\nprofile='minimal'\n").unwrap();
    assert!(
        activate_selected(
            &fixture.inputs(),
            &fixture.home(),
            &repo,
            &AtomicBool::new(false),
            |_| Ok(())
        )
        .unwrap()
        .changed
    );
    assert_eq!(
        fs::read(fixture.root.join("candidate-probes")).unwrap(),
        probes
    );
}

#[test]
fn native_scope_table_keeps_unknown_components_and_cross_targets_closed() {
    let fixture = Fixture::new();
    let mut selection = fixture.selection.clone();
    selection.profile = Profile::Default;
    require_qualified_selection(&selection).unwrap();
    let mut selection = fixture.selection.clone();
    selection.archives[0].package = "unknown-component".into();
    assert!(require_qualified_selection(&selection).is_err());
    let mut selection = fixture.selection.clone();
    selection.archives[0].target = "x86_64-unknown-linux-gnu".into();
    assert!(require_qualified_selection(&selection).is_err());
    assert!(!fixture.home().exists());
    assert!(!fixture.root.join("candidate-probes").exists());
}

#[test]
fn update_hash_unsafe_leaves_refuse_before_delegate_and_preserve_external_files() {
    if !isolated(
        "toolchain_intake::installation::tests::update_hash_unsafe_leaves_refuse_before_delegate_and_preserve_external_files",
    ) {
        return;
    }
    for kind in ["dangling", "hardlink", "directory"] {
        let fixture = Fixture::new();
        fs::create_dir(fixture.home()).unwrap();
        let directory = fixture.home().join("update-hashes");
        fs::create_dir(&directory).unwrap();
        let leaf = directory.join("1.99.99-aarch64-apple-darwin");
        let external = fixture.root.join("outside-home");
        match kind {
            "dangling" => symlink(&external, &leaf).unwrap(),
            "hardlink" => {
                fs::write(&external, b"preserve external").unwrap();
                fs::hard_link(&external, &leaf).unwrap();
            }
            _ => fs::create_dir(&leaf).unwrap(),
        }
        let error = fixture
            .install()
            .err()
            .expect("unsafe update hash must refuse");
        assert!(
            error.contains("unsafe or oversized toolchain file"),
            "{error}"
        );
        assert!(!fixture.root.join("candidate-probes").exists());
        assert!(fs::symlink_metadata(&leaf).is_ok());
        if kind == "hardlink" {
            assert_eq!(fs::read(&external).unwrap(), b"preserve external");
        } else {
            assert!(!external.exists());
        }
    }
}

#[test]
fn raw_native_dangling_update_hash_control_demonstrates_external_fixture_write() {
    if !isolated(
        "toolchain_intake::installation::tests::raw_native_dangling_update_hash_control_demonstrates_external_fixture_write",
    ) {
        return;
    }
    let fixture = Fixture::new();
    assert_eq!(
        digest_reader(File::open(Fixture::evaluator()).unwrap(), 100 * 1024 * 1024)
            .unwrap()
            .0
            .as_str(),
        QUALIFIED_RUSTUP_SHA256
    );
    let mirror = fixture.root.join("mirror");
    fs::create_dir_all(mirror.join("dist/2026-10-15")).unwrap();
    fs::write(
        mirror.join("dist/channel-rust-1.99.99.toml"),
        &fixture.manifest,
    )
    .unwrap();
    fs::write(
        mirror.join("dist/channel-rust-1.99.99.toml.sha256"),
        format!("{}\n", digest_bytes(&fixture.manifest)),
    )
    .unwrap();
    for (identity, path) in &fixture.archives {
        fs::copy(
            path,
            mirror
                .join("dist/2026-10-15")
                .join(identity.url.rsplit('/').next().unwrap()),
        )
        .unwrap();
    }
    fs::create_dir_all(fixture.home().join("update-hashes")).unwrap();
    fs::write(
        fixture.home().join("settings.toml"),
        b"version='12'\ndefault_toolchain='1.88.99-aarch64-apple-darwin'\n",
    )
    .unwrap();
    let external = fixture.root.join("outside-home");
    symlink(
        &external,
        fixture
            .home()
            .join("update-hashes/1.99.99-aarch64-apple-darwin"),
    )
    .unwrap();
    let mut command = std::process::Command::new(Fixture::evaluator());
    command
        .env_clear()
        .current_dir(&fixture.root)
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.root)
        .env("CARGO_HOME", fixture.root.join("cargo"))
        .env("RUSTUP_HOME", fixture.home())
        .env("RUSTUP_DIST_SERVER", format!("file://{}", mirror.display()))
        .env(
            "RUSTUP_UPDATE_ROOT",
            format!("file://{}/no-update", fixture.root.display()),
        )
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env(
            "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
            fixture.root.join("no-fallback"),
        )
        .args([
            "toolchain",
            "install",
            "1.99.99-aarch64-apple-darwin",
            "--profile",
            "minimal",
            "--no-self-update",
        ]);
    let output = process::run(
        &mut command,
        &fixture.root,
        &AtomicBool::new(false),
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fs::read(&external).unwrap().is_empty(),
        "raw native write must demonstrate the bypass detector"
    );
    assert!(fixture.root.join("candidate-probes").exists());
}

#[test]
fn signals_during_static_install_verification_never_return_success() {
    if !isolated(
        "toolchain_intake::installation::tests::signals_during_static_install_verification_never_return_success",
    ) {
        return;
    }
    let cancellation = NativeCancellation::install().unwrap();
    for signal in ["-INT", "-TERM"] {
        for existing in [false, true] {
            cancellation.flag().store(false, Ordering::SeqCst);
            let fixture = Fixture::new();
            if existing {
                fixture.install().unwrap();
            }
            let before = fs::read(fixture.home().join("settings.toml")).ok();
            VERIFICATION_CHECKPOINT.with(|checkpoint| {
                *checkpoint.borrow_mut() = Some(Box::new(move || {
                    let result = std::process::Command::new("/bin/kill")
                        .args([signal, &std::process::id().to_string()])
                        .status()
                        .unwrap();
                    assert!(result.success());
                }));
            });
            let result = install_selected(
                &fixture.inputs(),
                &fixture.archives,
                &fixture.home(),
                &Fixture::evaluator(),
                true,
                cancellation.flag(),
                || Ok(()),
            );
            assert!(cancellation.flag().load(Ordering::SeqCst));
            let error = result
                .err()
                .expect("signal inside verification must refuse success");
            assert!(
                error.contains("cancelled during installed verification"),
                "{error}"
            );
            assert!(error.contains("installed data retained"), "{error}");
            let slot = fixture
                .home()
                .join("toolchains/1.99.99-aarch64-apple-darwin");
            assert!(slot.join("bin/rustc").is_file());
            let after = fs::read(fixture.home().join("settings.toml")).unwrap();
            if existing {
                assert_eq!(Some(after), before);
            } else {
                assert!(error.contains("owned initial default unset"), "{error}");
                assert!(
                    barbican::rust_distribution::rustup_default(Some(&after))
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}

#[test]
#[ignore = "authentic trusted 1.95 machinery proof: explicit reviewed inputs, execution authority and private roots required"]
fn authentic_trusted_baseline_profile_matrix() {
    use serde_json::json;
    use std::time::Instant;
    let cancellation = NativeCancellation::install().unwrap();
    assert_eq!(
        std::env::var("BARBICAN_AUTHENTIC_BASELINE_PROOF").unwrap(),
        "approved-existing-1.95.0-only"
    );
    let root = PathBuf::from(
        std::env::var_os("BARBICAN_AUTHENTIC_PROOF_ROOT").expect("new task-owned proof root"),
    );
    assert!(root.is_absolute() && root.starts_with("/private/tmp/"));
    assert!(!root.exists(), "proof must not overwrite an earlier run");
    let data_path = PathBuf::from(
        std::env::var_os("BARBICAN_AUTHENTIC_DATA").expect("reviewed private data store"),
    );
    let id = barbican::Sha256Digest::try_from(
        std::env::var("BARBICAN_AUTHENTIC_REVIEW_ID").expect("exact review ID"),
    )
    .unwrap();
    let data = super::super::store::PrivateStore::open(&data_path, &[]).unwrap();
    let seed = super::super::trust::bundled_seed().unwrap();
    let started = Instant::now();
    let review = super::super::review::load(
        &data,
        &id,
        &seed,
        barbican::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    assert_eq!(review.subject.record().release, "1.95.0");
    assert_eq!(review.subject.record().host, "aarch64-apple-darwin");
    assert_eq!(
        review
            .subject
            .record()
            .authentication
            .manifest_sha256
            .as_str(),
        "821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9"
    );
    assert_eq!(review.record.evidence.schema_version, 2);
    assert_eq!(review.subject.record().profile, "default");
    assert_eq!(review.selection.archives.len(), 6);
    println!(
        "{}",
        json!({"phase":"authenticate-and-reconstruct", "seconds":started.elapsed().as_secs_f64(), "review_id":id, "authority":"explicit already-trusted 1.95.0 machinery qualification; no new personal acceptance"})
    );
    let captured = data
        .read(
            Path::new(&format!("reviews/{id}.json")),
            barbican::toolchain_admission::MAX_RECORD_BYTES as u64,
        )
        .unwrap();
    let evaluator = Fixture::evaluator();
    let manifest = Manifest::parse(&review.manifest_bytes, "1.95.0").unwrap();
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    for (name, profile, components) in [
        ("minimal", Profile::Minimal, vec![]),
        (
            "minimal-docs",
            Profile::Minimal,
            vec!["rust-docs".to_owned()],
        ),
        (
            "minimal-tools",
            Profile::Minimal,
            vec!["clippy".to_owned(), "rustfmt".to_owned()],
        ),
        ("default", Profile::Default, vec![]),
    ] {
        let request = SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile,
            components,
            targets: vec![],
            encoding: Encoding::Xz,
        };
        let selection = manifest.select(&request).unwrap();
        let inventories: Vec<_> = review
            .inventories
            .iter()
            .filter(|i| selection.archives.contains(&i.identity))
            .cloned()
            .collect();
        let archives: Vec<_> = review
            .archives
            .iter()
            .filter(|(a, _)| selection.archives.contains(a))
            .cloned()
            .collect();
        let subject = Subject::reconstruct(
            &manifest,
            &request,
            review.subject.record().authentication.clone(),
            inventories.clone(),
        )
        .unwrap();
        let inputs = SelectedInputs {
            subject: &subject,
            selection: &selection,
            manifest: &review.manifest_bytes,
            inventories: &inventories,
        };
        let case = root.join(name);
        fs::DirBuilder::new().mode(0o700).create(&case).unwrap();
        let home = case.join("rustup");
        let cancelled = cancellation.flag();
        let started = Instant::now();
        let installed = install_selected(
            &inputs,
            &archives,
            &home,
            &evaluator,
            true,
            cancelled,
            || data.check_capture(&captured),
        )
        .unwrap();
        assert!(!installed.already_present);
        assert!(installed.initial_default_assigned);
        let install_seconds = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let checked = verify_selected_with_cancellation(
            &subject,
            &selection,
            &review.manifest_bytes,
            &inventories,
            &home,
            cancelled,
        )
        .unwrap();
        let inspection_seconds = started.elapsed().as_secs_f64();
        assert_eq!(
            checked.checked_files,
            installed.correspondence.checked_files
        );
        let existing = install_selected(
            &inputs,
            &archives,
            &home,
            &case.join("must-not-dispatch-evaluator"),
            false,
            cancelled,
            || data.check_capture(&captured),
        )
        .unwrap();
        assert!(existing.already_present);
        let repo = case.join("repo");
        fs::create_dir(&repo).unwrap();
        let pin = repo.join("rust-toolchain.toml");
        let before = format!(
            "# preserve authentic proof context\n[toolchain]\nchannel = '1.94.0'\nprofile = '{}'\ncomponents = {}\n",
            subject.record().profile,
            serde_json::to_string(&request.components).unwrap()
        );
        fs::write(&pin, &before).unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o640)).unwrap();
        let activated = activate_selected(&inputs, &home, &repo, cancelled, |actual| {
            data.check_capture(&captured)?;
            if actual.subject_id != subject.id().to_string() {
                return Err("qualified baseline identity changed".into());
            }
            Ok(())
        })
        .unwrap();
        assert!(activated.changed);
        let after = fs::read_to_string(&pin).unwrap();
        assert_eq!(after, before.replace("'1.94.0'", "\"1.95.0\""));
        assert_eq!(fs::metadata(&pin).unwrap().mode() & 0o777, 0o640);
        assert!(
            !activate_selected(&inputs, &home, &repo, cancelled, |_| data
                .check_capture(&captured))
            .unwrap()
            .changed
        );
        if let Some(docs) = inventories
            .iter()
            .find(|i| i.identity.package == "rust-docs")
        {
            let relative = docs
                .payload
                .iter()
                .find(|(_, e)| matches!(e.kind,EntryKind::File {size,..} if size < 4096))
                .unwrap()
                .0;
            let path = checked.slot.join(relative);
            let original = fs::read(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().mode() & 0o777;
            fs::write(&path, b"authored tamper control").unwrap();
            assert!(
                verify_selected_with_cancellation(
                    &subject,
                    &selection,
                    &review.manifest_bytes,
                    &inventories,
                    &home,
                    cancelled
                )
                .is_err()
            );
            check_cancelled(cancelled, "during authentic negative control").unwrap();
            fs::write(&path, &original).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
            assert!(
                verify_selected_with_cancellation(
                    &subject,
                    &selection,
                    &review.manifest_bytes,
                    &inventories,
                    &home,
                    cancelled
                )
                .is_err()
            );
            check_cancelled(cancelled, "during authentic negative control").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let held = case.join("held-doc");
            fs::rename(&path, &held).unwrap();
            assert!(
                verify_selected_with_cancellation(
                    &subject,
                    &selection,
                    &review.manifest_bytes,
                    &inventories,
                    &home,
                    cancelled
                )
                .is_err()
            );
            check_cancelled(cancelled, "during authentic negative control").unwrap();
            fs::create_dir(&path).unwrap();
            assert!(
                verify_selected_with_cancellation(
                    &subject,
                    &selection,
                    &review.manifest_bytes,
                    &inventories,
                    &home,
                    cancelled
                )
                .is_err()
            );
            check_cancelled(cancelled, "during authentic negative control").unwrap();
            fs::remove_dir(&path).unwrap();
            fs::rename(&held, &path).unwrap();
            let extra = checked.slot.join("share/doc/authored-unexpected");
            fs::write(&extra, b"authored extra control").unwrap();
            assert!(
                verify_selected_with_cancellation(
                    &subject,
                    &selection,
                    &review.manifest_bytes,
                    &inventories,
                    &home,
                    cancelled
                )
                .is_err()
            );
            check_cancelled(cancelled, "during authentic negative control").unwrap();
            fs::remove_file(extra).unwrap();
            verify_selected_with_cancellation(
                &subject,
                &selection,
                &review.manifest_bytes,
                &inventories,
                &home,
                cancelled,
            )
            .unwrap();
        }
        check_cancelled(cancelled, "before authentic proof result").unwrap();
        println!(
            "{}",
            json!({"case":name,"status":"PASS","scope":"authentic baseline machinery, not personal/repository admission","subject_id":subject.id(),"checked_files":checked.checked_files,"install_seconds":install_seconds,"inspection_seconds":inspection_seconds,"slot":checked.slot,"initial_default_assigned":installed.initial_default_assigned,"activation":"changed then unchanged; compatibility unchecked"})
        );
    }
}

#[test]
fn native_creation_modes_refuse_before_first_probe_and_preserve_defaults() {
    const MODE: &str = "BARBICAN_NATIVE_CREATION_MODE_CHILD";
    let mode = match std::env::var(MODE) {
        Ok(mode) => mode,
        Err(_) => {
            for mode in ["077", "022"] {
                let output = std::process::Command::new("/bin/sh")
                    .args(["-c", "umask \"$1\"; shift; exec \"$@\"", "native-permission-control", mode])
                    .arg(std::env::current_exe().unwrap())
                    .args(["--exact", "toolchain_intake::installation::tests::native_creation_modes_refuse_before_first_probe_and_preserve_defaults", "--nocapture"])
                    .env(MODE, mode)
                    .env_remove("RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS")
                    .env_remove("RUSTUP_DIST_SERVER")
                    .env_remove("RUSTUP_UPDATE_ROOT")
                    .output().unwrap();
                assert!(
                    output.status.success(),
                    "{mode}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
    };
    for existing_default in [false, true] {
        let fixture = Fixture::new();
        let settings = fixture.home().join("settings.toml");
        let before = if existing_default {
            fs::create_dir(fixture.home()).unwrap();
            let bytes = b"version='12'\ndefault_toolchain='1.95.0-aarch64-apple-darwin'\nprofile='default'\n".to_vec();
            fs::write(&settings, &bytes).unwrap();
            Some(bytes)
        } else {
            None
        };
        let result = if mode == "077" {
            // A missing evaluator proves refusal precedes even evaluator validation/help.
            install_selected(
                &fixture.inputs(),
                &fixture.archives,
                &fixture.home(),
                &fixture.root.join("must-not-open-evaluator"),
                true,
                &AtomicBool::new(false),
                || Ok(()),
            )
        } else {
            fixture.install()
        };
        if mode == "077" {
            let error = result
                .err()
                .expect("restrictive creation modes must refuse before a probe");
            assert!(error.contains("command-local umask 022"), "{error}");
            assert!(error.contains("no native process started"), "{error}");
            assert!(!fixture.root.join("candidate-probes").exists());
            assert!(
                !fixture
                    .home()
                    .join("toolchains/1.99.99-aarch64-apple-darwin")
                    .exists()
            );
            assert_eq!(fs::read(&settings).ok(), before);
        } else {
            result.unwrap();
            assert!(fixture.root.join("candidate-probes").is_file());
        }
    }
}
