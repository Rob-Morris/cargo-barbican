use super::super::{process, source};
use super::*;
use std::ffi::OsString;
use std::fs;

// These are authored fixtures, not fetched packages. The helper only records Cargo's
// compiler arguments in the owned stage, then execs the explicitly supplied rustc.
// No installed executable is run. Build/proc-macro bodies below are accepted test
// code; the production evaluator still rejects wrappers before any version probe.
const CAPTURE: &str = r#"
use std::{env, fs, io::Write, os::unix::process::CommandExt, process::Command};
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Ok(package) = env::var("CARGO_PKG_NAME") {
        let path = std::path::PathBuf::from(env::var_os("OWNED_RUSTC_LOG").unwrap())
            .join(format!("{}.args", std::process::id()));
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        let version = env::var("CARGO_PKG_VERSION").unwrap();
        let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
        for value in [&package, &version, &manifest].into_iter().chain(args.iter()) {
            file.write_all(value.as_bytes()).unwrap(); file.write_all(&[0]).unwrap();
        }
    }
    panic!("rustc exec failed: {}", Command::new(&args[0]).args(&args[1..]).exec());
}
"#;

fn write(root: &Path, name: &str, body: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn authored_fixture(root: &Path, resolver: u8) {
    let edition = if resolver == 3 { "2024" } else { "2021" };
    write(
        root,
        "Cargo.toml",
        &format!(
            "[workspace]\nmembers=[\"app\",\"shared\",\"bridge\",\"mac\",\"extra\",\"dev-only\",\"inactive\",\"unselected\",\"unused-optional\"]\nresolver=\"{resolver}\"\n"
        ),
    );
    let package = |name: &str| {
        format!("[package]\nname=\"owned-{name}\"\nversion=\"1.0.0\"\nedition=\"{edition}\"\n")
    };
    write(
        root,
        "app/Cargo.toml",
        &(package("app")
            + r#"
[features]
extra=["dep:owned-extra"]
unused=["dep:owned-unused-optional"]
[dependencies]
owned-shared={path="../shared",features=["target"]}
owned-bridge={path="../bridge"}
owned-mac={path="../mac"}
owned-extra={path="../extra",optional=true}
owned-unused-optional={path="../unused-optional",optional=true}
[build-dependencies]
owned-shared={path="../shared",features=["build"]}
[dev-dependencies]
owned-shared={path="../shared",features=["dev"]}
owned-dev-only={path="../dev-only"}
[target.'cfg(target_os = "none")'.dependencies]
owned-shared={path="../shared",features=["inactive"]}
owned-inactive={path="../inactive"}
[target.'cfg(unix)'.dependencies]
owned-shared={path="../shared",features=["unix"]}
[target.'cfg(any(target_os = "macos", target_os = "linux"))'.dependencies]
owned-shared={path="../shared",features=["native"]}
[[bin]]
name="owned-selected"
path="selected.rs"
required-features=["extra"]
[[bin]]
name="owned-unselected-bin"
path="unselected.rs"
required-features=["unused"]
"#),
    );
    write(
        root,
        "app/selected.rs",
        "fn main() { let _ = owned_shared::value() + owned_bridge::value() + owned_extra::value() + owned_mac::value!(); }\n",
    );
    write(
        root,
        "app/unselected.rs",
        "compile_error!(\"unselected binary must never be compiled\"); fn main() {}\n",
    );
    write(
        root,
        "app/build.rs",
        "fn main() { assert_eq!(owned_shared::value(), 1); std::fs::write(std::env::var_os(\"OWNED_BUILD_SENTINEL\").unwrap(), b\"accepted\").unwrap(); }\n",
    );
    write(
        root,
        "shared/Cargo.toml",
        &(package("shared")
            + "[features]\ntarget=[]\nbridge=[]\nbuild=[]\nmac=[]\ndev=[]\ninactive=[]\nunselected=[]\nunix=[]\nnative=[]\n"),
    );
    write(
        root,
        "bridge/Cargo.toml",
        &(package("bridge")
            + "[dependencies]\nowned-shared={path=\"../shared\",features=[\"bridge\"]}\n"),
    );
    write(
        root,
        "bridge/src/lib.rs",
        "pub fn value() -> u8 { owned_shared::value() }\n",
    );
    write(
        root,
        "mac/Cargo.toml",
        &(package("mac")
            + "[lib]\nproc-macro=true\n[dependencies]\nowned-shared={path=\"../shared\",features=[\"mac\"]}\n"),
    );
    write(
        root,
        "mac/src/lib.rs",
        "extern crate proc_macro; #[proc_macro] pub fn value(_: proc_macro::TokenStream) -> proc_macro::TokenStream { assert_eq!(owned_shared::value(), 1); \"1u8\".parse().unwrap() }\n",
    );
    for name in [
        "shared",
        "extra",
        "dev-only",
        "inactive",
        "unselected",
        "unused-optional",
    ] {
        if name != "shared" {
            let dependencies = if name == "unselected" {
                "[dependencies]\nowned-shared={path=\"../shared\",features=[\"unselected\"]}\n"
            } else if name == "inactive" {
                "[dependencies]\nowned-shared={path=\"../shared\",features=[\"inactive\"]}\n"
            } else {
                ""
            };
            write(
                root,
                &format!("{name}/Cargo.toml"),
                &(package(name) + dependencies),
            );
        }
        write(
            root,
            &format!("{name}/src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Unit {
    package: String,
    context: CompilationContext,
    features: BTreeSet<String>,
}
#[derive(Debug)]
struct Invocation {
    unit: Unit,
    version: String,
    manifest: PathBuf,
    build_script: bool,
    crate_name: String,
    output: PathBuf,
    suffix: String,
    externs: Vec<String>,
}

fn rustc_observations(directory: &Path) -> Vec<Invocation> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            let fields: Vec<&str> = bytes
                .split(|b| *b == 0)
                .filter(|field| !field.is_empty())
                .map(|field| std::str::from_utf8(field).unwrap())
                .collect();
            let value = |flag| {
                fields
                    .windows(2)
                    .find(|pair| pair[0] == flag)
                    .map(|pair| pair[1])
            };
            let crate_name = value("--crate-name").expect("only compiler units are logged");
            let build_script = crate_name == "build_script_build";
            let context = if value("--crate-type") == Some("proc-macro") {
                CompilationContext::HostProcMacro
            } else if value("--target").is_some() {
                CompilationContext::Target
            } else {
                CompilationContext::HostBuild
            };
            Invocation {
                unit: Unit {
                    package: fields[0].into(),
                    context,
                    features: fields
                        .windows(2)
                        .filter(|pair| pair[0] == "--cfg")
                        .filter_map(|pair| {
                            pair[1]
                                .strip_prefix("feature=\"")
                                .and_then(|s| s.strip_suffix('"'))
                        })
                        .map(str::to_owned)
                        .collect(),
                },
                version: fields[1].into(),
                manifest: fields[2].into(),
                build_script,
                crate_name: crate_name.into(),
                output: value("--out-dir").unwrap().into(),
                suffix: fields
                    .iter()
                    .find_map(|arg| arg.strip_prefix("extra-filename="))
                    .unwrap()
                    .into(),
                externs: fields
                    .windows(2)
                    .filter(|pair| pair[0] == "--extern")
                    .map(|pair| pair[1].into())
                    .collect(),
            }
        })
        .collect()
}

fn node_unit(node: &GraphNode) -> Unit {
    Unit {
        package: node.package.name.clone(),
        context: node.context.clone(),
        features: node.features.clone(),
    }
}

type Edge = (Unit, DependencyKind, Unit);
fn observed_edges(invocations: &[Invocation]) -> BTreeSet<Edge> {
    invocations
        .iter()
        .flat_map(|invocation| {
            invocation
                .externs
                .iter()
                .filter(|ext| ext.as_str() != "proc_macro")
                .map(|ext| {
                    let (_, path) = ext
                        .split_once('=')
                        .expect("non-sysroot extern must name an artifact");
                    let path = Path::new(path);
                    let filename = path.file_name().unwrap().to_str().unwrap();
                    let matches: Vec<_> = invocations
                        .iter()
                        .filter(|candidate| {
                            !candidate.build_script
                                && path.parent() == Some(candidate.output.as_path())
                                && filename.starts_with(&format!(
                                    "lib{}{}.",
                                    candidate.crate_name, candidate.suffix
                                ))
                        })
                        .collect();
                    assert_eq!(
                        matches.len(),
                        1,
                        "extern must bind exactly one actual compiler unit: {ext}"
                    );
                    // A package build-script unit supplies build edges for that package.
                    // Resolve its parent by actual non-build unit identity, not tree ancestry.
                    let parent = if invocation.build_script {
                        let parents: Vec<_> = invocations
                            .iter()
                            .filter(|candidate| {
                                !candidate.build_script
                                    && candidate.unit.package == invocation.unit.package
                                    && candidate.unit.features == invocation.unit.features
                            })
                            .collect();
                        assert_eq!(
                            parents.len(),
                            1,
                            "fixture build-script parent is unambiguous"
                        );
                        parents[0].unit.clone()
                    } else {
                        invocation.unit.clone()
                    };
                    (
                        parent,
                        if invocation.build_script {
                            DependencyKind::Build
                        } else {
                            DependencyKind::Normal
                        },
                        matches[0].unit.clone(),
                    )
                })
        })
        .collect()
}

fn qualify(resolver: u8) {
    let stage = source::Stage::new().unwrap();
    let root = stage.root.join("source");
    authored_fixture(&root, resolver);
    let host = process::native_host().expect("required native qualification cannot skip this host");
    let toolchain = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or(process::absolute_home().unwrap().join(".rustup"))
        .join("toolchains")
        .join(format!("1.95.0-{host}"))
        .join("bin");
    let budget = process::Budget::new(false).unwrap();
    let cargo = process::Executable::capture(&toolchain.join("cargo"), &budget).unwrap();
    let rustc = process::Executable::capture(&toolchain.join("rustc"), &budget).unwrap();
    super::super::output_files::require_native_executable(&cargo.path).unwrap();
    super::super::output_files::require_native_executable(&rustc.path).unwrap();
    let home = stage.root.join("home");
    let cargo_home = stage.root.join("cargo-home");
    let target = stage.root.join("target");
    let logs = stage.root.join("rustc-arguments");
    for path in [&home, &cargo_home, &logs] {
        fs::create_dir(path).unwrap();
    }
    let mut environment = process::base_environment(&home, &cargo_home, &rustc.path);
    environment.insert("CARGO_TARGET_DIR".into(), target.as_os_str().into());
    let invoke =
        |executable: &process::Executable, args: &[String], env: &BTreeMap<OsString, OsString>| {
            let output = process::run(executable, args, &stage.root, env, &budget).unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
    for (executable, version, commit) in [
        (&cargo, "cargo", "f2d3ce0bd7f24a49f8f72d9000448f8838c4e850"),
        (&rustc, "rustc", "59807616e1fa2540724bfbac14d7976d7e4a3860"),
    ] {
        let output = invoke(executable, &["-vV".into()], &environment);
        assert!(output.starts_with(&format!("{version} 1.95.0 ")));
        assert!(
            output
                .lines()
                .any(|line| line == format!("commit-hash: {commit}"))
        );
        assert!(output.lines().any(|line| line == format!("host: {host}")));
    }
    let manifest = root.join("app/Cargo.toml").to_str().unwrap().to_owned();
    invoke(
        &cargo,
        &[
            "generate-lockfile".into(),
            "--offline".into(),
            "--manifest-path".into(),
            manifest.clone(),
        ],
        &environment,
    );
    let request = ReviewRequest {
        spec: None,
        git: Some("https://fixture.invalid/owned-graph.git".into()),
        rev: Some("a".repeat(40)),
        package: Some("owned-app".into()),
        bins: vec!["owned-selected".into()],
        features: vec!["extra".into()],
        no_default_features: true,
        all_features: false,
        profile: "dev".into(),
        target: Some(host.clone()),
        from: None,
        cargo: cargo.path.clone(),
        rustc: rustc.path.clone(),
    };
    let common = vec![
        "--manifest-path".into(),
        manifest,
        "--frozen".into(),
        "--offline".into(),
    ];
    let mut args = vec!["metadata".into(), "--format-version=1".into()];
    args.extend(common.clone());
    args.extend(request.feature_args());
    let metadata: Value = serde_json::from_str(&invoke(&cargo, &args, &environment)).unwrap();
    let mut args = vec![
        "tree".into(),
        "--package".into(),
        "owned-app".into(),
        "--target".into(),
        host.clone(),
        "--edges".into(),
        "normal,build".into(),
        "--format".into(),
        "||B1||{p}||{f}".into(),
        "--prefix".into(),
        "indent".into(),
        "--charset".into(),
        "ascii".into(),
        "--no-dedupe".into(),
    ];
    args.extend(common.clone());
    args.extend(request.feature_args());
    let tree = invoke(&cargo, &args, &environment);
    let inventory = source::inventory(&root, "fixture", &budget).unwrap();
    let materialisation = source::inventory_digest(&inventory).unwrap();
    // Synthetic immutable origins exercise production source binding; this test
    // makes no Git transport/authentication or archive verification claim.
    let packages = metadata["packages"].as_array().unwrap();
    assert_eq!(
        packages.len(),
        9,
        "metadata must include the excluded fixture packages"
    );
    let origins = packages
        .iter()
        .map(|package| {
            let directory = Path::new(package["manifest_path"].as_str().unwrap())
                .parent()
                .unwrap();
            (
                package["id"].as_str().unwrap().to_owned(),
                PackageIdentity {
                    name: package["name"].as_str().unwrap().into(),
                    version: "1.0.0".into(),
                    source: PackageSource::Git {
                        url: request.git.clone().unwrap(),
                        rev: request.rev.clone().unwrap(),
                        subdirectory: directory
                            .strip_prefix(&root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .into(),
                        materialisation_sha256: materialisation.clone(),
                    },
                },
            )
        })
        .collect();
    let package = packages
        .iter()
        .find(|package| package["name"] == "owned-app")
        .unwrap();
    let manifest_text = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let manifests = vec![(
        root.join("Cargo.toml"),
        barbican::tool_inputs::source_manifest(&manifest_text).unwrap(),
    )];
    let (graph, selection) = bind(
        &metadata, &tree, &origins, package, &request, &host, &manifests,
    )
    .unwrap();
    assert_eq!(selection.resolver, resolver);
    assert_eq!(
        selection.bins,
        BTreeMap::from([("owned-selected".into(), BTreeSet::from(["extra".into()]))])
    );
    let mut unbound = metadata.clone();
    let root_resolution = unbound["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|node| node["id"] == package["id"])
        .unwrap();
    let shared_dependency = root_resolution["deps"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|dep| dep["name"] == "owned_shared")
        .unwrap();
    shared_dependency["dep_kinds"] = serde_json::json!([{ "kind": "dev", "target": null }]);
    assert!(
        bind(
            &unbound, &tree, &origins, package, &request, &host, &manifests
        )
        .unwrap_err()
        .contains("not bound to normal/build")
    );
    let mut unavailable = request.clone();
    unavailable.bins = vec!["owned-unselected-bin".into()];
    assert!(
        bind(
            &metadata,
            &tree,
            &origins,
            package,
            &unavailable,
            &host,
            &manifests
        )
        .unwrap_err()
        .contains("required features")
    );
    assert!(
        !target.exists(),
        "static graph collection executed fixture code"
    );
    let sentinel = stage.root.join("accepted-build-ran");
    assert!(!sentinel.exists());
    let expected: BTreeSet<_> = graph.nodes.values().map(node_unit).collect();
    assert_eq!(expected.len(), 6);
    let shared: BTreeSet<_> = expected
        .iter()
        .filter(|unit| unit.package == "owned-shared")
        .map(|unit| (unit.context.clone(), unit.features.clone()))
        .collect();
    assert_eq!(
        shared,
        BTreeSet::from([
            (
                CompilationContext::Target,
                BTreeSet::from([
                    "bridge".into(),
                    "target".into(),
                    "unix".into(),
                    "native".into()
                ])
            ),
            (
                CompilationContext::HostBuild,
                BTreeSet::from(["build".into(), "mac".into()])
            ),
        ])
    );
    assert!(expected.iter().all(|unit| {
        ![
            "owned-dev-only",
            "owned-inactive",
            "owned-unselected",
            "owned-unused-optional",
        ]
        .contains(&unit.package.as_str())
    }));

    // Explicit fixture acceptance: every executable source is authored above;
    // only after static binding succeeds do we compile these reviewed bytes.
    write(&stage.root, "capture.rs", CAPTURE);
    let capture = stage.root.join("capture");
    invoke(
        &rustc,
        &[
            stage.root.join("capture.rs").to_str().unwrap().into(),
            "--edition=2024".into(),
            "-o".into(),
            capture.to_str().unwrap().into(),
        ],
        &environment,
    );
    environment.insert("RUSTC_WRAPPER".into(), capture.as_os_str().into());
    environment.insert("OWNED_RUSTC_LOG".into(), logs.as_os_str().into());
    environment.insert("OWNED_BUILD_SENTINEL".into(), sentinel.as_os_str().into());
    let mut args = vec![
        "build".into(),
        "--package".into(),
        "owned-app".into(),
        "--bin".into(),
        "owned-selected".into(),
        "--target".into(),
        host.clone(),
    ];
    args.extend(common);
    args.extend(request.feature_args());
    invoke(&cargo, &args, &environment);
    assert_eq!(fs::read(&sentinel).unwrap(), b"accepted");
    assert_eq!(
        source::inventory(&root, "fixture", &budget).unwrap(),
        inventory
    );
    let observations = rustc_observations(&logs);
    let actual_packages: BTreeSet<_> = observations
        .iter()
        .map(|invocation| PackageIdentity {
            name: invocation.unit.package.clone(),
            version: invocation.version.clone(),
            source: PackageSource::Git {
                url: request.git.clone().unwrap(),
                rev: request.rev.clone().unwrap(),
                subdirectory: invocation
                    .manifest
                    .strip_prefix(&root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .into(),
                materialisation_sha256: materialisation.clone(),
            },
        })
        .collect();
    assert_eq!(
        graph
            .nodes
            .values()
            .map(|node| node.package.clone())
            .collect::<BTreeSet<_>>(),
        actual_packages,
        "production original identities differ from actual compiler package/version/source directories"
    );
    assert_eq!(
        observations.iter().filter(|unit| unit.build_script).count(),
        1
    );
    assert_eq!(
        graph
            .nodes
            .values()
            .filter(|node| node.build_script)
            .map(|node| node.package.name.clone())
            .collect::<BTreeSet<_>>(),
        observations
            .iter()
            .filter(|unit| unit.build_script)
            .map(|unit| unit.unit.package.clone())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        graph
            .nodes
            .values()
            .filter(|node| node.proc_macro)
            .map(|node| node.package.name.clone())
            .collect::<BTreeSet<_>>(),
        observations
            .iter()
            .filter(|unit| unit.unit.context == CompilationContext::HostProcMacro)
            .map(|unit| unit.unit.package.clone())
            .collect::<BTreeSet<_>>()
    );
    let actual: BTreeSet<_> = observations
        .iter()
        .filter(|unit| !unit.build_script)
        .map(|unit| unit.unit.clone())
        .collect();
    assert_eq!(
        expected, actual,
        "production graph differs from actual rustc units"
    );
    let expected_edges: BTreeSet<_> = graph
        .edges
        .iter()
        .map(|edge| {
            let targets = if graph.nodes[&edge.from].package.name == "owned-app"
                && graph.nodes[&edge.to].package.name == "owned-shared"
                && edge.kind == DependencyKind::Normal
            {
                BTreeSet::from([
                    String::new(),
                    "cfg(unix)".into(),
                    "cfg(target_os = \"none\")".into(),
                    "cfg(any(target_os = \"macos\", target_os = \"linux\"))".into(),
                ])
            } else {
                BTreeSet::from([String::new()])
            };
            assert_eq!(edge.declared_targets, targets);
            (
                node_unit(&graph.nodes[&edge.from]),
                edge.kind.clone(),
                node_unit(&graph.nodes[&edge.to]),
            )
        })
        .collect();
    assert_eq!(expected_edges.len(), 7);
    assert_eq!(
        expected_edges,
        observed_edges(&observations),
        "production parent/context/features/kind differs from actual --extern artifacts"
    );
    let mut missing = origins.clone();
    missing.remove(package["id"].as_str().unwrap());
    assert!(
        bind(
            &metadata, &tree, &missing, package, &request, &host, &manifests
        )
        .is_err()
    );
    assert!(
        bind(
            &metadata,
            &format!("{tree}truncated"),
            &origins,
            package,
            &request,
            &host,
            &manifests
        )
        .is_err()
    );
    let owned_stage = stage.root.clone();
    drop(stage);
    assert!(
        !owned_stage.exists(),
        "owned native fixture stage was not removed"
    );
    eprintln!(
        "native production graph qualification: resolver={resolver}, host={host}, cargo={}, rustc={}, source={}, controlled offline environment; {} units / {} exact extern edges; synthetic Git origins; owned stage cleanup verified",
        cargo.sha256,
        rustc.sha256,
        materialisation,
        actual.len(),
        expected_edges.len()
    );
}

#[test]
fn native_production_graph_matches_rustc_resolver2() {
    qualify(2);
}

#[test]
fn native_production_graph_matches_rustc_resolver3_edition2024() {
    qualify(3);
}

#[test]
fn captured_cargo_audit_declarations_preserve_all_alternatives_without_selecting_absent_edges() {
    let capture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/cargo-tools/captured-declared-targets.json"
    ))
    .unwrap();
    let cases = capture["edges"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["selected_by_native_tree"] == true)
            .count(),
        9
    );
    for case in cases {
        let parent_id = case["from"].as_str().unwrap();
        let child_id = case["to"].as_str().unwrap();
        let package = |id: &str| {
            let (name, version) = id.rsplit_once('#').unwrap().1.rsplit_once('@').unwrap();
            serde_json::json!({"id":id, "name":name, "version":version,
                "source":barbican::CRATES_IO_SOURCE, "manifest_path":format!("/owned-capture/{name}/Cargo.toml"),
                "targets":[{"name":name,"kind":["bin"]}]})
        };
        // This minimal protocol regression retains captured declarations/selection.
        // Synthetic bin targets and checksum labels make it self-contained; native
        // compiler equivalence is established separately by the authored fixtures.
        let parent = package(parent_id);
        let child = package(child_id);
        let metadata = serde_json::json!({"workspace_root":"/owned-capture", "packages":[parent,child],
            "resolve":{"nodes":[{"id":parent_id,"deps":[{"pkg":child_id,"dep_kinds":case["dep_kinds"]}]},
                {"id":child_id,"deps":[]}]}});
        let origins = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| {
                (
                    package["id"].as_str().unwrap().to_owned(),
                    PackageIdentity {
                        name: package["name"].as_str().unwrap().into(),
                        version: package["version"].as_str().unwrap().into(),
                        source: PackageSource::CratesIo {
                            archive_sha256: sha256(package["id"].as_str().unwrap().as_bytes()),
                        },
                    },
                )
            })
            .collect();
        let selected = case["selected_by_native_tree"].as_bool().unwrap();
        let mut tree = format!("||B1||{}||\n", display(&parent).unwrap());
        if selected {
            tree.push_str(&format!("`-- ||B1||{}||\n", display(&child).unwrap()));
        }
        let request = ReviewRequest {
            spec: Some(format!(
                "{}@{}",
                parent["name"].as_str().unwrap(),
                parent["version"].as_str().unwrap()
            )),
            git: None,
            rev: None,
            package: None,
            bins: vec![],
            features: vec![],
            no_default_features: true,
            all_features: false,
            profile: "dev".into(),
            target: None,
            from: None,
            cargo: "/unused/cargo".into(),
            rustc: "/unused/rustc".into(),
        };
        let manifests = [(
            PathBuf::from("/owned-capture/Cargo.toml"),
            serde_json::json!({"workspace":{"resolver":"2"}}),
        )];
        let (graph, _) = bind(
            &metadata,
            &tree,
            &origins,
            &parent,
            &request,
            "aarch64-apple-darwin",
            &manifests,
        )
        .unwrap();
        assert_eq!(graph.nodes.len(), if selected { 2 } else { 1 });
        assert_eq!(graph.edges.len(), usize::from(selected));
        if selected {
            let expected = case["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kind| kind["target"].as_str().unwrap_or("").to_owned())
                .collect();
            assert_eq!(
                graph.edges.first().unwrap().declared_targets,
                expected,
                "{parent_id} -> {child_id}"
            );
            for invalid in [
                serde_json::json!([{"kind":"unknown","target":null}]),
                serde_json::json!([{"target":null}]),
                serde_json::json!([{"kind":null,"target":17}]),
                serde_json::json!([{"kind":"dev","target":null}]),
                serde_json::json!([]),
            ] {
                let mut malformed = metadata.clone();
                malformed["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = invalid;
                assert!(
                    bind(
                        &malformed,
                        &tree,
                        &origins,
                        &parent,
                        &request,
                        "aarch64-apple-darwin",
                        &manifests
                    )
                    .is_err()
                );
            }
        }
    }
}
