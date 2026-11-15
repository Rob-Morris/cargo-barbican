use super::collection::ReviewRequest;
use super::process::{Evaluator, Result, err};
use barbican::cargo_tool::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("metadata missing {key}"))
}
fn display(package: &Value) -> Result<String> {
    let proc_macro = package
        .get("targets")
        .and_then(Value::as_array)
        .ok_or("metadata targets missing")?
        .iter()
        .any(|target| {
            target
                .get("kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "proc-macro"))
        });
    let mut result = format!(
        "{} v{}{}",
        text(package, "name")?,
        text(package, "version")?,
        if proc_macro { " (proc-macro)" } else { "" }
    );
    match package.get("source").and_then(Value::as_str) {
        None => result.push_str(&format!(
            " ({})",
            Path::new(text(package, "manifest_path")?)
                .parent()
                .ok_or("manifest parent unavailable")?
                .display()
        )),
        Some(source) if source.starts_with("git+") => {
            let source = source
                .strip_prefix("git+")
                .ok_or("invalid Git metadata source")?;
            let (base, revision) = source
                .rsplit_once('#')
                .ok_or("Git metadata source missing commit")?;
            if revision.len() != 40 {
                return Err("Git metadata commit is not exact".into());
            }
            result.push_str(&format!(" ({base}#{})", &revision[..7]));
        }
        Some(source)
            if source == barbican::CRATES_IO_SOURCE
                || source == "sparse+https://index.crates.io/" => {}
        _ => return Err("unqualified metadata source".into()),
    }
    Ok(result)
}
fn package_index(metadata: &Value) -> Result<BTreeMap<String, &Value>> {
    let mut index = BTreeMap::new();
    for package in metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("metadata packages missing")?
    {
        let display = display(package)?;
        if index.insert(display, package).is_some() {
            return Err("Cargo display cannot uniquely bind metadata package source".into());
        }
    }
    Ok(index)
}
pub(crate) fn selected_ids(metadata: &Value, tree: &str) -> Result<BTreeSet<String>> {
    let index = package_index(metadata)?;
    barbican::cargo_tool::parse_tree_protocol(tree)
        .map_err(err)?
        .into_iter()
        .map(|entry| {
            let package = index
                .get(&entry.display)
                .ok_or("tree package display has no exact metadata source binding")?;
            Ok(text(package, "id")?.to_owned())
        })
        .collect()
}

pub(crate) fn bind(
    metadata: &Value,
    tree: &str,
    origins: &BTreeMap<String, PackageIdentity>,
    root: &Value,
    request: &ReviewRequest,
    host: &str,
    manifests: &[(PathBuf, Value)],
) -> Result<(InstallGraph, BuildSelection)> {
    let index = package_index(metadata)?;
    let entries = barbican::cargo_tool::parse_tree_protocol(tree).map_err(err)?;
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut stack: Vec<(String, String, CompilationContext)> = Vec::new();
    let mut graph_root = None;
    for entry in entries {
        let package = *index
            .get(&entry.display)
            .ok_or("tree package display has no exact metadata source binding")?;
        let id = text(package, "id")?;
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .ok_or("metadata targets missing")?;
        let has_kind = |kind: &str| {
            targets.iter().any(|target| {
                target
                    .get("kind")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| kinds.iter().any(|k| k == kind))
            })
        };
        if entry.depth == 0 && (graph_root.is_some() || id != text(root, "id")?) {
            return Err("tree root differs from selected binary package".into());
        }
        if entry.depth > stack.len() {
            return Err("tree depth has no parent".into());
        }
        stack.truncate(entry.depth);
        let parent = stack.last();
        let proc_macro = has_kind("proc-macro");
        let context = if proc_macro {
            CompilationContext::HostProcMacro
        } else if entry.build_edge
            || parent.is_some_and(|(_, _, context)| *context != CompilationContext::Target)
        {
            CompilationContext::HostBuild
        } else {
            CompilationContext::Target
        };
        let key = format!(
            "{}:{}",
            sha256(
                &canonical_bytes(origins.get(id).ok_or("tree ID lacks immutable source")?)
                    .map_err(err)?
            ),
            match context {
                CompilationContext::Target => "target",
                CompilationContext::HostBuild => "host-build",
                CompilationContext::HostProcMacro => "host-proc-macro",
            }
        );
        let node = GraphNode {
            package: origins
                .get(id)
                .ok_or("tree ID lacks immutable original source")?
                .clone(),
            context: context.clone(),
            features: entry.features,
            build_script: has_kind("custom-build"),
            proc_macro,
            native_links: package.get("links").is_some_and(|v| !v.is_null()),
        };
        if let Some(old) = nodes.insert(key.clone(), node.clone())
            && old != node
        {
            return Err("same Cargo package/context has inconsistent features or surfaces".into());
        }
        if let Some((parent_key, parent_id, _)) = parent {
            let resolve = metadata
                .pointer("/resolve/nodes")
                .and_then(Value::as_array)
                .ok_or("metadata resolve nodes missing")?;
            let parent_node = resolve
                .iter()
                .find(|n| n.get("id").and_then(Value::as_str) == Some(parent_id))
                .ok_or("tree parent absent from resolution")?;
            let deps = parent_node
                .get("deps")
                .and_then(Value::as_array)
                .ok_or("metadata dependency identities missing")?;
            let mut declared_targets = BTreeSet::new();
            for dep in deps
                .iter()
                .filter(|dep| dep.get("pkg").and_then(Value::as_str) == Some(id))
            {
                let kinds = dep
                    .get("dep_kinds")
                    .and_then(Value::as_array)
                    .filter(|kinds| !kinds.is_empty())
                    .ok_or("metadata dependency kinds missing")?;
                for declaration in kinds {
                    let kind = match declaration.get("kind") {
                        Some(Value::Null) => DependencyKind::Normal,
                        Some(Value::String(kind)) if kind == "build" => DependencyKind::Build,
                        Some(Value::String(kind)) if kind == "dev" => continue,
                        _ => return Err("unknown metadata dependency kind".into()),
                    };
                    if (kind == DependencyKind::Build) != entry.build_edge {
                        continue;
                    }
                    let target = match declaration.get("target") {
                        Some(Value::Null) => "",
                        Some(Value::String(target)) => target.as_str(),
                        _ => return Err("invalid metadata dependency target declaration".into()),
                    };
                    declared_targets.insert(target.to_owned());
                }
            }
            if declared_targets.is_empty() {
                return Err("tree edge not bound to normal/build metadata dependency".into());
            }
            edges.insert(GraphEdge {
                from: parent_key.clone(),
                to: key.clone(),
                kind: if entry.build_edge {
                    DependencyKind::Build
                } else {
                    DependencyKind::Normal
                },
                declared_targets,
            });
        } else {
            graph_root = Some(key.clone());
        }
        stack.push((key, id.into(), context));
    }
    let graph = InstallGraph {
        root: graph_root.ok_or("empty install graph")?,
        nodes,
        edges,
    };
    graph.validate().map_err(err)?;
    let available_features = &graph.nodes[&graph.root].features;
    let mut bins = BTreeMap::new();
    for target in root
        .get("targets")
        .and_then(Value::as_array)
        .ok_or("root targets missing")?
    {
        if !target
            .get("kind")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
        {
            continue;
        }
        let name = text(target, "name")?;
        let required: BTreeSet<String> = target
            .get("required-features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("invalid binary required feature")
            })
            .collect::<std::result::Result<_, _>>()?;
        if request.bins.is_empty() {
            if required.is_subset(available_features) {
                bins.insert(name.into(), required);
            }
        } else if request.bins.iter().any(|bin| bin == name) {
            if !required.is_subset(available_features) {
                return Err("selected binary required features are not enabled".into());
            }
            bins.insert(name.into(), required);
        }
    }
    if request.bins.iter().any(|bin| !bins.contains_key(bin)) {
        return Err("selected binary is unavailable in exact source/feature selection".into());
    }
    let workspace = Path::new(text(metadata, "workspace_root")?).join("Cargo.toml");
    let workspace_manifest = &manifests
        .iter()
        .find(|(path, _)| *path == workspace)
        .ok_or("actual workspace manifest absent from original inputs")?
        .1;
    let resolver = if let Some(value) = workspace_manifest
        .pointer("/workspace/resolver")
        .or_else(|| workspace_manifest.pointer("/package/resolver"))
        .and_then(Value::as_str)
    {
        value.parse::<u8>().map_err(err)?
    } else {
        match workspace_manifest
            .pointer("/package/edition")
            .and_then(Value::as_str)
        {
            Some("2024") => 3,
            Some("2021") => 2,
            _ => return Err("Cargo resolver 1 or unknown default is unqualified".into()),
        }
    };
    let selection = BuildSelection {
        bins,
        requested_features: request.features.iter().cloned().collect(),
        default_features: !request.no_default_features,
        all_features: request.all_features,
        profile: match request.profile.as_str() {
            "release" => BuildProfile::Release,
            "dev" => BuildProfile::Dev,
            _ => return Err("custom profiles are unqualified".into()),
        },
        host: host.into(),
        target: host.into(),
        resolver,
    };
    selection.validate().map_err(err)?;
    Ok((graph, selection))
}
pub(crate) fn build_evaluator(evaluator: &Evaluator) -> Result<BuildEvaluator> {
    fn identity(
        executable: &super::process::Executable,
        output: &str,
        host: &str,
    ) -> Result<ExecutableIdentity> {
        let field = |name: &str| {
            output
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::to_owned)
                .ok_or_else(|| format!("trusted evaluator missing {name}"))
        };
        Ok(ExecutableIdentity {
            sha256: executable.sha256.clone(),
            version: field("release: ")?,
            commit: field("commit-hash: ")?,
            host: host.into(),
        })
    }
    Ok(BuildEvaluator{cargo:identity(&evaluator.cargo,&evaluator.cargo_version,&evaluator.host)?,rustc:identity(&evaluator.rustc,&evaluator.rustc_version,&evaluator.host)?,qualification_sha256:sha256(format!("cargo-tool/v1;cargo=f2d3ce0bd7f24a49f8f72d9000448f8838c4e850;rustc=59807616e1fa2540724bfbac14d7976d7e4a3860;host={};resolver=2,3;verified-path;controlled-environment",evaluator.host).as_bytes())})
}
