use serde::Deserialize;
use std::fs;
use std::io::Read;
use std::path::Path;

pub(super) const WORKFLOW_PATH: &str = ".github/workflows/barbican-admission.yml";
const TEMPLATE: &str = include_str!("../../../../../templates/ci/github-admission.yml");
const SIGNAL_GUARD: &str = "trap 'exit 130' INT\ntrap 'exit 143' TERM\ntrap 'signal_status=$?; if [[ $signal_status == 130 || $signal_status == 143 ]]; then printf \"cancelled=true\\n\" >> \"$GITHUB_OUTPUT\"; fi' EXIT";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    schema_version: u32,
    controller_tag: String,
    provider_repository: String,
    provider_revision: String,
    provider_script: String,
    approved_repository: String,
    approved_revision: String,
    review_id: String,
}

pub(super) fn render(path: &Path) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("read CI bootstrap configuration: {e}"))?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 {
        return Err("CI bootstrap configuration must be a bounded regular non-symlink file".into());
    }
    let mut text = String::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(16 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 16 * 1024 {
        return Err("CI bootstrap configuration exceeds byte limit".into());
    }
    render_text(&text)
}

fn render_text(text: &str) -> Result<String, String> {
    let config: Bootstrap = serde_json::from_str(text)
        .map_err(|e| format!("invalid CI bootstrap configuration: {e}"))?;
    if config.schema_version != 1 {
        return Err("unsupported CI bootstrap schema_version".into());
    }
    for repository in [&config.provider_repository, &config.approved_repository] {
        let parts: Vec<_> = repository.split('/').collect();
        if parts.len() != 2 || parts.iter().any(|part| !safe_name(part)) {
            return Err("CI bootstrap repositories must be explicit owner/repository names".into());
        }
    }
    for revision in [&config.provider_revision, &config.approved_revision] {
        if !hex(revision, 40) {
            return Err("CI bootstrap revisions must be full lowercase 40-hex commits".into());
        }
    }
    if !hex(&config.review_id, 64) {
        return Err("CI bootstrap review_id must be an exact lowercase SHA256".into());
    }
    if !safe_name(&config.controller_tag) {
        return Err("CI controller_tag must be a single safe immutable tag name".into());
    }
    if !config.provider_script.ends_with(".sh")
        || config.provider_script.len() > 256
        || config
            .provider_script
            .split('/')
            .any(|part| !safe_name(part))
    {
        return Err(
            "CI provider_script must be a confined shell-script path with safe components".into(),
        );
    }
    let mut workflow = TEMPLATE.replace(
        "@@SIGNAL_GUARD@@",
        &SIGNAL_GUARD.replace('\n', "\n          "),
    );
    for (key, value) in [
        ("CONTROLLER_TAG", &config.controller_tag),
        ("PROVIDER_REPOSITORY", &config.provider_repository),
        ("PROVIDER_REVISION", &config.provider_revision),
        ("PROVIDER_SCRIPT", &config.provider_script),
        ("APPROVED_REPOSITORY", &config.approved_repository),
        ("APPROVED_REVISION", &config.approved_revision),
        ("REVIEW_ID", &config.review_id),
    ] {
        workflow = workflow.replace(&format!("@@{key}@@"), value);
    }
    Ok(workflow)
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !value.starts_with(['.', '-'])
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn config() -> String {
        serde_json::json!({"schema_version":1,"controller_tag":"barbican-ci-v1","provider_repository":"owner/tools","provider_revision":"a".repeat(40),"provider_script":"ci/provision.sh","approved_repository":"owner/repo","approved_revision":"b".repeat(40),"review_id":"c".repeat(64)}).to_string()
    }

    #[test]
    fn bootstrap_rejects_mutable_refs_paths_and_expression_injection() {
        for (from, to) in [
            ("owner/tools", "owner/tools/extra"),
            ("owner/tools", "owner/${{ secrets.TOKEN }}"),
            ("ci/provision.sh", "../provision.sh"),
            ("ci/provision.sh", "ci/provision.sh;exit"),
            ("barbican-ci-v1", "-option"),
            ("barbican-ci-v1", "tag/branch"),
            (&"a".repeat(40), "main"),
            (&"c".repeat(64), "short"),
            ("\"schema_version\":1", "\"schema_version\":2"),
        ] {
            assert!(render_text(&config().replace(from, to)).is_err(), "{to}");
        }
        let mut value: serde_json::Value = serde_json::from_str(&config()).unwrap();
        value["arbitrary_command"] = "echo unsafe".into();
        assert!(render_text(&value.to_string()).is_err());
    }

    #[test]
    fn generated_controller_keeps_authority_and_candidate_execution_order() {
        let workflow = render_text(&config()).unwrap();
        assert!(!workflow.contains("@@"));
        assert!(workflow.contains("workflow_dispatch:"));
        assert!(!workflow.contains("pull_request:"));
        assert!(!workflow.contains("pull_request_target:"));
        assert!(!workflow.contains("workflow_run:"));
        assert!(!workflow.contains("secrets."));
        assert!(!workflow.contains("cargo install"));
        assert!(!workflow.contains("cached-admission"));
        assert!(!workflow.contains("rust-cache"));
        let mut previous = 0;
        for stage in [
            "id: controller",
            "id: provider_checkout",
            "id: provision",
            "id: approved_checkout",
            "id: candidate_checkout",
            "id: accept",
            "id: install",
            "id: installed",
            "id: admission",
            "id: conformance",
            "id: fetch",
            "id: pre_release",
        ] {
            let offset = workflow.find(stage).unwrap();
            assert!(offset >= previous, "{stage}");
            previous = offset;
        }
        assert_eq!(workflow.matches("persist-credentials: false").count(), 3);
        for id in [
            "evidence_toolchain",
            "base",
            "age_lock",
            "assess",
            "summary",
        ] {
            let step = workflow
                .split(&format!("- id: {id}\n"))
                .nth(1)
                .unwrap()
                .split("      - id:")
                .next()
                .unwrap();
            assert!(step.contains("!cancelled()"), "{id}");
        }
        assert!(workflow.contains("--approved-repo \"$GITHUB_WORKSPACE/approved\""));
        assert!(workflow.contains("not a candidate-SHA required check"));
        for (step, cancelled) in [
            ("evidence_toolchain", "pre_release"),
            ("base", "evidence_toolchain"),
            ("age_lock", "base"),
            ("assess", "age_lock"),
        ] {
            let step = workflow
                .split(&format!("- id: {step}\n"))
                .nth(1)
                .unwrap()
                .split("      - id:")
                .next()
                .unwrap();
            assert!(step.contains(&format!("steps.{cancelled}.outputs.cancelled != 'true'")));
        }
    }

    fn run_script(workflow: &str, id: &str) -> String {
        let step = workflow
            .split(&format!("- id: {id}\n"))
            .nth(1)
            .unwrap()
            .split("      - id:")
            .next()
            .unwrap();
        step.split("        run: |\n")
            .nth(1)
            .unwrap()
            .lines()
            .map(|line| line.strip_prefix("          ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn generated_shell_observes_late_signals_and_never_reports_green_cancellation() {
        let workflow = render_text(&config()).unwrap();
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let root = std::env::temp_dir().join(format!(
                "barbican-ci-signal-{}-{signal}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            let mock = root.join("bin/cargo-barbican");
            // Bootstrap compiler selection must not leak into target-stage calls.
            fs::write(&mock, "#!/bin/sh\n[ -z \"${RUSTUP_TOOLCHAIN+x}\" ] || exit 91\nprintf completed > \"$COMPLETED\"\n").unwrap();
            fs::set_permissions(&mock, fs::Permissions::from_mode(0o700)).unwrap();
            let script = format!(
                "{}\nprintf ready > \"$READY\"\nwhile [[ ! -f \"$RELEASE\" ]]; do sleep 0.02; done\nprintf unsafe > \"$LATER\"\n",
                run_script(&workflow, "pre_release")
            );
            let output = root.join("output");
            let mut child = Command::new("/bin/bash")
                .args(["-e", "-o", "pipefail", "-c", &script])
                .env("BARBICAN_TOOLS", &root)
                .env("BARBICAN_DATA", root.join("data"))
                .env("BARBICAN_CACHE", root.join("cache"))
                .env("GITHUB_OUTPUT", &output)
                .env("RUSTUP_TOOLCHAIN", "1.90.0-bootstrap-host")
                .env("COMPLETED", root.join("completed"))
                .env("READY", root.join("ready"))
                .env("RELEASE", root.join("release"))
                .env("LATER", root.join("later"))
                .process_group(0)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !root.join("ready").exists() && Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !root.join("ready").exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("generated shell did not reach the controlled late-signal boundary");
            }
            assert!(root.join("completed").exists());
            assert!(
                Command::new("/bin/bash")
                    .args([
                        "-c",
                        "kill -s \"$1\" -- \"-$2\"",
                        "signal-owned-test-group",
                        signal,
                        &child.id().to_string()
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("generated shell failed to terminate after {signal}");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(code));
            assert_eq!(fs::read_to_string(&output).unwrap(), "cancelled=true\n");
            assert!(!root.join("later").exists());
            let summary = Command::new("/bin/bash")
                .args([
                    "-e",
                    "-o",
                    "pipefail",
                    "-c",
                    &run_script(&workflow, "summary"),
                ])
                .env("GITHUB_OUTPUT", &output)
                .env("GITHUB_STEP_SUMMARY", root.join("summary"))
                .env("SIGNAL_CANCELLATIONS", "true")
                .env("GATE", "success")
                .output()
                .unwrap();
            assert_eq!(summary.status.code(), Some(130));
            fs::remove_dir_all(root).unwrap();
        }
    }
}
