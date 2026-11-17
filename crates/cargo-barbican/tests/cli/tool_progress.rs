use super::common::*;
use std::process::Command;

#[test]
fn stdio_tool_progress_keeps_candidate_bytes_out_of_diagnostics_and_json_separate() {
    use std::os::unix::fs::OpenOptionsExt;
    let temp = fresh_temp_dir();
    let candidate = "candidate-sentinel-should-never-appear";
    let invalid = temp.join(candidate);
    // A bounded inert file exercises evaluator hashing and then fails native
    // format validation. No scanner, candidate or build program executes.
    let file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o700)
        .open(&invalid)
        .unwrap();
    file.set_len(1024 * 1024).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cargo-barbican"))
            .current_dir(&temp)
            .env_clear()
            .env("HOME", &*temp)
            .env("PATH", "/usr/bin:/bin")
            .arg("--data-dir")
            .arg(temp.join("data"))
            .arg("--cache-dir")
            .arg(temp.join("cache"))
            .args(args)
            .output()
            .unwrap()
    };
    let args = [
        "tool",
        "review",
        "fixture@1.0.0",
        "--standalone",
        "--format",
        "json",
        "--cargo",
        invalid.to_str().unwrap(),
    ];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "blocked-or-unavailable");
    let lines = std::str::from_utf8(&output.stderr).unwrap();
    for line in lines.lines() {
        assert!(line.starts_with("Tool progress ["), "{line}");
        assert!(!line.contains(candidate));
        assert!(!line.chars().any(char::is_control));
    }
    for (args, status) in [
        (vec!["tool", "review", "invalid", "--format", "json"], 2),
        (
            vec!["tool", "installation-check", "invalid", "--format", "json"],
            2,
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(status));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["status"],
            "invalid-input"
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn injected_review_and_validated_excluded_command_keep_progress_disabled() {
    let temp = fresh_temp_dir();
    let cli = Cli::try_parse_from([
        "cargo-barbican",
        "--data-dir",
        temp.join("data").to_str().unwrap(),
        "--cache-dir",
        temp.join("cache").to_str().unwrap(),
        "tool",
        "review",
        "fixture@1.0.0",
        "--standalone",
        "--format",
        "json",
        "--cargo",
        "/nonexistent/trusted-cargo",
    ])
    .unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_cli_with_runner(
        cli,
        &temp,
        &FakeCratesIoClient::default(),
        &FakeCommandRunner::default(),
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(status, ExitCode::from(1));
    assert!(err.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["status"],
        "blocked-or-unavailable"
    );
    let id = format!("cargo-tool:installed-binding:v1:{}", "a".repeat(64));
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-barbican"))
        .current_dir(&temp)
        .env_clear()
        .env("HOME", &*temp)
        .env("PATH", "/usr/bin:/bin")
        .arg("--data-dir")
        .arg(temp.join("data"))
        .arg("--cache-dir")
        .arg(temp.join("cache"))
        .args(["tool", "installation-check", &id, "--format", "json"])
        .output()
        .unwrap();
    assert!(output.stderr.is_empty());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["status"],
        "blocked-or-unavailable"
    );
}
