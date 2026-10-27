#![cfg(unix)]

mod adoption_support;
use adoption_support::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::time::Duration;

fn fixture() -> Fixture {
    let f = Fixture::new();
    f.init(&[]);
    f.write("reviewed-targets.toml", "[[rust.families]]\nname='family'\nreview_record='docs/review.md'\n[rust.families.resolved]\nserde='1.0.228'\n");
    f.write("docs/review.md", "# Reviewed\n");
    f
}

#[test]
fn native_browser_handles_missing_and_unsafe_lock_without_opening_fifo() {
    let f = fixture();
    for kind in ["missing", "symlink", "directory", "fifo"] {
        if kind == "symlink" {
            symlink("Cargo.toml", f.path("Cargo.lock")).unwrap();
        }
        if kind == "directory" {
            fs::create_dir(f.path("Cargo.lock")).unwrap();
        }
        if kind == "fifo" {
            assert!(
                f.command("mkfifo")
                    .arg(f.path("Cargo.lock"))
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let output = f.run_with_timeout(
            &mut f.barbican(&["pin", "show", "family"]),
            Duration::from_secs(10),
        );
        assert!(output.status.success(), "{}", rendered(&output));
        assert!(rendered(&output).contains("parity: unavailable"));
        if kind == "directory" {
            fs::remove_dir(f.path("Cargo.lock")).unwrap();
        } else if kind != "missing" {
            fs::remove_file(f.path("Cargo.lock")).unwrap();
        }
    }
}

#[test]
fn native_record_ancestor_and_protected_aliases_are_unavailable_without_reads() {
    let f = fixture();
    fs::remove_file(f.path("docs/review.md")).unwrap();
    fs::rename(f.path("docs"), f.path("saved-docs")).unwrap();
    f.write("outside/review.md", "# must not read this evidence\n");
    symlink("outside", f.path("docs")).unwrap();
    let output = f.ok(&mut f.barbican(&["pin", "show", "family"]));
    assert!(rendered(&output).contains("unavailable"));
    fs::remove_file(f.path("docs")).unwrap();
    fs::create_dir(f.path("docs")).unwrap();
    fs::hard_link(f.path("Cargo.toml"), f.path("docs/review.md")).unwrap();
    let output = f.ok(&mut f.barbican(&["pin", "show", "family"]));
    assert!(rendered(&output).contains("protected input"));
    fs::remove_file(f.path("docs/review.md")).unwrap();
    assert!(
        f.command("mkfifo")
            .arg(f.path("docs/review.md"))
            .status()
            .unwrap()
            .success()
    );
    let output = f.run_with_timeout(&mut f.barbican(&["pin", "list"]), Duration::from_secs(10));
    assert!(output.status.success());
    assert!(rendered(&output).contains("unavailable"));
}

#[test]
fn native_suggestions_quote_family_names_for_shell_and_option_boundaries() {
    let f = fixture();
    let name = "--help'; touch pwned; echo '";
    let text = fs::read_to_string(f.path("reviewed-targets.toml"))
        .unwrap()
        .replace("'family'", &serde_json::to_string(name).unwrap());
    f.write("reviewed-targets.toml", &text);
    let output = f.ok(&mut f.barbican(&["pin", "list"]));
    let text = String::from_utf8(output.stdout).unwrap();
    let command = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Inspect: "))
        .unwrap();
    let shell = command.replacen(
        "cargo barbican",
        &format!("'{}'", env!("CARGO_BIN_EXE_cargo-barbican")),
        1,
    );
    let output = f.ok(f.command("sh").args(["-c", &shell]));
    assert!(rendered(&output).contains("Declared members"));
    assert!(!f.path("pwned").exists());
}
