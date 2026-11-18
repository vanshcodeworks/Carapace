//! Tests for the CLI presentation layer: help text and color policy.

use std::process::Command;

fn cara() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cara"))
}

#[test]
fn help_is_rich_and_has_examples() {
    let out = cara().arg("--help").output().expect("run cara --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("untrusted programs"), "{text}");
    assert!(text.contains("Examples:"), "{text}");
    assert!(text.contains("cara doctor"), "{text}");
    assert!(text.contains("cara mcp"), "{text}");
}

#[test]
fn short_help_has_tagline() {
    let out = cara().arg("-h").output().expect("run cara -h");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("Local sandbox for untrusted code"), "{text}");
}

#[test]
fn no_color_keeps_output_plain() {
    let out = cara()
        .args(["doctor", "--json"])
        .env("NO_COLOR", "1")
        .output()
        .expect("run cara doctor --json");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("\x1b["),
        "JSON must never contain ANSI: {text}"
    );
}

#[test]
fn version_is_reported() {
    let out = cara()
        .arg("--version")
        .output()
        .expect("run cara --version");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("cara 0.1.0"), "{text}");
}
