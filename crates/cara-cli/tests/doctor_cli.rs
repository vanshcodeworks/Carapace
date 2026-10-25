//! End-to-end test of `cara doctor` through the real binary.

use std::process::Command;

#[test]
fn doctor_json_is_valid_and_exit_code_is_defined() {
    let out = Command::new(env!("CARGO_BIN_EXE_cara"))
        .args(["doctor", "--json"])
        .output()
        .expect("cara binary runs");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 4,
        "doctor must exit 0 (ready) or 4 (not ready), got {code}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert!(v["checks"].is_array(), "report has a checks array");
    assert!(v["checks"].as_array().unwrap().len() >= 12);
}

#[test]
fn doctor_human_mode_mentions_verdict() {
    let out = Command::new(env!("CARGO_BIN_EXE_cara"))
        .args(["doctor"])
        .output()
        .expect("cara binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Result: READY") || stdout.contains("Result: NOT READY"));
}

#[test]
#[cfg(target_os = "linux")]
fn strict_env_doctor_is_ready() {
    if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cara"))
        .args(["doctor", "--json"])
        .output()
        .expect("cara binary runs");
    assert_eq!(out.status.code(), Some(0), "dev environment must be READY");
}
