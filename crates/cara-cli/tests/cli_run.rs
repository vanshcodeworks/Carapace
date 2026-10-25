//! End-to-end CLI tests: policy check/explain and `cara run` through the
//! real binary (environment-gated; check.sh bridges WSL cgroup contexts).

use std::process::Command;

fn cara() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cara"))
}

fn env_ready() -> bool {
    // Same gate the binary applies; skip quietly where cgroup delegation
    // is unavailable (plain CI containers).
    cara().args(["doctor", "--json"]).output().is_ok_and(|o| {
        let s = String::from_utf8_lossy(&o.stdout);
        s.contains("\"ready\":true") || o.status.code() == Some(0)
    })
}

#[test]
fn policy_check_valid_and_invalid() {
    let dir = std::env::temp_dir().join(format!("cara-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.toml");
    std::fs::write(
        &good,
        "[limits]\nmemory = \"128MB\"\ntimeout = \"5s\"\n[network]\nmode = \"none\"\n",
    )
    .unwrap();
    let out = cara()
        .args(["policy", "check", good.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "[limits]\nmemory = \"128QWERTY\"\n").unwrap();
    let out = cara()
        .args(["policy", "check", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_explain_is_plain_english() {
    let dir = std::env::temp_dir().join(format!("cara-cli-exp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("p.toml");
    std::fs::write(&f, "preset = \"strict\"\n").unwrap();
    let out = cara()
        .args(["policy", "explain", f.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("NO network"), "{text}");
    assert!(text.contains("fork bombs"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_echo_through_full_stack() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let out = cara()
        .args(["run", "--json", "--", "/bin/echo", "hello", "carapace"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["stdout"], "hello carapace\n");
    assert!(report["cpu_time_ms"].is_number());
}

#[test]
fn run_timeout_kills_with_reason() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let out = cara()
        .args([
            "run",
            "--json",
            "--timeout",
            "500ms",
            "--",
            "/bin/sleep",
            "300",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["kill_reason"], "timeout");
}

#[test]
fn run_fails_closed_on_unknown_network_mode_in_policy() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let dir = std::env::temp_dir().join(format!("cara-cli-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // allowlist parses, but the backend must refuse (fail closed).
    let f = dir.join("al.toml");
    std::fs::write(
        &f,
        "[network]\nmode = \"allowlist\"\nallow = [\"pypi.org\"]\n",
    )
    .unwrap();
    let out = cara()
        .args([
            "run",
            "--policy",
            f.to_str().unwrap(),
            "--json",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not implemented"),
        "must fail closed loudly: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_with_read_write_bind_sees_host_dir() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let dir = std::env::temp_dir().join(format!("cara-cli-bind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payload = dir.join("answer.txt");
    std::fs::write(&payload, "42\n").unwrap();
    let policy = dir.join("p.toml");
    std::fs::write(
        &policy,
        format!(
            "[filesystem]\nread_write = [\"{}\"]\n",
            dir.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    let target = payload.to_str().unwrap().replace('\\', "/");
    let out = cara()
        .args([
            "run",
            "--policy",
            policy.to_str().unwrap(),
            "--json",
            "--",
            "/bin/cat",
            &target,
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report["stdout"], "42\n",
        "payload readable through the rw bind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
