//! End-to-end CLI tests: policy check/explain and `cara run` through the
//! real binary (environment-gated; check.sh bridges WSL cgroup contexts).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

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
fn run_removes_its_cgroup_leaf_before_exit() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let mut child = cara()
        .args(["run", "--json", "--", "/bin/true"])
        .spawn()
        .unwrap();
    let supervisor_pid = child.id();
    assert!(child.wait().unwrap().success());
    // Drop's async remover cannot outlive a short-lived CLI process; the
    // leaf must be gone before exit (normally-path removal in wait()).
    let needle = format!("cara-run-{supervisor_pid}-");
    let leftovers = find_cgroup_names(&needle);
    assert!(
        leftovers.is_empty(),
        "cgroup leaf left behind after process exit: {leftovers:?}"
    );
}

#[test]
fn doctor_removes_its_cgroup_probe_leaf_before_exit() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // The doctor gate creates an attach-probe leaf named like a run leaf.
    // A detached Drop remover would die with this short-lived process.
    let mut child = cara()
        .args(["doctor", "--json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let doctor_pid = child.id();
    assert!(child.wait().unwrap().success());
    let leftovers = find_cgroup_names(&format!("cara-run-{doctor_pid}-"));
    assert!(
        leftovers.is_empty(),
        "doctor probe leaf left behind after process exit: {leftovers:?}"
    );
}

/// Recursively scans the unified cgroup tree for directory names starting
/// with `needle` (the CLI's own leaf names embed the supervisor PID).
fn find_cgroup_names(needle: &str) -> Vec<String> {
    fn walk(dir: &std::path::Path, needle: &str, out: &mut Vec<String>, depth: u8) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(needle) {
                out.push(entry.path().display().to_string());
            }
            walk(&entry.path(), needle, out, depth - 1);
        }
    }
    let mut out = Vec::new();
    walk(std::path::Path::new("/sys/fs/cgroup"), needle, &mut out, 6);
    out
}

#[test]
fn run_provides_default_path_and_home() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let out = cara()
        .args([
            "run",
            "--json",
            "--",
            "/bin/sh",
            "-c",
            "printf 'PATH=%s\\nHOME=%s\\n' \"$PATH\" \"$HOME\"; echo probe > /work/probe",
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
    let stdout = report["stdout"].as_str().unwrap();
    assert!(
        stdout.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "default PATH missing: {stdout}"
    );
    assert!(
        stdout.contains("HOME=/work"),
        "default HOME missing: {stdout}"
    );
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
fn run_fails_closed_on_malformed_allowlist_entry() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let dir = std::env::temp_dir().join(format!("cara-cli-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Hostnames are refused at policy check time: no DNS resolution and
    // no ambiguous input. The payload must never run.
    let f = dir.join("al.toml");
    std::fs::write(
        &f,
        "[network]\nmode = \"allowlist\"\nallow = [\"pypi.org:443\"]\n",
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
    assert_eq!(
        out.status.code(),
        Some(3),
        "invalid policy exit code: {stderr}"
    );
    assert!(
        stderr.contains("hostnames are not supported"),
        "must name the bad entry: {stderr}"
    );
    // No report: the run was rejected before any sandbox was spawned.
    assert!(
        out.stdout.is_empty(),
        "invalid policy must not produce a report"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The real allowlist proof: a live TCP listener on an allowed port answers
/// the payload, a live listener on a denied port never sees a connection,
/// and the JSON report is still produced with no kill reason.
///
/// This is environment-gated like the other end-to-end tests, but it runs
/// on the reference WSL host (see docs/agent/ENV.md).
#[test]
fn run_allowlist_permits_listed_connect_and_denies_others() {
    if !env_ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }

    let allowed_listener = TcpListener::bind("127.0.0.1:0").expect("bind allowed port");
    allowed_listener.set_nonblocking(true).expect("nonblocking");
    let allowed_port = allowed_listener.local_addr().unwrap().port();

    let denied_listener = TcpListener::bind("127.0.0.1:0").expect("bind denied port");
    denied_listener.set_nonblocking(true).expect("nonblocking");
    let denied_port = denied_listener.local_addr().unwrap().port();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            match allowed_listener.accept() {
                Ok((mut conn, _)) => {
                    let mut req = [0u8; 4];
                    conn.read_exact(&mut req).expect("read request");
                    conn.write_all(b"pong").expect("write reply");
                    return req;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("allowed listener failed: {e}"),
            }
        }
    });

    let dir = std::env::temp_dir().join(format!("cara-cli-allow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("allow.toml");
    std::fs::write(
        &policy,
        format!("[network]\nmode = \"allowlist\"\nallow = [\"127.0.0.1:{allowed_port}\"]\n"),
    )
    .unwrap();

    let script = format!(
        "import socket\n\
         s = socket.create_connection(('127.0.0.1', {allowed_port}), timeout=5)\n\
         s.sendall(b'ping')\n\
         print('allowed:' + s.recv(4).decode())\n\
         s.close()\n\
         try:\n\
         \x20   s2 = socket.create_connection(('127.0.0.1', {denied_port}), timeout=5)\n\
         \x20   print('denied:unexpected-success')\n\
         \x20   s2.close()\n\
         except (ConnectionRefusedError, PermissionError):\n\
         \x20   print('denied:refused')\n"
    );
    let out = cara()
        .args([
            "run",
            "--policy",
            policy.to_str().unwrap(),
            "--json",
            "--",
            "/usr/bin/python3",
            "-c",
            &script,
        ])
        .output()
        .unwrap();
    let stderr_cli = String::from_utf8_lossy(&out.stderr);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("no JSON report: {e}; cli stderr={stderr_cli}"));

    assert_eq!(
        report["exit_code"], 0,
        "allowed connect must work; denied connect must be a clean refusal: {report}"
    );
    assert!(
        report["kill_reason"].is_null(),
        "the sandbox must keep running after a denied connect: {report}"
    );
    let stdout = report["stdout"].as_str().unwrap();
    assert!(
        stdout.contains("allowed:pong"),
        "allowed connect failed: {stdout}"
    );
    assert!(
        stdout.contains("denied:refused"),
        "denied connect must raise ConnectionRefusedError: {stdout}"
    );

    let sandbox_stderr = report["stderr"].as_str().unwrap();
    assert!(
        sandbox_stderr.contains(&format!("allow connect 127.0.0.1:{allowed_port}")),
        "decision log missing allow line: {sandbox_stderr}"
    );
    assert!(
        sandbox_stderr.contains(&format!("deny connect 127.0.0.1:{denied_port}")),
        "decision log missing deny line: {sandbox_stderr}"
    );

    assert_eq!(
        server.join().expect("server thread"),
        *b"ping",
        "the allowed listener did not receive the payload's request"
    );
    match denied_listener.accept() {
        Ok(_) => panic!("a denied connect reached the listener"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("denied listener error: {e}"),
    }
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
