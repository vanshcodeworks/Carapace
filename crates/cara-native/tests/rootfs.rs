//! C2 rootfs tests: filesystem isolation properties of the sandbox.

use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::Duration;

fn backend() -> NativeBackend {
    NativeBackend::new()
}

fn maybe_skip(b: &NativeBackend) -> bool {
    !b.environment().ready()
}

fn sh(script: &str) -> SandboxSpec {
    SandboxSpec::new("/bin/sh")
        .args(["-c", script])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(15))
        .max_output(4 * 1024 * 1024)
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let mut h = backend().spawn(&spec).expect("spawn");
    h.wait().expect("wait")
}

fn sh_out(script: &str) -> (i32, String, String) {
    let r = run(sh(script));
    (
        r.exit_code.unwrap_or(-1),
        String::from_utf8_lossy(&r.stdout).into_owned(),
        String::from_utf8_lossy(&r.stderr).into_owned(),
    )
}

#[test]
fn etc_is_sandbox_owned_not_host() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (code, out, _) = sh_out("cat /etc/passwd");
    assert_eq!(code, 0);
    assert!(
        out.contains("carapace-sandbox-marker"),
        "passwd must be the sandbox's own"
    );
    // The host dev user (uid 1000) must NOT be visible.
    assert!(!out.contains("dev:"), "host users leaked: {out}");
}

#[test]
fn usr_is_read_only() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (code, _, err) = sh_out("echo x > /usr/bin/cara-probe 2>&1; echo rc=$?");
    let _ = code;
    assert!(
        err.contains("Read-only file system"),
        "writes to /usr must fail with EROFS, got: {err}"
    );
    // Host check: nothing appeared there for real.
    assert!(std::fs::metadata("/usr/bin/cara-probe").is_err());
}

#[test]
fn host_paths_are_absent() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    for p in ["/home", "/root", "/etc/shadow", "/var"] {
        let (_, out, _) = sh_out(&format!("ls {p} 2>&1 || true"));
        assert!(
            out.contains("No such file or directory"),
            "{p} must not exist inside the sandbox, saw: {out}"
        );
    }
}

#[test]
fn proc_shows_only_own_processes() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (_, out, _) = sh_out("ls /proc | grep -E '^[0-9]+$' | sort -n | tail -1");
    let max_pid: i64 = out.trim().parse().unwrap_or(999);
    assert!(
        max_pid <= 10,
        "fresh PID namespace must not expose host pids, saw max pid {max_pid}"
    );
}

#[test]
fn sys_is_not_mounted() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (_, out, _) = sh_out("ls /sys 2>&1; cat /proc/mounts | grep -c sysfs || true");
    assert!(
        !out.contains("sysfs"),
        "/sys must not be mounted inside the sandbox: {out}"
    );
}

#[test]
fn dev_has_only_safe_devices() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (code, out, _) = sh_out("ls /dev; echo hi > /dev/null && echo devnull-ok");
    assert_eq!(code, 0);
    assert!(out.contains("devnull-ok"), "/dev/null must work: {out}");
    for absent in ["sda", "tty", "pts", "mem", "kvm"] {
        assert!(
            !out.contains(absent),
            "/dev must not expose {absent}: {out}"
        );
    }
}

#[test]
fn work_is_writable_and_capped() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // 16 MiB scratch; ask for 64 MiB → must fail with ENOSPC.
    let mut spec = sh("dd if=/dev/zero of=/work/big bs=1M count=64 2>&1; echo rc=$?");
    spec.limits.scratch_bytes = 16 * 1024 * 1024;
    let r = run(spec);
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("No space left on") || out.contains("rc=1"),
        "oversized writes must fail, got: {out}"
    );
    // Small writes fine.
    let (code, out2, _) = sh_out("echo payload > /work/f.txt && cat /work/f.txt");
    assert_eq!(code, 0);
    assert!(out2.contains("payload"));
}

#[test]
fn old_root_is_gone() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let (_, out, _) = sh_out("ls /.cara-old 2>&1; ls / | tr '\\n' ' '");
    assert!(
        out.contains("No such file or directory"),
        "old root must be detached: {out}"
    );
}

#[test]
fn python3_hello_world() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if std::fs::metadata("/usr/bin/python3").is_err() {
        eprintln!("skipping: no python3 on host");
        return;
    }
    let spec = SandboxSpec::new("/usr/bin/python3")
        .args([
            "-c",
            "import platform; print(6*7); print(platform.machine())",
        ])
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/work")
        .timeout(Duration::from_secs(30));
    let r = run(spec);
    assert_eq!(
        r.exit_code,
        Some(0),
        "python3 must run: {:?}",
        String::from_utf8_lossy(&r.stderr)
    );
    let out = String::from_utf8_lossy(&r.stdout);
    assert!(out.contains("42"), "python computed: {out}");
    assert!(out.contains("x86_64"));
}

#[test]
fn no_staging_dirs_leak_on_host() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let before = count_staging();
    let _ = run(sh("echo done"));
    let after = count_staging();
    assert_eq!(before, after, "staging dirs must be cleaned up");
}

fn count_staging() -> usize {
    std::fs::read_dir("/tmp")
        .map(|d| {
            d.flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with("cara-root.")
                })
                .count()
        })
        .unwrap_or(0)
}
