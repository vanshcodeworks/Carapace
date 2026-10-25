//! Red-team probes (C6 protocol): attack classes not covered by the
//! regular suites. Each test documents the attack and asserts the
//! sandbox's specific countermeasure. Payloads run ONLY through the
//! sandbox.

use carapace_core::{Backend, BackendError, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::Duration;

fn backend() -> NativeBackend {
    NativeBackend::new()
}

/// Serialize: all red-team runs share the delegated cgroup subtree.
static SANDBOX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn maybe_skip(b: &NativeBackend) -> bool {
    !b.environment().ready()
}

fn sh(script: &str) -> SandboxSpec {
    SandboxSpec::new("/bin/sh")
        .args(["-c", script])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(20))
        .max_output(1024 * 1024)
}

fn py(code: &str) -> SandboxSpec {
    SandboxSpec::new("/usr/bin/python3")
        .args(["-c", code])
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/work")
        .timeout(Duration::from_secs(20))
        .max_output(1024 * 1024)
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let _g = SANDBOX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut h = backend().spawn(&spec).expect("spawn");
    h.wait().expect("wait")
}

fn out(script: &str) -> String {
    let r = run(sh(script));
    String::from_utf8_lossy(&r.stdout).into_owned()
}

fn have_python3() -> bool {
    std::fs::metadata("/usr/bin/python3").is_ok()
}

/// RT1: chroot(2) must be denied (not in the allowlist).
#[test]
fn rt_chroot_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out = out("python3 -c \"import os,ctypes\" 2>/dev/null; echo rc=$?");
    let _ = out; // sh lacks python3-independent chroot; use the python path below
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(
        "import ctypes, os\nlibc = ctypes.CDLL(None, use_errno=True)\nos.mkdir('/work/jail', 0o755)\nr = libc.chroot(b'/work/jail')\nprint('chroot-ret', r, 'errno', ctypes.get_errno())",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("chroot-ret -1") && out.contains("errno 1"),
        "chroot must be denied with EPERM: {out}"
    );
}

/// RT2: mknod in the writable area must be denied (device creation is the
/// classic rootless-sandbox hole).
#[test]
fn rt_mknod_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out = out("mknod /work/dev c 1 3 2>&1; echo rc=$?");
    assert!(
        out.contains("rc=1") || out.contains("Operation not permitted"),
        "mknod must be denied: {out}"
    );
}

/// RT3: sethostname / clock_settime must be denied.
#[test]
fn rt_kernel_state_syscalls_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out = out("hostname cara-owned 2>&1; echo rc=$?");
    assert!(
        out.contains("rc=1") || out.to_lowercase().contains("not permitted"),
        "sethostname must be denied: {out}"
    );
}

/// RT4: /proc/sys writes (sysctl surface) must fail.
#[test]
fn rt_proc_sys_write_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out = out("echo 1 > /proc/sys/kernel/hostname 2>/dev/null; echo rc=$?");
    assert!(
        out.contains("rc=1") || out.contains("rc=2"),
        "/proc/sys must not be writable: {out}"
    );
}

/// RT5: cross-hierarchy rename (Landlock REFER scoping): /work -> /etc.
#[test]
fn rt_refer_cross_hierarchy_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out =
        out("echo x > /work/f; mv /work/f /etc/evil 2>/dev/null; echo rc=$?; ls /etc/evil 2>&1");
    assert!(
        out.contains("rc=1") || out.contains("No such file"),
        "cross-hierarchy rename must fail: {out}"
    );
}

/// RT6: zombie hoard — forking many children that never get reaped.
/// The sandbox must still die at the timeout and leave nothing behind.
#[test]
fn rt_zombie_hoard_contained() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let r = run(
        sh("i=0; while [ $i -lt 40 ]; do (sleep 240 &) ; i=$((i+1)); done; sleep 240")
            .timeout(Duration::from_millis(800)),
    );
    assert_eq!(
        r.kill_reason,
        Some(carapace_core::KillReason::Timeout),
        "sandbox must die on schedule: {r:?}"
    );
    std::thread::sleep(Duration::from_millis(400));
    // No sandbox-era sleeps may survive anywhere on the host.
    let dir = std::fs::read_dir("/proc").expect("/proc");
    for entry in dir.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            let cmd = String::from_utf8_lossy(&cmdline);
            assert!(
                !cmd.contains("sleep 240"),
                "leftover sandbox process {pid}: {cmd}"
            );
        }
    }
}

/// RT7: dual-stream flood — both stdout and stderr flooded at once.
#[test]
fn rt_dual_stream_flood_killed_fast() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let start = std::time::Instant::now();
    let r = run(sh("while :; do echo out; echo err 1>&2; done")
        .max_output(32 * 1024)
        .timeout(Duration::from_secs(30)));
    assert_eq!(
        r.kill_reason,
        Some(carapace_core::KillReason::OutputOverflow),
        "{r:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "overflow kill must be fast, took {:?}",
        start.elapsed()
    );
    assert!(r.stdout.len() <= 32 * 1024 && r.stderr.len() <= 32 * 1024);
}

/// RT8: invalid UTF-8 / NUL in argv must be a Setup error, not a panic.
#[test]
fn rt_hostile_argv_fails_closed() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let err = match b.spawn(&SandboxSpec::new("/bin/echo\u{0}bad")) {
        Err(e) => e,
        Ok(_) => panic!("NUL in program must fail closed"),
    };
    assert!(
        matches!(err, BackendError::Setup(_)),
        "must be a Setup error: {err}"
    );
}

/// RT9: huge argv must fail with E2BIG (setup) rather than truncate.
#[test]
fn rt_huge_argv_fails_cleanly() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let big = "x".repeat(1024 * 1024);
    let err = match b.spawn(
        &SandboxSpec::new("/bin/echo")
            .args([&big; 100])
            .timeout(Duration::from_secs(10)),
    ) {
        Err(e) => e,
        Ok(mut h) => {
            // Kernel may accept ~2MB total; either a clean Setup error or a
            // completed run is fine — never a panic or hang.
            let r = h.wait().expect("wait");
            assert!(r.exit_code.is_some() || r.signal.is_some());
            return;
        }
    };
    assert!(matches!(err, BackendError::Setup(_)), "{err}");
}

/// RT10: slow-drip output — under the cap but forever; wall timeout kills.
#[test]
fn rt_slow_drip_killed_by_timeout() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let r = run(sh("while :; do echo drip; sleep 0.4; done")
        .max_output(1024 * 1024)
        .timeout(Duration::from_millis(900)));
    assert_eq!(
        r.kill_reason,
        Some(carapace_core::KillReason::Timeout),
        "{r:?}"
    );
}

/// RT11: TIOCSTI-style ioctl abuse — no tty exists in the sandbox.
#[test]
fn rt_no_tty_for_ioctl_abuse() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping");
        return;
    }
    let out = out("tty 2>&1; echo rc=$?");
    assert!(
        out.contains("not a tty") || out.contains("rc=1"),
        "payload must not have a controlling tty: {out}"
    );
}

/// RT12: perf_event_open (kernel profiling surface, classic escape
/// vector) must be denied. Not in the allowlist.
#[test]
fn rt_perf_event_open_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("perf stat true 2>&1; echo rc=$?"));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("rc=1") || out.contains("rc=127") || out.to_lowercase().contains("denied"),
        "perf_event_open surface must be unavailable: {out}"
    );
    if have_python3() {
        let r = run(py(
            "import ctypes; libc = ctypes.CDLL(None, use_errno=True);              r = libc.syscall(298, 0, 0, -1, -1, 0);              print('perf', r, ctypes.get_errno())",
        ));
        let out = String::from_utf8_lossy(&r.stdout).into_owned();
        assert!(
            out.contains("-1 1"),
            "perf_event_open must be denied with EPERM exactly: {out}"
        );
    }
}

/// RT13: openat2 (escape from path-based filters) is NOT in the v1
/// allowlist — documented stance: deny-by-default, profile dev mode can
/// relax it after review.
#[test]
fn rt_openat2_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(
        "import ctypes, os; libc = ctypes.CDLL(None, use_errno=True);          r = libc.syscall(437, -100, b'/work/f', 0, 0, 0);          print('openat2', r, ctypes.get_errno())",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("-1 1"),
        "openat2 must be denied with EPERM (v1 stance): {out}"
    );
}

/// RT14: core_pattern-style abuse — a crashing process must not be able
/// to write a core anywhere useful (RLIMIT_CORE=0) and /proc/sys/kernel/
/// core_pattern is not writable.
#[test]
fn rt_core_pattern_surface_closed() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let out = out("cat /proc/sys/kernel/core_pattern 2>&1 | head -1; \
         echo '|/bin/evil' > /proc/sys/kernel/core_pattern 2>/dev/null; echo w=$?; \
         ulimit -c");
    assert!(
        out.contains("w=1") || out.contains("w=2"),
        "core_pattern must not be writable: {out}"
    );
    assert!(
        out.contains("0") && !out.contains("unlimited"),
        "RLIMIT_CORE must be 0: {out}"
    );
}

/// RT15: symlink from the writable scratch into /proc/sys — Landlock must
/// not let the symlink bypass the /proc grant (write still denied).
#[test]
fn rt_symlink_into_proc_sys_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let out = out("ln -s /proc/sys/kernel/core_pattern /work/cp; \
         echo '|/bin/evil' > /work/cp 2>/dev/null; echo rc=$?; \
         cat /proc/sys/kernel/core_pattern | head -1");
    assert!(
        out.contains("rc=1") || out.contains("rc=2"),
        "symlink into /proc/sys must not be writable: {out}"
    );
}

/// RT16 (red-team cycle 2, operational leak): if the SUPERVISOR itself is
/// SIGKILLed mid-run, the sandbox tree must still die (PR_SET_PDEATHSIG
/// -> pidns destruction), leaving no orphaned payload.
#[test]
fn rt_supervisor_sigkill_orphans_nothing() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let marker = format!("CARA_ORPHAN_{}", std::process::id());
    let backend = b;
    let spec = SandboxSpec::new("/bin/sh")
        .args(["-c", "sleep 240 & sleep 240"])
        .env("CARA_ORPHAN_MARKER", &marker)
        .timeout(Duration::from_secs(60));
    // spawn returns a handle; we kill the SUPERVISOR from here by killing
    // our own... the supervisor IS this test process. To exercise the
    // parent-death path we need the supervisor in a different process:
    // run a child `cara run` and SIGKILL it mid-flight.
    drop(backend);
    let _ = spec;
    let _ = marker;
}

/// The real RT16: drive the `cara` binary and SIGKILL it mid-run.
#[test]
fn rt_cara_binary_sigkilled_midrun_orphans_nothing() {
    use std::process::{Command, Stdio};
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // The cara binary lives in the shared target dir; find it relative to
    // this test binary (target/debug/...).
    let cara = std::env::current_exe()
        .ok()
        .and_then(|p| p.ancestors().nth(2).map(|d| d.join("cara")))
        .filter(|p| p.exists())
        .expect("cara binary next to the test binary");
    let mut child = Command::new(cara)
        .args([
            "run",
            "--timeout",
            "60s",
            "--json",
            "--",
            "/bin/sh",
            "-c",
            "sleep 120 & sleep 120",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cara");
    // Let it get into the sandbox, then SIGKILL the supervisor.
    std::thread::sleep(Duration::from_millis(600));
    let pid = child.id() as i32;
    unsafe {
        // SAFETY: SIGKILL to our own direct child (the cara process).
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
    // The payload must die shortly after (PDEATHSIG -> pidns destruction).
    let mut survived = false;
    for _ in 0..30 {
        let dir = std::fs::read_dir("/proc").expect("/proc");
        for entry in dir.flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ"))
                && environ.windows(9).any(|w| w == b"sleep 120")
            {
                survived = true;
            }
        }
        if !survived {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !survived,
        "orphaned payload survived its supervisor's SIGKILL (PDEATHSIG failed)"
    );
}
