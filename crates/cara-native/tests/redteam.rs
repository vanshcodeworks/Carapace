//! Red-team probes (C6 protocol): attack classes not covered by the
//! regular suites. Each test documents the attack and asserts the
//! sandbox's specific countermeasure. Payloads run ONLY through the
//! sandbox.

use carapace_core::report::KillReason;
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
/// SIGKILLed mid-run, the sandbox tree must still die — stage-1 AND
/// stage-2 both arm PR_SET_PDEATHSIG (fork clears it for the child) — so
/// no orphaned payload survives.
#[test]
fn rt_cara_binary_sigkilled_midrun_orphans_nothing() {
    use std::process::{Command, Stdio};
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // Unique token in the shell's cmdline (it is the pidns init; if it
    // survives, every payload descendant does).
    let marker = format!(
        "CARA_RT16_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    // The cara binary lives in the shared target dir; find it relative to
    // this test binary (target/debug/...).
    let cara = std::env::current_exe()
        .ok()
        .and_then(|p| p.ancestors().nth(2).map(|d| d.join("cara")))
        .filter(|p| p.exists())
        .expect("cara binary next to the test binary");
    let payload = format!("sleep 120 & wait # {marker}");
    let mut child = Command::new(cara)
        .args(["run", "--timeout", "60s", "--json", "--", "/bin/sh", "-c"])
        .arg(&payload)
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
    // The payload must die shortly after (PDEATHSIG on stage-2 ->
    // pidns destruction).
    let mut survived = false;
    for _ in 0..30 {
        let dir = std::fs::read_dir("/proc").expect("/proc");
        for entry in dir.flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline"))
                && cmdline
                    .windows(marker.len())
                    .any(|w| w == marker.as_bytes())
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

// ---------------- red-team cycle 3: concurrency, leaks, API misuse -------

/// RT17: concurrent sandboxes must not cross-contaminate — 8 parallel runs
/// each write their own marker; every report contains exactly its own.
#[test]
fn rt_concurrent_sandboxes_isolated() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let mut handles = Vec::new();
    for i in 0..8 {
        let spec = SandboxSpec::new("/bin/sh")
            .args(["-c", &format!("echo marker-{i}; sleep 0.3; echo end-{i}")])
            .env("PATH", "/usr/bin:/bin")
            .timeout(Duration::from_secs(20));
        handles.push((
            i,
            std::thread::spawn(move || {
                let mut h = NativeBackend::new().spawn(&spec).expect("spawn");
                h.wait().expect("wait")
            }),
        ));
    }
    for (i, h) in handles {
        let r = h.join().expect("thread");
        let out = String::from_utf8_lossy(&r.stdout).into_owned();
        assert!(
            out.contains(&format!("marker-{i}")),
            "own marker missing: {out:?}"
        );
        assert!(
            !out.contains(&format!("marker-{}", (i + 1) % 8)),
            "cross-contamination in report for {i}: {out:?}"
        );
    }
}

/// RT22: concurrent long-running sandboxes must not deadlock. Stage-1 is a
/// fork of the embedding process, so it inherits every open descriptor. If
/// it keeps them, a long-lived stage-1 holds another sandbox's status/result
/// pipe write ends; that sandbox's `spawn` then blocks on EOF *before* its
/// timeout can start. Four infinite payloads with a 1 s timeout must all
/// return `Timeout` well inside the watchdog window.
#[test]
fn rt_concurrent_long_running_sandboxes_do_not_deadlock() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    const N: usize = 4;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(N + 1));
    let (tx, rx) = std::sync::mpsc::channel();
    for i in 0..N {
        let barrier = std::sync::Arc::clone(&barrier);
        let tx = tx.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let spec = SandboxSpec::new("/bin/sh")
                .args(["-c", "while :; do :; done"])
                .env("PATH", "/usr/bin:/bin")
                .timeout(Duration::from_secs(1));
            let r = match NativeBackend::new().spawn(&spec) {
                Ok(mut h) => h.wait(),
                Err(e) => Err(e),
            };
            let _ = tx.send((i, r));
        });
    }
    drop(tx);
    barrier.wait();
    for _ in 0..N {
        let (i, r) = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("concurrent sandboxes deadlocked: no result within 30s");
        let r = r.expect("wait");
        assert_eq!(
            r.kill_reason,
            Some(KillReason::Timeout),
            "sandbox {i} did not time out: {r:?}"
        );
    }
}

/// RT18: resource leaks across many sequential runs — fd count and memory
/// must return to baseline (close_range + Drop hygiene).
#[test]
fn rt_no_resource_leaks_over_many_runs() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let fd_count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    // Hold the sandbox lock for the whole measurement window: sibling
    // tests in this binary spawn sandboxes concurrently and legitimately
    // hold pipe fds while they run, which made a tight tolerance flaky
    // (observed before=17 after=23 on a fresh parallel run — concurrent
    // churn, not a per-run leak; each sandbox's fds are CLOEXEC or closed
    // in Drop by construction).
    let _guard = SANDBOX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Warm up (threads, caches) then measure around 30 runs.
    for _ in 0..3 {
        let mut h = b.spawn(&sh("true")).unwrap();
        h.wait().unwrap();
    }
    let before = fd_count();
    for _ in 0..30 {
        let mut h = b.spawn(&sh("true")).unwrap();
        h.wait().unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    let after = fd_count();
    // Small slack remains for the two cara-subprocess tests, which spawn
    // the CLI binary without this lock.
    assert!(
        after <= before + 6,
        "descriptor leak suspected: before={before} after={after}"
    );
}

/// RT19: wait() called twice must fail cleanly, not panic or double-report.
#[test]
fn rt_double_wait_is_clean_error() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let mut h = b.spawn(&sh("true")).unwrap();
    let r1 = h.wait().expect("first wait");
    assert_eq!(r1.exit_code, Some(0));
    let err = match h.wait() {
        Err(e) => e,
        Ok(_) => panic!("double wait must not re-report success"),
    };
    assert!(
        matches!(err, carapace_core::BackendError::Supervision(_)),
        "second wait must be a Supervision error: {err}"
    );
}

/// RT20: zero output cap — any write is an immediate overflow kill.
#[test]
fn rt_zero_output_cap_kills_immediately() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("echo hi").max_output(0).timeout(Duration::from_secs(10)));
    assert_eq!(r.kill_reason, Some(KillReason::OutputOverflow), "{r:?}");
    assert!(r.stdout.is_empty());
}

/// RT21: stdin is empty — a reader gets EOF, not a hang.
#[test]
fn rt_stdin_reads_eof() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let start = std::time::Instant::now();
    let r = run(sh("cat; echo survived-stdin-eof").timeout(Duration::from_secs(10)));
    assert_eq!(r.exit_code, Some(0));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(out.contains("survived-stdin-eof"), "{out:?}");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "must not block on stdin: {:?}",
        start.elapsed()
    );
}

// ---------------- red-team cycle 4: kernel surfaces, inheritance, isolation --

/// RT23: the new mount API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`,
/// `fsmount`, `fspick`, `mount_setattr`) is not in the allowlist. A mount
/// escape must be denied before argument validation, so every call returns
/// EPERM even with deliberately invalid arguments.
#[test]
fn rt_new_mount_api_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
calls = [("open_tree", 428), ("move_mount", 429), ("fsopen", 430),
         ("fsconfig", 431), ("fsmount", 432), ("fspick", 433),
         ("mount_setattr", 442)]
for name, nr in calls:
    ctypes.set_errno(0)
    ret = libc.syscall(nr, 0, 0, 0, 0, 0)
    print(name, ret, ctypes.get_errno())
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 7, "expected one line per syscall: {out:?}");
    for line in lines {
        assert!(
            line.ends_with("-1 1"),
            "mount API syscall not denied with EPERM: {line:?} (full: {out:?})"
        );
    }
}

/// RT24: Landlock REFER scoping covers hardlinks too, not just rename.
/// Linking a writable file into read-only `/etc` (and the reverse) must be
/// denied, and neither destination may appear.
#[test]
fn rt_cross_hierarchy_hardlink_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import os
open('/work/src', 'w').write('x')
for src, dst, label in [('/work/src', '/etc/rt24-link', 'out'),
                        ('/etc/passwd', '/work/passwd-link', 'in')]:
    try:
        os.link(src, dst)
        print(label, 'allowed')
    except OSError as e:
        print(label, 'denied', e.errno)
print('out-exists', os.path.exists('/etc/rt24-link'))
print('in-exists', os.path.exists('/work/passwd-link'))
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("out denied"),
        "link into /etc allowed: {out:?}"
    );
    assert!(
        out.contains("in denied"),
        "link from /etc into /work allowed: {out:?}"
    );
    assert!(
        out.contains("out-exists False") && out.contains("in-exists False"),
        "a cross-hierarchy link landed: {out:?}"
    );
}

/// RT25: `renameat2(RENAME_EXCHANGE)` across a Landlock hierarchy boundary
/// must fail and leave both files untouched (RT5 covers plain rename).
#[test]
fn rt_rename_exchange_across_hierarchy_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import ctypes, os
open('/work/a', 'w').write('A')
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ret = libc.syscall(316, -100, b'/work/a', -100, b'/etc/passwd', 2)
print('exchange', ret, ctypes.get_errno())
print('a', open('/work/a').read())
print('passwd', open('/etc/passwd').read().split(':')[0])
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("exchange -1") && !out.contains("exchange -1 0"),
        "RENAME_EXCHANGE across /work -> /etc must fail: {out:?}"
    );
    assert!(out.contains("a A"), "/work/a was swapped: {out:?}");
    assert!(
        out.contains("passwd root"),
        "/etc/passwd was swapped: {out:?}"
    );
}

/// RT26: `/tmp` and `/dev/shm` are fresh per-run tmpfs mounts. A marker
/// written by one sandbox must be invisible to the next, and a host file in
/// `/tmp` must be invisible inside.
#[test]
fn rt_tmp_and_shm_are_not_shared() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let host_marker = format!("/tmp/cara-rt26-host-{}", std::process::id());
    std::fs::write(&host_marker, b"host").expect("write host marker");

    let a = run(sh(
        "echo sandbox > /tmp/cara-rt26 && echo sandbox > /dev/shm/cara-rt26 && echo wrote",
    ));
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("wrote"),
        "first sandbox could not write markers: {a:?}"
    );

    let b_run = run(sh(&format!(
        "test -e /tmp/cara-rt26 && echo tmp-leak; \
         test -e /dev/shm/cara-rt26 && echo shm-leak; \
         test -e {host_marker} && echo host-leak; echo checked"
    )));
    let out = String::from_utf8_lossy(&b_run.stdout).into_owned();
    assert!(out.contains("checked"), "second sandbox failed: {out:?}");
    assert!(
        !out.contains("tmp-leak") && !out.contains("shm-leak") && !out.contains("host-leak"),
        "/tmp or /dev/shm leaked across sandboxes or from the host: {out:?}"
    );
    let _ = std::fs::remove_file(&host_marker);
}

/// RT27: a seccomp filter installed before exec applies to every thread the
/// payload creates. A worker thread must get EPERM for `socket(2)` exactly
/// like the main thread.
#[test]
fn rt_threads_inherit_seccomp() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import socket, threading
result = []
def attempt():
    try:
        socket.socket()
        result.append('allowed')
    except OSError as e:
        result.append('denied:%d' % e.errno)
t = threading.Thread(target=attempt)
t.start()
t.join()
print(result[0])
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("denied:1"),
        "seccomp did not apply to a payload thread: {out:?}"
    );
}

/// RT28: Landlock and seccomp survive fork+exec. A payload-spawned child
/// cannot write into read-only /etc and cannot create a socket either.
#[test]
fn rt_exec_inherits_landlock_and_seccomp() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import os, subprocess
w = subprocess.run(['/bin/sh', '-c', 'echo x > /etc/rt28-escape'],
                   capture_output=True, text=True)
s = subprocess.run(['/usr/bin/python3', '-c', 'import socket; socket.socket()'],
                   capture_output=True, text=True)
print('write-rc', w.returncode)
print('sock-rc', s.returncode)
print('escaped', os.path.exists('/etc/rt28-escape'))
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        !out.contains("write-rc 0"),
        "exec'd child wrote into /etc: {out:?}"
    );
    assert!(
        !out.contains("sock-rc 0"),
        "exec'd child created a socket: {out:?}"
    );
    assert!(
        out.contains("escaped False"),
        "write-then-exec child left a file in /etc: {out:?}"
    );
}

/// RT29: kernel information-leak syscalls are absent from the allowlist and
/// must fail with EPERM end to end (unit tests cover the list; this proves
/// the installed filter).
#[test]
fn rt_kernel_info_leak_syscalls_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
calls = [("syslog", 103), ("name_to_handle_at", 303),
         ("open_by_handle_at", 304), ("process_vm_readv", 310),
         ("process_vm_writev", 311), ("kcmp", 312), ("bpf", 321),
         ("userfaultfd", 323)]
for name, nr in calls:
    ctypes.set_errno(0)
    ret = libc.syscall(nr, 0, 0, 0, 0, 0)
    print(name, ret, ctypes.get_errno())
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 8, "expected one line per syscall: {out:?}");
    for line in lines {
        assert!(
            line.ends_with("-1 1"),
            "kernel info-leak syscall not denied with EPERM: {line:?} (full: {out:?})"
        );
    }
}

/// RT30: Landlock cannot mediate execution of an anonymous memfd, but
/// `execveat(2)` is not in the allowlist, so the memfd-exec bypass must be
/// closed by seccomp with EPERM (not ENOEXEC/EFAULT, which would mean the
/// syscall ran).
#[test]
fn rt_memfd_execveat_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py(r#"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.syscall(319, b'cara-rt30', 0)
print('memfd', fd)
os.write(fd, b'\x7fELF' + b'\x00' * 64)
ctypes.set_errno(0)
ret = libc.syscall(322, fd, b'', 0, 0, 0x1000)
print('execveat', ret, ctypes.get_errno())
"#));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("memfd 3"),
        "memfd_create should be allowed for ordinary payloads: {out:?}"
    );
    assert!(
        out.contains("execveat -1 1"),
        "execveat must be denied with EPERM before it can run the memfd: {out:?}"
    );
}

/// RT31: `execve` is not the only way to run written code — a payload can
/// `mmap(PROT_EXEC)` its own file. Landlock's EXECUTE right is checked on
/// that mapping too, so the mapping must fail while an anonymous executable
/// mapping (JITs, Node/V8) still works. This is the positive/negative pair
/// the `exec_on_write` claim needs; a regression here would allow
/// write-then-exec without `execve(2)`.
#[test]
fn rt_mmap_exec_of_written_file_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let code = r#"
import mmap, os
path = '/work/rt31'
with open(path, 'wb') as f:
    f.write(b'\x90' * 16)
fd = os.open(path, os.O_RDONLY)
try:
    m = mmap.mmap(fd, 16, prot=mmap.PROT_READ | mmap.PROT_EXEC)
    print('file-mapped')
    m.close()
except OSError as e:
    print('file-denied', e.errno)
try:
    anon = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    print('anon-mapped')
    anon.close()
except OSError as e:
    print('anon-denied', e.errno)
"#;
    let r = run(py(code));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        !out.contains("file-mapped"),
        "mmap(PROT_EXEC) of a written file succeeded: {out:?}"
    );
    assert!(
        out.contains("file-denied 1"),
        "expected EPERM from the noexec mount on the file mapping: {out:?}"
    );
    assert!(
        out.contains("anon-mapped"),
        "anonymous executable mappings must stay allowed (JITs): {out:?}"
    );

    // Positive control: the same mapping must work when the policy opts in,
    // proving the denial comes from exec_on_write and not an unrelated
    // mmap restriction.
    let allowed = run(py(code).exec_on_write(true));
    let out = String::from_utf8_lossy(&allowed.stdout).into_owned();
    assert!(
        out.contains("file-mapped"),
        "exec_on_write = true must permit the file mapping: {out:?}"
    );
}
