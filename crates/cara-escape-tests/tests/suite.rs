//! C6 escape suite: every catalog payload runs through the REAL sandbox.
//!
//! Hard rule: a payload is NEVER executed on the host. The only execution
//! path here is `NativeBackend::spawn` behind the doctor gate (fail closed,
//! threat-model §6) — if the environment is not Tier 1 ready, the cases
//! skip and nothing runs. For every catalog entry the suite asserts the
//! documented safe outcome plus host-side invariants: no leftover payload
//! processes (host /proc scan) and no files planted on the host.

use carapace_core::report::KillReason;
use carapace_core::{Backend, ExitReport, SandboxSpec};
use carapace_escape_tests::{Catalog, EscapeTest, Language};
use carapace_native::NativeBackend;
use std::time::Duration;

fn backend() -> NativeBackend {
    NativeBackend::new()
}

fn maybe_skip(b: &NativeBackend) -> bool {
    !b.environment().ready()
}

fn have_python3() -> bool {
    std::fs::metadata("/usr/bin/python3").is_ok()
}

fn sh(script: &str) -> SandboxSpec {
    SandboxSpec::new("/bin/sh")
        .args(["-c", script])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(10))
        .max_output(4 * 1024 * 1024)
}

fn py(code: &str) -> SandboxSpec {
    SandboxSpec::new("/usr/bin/python3")
        .args(["-c", code])
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/work")
        .timeout(Duration::from_secs(15))
        .max_output(4 * 1024 * 1024)
}

/// Builds the spec for one catalog entry: the language-appropriate base
/// plus the per-entry limit tweaks that keep runaway payloads fast and
/// deterministic.
fn spec_for(e: &EscapeTest) -> SandboxSpec {
    let mut spec = match e.language {
        Language::Sh => sh(e.payload),
        Language::Python => py(e.payload),
    };
    match e.id {
        "fork_bomb" => {
            spec.limits.timeout = Duration::from_secs(5);
            spec.limits.max_processes = 32;
        }
        "memory_hog" => {
            spec.limits.memory_bytes = 64 * 1024 * 1024;
            spec.limits.timeout = Duration::from_secs(15);
        }
        "cpu_spin" => {
            spec.limits.timeout = Duration::from_secs(4);
        }
        "disk_filler" => {
            spec.limits.scratch_bytes = 16 * 1024 * 1024;
            spec.limits.timeout = Duration::from_secs(15);
        }
        "output_flood" => {
            spec.limits.timeout = Duration::from_secs(5);
            spec.limits.max_output_bytes = 64 * 1024;
        }
        // The env-leak probe defines its exact environment itself: remove
        // the default HOME so the expected set is fully explicit.
        "env_leak" => {
            spec.env.remove("HOME");
            spec.env
                .insert("CARA_ESCAPE_MARKER".to_string(), "c6".to_string());
        }
        _ => {}
    }
    spec
}

fn stdout_of(r: &ExitReport) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}

fn combined_of(r: &ExitReport) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    )
}

/// Runs one catalog entry through the real sandbox and verifies every
/// documented claim about the outcome.
fn run_and_verify(id: &'static str) {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let entry = Catalog::get(id).unwrap_or_else(|| panic!("catalog entry {id} missing"));
    if entry.language == Language::Python && !have_python3() {
        eprintln!("skipping: no python3 on host");
        return;
    }
    let spec = spec_for(entry);
    // Fail closed: `spawn` refuses to run anything when the doctor gate is
    // not ready, so a payload can never end up executed unsandboxed.
    let mut h = b.spawn(&spec).expect("sandbox spawn must succeed");
    let r = h.wait().expect("sandbox wait must succeed");
    verify(entry, &r);
    // Host-side invariant for every entry: no process carrying this
    // payload survived the run.
    assert_no_payload_processes(entry.payload);
}

/// The per-entry assertions, one arm per catalog id. Adding a catalog
/// entry without adding its verifier fails the suite here and in
/// `catalog_and_suite_stay_in_sync` below.
fn verify(e: &EscapeTest, r: &ExitReport) {
    match e.id {
        "fork_bomb" => {
            assert!(
                matches!(r.kill_reason, Some(KillReason::Timeout)) || r.exit_code.is_some(),
                "run must end cleanly (timeout kill or self-exit), got {r:?}"
            );
            assert!(
                r.peak_processes.is_none_or(|p| p <= 64),
                "process count must stay near the pids.max cap (32 + accounting \
                 slack), saw {:?}",
                r.peak_processes
            );
            // No `sleep` stragglers survive the sandbox on the host.
            assert_no_payload_processes("sleep 300");
        }
        "memory_hog" => {
            assert_eq!(
                r.kill_reason,
                Some(KillReason::MemoryLimit),
                "must be OOM-killed at the memory limit, got {r:?}"
            );
            assert!(
                r.peak_memory_bytes.is_some_and(|m| m > 32 * 1024 * 1024),
                "peak memory must be recorded near the 64 MiB limit: {:?}",
                r.peak_memory_bytes
            );
            assert!(
                !stdout_of(r).contains("SURVIVED"),
                "the hog must not finish its allocation"
            );
        }
        "cpu_spin" => {
            assert_eq!(
                r.kill_reason,
                Some(KillReason::Timeout),
                "the spin must be killed at the wall timeout, got {r:?}"
            );
            assert!(
                r.wall_time >= Duration::from_millis(3500) && r.wall_time < Duration::from_secs(15),
                "wall time must be bounded by the 4s timeout, got {:?}",
                r.wall_time
            );
            let cpu = r.cpu_time.expect("cpu accounting must be present");
            assert!(
                cpu >= Duration::from_millis(500),
                "the spinner must actually consume cpu: {cpu:?}"
            );
            assert!(
                cpu.as_secs_f64() <= r.wall_time.as_secs_f64() * 1.5 + 0.25,
                "cpu_time must stay near the quota (100% of one core): \
                 cpu={cpu:?} wall={:?}",
                r.wall_time
            );
        }
        "disk_filler" => {
            let out = combined_of(r);
            assert!(
                out.contains("No space left on device")
                    || out.contains("File size limit exceeded")
                    || out.contains("rc=1")
                    || out.contains("rc=153"),
                "the /work fill must hit the RLIMIT_FSIZE / scratch cap: {out}"
            );
            assert!(
                out.contains("No space left on device")
                    || out.contains("rc2=1")
                    || out.contains("rc2=153"),
                "the /tmp fill must hit the 8 MiB root tmpfs cap: {out}"
            );
            // Host-side: nothing was written to the host's /tmp.
            assert!(
                std::fs::metadata("/tmp/big").is_err(),
                "host /tmp/big must not exist"
            );
        }
        "output_flood" => {
            assert_eq!(
                r.kill_reason,
                Some(KillReason::OutputOverflow),
                "must be killed at the output cap, got {r:?}"
            );
            assert!(
                r.stdout.len() <= 64 * 1024,
                "captured output must stay capped, got {} bytes",
                r.stdout.len()
            );
            assert!(
                r.wall_time < Duration::from_secs(5),
                "the cap must fire well before the timeout, got {:?}",
                r.wall_time
            );
        }
        "read_etc_passwd" => {
            assert_eq!(r.exit_code, Some(0), "cat must succeed: {r:?}");
            let out = stdout_of(r);
            assert!(
                out.contains("carapace-sandbox-marker"),
                "passwd must be the sandbox's own: {out}"
            );
            assert!(!out.contains("dev:"), "host users leaked: {out}");
        }
        "read_shadow" => {
            assert_ne!(
                r.exit_code,
                Some(0),
                "reading /etc/shadow must fail, got {r:?}"
            );
            let err = String::from_utf8_lossy(&r.stderr);
            assert!(
                err.contains("No such file or directory"),
                "/etc/shadow must not exist: {err}"
            );
            assert!(
                r.stdout.is_empty(),
                "no shadow content may be printed: {:?}",
                stdout_of(r)
            );
        }
        "read_home" => {
            assert_ne!(r.exit_code, Some(0), "listing /home /root must fail");
            let err = String::from_utf8_lossy(&r.stderr);
            assert!(
                err.matches("No such file or directory").count() >= 2,
                "both /home and /root must be absent: {err}"
            );
        }
        "write_outside" => {
            let out = combined_of(r);
            assert!(
                out.contains("rc1=1") || out.contains("rc1=2"),
                "the /etc write must be denied by Landlock: {out}"
            );
            assert!(
                out.contains("rc2=1") || out.contains("rc2=2"),
                "the /usr write must be denied: {out}"
            );
            assert!(
                out.contains("Read-only file system"),
                "/usr must be EROFS: {out}"
            );
            // Host-side invariants: nothing was planted for real.
            assert!(
                std::fs::metadata("/etc/pwned").is_err(),
                "host /etc/pwned must not exist"
            );
            assert!(
                std::fs::metadata("/usr/pwned").is_err(),
                "host /usr/pwned must not exist"
            );
        }
        "write_then_exec" => {
            let out = combined_of(r);
            assert!(
                !out.contains("CARA-WRITE-THEN-EXEC-ESCAPED"),
                "a file written to /work must not be executable under strict: {out}"
            );
            assert!(
                out.contains("Permission denied") || out.contains("rc=126"),
                "execve must fail with EACCES on the writable area: {out}"
            );
        }
        "symlink_escape" => {
            assert_eq!(r.exit_code, Some(0), "the link must resolve: {r:?}");
            let out = stdout_of(r);
            assert!(
                out.contains("carapace-sandbox-marker"),
                "the symlink must see the sandbox's own passwd, not the host's: {out}"
            );
            assert!(!out.contains("dev:"), "host users leaked: {out}");
        }
        "proc_escape" => {
            let out = stdout_of(r);
            assert!(out.contains("root=/"), "/proc/1/root must resolve: {out}");
            assert!(
                out.contains("/bin/sh -c"),
                "/proc/1 must be the sandbox's own shell init: {out}"
            );
            assert!(
                !out.to_lowercase().contains("systemd"),
                "the host init must not be visible: {out}"
            );
            let max_pid: i64 = out
                .lines()
                .last()
                .unwrap_or("")
                .trim()
                .parse()
                .unwrap_or(9999);
            assert!(
                max_pid <= 10,
                "fresh pid namespace must not expose host pids, saw max pid {max_pid}"
            );
        }
        "ptrace_attempt" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = combined_of(r);
            assert!(
                out.contains("ret -1") && out.contains("errno 1"),
                "ptrace must be denied with EPERM: {out}"
            );
        }
        "mount_attempt" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = combined_of(r);
            assert!(
                out.contains("ret -1") && out.contains("errno 1"),
                "mount(2) must be denied with EPERM: {out}"
            );
        }
        "unshare_attempt" => {
            let out = combined_of(r);
            assert!(
                out.contains("rc=1") || out.to_lowercase().contains("operation not permitted"),
                "unshare(2) must be denied: {out}"
            );
        }
        "socket_egress" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = stdout_of(r);
            assert!(
                out.contains("denied 1"),
                "socket(2) must be denied with EPERM: {out}"
            );
            assert!(!out.contains("CONNECTED"), "egress must fail: {out}");
        }
        "abstract_unix_escape" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = stdout_of(r);
            assert!(
                out.contains("denied 1"),
                "AF_UNIX socket(2) must be denied with EPERM: {out}"
            );
            assert!(!out.contains("BOUND"), "the bind must never run: {out}");
        }
        "setuid_escalation" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = combined_of(r);
            assert!(
                out.contains("setuid1-denied 1"),
                "setuid(1) must fail with EPERM (no CAP_SETUID): {out}"
            );
            assert!(
                out.contains("setres-denied 1"),
                "setresuid(1,1,1) must fail with EPERM: {out}"
            );
            assert!(!out.contains("-OK"), "a setuid call succeeded: {out}");
            assert!(
                out.contains("setuid-bit-binaries"),
                "the setuid-binary search must have run: {out}"
            );
            assert!(
                out.contains("NoNewPrivs:\t1"),
                "no_new_privs must be set: {out}"
            );
            assert!(
                out.contains("CapEff:\t0000000000000000"),
                "capabilities must be zero (setuid bits inert): {out}"
            );
        }
        "keyring_abuse" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = combined_of(r);
            assert!(
                out.contains("add_key ret -1") && out.contains("keyctl ret -1"),
                "keyring syscalls must fail: {out}"
            );
            assert_eq!(
                out.matches("errno 1").count(),
                2,
                "both keyring syscalls must be denied with EPERM: {out}"
            );
        }
        "fd_leak_scan" => {
            assert_eq!(r.exit_code, Some(0), "the scan must run: {r:?}");
            let mut fds: Vec<u32> = stdout_of(r)
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            fds.sort_unstable();
            assert_eq!(
                fds,
                vec![0, 1, 2, 3],
                "payload must see exactly 0,1,2 plus the scanner's own dirfd"
            );
        }
        "env_leak" => {
            assert_eq!(r.exit_code, Some(0), "the probe must print: {r:?}");
            let out = stdout_of(r);
            let names: Vec<&str> = out.split_whitespace().collect();
            assert!(
                names.contains(&"CARA_ESCAPE_MARKER"),
                "the spec env must reach the payload: {out:?}"
            );
            // The real leak test: nothing from the HOST process env may
            // appear (PATH is deliberately shared). Note the interpreter
            // itself may add names (CPython's PEP 538 adds LC_CTYPE) —
            // those are not host leaks.
            for (host_name, _) in std::env::vars() {
                if host_name == "PATH" {
                    continue;
                }
                assert!(
                    !names.contains(&host_name.as_str()),
                    "host env var {host_name} leaked into the sandbox"
                );
            }
        }
        _ => panic!("catalog entry {} has no suite verifier — add one", e.id),
    }
}

/// Host /proc scan: no process may carry `needle` in its cmdline after a
/// sandbox run — the tree must be fully dead, not merely reaped.
fn assert_no_payload_processes(needle: &str) {
    // The kernel tears the PID namespace down asynchronously: right after
    // wait() returns, a not-yet-reaped sibling can still be visible in the
    // host's /proc for a few milliseconds. That is teardown latency, not
    // an escape — retry with a settle window before declaring one.
    for _ in 0..20 {
        let mut alive = false;
        let dir = std::fs::read_dir("/proc").expect("/proc must be readable");
        for entry in dir.flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue; // already gone, or not ours to read
            };
            let cmd = String::from_utf8_lossy(&cmdline);
            if cmd.contains(needle) {
                alive = true;
                break;
            }
        }
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("payload escaped the sandbox: {needle:?} processes still alive after 2s");
}

/// One suite case per catalog entry, in catalog order.
macro_rules! escape_cases {
    ($($id:ident),+ $(,)?) => {
        const CASES: &[&str] = &[$(stringify!($id)),+];
        $(
            #[test]
            fn $id() {
                run_and_verify(stringify!($id));
            }
        )+
    };
}

escape_cases!(
    fork_bomb,
    memory_hog,
    cpu_spin,
    disk_filler,
    output_flood,
    read_etc_passwd,
    read_shadow,
    read_home,
    write_outside,
    write_then_exec,
    symlink_escape,
    proc_escape,
    ptrace_attempt,
    mount_attempt,
    unshare_attempt,
    socket_egress,
    abstract_unix_escape,
    setuid_escalation,
    keyring_abuse,
    fd_leak_scan,
    env_leak,
);

/// Positive control for `write_then_exec`: the same payload succeeds when
/// the spec explicitly opts in (`exec_on_write = true`), proving the
/// denial above is the policy field and not an unrelated failure.
#[test]
fn write_then_exec_allowed_when_spec_opts_in() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let entry = Catalog::get("write_then_exec").expect("catalog entry");
    let spec = spec_for(entry).exec_on_write(true);
    let mut h = b.spawn(&spec).expect("sandbox spawn must succeed");
    let r = h.wait().expect("sandbox wait must succeed");
    assert_eq!(r.exit_code, Some(0), "payload failed: {r:?}");
    assert!(
        String::from_utf8_lossy(&r.stdout).contains("CARA-WRITE-THEN-EXEC-ESCAPED"),
        "exec-on-write opt-in must allow running the written file: {r:?}"
    );
    assert_no_payload_processes(entry.payload);
}

#[test]
fn catalog_and_suite_stay_in_sync() {
    let catalog_ids: Vec<&str> = Catalog::all().iter().map(|t| t.id).collect();
    for id in CASES {
        assert!(
            catalog_ids.contains(id),
            "suite case {id} has no catalog entry"
        );
    }
    for t in Catalog::all() {
        assert!(
            CASES.contains(&t.id),
            "catalog entry {} has no suite case",
            t.id
        );
    }
    assert_eq!(CASES.len(), catalog_ids.len());
}
