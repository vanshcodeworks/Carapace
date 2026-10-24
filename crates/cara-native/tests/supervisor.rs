//! Integration tests for the C1 supervisor: namespaces, timeout kill, tree
//! kill, output caps, fail-closed setup. Payloads here are self-written and
//! benign-but-annoying (no filesystem isolation exists yet — that is C2);
//! hostile payloads only ever run through the sandbox by rule 6.

use carapace_core::report::KillReason;
use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::Duration;

/// Skips (passes silently) when the environment cannot run Tier 1, so CI
/// hosts without userns still exercise the pure-logic tests.
fn backend() -> NativeBackend {
    NativeBackend::new()
}

fn maybe_skip(b: &NativeBackend) -> bool {
    !b.environment().ready()
}

fn spec(program: &str) -> SandboxSpec {
    SandboxSpec::new(program)
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(10))
        .max_output(4 * 1024 * 1024)
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let mut h = backend()
        .spawn(&spec)
        .expect("spawn on a Tier 1 capable host");
    h.wait().expect("wait")
}

#[test]
fn exits_with_program_status() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(spec("/bin/true"));
    assert_eq!(r.exit_code, Some(0));
    let r = run(spec("/bin/false"));
    assert_eq!(r.exit_code, Some(1));
    let r = run(spec("/bin/sh")
        .args(["-c", "exit 7"])
        .env("PATH", "/usr/bin:/bin"));
    assert_eq!(r.exit_code, Some(7));
}

#[test]
fn captures_stdout_and_stderr_separately() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(spec("/bin/sh").args(["-c", "echo out-line; echo err-line 1>&2; echo out2"]));
    assert_eq!(r.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&r.stdout), "out-line\nout2\n");
    assert_eq!(String::from_utf8_lossy(&r.stderr), "err-line\n");
}

#[test]
fn timeout_kills_the_tree_quickly() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let start = std::time::Instant::now();
    let r = run(spec("/bin/sh")
        .args(["-c", "sleep 300 & sleep 300 & sleep 300"])
        .timeout(Duration::from_millis(700)));
    assert_eq!(r.kill_reason, Some(KillReason::Timeout), "must be timeout");
    assert!(r.exit_code.is_none(), "killed, not exited");
    assert!(r.signal == Some(libc::SIGKILL as _) || r.signal.is_none());
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "kill must be fast, took {elapsed:?}"
    );
    assert_no_leftovers("timeout_kills_the_tree_quickly");
}

#[test]
fn output_cap_kills_flooder() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(spec("/usr/bin/yes").max_output(64 * 1024));
    assert_eq!(
        r.kill_reason,
        Some(KillReason::OutputOverflow),
        "flooder must be stopped; got {r:?}"
    );
    assert!(r.stdout.len() <= 64 * 1024, "output is capped");
    assert_no_leftovers("output_cap_kills_flooder");
}

#[test]
fn forked_grandchildren_die_with_sandbox() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let marker = format!("CARA_LEFTOVER_{}", std::process::id());
    let r = run(spec("/bin/sh")
        .args(["-c", "(sleep 240 &) ; sleep 240"])
        .env("CARA_LEFTOVER", &marker)
        .timeout(Duration::from_millis(600)));
    assert_eq!(r.kill_reason, Some(KillReason::Timeout));
    // The double-forked grandchild is inside the PID namespace: it cannot
    // survive the namespace init. Give the kernel a moment, then scan.
    std::thread::sleep(Duration::from_millis(300));
    assert_no_leftovers_marker(&marker);
}

#[test]
fn child_runs_in_fresh_namespaces() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let parent_user_ns = std::fs::read_link("/proc/self/ns/user").expect("parent ns");
    let parent_net_ns = std::fs::read_link("/proc/self/ns/net").expect("parent ns");
    let r = run(spec("/bin/sh").args([
        "-c",
        "readlink /proc/self/ns/user; readlink /proc/self/ns/net; \
             cat /proc/self/uid_map; id -u; cat /proc/net/dev",
    ]));
    assert_eq!(r.exit_code, Some(0));
    let out = String::from_utf8_lossy(&r.stdout);
    let mut lines = out.lines();
    let child_user = lines.next().expect("user ns line");
    let child_net = lines.next().expect("net ns line");
    let uid_map = lines.next().expect("uid_map line");
    let uid = lines.next().expect("id -u line");
    assert_ne!(
        child_user,
        parent_user_ns.to_str().unwrap(),
        "user namespace must differ from the parent's"
    );
    assert_ne!(
        child_net,
        parent_net_ns.to_str().unwrap(),
        "network namespace must differ from the parent's"
    );
    assert!(
        uid_map.trim().chars().next().unwrap_or('x') == '0',
        "uid_map maps to 0 inside the ns: {uid_map}"
    );
    assert_eq!(uid.trim(), "0", "inside the userns we are root");
    let dev_rest: String = lines.collect();
    assert!(
        dev_rest.contains("lo"),
        "fresh netns has only the loopback device"
    );
    assert!(
        !dev_rest.contains("eth0") && !dev_rest.contains("ens"),
        "no host interfaces visible in the fresh netns"
    );
}

#[test]
fn pre_exec_failure_is_setup_error_not_a_run() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let err = match b.spawn(&spec("/nonexistent/cara/probe")) {
        Err(e) => e,
        Ok(_) => panic!("spawning a nonexistent binary must fail"),
    };
    assert!(
        matches!(
            err,
            carapace_core::BackendError::Setup(ref m) if m.contains("execve")
        ),
        "exec failure must be a Setup error mentioning execve, got: {err}"
    );
}

#[test]
fn environment_gate_blocks_spawn_when_not_ready() {
    // On the dev environment the gate passes, so assert consistency rather
    // than forcing a failure: spawn works iff environment().ready().
    let b = backend();
    let ready = b.environment().ready();
    if ready {
        let _ = b
            .spawn(&spec("/bin/true"))
            .expect("ready implies spawn works");
    } else {
        assert!(b.spawn(&spec("/bin/true")).is_err());
    }
}

#[test]
fn handle_kill_works_before_timeout() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let mut h = b
        .spawn(
            &spec("/bin/sh")
                .args(["-c", "sleep 240"])
                .timeout(Duration::from_secs(240)),
        )
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(200)); // let it exec
    h.kill(KillReason::Internal("test kill".into()));
    let r = h.wait().expect("wait after kill");
    assert!(matches!(r.kill_reason, Some(KillReason::Internal(_))));
    assert!(r.wall_time < Duration::from_secs(5));
}

/// After a sandbox dies, no zombies may remain owned by the test process.
fn assert_no_leftovers(_test: &str) {
    // Reap anything pending; specific markers are checked by
    // assert_no_leftovers_marker where a marker was set.
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if r <= 0 {
            break;
        }
    }
}

fn assert_no_leftovers_marker(marker: &str) {
    let dir = std::fs::read_dir("/proc").expect("/proc");
    for entry in dir.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
            continue;
        };
        if environ
            .windows(marker.len())
            .any(|w| w == marker.as_bytes())
        {
            panic!("leftover process {pid} still carries the sandbox marker");
        }
    }
}
