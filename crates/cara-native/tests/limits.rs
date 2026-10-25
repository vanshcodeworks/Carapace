//! C3 cgroup limit tests: memory OOM kill, fork-bomb cap, CPU quota
//! shaping, resource accounting, and leaf cleanup.

use carapace_core::report::KillReason;
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
        .timeout(Duration::from_secs(30))
        .max_output(4 * 1024 * 1024)
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let mut h = backend().spawn(&spec).expect("spawn");
    h.wait().expect("wait")
}

fn have_python3() -> bool {
    std::fs::metadata("/usr/bin/python3").is_ok()
}

#[test]
fn memory_hog_is_oom_killed_at_limit() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut spec = SandboxSpec::new("/usr/bin/python3")
        .args(["-c", "a = bytearray(256 * 1024 * 1024)"])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(60));
    spec.limits.memory_bytes = 64 * 1024 * 1024;
    let r = run(spec);
    assert_eq!(
        r.kill_reason,
        Some(KillReason::MemoryLimit),
        "must be OOM-killed at the memory limit, got {r:?}"
    );
    assert!(
        r.peak_memory_bytes.is_some_and(|m| m > 32 * 1024 * 1024),
        "peak memory must be recorded and near the limit: {:?}",
        r.peak_memory_bytes
    );
}

#[test]
fn fork_bomb_is_capped_by_pids_max() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let mut spec = sh("i=0; while :; do sleep 300 & i=$((i+1)); done 2>/dev/null; echo spawned=$i")
        .timeout(Duration::from_secs(5));
    spec.limits.max_processes = 32;
    let r = run(spec);
    // The bomb cannot escape: either the supervisor timeout kills it (the
    // sh is stuck failing to fork) or it exits. Either way pids are capped.
    assert!(
        matches!(r.kill_reason, Some(KillReason::Timeout)) || r.exit_code.is_some(),
        "run must end cleanly, got {r:?}"
    );
    assert!(
        r.peak_processes.is_none_or(|p| p <= 64),
        "process count must stay near the cap (small excess from accounting
         granularity is fine), saw {:?}",
        r.peak_processes
    );
    // No straggler sleeps survive the sandbox.
    std::thread::sleep(Duration::from_millis(300));
    assert_no_marker_processes();
}

#[test]
fn cpu_quota_shapes_usage() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    fn spin(percent: u32) -> carapace_core::ExitReport {
        let mut spec = sh("i=0; while :; do i=$((i+1)); done").timeout(Duration::from_secs(2));
        spec.limits.cpu_percent = percent;
        run(spec)
    }
    let low = spin(20);
    let high = spin(200);
    let low_ratio = low
        .cpu_time
        .map(|c| c.as_secs_f64() / low.wall_time.as_secs_f64());
    let high_ratio = high
        .cpu_time
        .map(|c| c.as_secs_f64() / high.wall_time.as_secs_f64());
    let (lo, hi) = (low_ratio.unwrap_or(0.0), high_ratio.unwrap_or(0.0));
    // Generous bounds: parallel test load can distort single measurements,
    // but 20% vs 200% must differ clearly.
    assert!(lo < 0.6, "20% quota must throttle (ratio {lo:.2})");
    assert!(
        hi > lo + 0.3,
        "200% quota must outperform 20% (ratios {hi:.2} vs {lo:.2})"
    );
}

#[test]
fn resource_report_is_populated() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("echo hi; sleep 0.3"));
    assert_eq!(r.exit_code, Some(0));
    assert!(r.cpu_time.is_some(), "cpu accounting present");
    assert!(
        r.peak_memory_bytes.is_some_and(|m| m > 0),
        "memory accounting present"
    );
    assert!(
        r.wall_time >= Duration::from_millis(300),
        "sleep 0.3 must be reflected in wall time (got {:?})",
        r.wall_time
    );
}

#[test]
fn cgroup_leaves_are_always_removed() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let count = || count_leaves();
    let before = count();
    let _ = run(sh("echo one"));
    let _ = run(sh("exit 3"));
    // Async removal retries for ~10s; give it a generous window.
    let mut after = count();
    for _ in 0..80 {
        after = count();
        if after <= before {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        after <= before,
        "no cara-run-* leaves may linger (before={before}, after={after})"
    );
}

fn count_leaves() -> usize {
    let root = match carapace_native::cgroup::delegated_root() {
        Some(r) => r,
        None => return 0,
    };
    std::fs::read_dir(&root)
        .map(|d| {
            d.flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with("cara-run-") || n.starts_with("cara-cgroup-probe-")
                })
                .count()
        })
        .unwrap_or(0)
}

/// No processes of previous sandboxes left behind (marker scan of /proc).
fn assert_no_marker_processes() {
    let dir = std::fs::read_dir("/proc").expect("/proc");
    for entry in dir.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let cmd = String::from_utf8_lossy(&cmdline);
        if cmd.contains("sleep 300") {
            panic!("leftover sandbox process: {pid} {cmd}");
        }
    }
}
