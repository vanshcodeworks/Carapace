//! Forced-interleaving test for the stage-2 PDEATHSIG window (P1).
//!
//! The race: stage-2 is forked, but `PR_SET_PDEATHSIG` is armed a few
//! instructions later. `fork(2)` clears the attribute, so if the
//! supervisor/stage-1 dies in that window, arming it afterwards has no
//! retroactive effect. The runtime closes this with a `/proc/<stage1>`
//! liveness check that treats a zombie as dead.
//!
//! Forcing the window: the child code has a `cfg(test)`-only pause hook
//! between `fork(2)` and `prctl`, used here. The test spawns a helper test
//! process that acts as the supervisor, waits for the hook marker, kills
//! the supervisor, waits until stage-1 is gone or a zombie, releases
//! stage-2, and proves the payload never executed (no marker file, no
//! leftover process). The hook does not exist in release builds.

use crate::NativeBackend;
use carapace_core::{Backend, SandboxSpec};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Test-harness helper. Re-executed as a child process by
/// [`forced_pdeathsig_race_never_execs_payload`]; does nothing in a normal
/// test run (the env marker is absent).
#[test]
fn pdeathsig_window_helper() {
    if std::env::var("CARA_PDEATHSIG_HELPER").as_deref() != Ok("1") {
        return;
    }
    let dir = std::env::var("CARA_PDEATHSIG_DIR").expect("helper needs CARA_PDEATHSIG_DIR");
    let mut spec = SandboxSpec::new("/bin/sh")
        .args(["-c", &format!("echo EXECUTED > {dir}/marker")])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(30));
    spec.read_write.push(PathBuf::from(&dir));
    let backend = NativeBackend::new();
    // If the environment is not ready, return: the parent sees EOF instead
    // of the hook marker and fails with a diagnosis.
    let Ok(mut handle) = backend.spawn(&spec) else {
        return;
    };
    let _ = handle.wait();
}

fn temp_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "cara-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir(&p).expect("temp dir");
    p
}

fn read_stat_state(pid: i32) -> Option<u8> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    stat[close + 1..]
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .copied()
}

/// Live = exists and is not a zombie/dead task. This mirrors the child's
/// `proc_pid_is_live`; the test uses it to wait for the exact "parent is
/// already dead" state before releasing stage-2.
fn process_live(pid: i32) -> bool {
    matches!(read_stat_state(pid), Some(s) if s != b'Z' && s != b'X' && s != b'x')
}

fn direct_child_of(pid: i32) -> Option<i32> {
    // `NativeBackend::spawn` runs on the test thread, not the main thread;
    // `/proc/<pid>/task/<pid>/children` only lists that thread's children.
    // Scan every task's children file.
    let task_dir = format!("/proc/{pid}/task");
    for task in std::fs::read_dir(task_dir).ok()?.flatten() {
        let children = task.path().join("children");
        if let Ok(s) = std::fs::read_to_string(children)
            && let Some(first) = s.split_whitespace().next()
            && let Ok(child) = first.parse()
        {
            return Some(child);
        }
    }
    None
}

/// Kills the supervisor helper if the test panics before reaching the
/// explicit kill: a leaked helper is a live sandbox, not just a test wart.
struct KillHelperOnDrop {
    child: Option<std::process::Child>,
}

impl Drop for KillHelperOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn forced_pdeathsig_race_never_execs_payload() {
    let backend = NativeBackend::new();
    if !backend.environment().ready() {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let dir = temp_dir("pdeathsig-race");
    let mut fds = [0 as libc::c_int; 2];
    let r = unsafe {
        // SAFETY: socketpair(2) into a valid 2-fd array; SOCK_STREAM.
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
    };
    assert_eq!(
        r,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );

    // Re-exec this test binary as the supervisor. The hook fd must survive
    // exec (raw socketpair fds have no O_CLOEXEC).
    let exe = std::env::current_exe().expect("current test binary");
    let child = Command::new(exe)
        .args([
            "--exact",
            "pdeathsig_test::pdeathsig_window_helper",
            "--nocapture",
        ])
        .env("CARA_PDEATHSIG_HELPER", "1")
        .env("CARA_PDEATHSIG_FD", fds[1].to_string())
        .env("CARA_PDEATHSIG_DIR", dir.to_str().expect("utf-8 dir"))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn supervisor helper");
    let helper_pid = child.id() as i32;
    let mut guard = KillHelperOnDrop { child: Some(child) };
    unsafe {
        // SAFETY: closing our copy of the child end.
        libc::close(fds[1]);
    }

    // Wait for stage-2's hook marker ('P') or helper exit.
    let mut pfd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN,
        revents: 0,
    };
    let pr = unsafe {
        // SAFETY: poll(2) on a valid fd array.
        libc::poll(&mut pfd, 1, 15_000)
    };
    if pr <= 0 {
        panic!("stage-2 never reached the forced fork->PDEATHSIG window");
    }
    let mut byte = [0u8; 1];
    let n = unsafe {
        // SAFETY: read(2) into a valid 1-byte buffer.
        libc::read(fds[0], byte.as_mut_ptr().cast(), 1)
    };
    assert_eq!(n, 1, "hook read failed");
    assert_eq!(byte[0], b'P', "unexpected hook marker");

    // Find stage-1 while the supervisor is still alive, then kill the
    // supervisor. Stage-2 is paused in the window the whole time.
    let stage1 = direct_child_of(helper_pid).expect("stage-1 must be a child of the supervisor");
    if let Some(mut child) = guard.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Force the precise losing interleaving: stage-1 must be gone or a
    // zombie before stage-2 is allowed to arm PDEATHSIG.
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_live(stage1) {
        assert!(
            Instant::now() < deadline,
            "stage-1 did not die after the supervisor was SIGKILLed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Release stage-2. It arms PDEATHSIG too late, sees stage-1 dead via
    // /proc and must exit without ever exec'ing the payload.
    let rel = unsafe {
        // SAFETY: write(2) of one byte to the peer we own.
        libc::write(fds[0], b"R".as_ptr().cast(), 1)
    };
    assert_eq!(rel, 1, "release write failed");
    unsafe {
        // SAFETY: closing our end after the release.
        libc::close(fds[0]);
    }

    let marker = dir.join("marker");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut leftover = false;
    while Instant::now() < deadline {
        if marker.exists() {
            break;
        }
        let token = dir.file_name().unwrap().to_string_lossy().into_owned();
        let mut found = false;
        for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline"))
                && String::from_utf8_lossy(&cmdline).contains(&token)
            {
                found = true;
                break;
            }
        }
        if found {
            leftover = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !marker.exists(),
        "payload executed after the supervisor died in the fork->PDEATHSIG window"
    );
    assert!(
        !leftover,
        "payload process survived the forced PDEATHSIG interleaving"
    );
    std::fs::remove_dir_all(&dir).ok();
}
