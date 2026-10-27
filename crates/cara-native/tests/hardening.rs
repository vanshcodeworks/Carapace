//! C4 hardening tests: seccomp allowlist, Landlock grants, capability
//! drop, no_new_privs, fd sanitization — each observable from inside.

use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::Duration;

fn backend() -> NativeBackend {
    NativeBackend::new()
}

fn maybe_skip(b: &NativeBackend) -> bool {
    !b.environment().ready()
}

fn py(code: &str) -> SandboxSpec {
    SandboxSpec::new("/usr/bin/python3")
        .args(["-c", code])
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/work")
        .timeout(Duration::from_secs(30))
        .max_output(1024 * 1024)
}

fn sh(script: &str) -> SandboxSpec {
    SandboxSpec::new("/bin/sh")
        .args(["-c", script])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(30))
        .max_output(1024 * 1024)
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let mut h = backend().spawn(&spec).expect("spawn");
    h.wait().expect("wait")
}

fn have_python3() -> bool {
    std::fs::metadata("/usr/bin/python3").is_ok()
}

#[test]
fn normal_python_still_works() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let r = run(py("import platform; print(6*7)"));
    assert_eq!(
        r.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(String::from_utf8_lossy(&r.stdout).contains("42"));
}

#[test]
fn seccomp_blocks_socket_creation() {
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
        "import socket\ns = socket.socket()\nprint('created', s.fileno())",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    let err = String::from_utf8_lossy(&r.stderr).into_owned();
    assert!(
        err.contains("Operation not permitted") || err.contains("Permission denied"),
        "socket(2) must be denied with EPERM, got stdout={out:?} stderr={err:?} exit={:?}",
        r.exit_code
    );
    assert_ne!(r.exit_code, Some(0));
}

/// Positive control for `seccomp_blocks_socket_creation`: with `mode = "full"`
/// the socket-family allowlist is added and the payload shares the host
/// network namespace, so a real loopback round-trip must work. This is the
/// end-to-end test the "full mode permits sockets" claim previously lacked.
#[test]
fn network_full_mode_permits_loopback_sockets() {
    use std::io::{Read, Write};
    use std::time::Instant;

    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let mut req = [0u8; 4];
                    conn.read_exact(&mut req).expect("read request");
                    conn.write_all(b"pong").expect("write reply");
                    return req;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("loopback accept failed: {e}"),
            }
        }
    });
    let mut spec = py(&format!(
        "import socket\n\
         s = socket.create_connection(('127.0.0.1', {port}), timeout=5)\n\
         s.sendall(b'ping')\n\
         print(s.recv(4).decode())"
    ));
    spec.network = carapace_core::NetworkMode::Full;
    let r = run(spec);
    assert_eq!(
        r.exit_code,
        Some(0),
        "full-mode loopback round-trip failed: {r:?}"
    );
    assert!(
        String::from_utf8_lossy(&r.stdout).contains("pong"),
        "payload did not receive the reply: {r:?}"
    );
    assert_eq!(
        server.join().expect("server thread"),
        *b"ping",
        "server did not receive the payload's request"
    );
}

#[test]
fn seccomp_blocks_unshare() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("unshare -Ur /bin/true; echo rc=$?"));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("rc=1") || out.to_lowercase().contains("operation not permitted"),
        "unshare(2) must be denied: {out}"
    );
    // And the mount namespace trickery even with a real binary.
    let r = run(sh("unshare -m true; echo rc2=$?"));
    let out2 = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out2.contains("rc2=1") || out2.to_lowercase().contains("operation not permitted"),
        "unshare(CLONE_NEWNS) must be denied: {out2}"
    );
}

#[test]
fn seccomp_blocks_clone_with_namespace_flags() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    // os.clone does not exist; use ctypes to call clone(2) directly with
    // CLONE_NEWUSER (0x10000000): the dedicated BPF block must deny it
    // while plain fork keeps working.
    let r = run(py(
        "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nr = libc.syscall(56, 0x10000000, 0, 0)\nprint('ret', r, 'errno', ctypes.get_errno())",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("errno 1"),
        "clone(CLONE_NEWUSER) must be denied with EPERM exactly: {out}"
    );
}

#[test]
fn landlock_denies_writes_outside_grants() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // /etc lives on a writable tmpfs mount — Landlock is the layer that
    // must stop the write (mount flags alone do not).
    let r = run(sh(
        "echo evil > /etc/pwned 2>/dev/null; echo rc=$? > /work/rc; cat /work/rc",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("rc=1") || out.contains("rc=2"),
        "writes under /etc must be denied by Landlock, saw: {out}"
    );
    // And inside /work everything is fine.
    let r = run(sh("echo ok > /work/f && cat /work/f"));
    assert!(String::from_utf8_lossy(&r.stdout).contains("ok"));
}

#[test]
fn landlock_denies_writes_to_proc() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("echo x > /proc/self/mem 2>/dev/null; echo rc=$?"));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    // Redirection failure in dash reports rc=1 or rc=2; both mean denied.
    assert!(
        out.contains("rc=1") || out.contains("rc=2"),
        "proc must not be writable: {out}"
    );
}

#[test]
fn no_fd_leaks_into_payload() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // python's listdir shows its own transient dirfd (3): acceptable. Any
    // OTHER fd above 2 is a leak.
    let r = run(py(
        "import os\nfds = sorted(int(f) for f in os.listdir('/proc/self/fd'))\nprint('extra', [f for f in fds if f > 3], 'base', [f for f in fds if f <= 2])",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    let err = String::from_utf8_lossy(&r.stderr).into_owned();
    assert!(
        out.contains("extra []") && out.contains("base [0, 1, 2]"),
        "payload must see only fds 0,1,2 (+ the listing's own dirfd): {out:?} stderr={err:?}"
    );
}

#[test]
fn no_new_privs_and_zero_capabilities() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    let r = run(sh("grep -E 'NoNewPrivs|CapEff' /proc/self/status"));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("NoNewPrivs:\t1"),
        "no_new_privs must be set: {out}"
    );
    assert!(
        out.contains("CapEff:\t0000000000000000"),
        "capabilities must be zero: {out}"
    );
}

#[test]
fn fsize_rlimit_caps_single_files() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    // scratch = 16 MiB; ask dd for a 64 MiB single file: must fail.
    let mut spec = sh("dd if=/dev/zero of=/work/big bs=1M count=64 2>&1; echo rc=$?");
    spec.limits.scratch_bytes = 16 * 1024 * 1024;
    let r = run(spec);
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("File size limit exceeded") || out.contains("rc=1"),
        "RLIMIT_FSIZE must cap single files: {out}"
    );
}

#[test]
fn io_uring_is_denied() {
    let b = backend();
    if maybe_skip(&b) {
        eprintln!("skipping: environment not Tier 1 ready");
        return;
    }
    if !have_python3() {
        eprintln!("skipping: no python3");
        return;
    }
    // io_uring_setup nr=425 via ctypes syscall(); use_errno=True so the
    // captured errno is meaningful.
    let r = run(py(
        "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nr = libc.syscall(425, 0, 0)\nprint('ret', r, 'errno', ctypes.get_errno())",
    ));
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    assert!(
        out.contains("errno 1"),
        "io_uring_setup must be denied with EPERM exactly: {out}"
    );
}
