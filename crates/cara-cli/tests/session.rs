//! End-to-end session tests: start/exec/put/get/ls/close through the real
//! `cara` binary.
//!
//! Environment-gated like the other sandbox tests (`CARA_STRICT_ENV_TESTS`,
//! set by scripts/check.sh inside the user cgroup slice): sessions need
//! cgroup delegation for their keeper leaf.
//!
//! Every test uses a unique policy file under the system temp dir and a
//! `SessionGuard` that closes the session on drop, so a failed assertion
//! never leaves a live keeper behind.

use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

fn cara() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cara"))
}

fn env_ready() -> bool {
    if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
        eprintln!("skipping: CARA_STRICT_ENV_TESTS is not set (needs the user cgroup slice)");
        return false;
    }
    true
}

/// Session tests are memory-heavy (each session is a cgroup leaf); run them
/// one at a time so the gate stays deterministic on small machines.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Writes a policy file and returns its path (kept alive by the caller).
struct PolicyFile {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl PolicyFile {
    fn new(name: &str, text: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "cara-sess-test-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create policy dir");
        let path = dir.join("policy.toml");
        std::fs::write(&path, text).expect("write policy");
        Self { dir, path }
    }

    fn arg(&self) -> &str {
        self.path.to_str().expect("utf-8 path")
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A live session; `Drop` closes it.
struct SessionGuard {
    id: String,
    dir: Option<String>,
}

impl SessionGuard {
    fn start(policy: &PolicyFile) -> Self {
        let out = cara()
            .args(["session", "start", "--policy", policy.arg(), "--json"])
            .output()
            .expect("run cara session start");
        assert!(
            out.status.success(),
            "session start failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("session start --json is JSON");
        Self {
            id: meta["id"].as_str().expect("id").to_string(),
            dir: meta["dir"].as_str().map(str::to_string),
        }
    }

    fn exec(&self, argv: &[&str]) -> Output {
        let mut cmd = cara();
        cmd.args(["session", "exec", &self.id, "--"]);
        cmd.args(argv);
        cmd.output().expect("run cara session exec")
    }

    fn exec_timeout(&self, timeout: &str, argv: &[&str]) -> Output {
        let mut cmd = cara();
        cmd.args(["session", "exec", &self.id, "--timeout", timeout, "--"]);
        cmd.args(argv);
        cmd.output().expect("run cara session exec")
    }

    fn put(&self, local: &str, remote: &str) -> Output {
        cara()
            .args(["session", "put", &self.id, local, remote])
            .output()
            .expect("run cara session put")
    }

    fn get(&self, remote: &str, local: &str) -> Output {
        cara()
            .args(["session", "get", &self.id, remote, local])
            .output()
            .expect("run cara session get")
    }

    fn ls(&self, path: &str) -> Output {
        cara()
            .args(["session", "ls", &self.id, path])
            .output()
            .expect("run cara session ls")
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = cara().args(["session", "close", &self.id]).output();
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const STRICT: &str = "[limits]\nmemory = \"128MB\"\ndisk = \"8MB\"\nmax_processes = 16\n";

#[test]
fn files_persist_across_execs_and_survive_the_cli_exit() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("persist", STRICT);
    let session = SessionGuard::start(&policy);

    // Each `cara session exec` is a separate host process; the keeper keeps
    // the tmpfs alive between them.
    let out = session.exec(&[
        "/bin/sh",
        "-c",
        "echo persisted > /work/f; mkdir -p /work/d/e",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    let out = session.exec(&["/bin/cat", "/work/f"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "persisted\n");

    let out = session.ls("d");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("e"), "{}", stdout(&out));
}

#[test]
fn upload_download_roundtrip_is_byte_exact() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("xfer", STRICT);
    let session = SessionGuard::start(&policy);

    // All 256 byte values, including NUL and newlines.
    let data: Vec<u8> = (0..=255u8).cycle().take(70000).collect();
    let dir = std::env::temp_dir().join(format!("cara-sess-xfer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.bin");
    let dst = dir.join("dst.bin");
    std::fs::write(&src, &data).unwrap();

    let out = session.put(src.to_str().unwrap(), "in/src.bin");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // Parent directories are created on demand.
    let out = session.exec(&["/usr/bin/wc", "-c", "/work/in/src.bin"]);
    assert!(stdout(&out).trim().starts_with("70000"), "{}", stdout(&out));

    let out = session.get("in/src.bin", dst.to_str().unwrap());
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(std::fs::read(&dst).unwrap(), data);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn traversal_absolute_paths_and_symlinks_are_refused() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("paths", STRICT);
    let session = SessionGuard::start(&policy);

    let dir = std::env::temp_dir().join(format!("cara-sess-path-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let local = dir.join("payload");
    std::fs::write(&local, b"x").unwrap();
    let local = local.to_str().unwrap().to_string();

    for bad in ["../escape", "/etc/passwd", "a/../../escape", "./a"] {
        let out = session.get(bad, &local);
        assert_ne!(out.status.code(), Some(0), "get {bad:?} must fail");
    }
    for bad in ["../escape", "/abs/escape"] {
        let out = session.put(&local, bad);
        assert_ne!(out.status.code(), Some(0), "put {bad:?} must fail");
    }

    // A symlink created by the payload is not followed by the host-side
    // file API, and neither is a symlinked directory.
    let out = session.exec(&[
        "/bin/sh",
        "-c",
        "ln -s /etc/passwd /work/link; ln -s /work /work/loop",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = session.get("link", &local);
    assert_ne!(out.status.code(), Some(0), "symlink get must fail");
    let out = session.ls("loop");
    assert_ne!(out.status.code(), Some(0), "symlink ls must fail");

    // The symlink itself is listed (but never followed).
    let out = session.ls(".");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("symlink"), "{}", stdout(&out));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn timeout_kills_the_payload_tree_and_the_session_survives() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("timeout", STRICT);
    let session = SessionGuard::start(&policy);

    let out = session.exec_timeout("1s", &["/bin/sh", "-c", "sleep 30 & sleep 30"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(stderr(&out).contains("timeout"), "{}", stderr(&out));

    // The keeper and its tmpfs are still healthy after a killed payload.
    let out = session.exec(&["/bin/echo", "alive"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "alive\n");
}

#[test]
fn disk_quota_is_enforced_inside_the_session() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("disk", "[limits]\nmemory = \"128MB\"\ndisk = \"2MB\"\n");
    let session = SessionGuard::start(&policy);

    // RLIMIT_FSIZE caps a single file at the scratch size, so two files
    // that individually fit still exceed the 2 MiB tmpfs: the second write
    // fails with ENOSPC, which is the quota doing its job.
    let out = session.exec(&[
        "/bin/sh",
        "-c",
        "dd if=/dev/zero of=/work/a bs=1k count=1500 2>/dev/null; \
         dd if=/dev/zero of=/work/b bs=1k count=1500",
    ]);
    assert_ne!(out.status.code(), Some(0), "the 2 MiB tmpfs must fill up");
    assert!(
        stderr(&out).contains("No space left on device"),
        "{}",
        stderr(&out)
    );

    // The session is still usable after ENOSPC.
    let out = session.exec(&["/bin/echo", "ok"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn noexec_is_the_default_and_exec_on_write_opts_in() {
    if !env_ready() {
        return;
    }
    let _guard = serial();

    // Strict: /work is mounted MS_NOEXEC, so neither execve nor an
    // executable mapping of a /work file can succeed.
    let strict = PolicyFile::new("noexec", STRICT);
    let session = SessionGuard::start(&strict);
    let out = session.exec(&[
        "/bin/sh",
        "-c",
        "printf '#!/bin/sh\\necho ran\\n' > /work/x.sh; chmod +x /work/x.sh; /work/x.sh",
    ]);
    assert_ne!(out.status.code(), Some(0), "exec from /work must fail");
    assert!(
        stderr(&out).contains("Permission denied"),
        "{}",
        stderr(&out)
    );

    let mmap_probe = concat!(
        "import mmap, os\n",
        "fd = os.open('/work/m', os.O_RDWR | os.O_CREAT, 0o700)\n",
        "os.write(fd, b'\\x90' * 16)\n",
        "try:\n",
        "    mmap.mmap(fd, 16, prot=mmap.PROT_READ | mmap.PROT_EXEC)\n",
        "except OSError as e:\n",
        "    print('denied', e.errno)\n",
        "else:\n",
        "    print('mapped')\n",
    );
    let out = session.exec(&["/usr/bin/python3", "-c", mmap_probe]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // EPERM is 1; the mount is noexec, not a permission error on the file.
    assert_eq!(stdout(&out).trim(), "denied 1", "{}", stdout(&out));

    // dev: exec_on_write = true, so the same file runs.
    let dev = PolicyFile::new(
        "execdev",
        "preset = \"dev\"\n[limits]\nmemory = \"256MB\"\n",
    );
    let session = SessionGuard::start(&dev);
    let out = session.exec(&[
        "/bin/sh",
        "-c",
        "printf '#!/bin/sh\\necho ran\\n' > /work/x.sh; chmod +x /work/x.sh; /work/x.sh",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "ran\n");

    let out = session.exec(&["/usr/bin/python3", "-c", mmap_probe]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "mapped", "{}", stdout(&out));
}

#[test]
fn close_removes_the_socket_work_dir_and_meta() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("close", STRICT);
    let session = SessionGuard::start(&policy);
    let dir = session.dir.clone().expect("dir");

    let out = session.exec(&["/bin/echo", "hi"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(std::path::Path::new(&dir).join("sock").exists());

    let out = cara()
        .args(["session", "close", &session.id])
        .output()
        .expect("close");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        !std::path::Path::new(&dir).exists(),
        "session dir must be removed: {dir}"
    );

    let out = cara().args(["session", "list"]).output().expect("list");
    assert!(
        !stdout(&out).contains(&session.id),
        "closed session still listed: {}",
        stdout(&out)
    );
}

#[test]
fn host_paths_and_network_stay_hidden() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("iso", STRICT);
    let session = SessionGuard::start(&policy);

    let out = session.exec(&["/bin/sh", "-c", "ls /home 2>&1; echo status=$?"]);
    assert!(
        stdout(&out).contains("status=2") || stdout(&out).contains("status=1"),
        "host /home must not be visible: {}",
        stdout(&out)
    );

    // With network = "none" the seccomp filter refuses socket(2) itself, so
    // even constructing a socket fails (EPERM) — before any connect.
    let probe = concat!(
        "import socket\n",
        "try:\n",
        "    s = socket.socket()\n",
        "    s.settimeout(1)\n",
        "    s.connect(('1.1.1.1', 80))\n",
        "except OSError as e:\n",
        "    print('blocked', e.errno)\n",
        "else:\n",
        "    print('connected')\n",
    );
    let out = session.exec(&["/usr/bin/python3", "-c", probe]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "blocked 1", "{}", stdout(&out));
}

#[test]
fn concurrent_execs_are_serialized_not_rejected() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("conc", STRICT);
    let session = SessionGuard::start(&policy);
    let id = session.id.clone();

    let handles: Vec<_> = (0..3)
        .map(|i| {
            let id = id.clone();
            std::thread::spawn(move || {
                let out = cara()
                    .args([
                        "session",
                        "exec",
                        &id,
                        "--",
                        "/bin/sh",
                        "-c",
                        &format!("echo job-{i}"),
                    ])
                    .output()
                    .expect("exec");
                (i, out)
            })
        })
        .collect();
    for handle in handles {
        let (i, out) = handle.join().expect("join");
        assert_eq!(out.status.code(), Some(0), "job {i}: {}", stderr(&out));
        assert_eq!(stdout(&out), format!("job-{i}\n"));
    }
}

/// Runs a prepared command, failing the test (instead of hanging) when it
/// does not finish within `deadline`.
fn run_bounded(mut cmd: Command, deadline: std::time::Duration) -> Output {
    use std::process::Stdio;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded command");
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("collect output");
            panic!(
                "command did not finish within {deadline:?}; stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn keeper_pid(dir: &str) -> i32 {
    let text = std::fs::read_to_string(std::path::Path::new(dir).join("meta.json"))
        .expect("read meta.json");
    let meta: serde_json::Value = serde_json::from_str(&text).expect("meta.json is JSON");
    meta["keeper_pid"].as_i64().expect("keeper_pid") as i32
}

#[test]
fn close_while_busy_kills_the_payload_and_returns() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("busy", STRICT);
    let session = SessionGuard::start(&policy);
    let id = session.id.clone();

    // A payload that would run for 30s (well past the default timeout).
    let mut busy = cara();
    busy.args([
        "session",
        "exec",
        &id,
        "--timeout",
        "30s",
        "--",
        "/bin/sh",
        "-c",
        "echo started; sleep 30",
    ]);
    let mut child = busy
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn a long exec");
    // Give it time to reach the payload.
    std::thread::sleep(std::time::Duration::from_millis(700));

    let out = run_bounded(
        {
            let mut cmd = cara();
            cmd.args(["session", "close", &id]);
            cmd
        },
        std::time::Duration::from_secs(15),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // The waiting exec must fail promptly (keeper gone), not run to its
    // 30s timeout.
    let start = std::time::Instant::now();
    let status = child.wait().expect("wait for the killed exec");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "the exec outlived its keeper"
    );
    assert!(!status.success(), "exec must not report success");
}

#[test]
fn keeper_death_takes_the_payload_and_prune_reclaims_the_state() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("kill", STRICT);
    let session = SessionGuard::start(&policy);
    let id = session.id.clone();
    let dir = session.dir.clone().expect("dir");

    let mut busy = cara();
    busy.args([
        "session",
        "exec",
        &id,
        "--timeout",
        "30s",
        "--",
        "/bin/sh",
        "-c",
        "echo started; sleep 30",
    ]);
    let mut child = busy
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn a long exec");
    std::thread::sleep(std::time::Duration::from_millis(700));

    // SIGKILL the keeper: the PDEATHSIG chain must take the payload with it.
    let pid = keeper_pid(&dir);
    let out = Command::new("/bin/kill")
        .args(["-9", &pid.to_string()])
        .output()
        .expect("run kill");
    assert!(
        out.status.success(),
        "kill the keeper: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let start = std::time::Instant::now();
    let status = child.wait().expect("wait for the killed exec");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "the payload outlived its keeper"
    );
    assert!(!status.success(), "exec must not report success");

    // The dead session's directory and cgroup leaf are reclaimed.
    let out = run_bounded(
        {
            let mut cmd = cara();
            cmd.args(["session", "prune", "--json"]);
            cmd
        },
        std::time::Duration::from_secs(20),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        !std::path::Path::new(&dir).exists(),
        "prune must remove the dead session dir"
    );
}

#[test]
fn unknown_and_malformed_ids_are_rejected() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let out = cara()
        .args(["session", "exec", "../../etc", "--", "/bin/true"])
        .output()
        .expect("exec");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));

    let out = cara()
        .args(["session", "close", "deadbeefdeadbeefdeadbeefdeadbeef"])
        .output()
        .expect("close");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
}

#[test]
fn session_start_requires_an_absolute_program() {
    if !env_ready() {
        return;
    }
    let _guard = serial();
    let policy = PolicyFile::new("abs", STRICT);
    let session = SessionGuard::start(&policy);
    let out = session.exec(&["true"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(stderr(&out).contains("absolute path"), "{}", stderr(&out));
}
