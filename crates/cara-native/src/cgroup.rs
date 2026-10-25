//! cgroup v2 leaf management for sandbox limits (milestone C3).
//!
//! Design: every run gets a leaf `cara-run-<unique>` under the process's
//! delegated subtree (usually systemd's `user@<uid>.service`). The leaf is
//! created and the child attached to it while the child is still parked on
//! the go-pipe — before it can exec or fork — so no descendant can escape
//! the limits. The leaf is removed on every teardown path.

use carapace_core::spec::Limits;
use std::path::{Path, PathBuf};

/// Controllers Tier 1 requires for its documented limits.
pub const REQUIRED: [&str; 3] = ["memory", "cpu", "pids"];

/// A run's cgroup leaf: owns its lifecycle from creation to removal.
pub struct CgroupLeaf {
    path: PathBuf,
    removed: bool,
}

/// Resolves the delegated root the same way doctor does (own cgroup
/// ancestors first, then the systemd user-manager slice). Public for
/// doctor reuse and tests.
pub fn delegated_root() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(own) = own_cgroup_dir() {
        let mut cur = own.clone();
        loop {
            candidates.push(cur.clone());
            if !cur.pop() {
                break;
            }
        }
    }
    // SAFETY: plain getter with no failure mode.
    let uid = unsafe { libc::getuid() };
    candidates.push(PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    )));
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for cur in candidates {
        let probe = cur.join(format!(
            ".cara-cgroup-probe-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        match std::fs::create_dir(&probe) {
            Ok(()) => {
                let _ = std::fs::remove_dir(&probe);
                return Some(cur);
            }
            Err(_) => continue,
        }
    }
    None
}

/// Resolves the cgroup v2 directory of this process.
fn own_cgroup_dir() -> Option<PathBuf> {
    let line = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let v2 = line.lines().find(|l| l.starts_with("0::"))?;
    let rel = v2.trim_start_matches("0::").trim();
    if rel.is_empty() {
        Some(PathBuf::from("/sys/fs/cgroup"))
    } else {
        Some(PathBuf::from("/sys/fs/cgroup").join(rel))
    }
}

/// Full capability probe: can this process create a leaf AND move a
/// forked child into it? This is what sandboxing actually requires —
/// mkdir alone is not enough (nsdelegate forbids moving tasks into a
/// delegated subtree from outside it, e.g. WSL's /non-systemd context).
/// Returns the delegated root on success.
pub fn attach_capable_root() -> Option<PathBuf> {
    let root = delegated_root()?;
    // Fork a child that stays alive while we try the attach.
    // SAFETY: probe context; the child branch only sleeps then _exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        unsafe {
            // SAFETY: park then exit; async-signal-safe calls only.
            libc::sleep(30);
            libc::_exit(0);
        }
    }
    let limits = carapace_core::Limits::default();
    let ok = CgroupLeaf::create(&root, &limits, pid).is_ok();
    // Clean up whether or not the attach worked.
    unsafe {
        // SAFETY: signal and reap our probe child.
        libc::kill(pid, libc::SIGKILL);
        let mut st: libc::c_int = 0;
        libc::waitpid(pid, &mut st, 0);
    }
    if ok { Some(root) } else { None }
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn controllers_at(dir: &Path) -> Vec<String> {
    read_trim(&dir.join("cgroup.controllers"))
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

impl CgroupLeaf {
    /// Creates the leaf under `root`, applies the limits, and attaches the
    /// (still parked) child. Fails closed: any error aborts the sandbox.
    pub fn create(root: &Path, limits: &Limits, child_pid: libc::pid_t) -> std::io::Result<Self> {
        let unique = format!(
            "cara-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = root.join(unique);
        std::fs::create_dir(&path)?;

        // Controllers must be available in the fresh leaf; if not, try to
        // enable them at the delegated root (may legitimately fail when
        // they are already on — then re-check).
        let need_enable: Vec<String> = REQUIRED
            .iter()
            .filter(|c| !controllers_at(&path).contains(&c.to_string()))
            .map(|c| (*c).to_string())
            .collect();
        if !need_enable.is_empty() {
            let add = need_enable
                .iter()
                .map(|c| format!("+{c}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = std::fs::write(root.join("cgroup.subtree_control"), add);
            let missing: Vec<&str> = REQUIRED
                .iter()
                .filter(|c| !controllers_at(&path).contains(&c.to_string()))
                .copied()
                .collect();
            if !missing.is_empty() {
                let _ = std::fs::remove_dir(&path);
                return Err(std::io::Error::other(format!(
                    "delegated cgroup controllers missing: {}",
                    missing.join(", ")
                )));
            }
        }

        // Limits. memory.swap.max=0: no swap escape hatch for the cap.
        // Errors carry the file name so setup failures are diagnosable.
        let ctx = |f: &str, e: std::io::Error| std::io::Error::other(format!("{f}: {e}"));
        wr(&path, "memory.max", &limits.memory_bytes.to_string())
            .map_err(|e| ctx("memory.max", e))?;
        let _ = wr(&path, "memory.swap.max", "0"); // absent on swapless kernels
        wr(&path, "pids.max", &limits.max_processes.to_string()).map_err(|e| ctx("pids.max", e))?;
        // cpu.max: "<quota> <period>"; quota = period * percent / 100.
        let period_us: u64 = 100_000;
        let quota = (period_us.saturating_mul(limits.cpu_percent as u64) / 100).max(1000);
        wr(&path, "cpu.max", &format!("{quota} {period_us}")).map_err(|e| ctx("cpu.max", e))?;
        // io.max (best effort — needs the io controller and a device).
        // TODO(C3-followup): io.max for the scratch device when io is
        // delegated; documented as optional in doctor.

        // Attach the child (it has no descendants yet: it is parked on the
        // go pipe). Writing its pid moves it from its current cgroup into
        // the leaf; every process it later spawns inherits the leaf.
        wr(&path, "cgroup.procs", &child_pid.to_string()).map_err(|e| ctx("cgroup.procs", e))?;

        Ok(Self {
            path,
            removed: false,
        })
    }

    /// SIGKILLs every process in the leaf (third kill switch, ADR-0002).
    pub fn kill(&self) {
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
    }

    /// Reads resource accounting from the leaf. All values optional: file
    /// presence depends on kernel version; absence is reported as None.
    pub fn stats(&self) -> CgroupStats {
        let cpu_usec = read_trim(&self.path.join("cpu.stat")).and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("usage_usec "))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
        });
        let peak_mem =
            read_trim(&self.path.join("memory.peak")).and_then(|s| s.parse::<u64>().ok());
        let oom_kill = read_trim(&self.path.join("memory.events"))
            .map(|s| {
                s.lines()
                    .find(|l| l.starts_with("oom_kill"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .is_some_and(|v| v != "0")
            })
            .unwrap_or(false);
        let peak_pids = read_trim(&self.path.join("pids.peak")).and_then(|s| s.parse::<u64>().ok());
        CgroupStats {
            cpu_usec,
            peak_memory_bytes: peak_mem,
            oom_kill,
            peak_processes: peak_pids,
        }
    }

    /// Removes the leaf. After the whole tree is dead the leaf holds no
    /// processes and rmdir succeeds; retries briefly because cgroup
    /// teardown is asynchronous.
    pub fn remove(mut self) {
        self.remove_sync();
    }

    /// Synchronous removal with bounded retries (cgroup destruction is
    /// asynchronous: rmdir can return EBUSY briefly after the last process
    /// left).
    fn remove_sync(&mut self) {
        if self.removed {
            return;
        }
        for _ in 0..200 {
            if std::fs::remove_dir(&self.path).is_ok() {
                self.removed = true;
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        eprintln!(
            "carapace: WARNING: could not remove cgroup leaf {} (leftover)",
            self.path.display()
        );
        self.removed = true;
    }

    /// Non-blocking removal: a detached thread retries for up to ~10s, so
    /// supervising code never waits on kernel teardown (observed to take
    /// seconds on the reference kernel).
    fn remove_async(path: PathBuf) {
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                for _ in 0..500 {
                    if std::fs::remove_dir(&path).is_ok() {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                eprintln!(
                    "carapace: WARNING: could not remove cgroup leaf {} (leftover)",
                    path.display()
                );
            })
            .ok();
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        if !self.removed {
            let path = self.path.clone();
            self.removed = true;
            Self::remove_async(path);
        }
    }
}

fn wr(dir: &Path, file: &str, value: &str) -> std::io::Result<()> {
    std::fs::write(dir.join(file), value)
}

/// Snapshot of the accounting files at run end.
#[derive(Debug, Clone, Copy, Default)]
pub struct CgroupStats {
    pub cpu_usec: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub oom_kill: bool,
    pub peak_processes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_root_exists_on_dev_env() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        let root = delegated_root().expect("dev env has a delegated root");
        assert!(root.to_string_lossy().contains("user@1000.service"));
    }

    #[test]
    fn leaf_lifecycle_roundtrip() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        let root = delegated_root().expect("delegated root");
        // Fork a child that stays alive while we exercise the leaf.
        // SAFETY: probe context; the child branch only sleeps then _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                // SAFETY: sleep + _exit only; async-signal-safe.
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        let limits = carapace_core::Limits::default();
        let leaf = match CgroupLeaf::create(&root, &limits, pid) {
            Ok(l) => l,
            Err(e) => {
                // // SAFETY: our child
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut st = 0;
                // // SAFETY: our child
                unsafe { libc::waitpid(pid, &mut st, 0) };
                panic!("leaf create failed: {e}");
            }
        };
        // Limit files were written with the configured values.
        assert_eq!(
            read_trim(&leaf.path().join("memory.max")).as_deref(),
            Some(limits.memory_bytes.to_string().as_str())
        );
        assert_eq!(
            read_trim(&leaf.path().join("pids.max")).as_deref(),
            Some(limits.max_processes.to_string().as_str())
        );
        let s = leaf.stats();
        assert!(s.cpu_usec.is_some(), "cpu.stat must exist");
        assert!(s.peak_memory_bytes.is_some(), "memory.peak must exist");
        // The child is inside the leaf: cgroup.kill must terminate it.
        leaf.kill();
        let mut st = 0;
        // // SAFETY: our child
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert!(libc::WIFSIGNALED(st));
        // Now the leaf is empty and must be removable.
        let path = leaf.path().to_path_buf();
        leaf.remove();
        assert!(!path.exists(), "leaf must be removed");
    }
}
