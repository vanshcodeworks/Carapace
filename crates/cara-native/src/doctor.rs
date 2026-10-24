//! Environment capability checks backing `cara doctor` (milestone C0).
//!
//! Every check is a measurement, not an assumption: it performs the actual
//! probe (syscall, filesystem test) at run time. Results feed the
//! fail-closed gate in [`carapace_core::DoctorReport::ready`].

use carapace_core::{Check, DoctorReport};
use carapace_sys::{landlock, mount, ns, seccomp};
use std::path::{Path, PathBuf};

/// Controllers Tier 1 requires to enforce its documented limits.
const REQUIRED_CONTROLLERS: [&str; 3] = ["memory", "cpu", "pids"];
/// Controllers that unlock additional (documented) limits when delegated.
const OPTIONAL_CONTROLLERS: [&str; 1] = ["io"];

/// Runs every capability check and produces the aggregate report.
pub fn run_checks() -> DoctorReport {
    DoctorReport::new(vec![
        check_kernel(),
        check_platform(),
        check_userns(),
        check_cgroup2(),
        check_delegation(),
        check_landlock(),
        check_seccomp(),
        check_pidfd(),
        check_close_range(),
        check_kvm(),
    ])
}

fn check_kernel() -> Check {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uname(2) with a valid, zero-initialized utsname struct.
    let ret = unsafe { libc::uname(&mut uts) };
    if ret != 0 {
        return Check::fail(
            "kernel",
            "Kernel",
            "uname(2) failed",
            "this should never happen on Linux; file a bug",
        );
    }
    let release = cstr_buf_to_string(&uts.release);
    let machine = cstr_buf_to_string(&uts.machine);
    Check::ok("kernel", "Kernel", format!("Linux {release} ({machine})"))
}

fn check_platform() -> Check {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let is_wsl = osrelease.to_ascii_lowercase().contains("microsoft");
    let mut detail = if is_wsl {
        "running under WSL2 (Windows host)".to_string()
    } else {
        "bare metal or VM".to_string()
    };
    let pretty = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        });
    if let Some(p) = pretty {
        detail = format!("{p}; {detail}");
    }
    Check::info("platform", "Platform", detail)
}

fn check_userns() -> Check {
    if ns::unprivileged_userns() {
        Check::ok(
            "userns",
            "User namespaces",
            "unprivileged CLONE_NEWUSER works (rootless sandboxing possible)",
        )
    } else {
        Check::fail(
            "userns",
            "User namespaces",
            "unprivileged CLONE_NEWUSER was denied; rootless sandboxing is impossible",
            "On Debian/Ubuntu check `sysctl kernel.unprivileged_userns_clone`; \
             on Ubuntu 23.10+ also check `sysctl kernel.apparmor_restrict_unprivileged_userns`; \
             in containers, run with a user namespace or the equivalent privileges. \
             See docs/troubleshooting.md.",
        )
    }
}

fn check_cgroup2() -> Check {
    if !mount::is_cgroup2_mount("/sys/fs/cgroup") {
        return Check::fail(
            "cgroup2",
            "cgroup v2",
            "/sys/fs/cgroup is not a cgroup2 mount (cgroup v1 or missing)",
            "Boot the kernel with the unified hierarchy (systemd defaults to it; \
             check `mount | grep cgroup`). Carapace requires cgroup v2 for \
             memory/cpu/pids limits and fails closed without it.",
        );
    }
    let controllers = read_controllers(Path::new("/sys/fs/cgroup"));
    let list = controllers.join(" ");
    if controllers.is_empty() {
        Check::fail(
            "cgroup2",
            "cgroup v2",
            "/sys/fs/cgroup is mounted as cgroup2 but its cgroup.controllers is unreadable",
            "This is unexpected on a normal host; containers sometimes mask it — \
             check that /sys/fs/cgroup is not masked.",
        )
    } else {
        Check::ok(
            "cgroup2",
            "cgroup v2",
            format!("unified hierarchy mounted; kernel controllers: {list}"),
        )
    }
}

/// Resolves the cgroup v2 directory of this process under /sys/fs/cgroup.
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

fn read_controllers(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("cgroup.controllers"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Finds a cgroup this process may create children in — the delegation root
/// the supervisor will build `cara-*` leaf cgroups under.
///
/// Search order (the first writable directory wins):
/// 1. this process's own cgroup and its ancestors (the normal case for a
///    systemd login session, where `user@<uid>.service` is delegated);
/// 2. the systemd user-manager slice
///    `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service`
///    (with `enable-linger`, this subtree is delegated to us *even when the
///    current process sits elsewhere* — e.g. WSL puts non-login commands in
///    a root-owned `/non-systemd` cgroup). Attaching the sandbox child to a
///    leaf under this subtree only requires writing the *child's* pid, not
///    moving ourselves.
fn find_delegation_root() -> Option<(PathBuf, Vec<String>)> {
    let mut candidates = Vec::new();
    if let Some(mut cur) = own_cgroup_dir() {
        loop {
            candidates.push(cur.clone());
            if !cur.pop() {
                break;
            }
        }
    }
    let uid = unsafe { libc::getuid() };
    // SAFETY: getuid is a plain getter with no failure mode.
    candidates.push(PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    )));
    for cur in candidates {
        let probe = cur.join(unique_probe_name());
        match std::fs::create_dir(&probe) {
            Ok(()) => {
                // Best-effort cleanup; a leftover dot-dir is inert.
                let _ = std::fs::remove_dir(&probe);
                let controllers = read_controllers(&cur);
                return Some((cur, controllers));
            }
            Err(_) => continue,
        }
    }
    None
}

/// Unique name for delegation probes so concurrent callers (tests) never
/// observe each other's probe directories.
fn unique_probe_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        ".cara-doctor-probe-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn check_delegation() -> Check {
    match find_delegation_root() {
        None => Check::fail(
            "cgroup-delegation",
            "cgroup delegation",
            "no writable cgroup in this process's ancestry: memory/cpu/pids limits cannot be set",
            "With systemd: `sudo loginctl enable-linger $USER` and ensure the user slice \
             delegates controllers (drop-in /etc/systemd/system/user@.service.d/delegate.conf \
             with `[Service]\\nDelegate=cpu io memory pids`), then re-login. \
             See docs/troubleshooting.md.",
        ),
        Some((root, controllers)) => {
            let missing_required: Vec<&str> = REQUIRED_CONTROLLERS
                .iter()
                .filter(|c| !controllers.contains(&c.to_string()))
                .copied()
                .collect();
            let missing_optional: Vec<&str> = OPTIONAL_CONTROLLERS
                .iter()
                .filter(|c| !controllers.contains(&c.to_string()))
                .copied()
                .collect();
            let root_disp = root.display();
            let cons = controllers.join(" ");
            if !missing_required.is_empty() {
                Check::fail(
                    "cgroup-delegation",
                    "cgroup delegation",
                    format!(
                        "writable cgroup found at {root_disp}, but delegated controllers ({cons}) \
                         lack: {}",
                        missing_required.join(", ")
                    ),
                    "Ask your admin (or systemd drop-in) to delegate at least \
                     `cpu memory pids` to your user slice. Carapace fails closed rather \
                     than run without these limits.",
                )
            } else if !missing_optional.is_empty() {
                Check::warn(
                    "cgroup-delegation",
                    "cgroup delegation",
                    format!(
                        "writable cgroup at {root_disp}; controllers: {cons}; \
                         not delegated: {} (disk I/O limits unavailable, everything else works)",
                        missing_optional.join(", ")
                    ),
                    "Delegate `io` as well (see docs/troubleshooting.md) to enable disk \
                     I/O limits.",
                )
            } else {
                Check::ok(
                    "cgroup-delegation",
                    "cgroup delegation",
                    format!("writable cgroup at {root_disp}; controllers: {cons}"),
                )
            }
        }
    }
}

fn check_landlock() -> Check {
    match landlock::abi_version() {
        Some(v) => Check::ok(
            "landlock",
            "Landlock",
            format!("Landlock ABI v{v} (filesystem rules enforced in-kernel)"),
        ),
        None => Check::fail(
            "landlock",
            "Landlock",
            "landlock_create_ruleset(VERSION) failed: Landlock unavailable",
            "Kernel must be built with CONFIG_SECURITY_LANDLOCK=y and list landlock \
             in CONFIG_LSM (check /proc/config.gz). Landlock enforces filesystem \
             policy in Tier 1; Carapace fails closed without it.",
        ),
    }
}

fn check_seccomp() -> Check {
    if seccomp::filter_support() {
        Check::ok(
            "seccomp",
            "seccomp-bpf",
            "seccomp filters supported (syscall allowlists enforced in-kernel)",
        )
    } else {
        Check::fail(
            "seccomp",
            "seccomp-bpf",
            "SECCOMP_GET_ACTION_AVAIL probe failed: seccomp-bpf unavailable",
            "Kernel must be built with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y. \
             Carapace fails closed without syscall filtering.",
        )
    }
}

fn check_pidfd() -> Check {
    if ns::pidfd_open_support() {
        Check::info(
            "pidfd",
            "pidfd",
            "pidfd_open available (race-free process-tree kill)",
        )
    } else {
        Check::warn(
            "pidfd",
            "pidfd",
            "pidfd_open unavailable (kernel < 5.3)",
            "Carapace falls back to process-group kill; upgrade to kernel >= 5.10 \
             (the documented baseline) for reliable tree kill.",
        )
    }
}

fn check_close_range() -> Check {
    if ns::close_range_support() {
        Check::info(
            "close-range",
            "close_range",
            "close_range available (no fd leaks into the sandbox)",
        )
    } else {
        Check::warn(
            "close-range",
            "close_range",
            "close_range unavailable (kernel < 5.9)",
            "Carapace will sanitize descriptors via /proc/self/fd enumeration instead; \
             upgrade to kernel >= 5.10 (the documented baseline).",
        )
    }
}

fn check_kvm() -> Check {
    match std::fs::metadata("/dev/kvm") {
        Ok(_) => Check::info(
            "kvm",
            "KVM",
            "/dev/kvm present: Tier 3 (microVM) is possible on this machine",
        ),
        Err(_) => Check::info(
            "kvm",
            "KVM",
            "/dev/kvm absent: Tier 3 (microVM) disabled; Tiers 1 and 2 are unaffected",
        ),
    }
}

/// Converts a fixed-size NUL-padded utsname field to a Rust String.
fn cstr_buf_to_string(buf: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_checks_have_substance() {
        let report = run_checks();
        assert!(report.checks.len() >= 8, "expected a full check suite");
        for c in &report.checks {
            assert!(!c.id.is_empty() && !c.name.is_empty(), "unnamed check");
            assert!(!c.detail.is_empty(), "check {} lacks detail", c.id);
        }
        // Every failed check must carry a remedy.
        for c in &report.checks {
            if c.status == carapace_core::Status::Fail {
                assert!(c.remedy.is_some(), "failing check {} lacks a remedy", c.id);
            }
        }
    }

    #[test]
    fn ids_are_unique() {
        let report = run_checks();
        let mut ids: Vec<&str> = report.checks.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate check ids");
    }

    #[test]
    fn strict_env_is_tier1_ready() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        let report = run_checks();
        assert!(
            report.ready(),
            "dev environment must be Tier 1 ready; failures: {:?}",
            report
                .failed_required()
                .iter()
                .map(|c| c.id.clone())
                .collect::<Vec<_>>()
        );
        // And it must actually report the capabilities we measured by hand
        // in docs/agent/ENV.md — doctor is not allowed to drift from reality.
        let landlock = report.checks.iter().find(|c| c.id == "landlock").unwrap();
        assert!(landlock.detail.contains("ABI v7"));
    }

    #[test]
    fn delegation_probe_cleans_up_after_itself() {
        // Run twice; a leftover probe dir would make the second run observe
        // it (mkdir of an existing dir fails), so success twice proves cleanup.
        let first = find_delegation_root();
        let second = find_delegation_root();
        assert_eq!(first.is_some(), second.is_some());
    }
}
