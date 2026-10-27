//! Environment capability checks backing `cara doctor` (milestone C0).
//!
//! Every check is a measurement, not an assumption: [`Facts::collect`]
//! performs the actual probes (syscalls, filesystem reads) at run time, and
//! [`classify`] turns those facts into the report. Classification is pure so
//! every known blocker can be simulated and tested without touching the
//! host.
//!
//! Remedies are printed, never applied. Each one names the exact command or
//! configuration change and cites the upstream documentation for it.

use carapace_core::{Check, DoctorReport};
use carapace_sys::{landlock, mount, ns, seccomp};
use std::path::{Path, PathBuf};

/// Controllers Tier 1 requires to enforce its documented limits.
const REQUIRED_CONTROLLERS: [&str; 3] = ["memory", "cpu", "pids"];
/// Controllers that unlock additional (documented) limits when delegated.
const OPTIONAL_CONTROLLERS: [&str; 1] = ["io"];

/// Appended to every remedy: Carapace observes the host; it never edits it.
const REMEDY_NOTE: &str = "Carapace prints remedies only; it never changes host \
settings or applies them for you.";

const URL_APPARMOR_USERNS: &str =
    "https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction";
/// `kernel.unprivileged_userns_clone` is a Debian kernel patch, not a
/// mainline sysctl; the authoritative description is the patch itself.
/// (Debian's wiki page for it sits behind an anti-bot challenge.)
const URL_DEBIAN_USERNS_PATCH: &str = "https://salsa.debian.org/kernel-team/linux/-/blob/master/debian/patches/debian/add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch";
const URL_USER_NAMESPACES: &str = "https://docs.kernel.org/admin-guide/sysctl/user.html";
const URL_CGROUP2: &str = "https://docs.kernel.org/admin-guide/cgroup-v2.html";
const URL_CGROUP_DELEGATION: &str = "https://systemd.io/CGROUP_DELEGATION/";
const URL_USR_MERGE: &str = "https://systemd.io/THE_CASE_FOR_THE_USR_MERGE/";
const URL_LANDLOCK: &str = "https://docs.kernel.org/userspace-api/landlock.html";
const URL_SECCOMP: &str = "https://docs.kernel.org/userspace-api/seccomp_filter.html";
const URL_PIDFD: &str = "https://man7.org/linux/man-pages/man2/pidfd_open.2.html";
const URL_CLOSE_RANGE: &str = "https://man7.org/linux/man-pages/man2/close_range.2.html";

/// One remedy is the body plus the two invariants every remedy carries.
fn remedy(body: &str, upstream: &str) -> String {
    format!("{body}\n{REMEDY_NOTE}\nUpstream: {upstream}")
}

/// Raw host measurements. Constructing one is cheap and side-effect free
/// apart from the delegation probe (which creates and removes a cgroup
/// leaf, as it always has).
#[derive(Debug, Clone)]
struct Facts {
    kernel_release: Option<String>,
    machine: String,
    pretty_os: Option<String>,
    is_wsl: bool,
    userns_works: bool,
    apparmor_restrict_userns: Option<i64>,
    unprivileged_userns_clone: Option<i64>,
    max_user_namespaces: Option<i64>,
    cgroup2_mounted: bool,
    cgroup2_controllers: Vec<String>,
    /// Mount points of cgroup v1 hierarchies found in /proc/mounts.
    cgroup_v1_mounts: Vec<String>,
    /// Writable delegated cgroup root, if attaching a child works.
    delegation_root: Option<PathBuf>,
    delegated_controllers: Vec<String>,
    runtime_missing: Vec<String>,
    landlock_abi: Option<u32>,
    seccomp_supported: bool,
    pidfd: bool,
    close_range: bool,
    init_name: Option<String>,
    kvm: bool,
}

impl Facts {
    fn collect() -> Self {
        let mut uts: libc::utsname = unsafe {
            // SAFETY: utsname is a plain POD C struct; zeroed is valid.
            std::mem::zeroed()
        };
        // SAFETY: uname(2) with a valid, zero-initialized utsname struct.
        let uname_ok = unsafe { libc::uname(&mut uts) } == 0;
        let kernel_release = uname_ok.then(|| cstr_buf_to_string(&uts.release));
        let machine = if uname_ok {
            cstr_buf_to_string(&uts.machine)
        } else {
            String::new()
        };
        let is_wsl = kernel_release
            .as_deref()
            .is_some_and(|r| r.to_ascii_lowercase().contains("microsoft"));
        let pretty_os = read_pretty_os();
        let delegation_root = crate::cgroup::attach_capable_root();
        let delegated_controllers = delegation_root
            .as_deref()
            .map(read_controllers)
            .unwrap_or_default();
        Self {
            kernel_release,
            machine,
            pretty_os,
            is_wsl,
            userns_works: ns::unprivileged_userns(),
            apparmor_restrict_userns: read_sysctl_i64(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            ),
            unprivileged_userns_clone: read_sysctl_i64(
                "/proc/sys/kernel/unprivileged_userns_clone",
            ),
            max_user_namespaces: read_sysctl_i64("/proc/sys/user/max_user_namespaces"),
            cgroup2_mounted: mount::is_cgroup2_mount("/sys/fs/cgroup"),
            cgroup2_controllers: read_controllers(Path::new("/sys/fs/cgroup")),
            cgroup_v1_mounts: cgroup_v1_mounts(),
            delegation_root,
            delegated_controllers,
            runtime_missing: ["/usr/bin/sh", "/usr/lib", "/usr/lib64"]
                .iter()
                .filter(|p| std::fs::metadata(p).is_err())
                .map(|p| (*p).to_string())
                .collect(),
            landlock_abi: landlock::abi_version(),
            seccomp_supported: seccomp::filter_support(),
            pidfd: ns::pidfd_open_support(),
            close_range: ns::close_range_support(),
            init_name: std::fs::read_to_string("/proc/1/comm")
                .ok()
                .map(|s| s.trim().to_string()),
            kvm: std::fs::metadata("/dev/kvm").is_ok(),
        }
    }
}

fn read_sysctl_i64(path: &str) -> Option<i64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_pretty_os() -> Option<String> {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        })
}

/// cgroup v1 mount points (the unified hierarchy is detected separately).
fn cgroup_v1_mounts() -> Vec<String> {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    let mut out: Vec<String> = mounts
        .lines()
        .filter_map(|line| {
            // /proc/mounts: <device> <mount point> <fs type> <options> ...
            let mut fields = line.split_whitespace();
            let _device = fields.next()?;
            let mount_point = fields.next()?;
            let fs_type = fields.next()?;
            (fs_type == "cgroup").then(|| mount_point.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Runs every capability check and produces the aggregate report.
pub fn run_checks() -> DoctorReport {
    classify(&Facts::collect())
}

/// Pure classification: every host fact is an input, so tests can simulate
/// any environment without changing the machine.
fn classify(f: &Facts) -> DoctorReport {
    DoctorReport::new(vec![
        check_kernel(f),
        check_platform(f),
        check_userns(f),
        check_cgroup2(f),
        check_delegation(f),
        check_landlock(f),
        check_seccomp(f),
        check_pidfd(f),
        check_close_range(f),
        check_runtime_layout(f),
        check_init(f),
        check_kvm(f),
    ])
}

fn check_kernel(f: &Facts) -> Check {
    let Some(release) = &f.kernel_release else {
        return Check::fail(
            "kernel",
            "Kernel",
            "uname(2) failed",
            "this should never happen on Linux; file a bug",
        );
    };
    Check::ok(
        "kernel",
        "Kernel",
        format!("Linux {release} ({})", f.machine),
    )
}

fn check_platform(f: &Facts) -> Check {
    let mut detail = if f.is_wsl {
        "running under WSL2 (Windows host)".to_string()
    } else {
        "bare metal or VM".to_string()
    };
    if let Some(p) = &f.pretty_os {
        detail = format!("{p}; {detail}");
    }
    Check::info("platform", "Platform", detail)
}

/// User namespaces: report the exact blocker, because the remedies differ.
/// AppArmor's restriction is checked first: where it exists it is the
/// documented cause on Ubuntu 23.10+, even if the older sysctl also exists.
fn check_userns(f: &Facts) -> Check {
    if f.userns_works {
        return Check::ok(
            "userns",
            "User namespaces",
            "unprivileged CLONE_NEWUSER works (rootless sandboxing possible)",
        );
    }

    let detail = "unprivileged CLONE_NEWUSER was denied; rootless sandboxing is impossible";

    if f.apparmor_restrict_userns == Some(1) {
        return Check::fail(
            "userns",
            "User namespaces",
            format!(
                "{detail} (AppArmor restricts unprivileged user namespaces: \
                 kernel.apparmor_restrict_unprivileged_userns=1)"
            ),
            remedy(
                "AppArmor is restricting unprivileged user namespaces.\n\
                 Exact system-wide remedy: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n\
                 Persist: create /etc/sysctl.d/60-apparmor-namespace.conf containing\n\
                 kernel.apparmor_restrict_unprivileged_userns=0\n\
                 then reboot or run sudo sysctl --system.\n\
                 Trade-off: this weakens host hardening for every unconfined app. The scoped\n\
                 alternative is an AppArmor profile with `allow userns create,` for the cara\n\
                 binary (see upstream). Carapace cannot detect a per-binary profile, so it\n\
                 reports the system-wide remedy.",
                URL_APPARMOR_USERNS,
            ),
        );
    }
    if f.unprivileged_userns_clone == Some(0) {
        return Check::fail(
            "userns",
            "User namespaces",
            format!("{detail} (kernel.unprivileged_userns_clone=0)"),
            remedy(
                "The distro kernel sysctl disables unprivileged user namespaces.\n\
                 Exact remedy: sudo sysctl -w kernel.unprivileged_userns_clone=1\n\
                 Persist: create /etc/sysctl.d/60-cara-userns.conf containing\n\
                 kernel.unprivileged_userns_clone=1\n\
                 then reboot or run sudo sysctl --system.\n\
                 This knob is Debian-specific (a Debian kernel patch); the upstream\n\
                 patch is linked below. Modern kernels use user.max_user_namespaces.",
                URL_DEBIAN_USERNS_PATCH,
            ),
        );
    }
    if f.max_user_namespaces == Some(0) {
        return Check::fail(
            "userns",
            "User namespaces",
            format!("{detail} (user.max_user_namespaces=0)"),
            remedy(
                "The kernel's global user-namespace limit is zero.\n\
                 Exact remedy: sudo sysctl -w user.max_user_namespaces=10000\n\
                 Persist it in /etc/sysctl.d/60-cara-userns.conf with the same line,\n\
                 then reboot or run sudo sysctl --system.",
                URL_USER_NAMESPACES,
            ),
        );
    }
    Check::fail(
        "userns",
        "User namespaces",
        detail,
        remedy(
            "No single known sysctl explains the denial. Inspect the layers in order:\n\
             cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns  (Ubuntu 23.10+)\n\
             cat /proc/sys/kernel/unprivileged_userns_clone             (Debian kernels)\n\
             cat /proc/sys/user/max_user_namespaces\n\
             Then apply the matching remedy from docs/troubleshooting.md. In a container,\n\
             the runtime must grant a user namespace or the equivalent privileges.",
            URL_USER_NAMESPACES,
        ),
    )
}

/// cgroup v2 and the v1/hybrid cases. A hybrid host is usable only when the
/// required controllers are actually available through cgroup2.
fn check_cgroup2(f: &Facts) -> Check {
    let v1 = &f.cgroup_v1_mounts;
    let missing_required: Vec<&str> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|c| !f.cgroup2_controllers.iter().any(|x| x == *c))
        .copied()
        .collect();
    let controller_list = f.cgroup2_controllers.join(" ");

    if !f.cgroup2_mounted {
        let (detail, body) = if v1.is_empty() {
            (
                "/sys/fs/cgroup is not a cgroup2 mount (cgroup v1 or missing)".to_string(),
                "Mount the unified cgroup v2 hierarchy and delegate it to your user. Carapace\n\
                 requires cgroup v2 for memory/cpu/pids limits and fails closed without it."
                    .to_string(),
            )
        } else {
            (
                format!(
                    "cgroup v1/hybrid hierarchy mounted instead of cgroup2 (v1 mounts: {})",
                    v1.join(", ")
                ),
                "Boot with the unified cgroup v2 hierarchy:\n\
                 systemd hosts: add systemd.unified_cgroup_hierarchy=1 to the kernel command line\n\
                 (edit GRUB_CMDLINE_LINUX in /etc/default/grub, then sudo update-grub and reboot).\n\
                 Non-systemd hosts: add cgroup_no_v1=all to the kernel command line.\n\
                 Verify after reboot: `mount | grep cgroup` shows cgroup2 on /sys/fs/cgroup."
                    .to_string(),
            )
        };
        return Check::fail("cgroup2", "cgroup v2", detail, remedy(&body, URL_CGROUP2));
    }

    if f.cgroup2_controllers.is_empty() {
        return Check::fail(
            "cgroup2",
            "cgroup v2",
            "/sys/fs/cgroup is mounted as cgroup2 but its cgroup.controllers is unreadable",
            remedy(
                "This is unexpected on a normal host; containers sometimes mask /sys/fs/cgroup.\n\
                 Check that /sys/fs/cgroup is not masked and is readable by your user.",
                URL_CGROUP2,
            ),
        );
    }

    if !missing_required.is_empty() {
        if !v1.is_empty() {
            return Check::fail(
                "cgroup2",
                "cgroup v2",
                format!(
                    "hybrid hierarchy: cgroup2 is mounted but v1 also owns controllers \
                     (v1 mounts: {}); cgroup2 lacks required controllers: {}",
                    v1.join(", "),
                    missing_required.join(", ")
                ),
                remedy(
                    "The v1 mounts are keeping the required controllers out of cgroup2.\n\
                     Boot with the unified hierarchy only:\n\
                     systemd hosts: add systemd.unified_cgroup_hierarchy=1 to the kernel command line\n\
                     (then sudo update-grub and reboot). Non-systemd hosts: add cgroup_no_v1=all.\n\
                     Verify: cat /sys/fs/cgroup/cgroup.controllers lists memory cpu pids.",
                    URL_CGROUP2,
                ),
            );
        }
        return Check::fail(
            "cgroup2",
            "cgroup v2",
            format!(
                "/sys/fs/cgroup is mounted as cgroup2 but required controllers are missing \
                 (have: {controller_list})"
            ),
            remedy(
                "The kernel does not expose the required controllers in this cgroup2 mount.\n\
                 Check `cat /sys/fs/cgroup/cgroup.controllers`; if a controller is missing from\n\
                 the kernel entirely, boot a kernel built with CONFIG_MEMCG, CONFIG_CGROUP_SCHED\n\
                 and CONFIG_CGROUP_PIDS. If it is present but not enabled here, remove the v1\n\
                 mounts (systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all).",
                URL_CGROUP2,
            ),
        );
    }

    if !v1.is_empty() {
        return Check::warn(
            "cgroup2",
            "cgroup v2",
            format!(
                "hybrid hierarchy: cgroup2 has the required controllers ({controller_list}); \
                 v1 mounts are also present but unused by Carapace (v1 mounts: {})",
                v1.join(", ")
            ),
            remedy(
                "No action is needed for Carapace: memory/cpu/pids are enforced through cgroup2.\n\
                 To simplify the host, boot with systemd.unified_cgroup_hierarchy=1 (systemd) or\n\
                 cgroup_no_v1=all (non-systemd).",
                URL_CGROUP2,
            ),
        );
    }

    Check::ok(
        "cgroup2",
        "cgroup v2",
        format!("unified hierarchy mounted; kernel controllers: {controller_list}"),
    )
}

fn check_delegation(f: &Facts) -> Check {
    if !f.cgroup2_mounted {
        return Check::info(
            "cgroup-delegation",
            "cgroup delegation",
            "not evaluated: cgroup v2 is not mounted (see the cgroup v2 check)",
        );
    }
    let Some(root) = &f.delegation_root else {
        return Check::fail(
            "cgroup-delegation",
            "cgroup delegation",
            "cannot move a child process into a delegated cgroup leaf from here \
             (memory/cpu/pids limits would be unenforceable)",
            remedy(
                "This process is outside a delegated cgroup subtree (WSL puts wsl.exe commands\n\
                 in /non-systemd; containers often do the same).\n\
                 Quickest fix, no host changes: run cara inside the user manager:\n\
                 systemd-run --user --scope --quiet cara doctor\n\
                 For a normal login, enable delegation permanently:\n\
                 sudo loginctl enable-linger $USER\n\
                 sudo systemctl edit user@.service\n\
                 # add under [Service]: Delegate=cpu memory pids io\n\
                 sudo systemctl daemon-reload   # then log out and back in\n\
                 Verify: cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers",
                URL_CGROUP_DELEGATION,
            ),
        );
    };

    let controllers = &f.delegated_controllers;
    let missing_required: Vec<&str> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|c| !controllers.iter().any(|x| x == *c))
        .copied()
        .collect();
    let missing_optional: Vec<&str> = OPTIONAL_CONTROLLERS
        .iter()
        .filter(|c| !controllers.iter().any(|x| x == *c))
        .copied()
        .collect();
    let root_disp = root.display();
    let cons = controllers.join(" ");

    if !missing_required.is_empty() {
        return Check::fail(
            "cgroup-delegation",
            "cgroup delegation",
            format!(
                "writable cgroup found at {root_disp}, but delegated controllers ({cons}) \
                 lack: {}",
                missing_required.join(", ")
            ),
            remedy(
                "Delegate at least `cpu memory pids` to your user slice:\n\
                 sudo systemctl edit user@.service\n\
                 # add under [Service]: Delegate=cpu memory pids io\n\
                 sudo systemctl daemon-reload   # then log out and back in\n\
                 Verify: cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers\n\
                 In containers, delegate the same controllers from the container manager.",
                URL_CGROUP_DELEGATION,
            ),
        );
    }
    if !missing_optional.is_empty() {
        return Check::warn(
            "cgroup-delegation",
            "cgroup delegation",
            format!(
                "writable cgroup at {root_disp}; controllers: {cons}; \
                 not delegated: {} (disk I/O limits unavailable, everything else works)",
                missing_optional.join(", ")
            ),
            remedy(
                "Delegate `io` as well to enable disk I/O limits:\n\
                 sudo systemctl edit user@.service\n\
                 # add under [Service]: Delegate=cpu memory pids io\n\
                 sudo systemctl daemon-reload   # then log out and back in",
                URL_CGROUP_DELEGATION,
            ),
        );
    }
    Check::ok(
        "cgroup-delegation",
        "cgroup delegation",
        format!("writable cgroup at {root_disp}; controllers: {cons}"),
    )
}

fn check_landlock(f: &Facts) -> Check {
    match f.landlock_abi {
        Some(v) => Check::ok(
            "landlock",
            "Landlock",
            format!("Landlock ABI v{v} (filesystem rules enforced in-kernel)"),
        ),
        None => Check::fail(
            "landlock",
            "Landlock",
            "landlock_create_ruleset(VERSION) failed: Landlock unavailable",
            remedy(
                "The kernel lacks Landlock (mainline since 5.13) or it is not active.\n\
                 Check: zgrep -E 'CONFIG_(SECURITY_LANDLOCK|LSM)=' /proc/config.gz\n\
                 (or /boot/config-$(uname -r)). Required: CONFIG_SECURITY_LANDLOCK=y and\n\
                 landlock listed in CONFIG_LSM (or in the lsm= boot parameter).\n\
                 Change the kernel config/boot parameters and reboot.",
                URL_LANDLOCK,
            ),
        ),
    }
}

fn check_seccomp(f: &Facts) -> Check {
    if f.seccomp_supported {
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
            remedy(
                "The kernel must be built with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y.\n\
                 Check: zgrep -E 'CONFIG_SECCOMP(_FILTER)?=' /proc/config.gz\n\
                 (or /boot/config-$(uname -r)); boot a kernel with both enabled.",
                URL_SECCOMP,
            ),
        )
    }
}

fn check_pidfd(f: &Facts) -> Check {
    if f.pidfd {
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
            remedy(
                "pidfd_open(2) requires Linux >= 5.3. Carapace falls back to process-group\n\
                 kill (less race-free); the documented baseline is Linux >= 5.10.\n\
                 Upgrade the kernel to restore the race-free path.",
                URL_PIDFD,
            ),
        )
    }
}

fn check_close_range(f: &Facts) -> Check {
    if f.close_range {
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
            remedy(
                "close_range(2) requires Linux >= 5.9. Carapace sanitizes descriptors via\n\
                 /proc/self/fd enumeration instead (slower and racier); the documented\n\
                 baseline is Linux >= 5.10. Upgrade the kernel to restore close_range.",
                URL_CLOSE_RANGE,
            ),
        )
    }
}

/// The v1 rootfs recipe bind-mounts the host /usr read-only and needs the
/// merged-usr layout (/usr/bin/sh, /usr/lib, /usr/lib64, with /bin -> usr/bin
/// symlinks created inside the sandbox). Detect a non-merged layout here
/// (with a remedy) instead of at spawn time.
fn check_runtime_layout(f: &Facts) -> Check {
    if f.runtime_missing.is_empty() {
        return Check::ok(
            "runtime-layout",
            "Runtime layout",
            "merged-usr layout present (v1 recipe mounts host /usr read-only)",
        );
    }
    Check::fail(
        "runtime-layout",
        "Runtime layout",
        format!(
            "missing: {} (the v1 recipe requires a merged-usr host)",
            f.runtime_missing.join(", ")
        ),
        remedy(
            "The v1 rootfs mounts the host /usr and recreates /bin, /lib and /lib64 as\n\
             symlinks, so those paths must be the usual merged-/usr links.\n\
             Debian/Ubuntu exact remedy: sudo apt install usrmerge   (then reboot)\n\
             Verify after reboot: ls -ld /bin /lib /lib64 shows symlinks into usr/.\n\
             Fedora/Arch and most current distros are already merged. If you cannot merge,\n\
             this host is unsupported by Tier 1 and Carapace fails closed.",
            URL_USR_MERGE,
        ),
    )
}

fn check_init(f: &Facts) -> Check {
    match &f.init_name {
        Some(n) if n.starts_with("systemd") || n == "init" => Check::ok(
            "init",
            "Init system",
            format!("PID 1 is {n} (systemd delegation remedies apply)"),
        ),
        Some(n) => Check::warn(
            "init",
            "Init system",
            format!("PID 1 is {n}, not systemd"),
            remedy(
                "The delegation remedies in docs/troubleshooting.md assume systemd\n\
                 (user@<uid>.service slices). Without systemd you must arrange a delegated\n\
                 cgroup v2 subtree yourself: create a cgroup subtree, chown it to your uid,\n\
                 and enable the required controllers in its cgroup.subtree_control.\n\
                 Carapace fails closed until delegation works.",
                URL_CGROUP_DELEGATION,
            ),
        ),
        None => Check::info(
            "init",
            "Init system",
            "PID 1 unreadable; delegation remedies may not apply".to_string(),
        ),
    }
}

fn check_kvm(f: &Facts) -> Check {
    if f.kvm {
        Check::info(
            "kvm",
            "KVM",
            "/dev/kvm present: Tier 3 (microVM) is possible on this machine",
        )
    } else {
        Check::info(
            "kvm",
            "KVM",
            "/dev/kvm absent: Tier 3 (microVM) disabled; Tiers 1 and 2 are unaffected",
        )
    }
}

fn read_controllers(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("cgroup.controllers"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
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
    use carapace_core::Status;

    /// A synthetic environment where every required capability works. Each
    /// blocker test mutates exactly one field, so the failure it asserts can
    /// only come from that field.
    fn healthy() -> Facts {
        Facts {
            kernel_release: Some("6.18.0-test".to_string()),
            machine: "x86_64".to_string(),
            pretty_os: Some("Ubuntu 24.04 LTS".to_string()),
            is_wsl: false,
            userns_works: true,
            apparmor_restrict_userns: Some(0),
            unprivileged_userns_clone: Some(1),
            max_user_namespaces: Some(15000),
            cgroup2_mounted: true,
            cgroup2_controllers: ["cpuset", "cpu", "io", "memory", "pids"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cgroup_v1_mounts: Vec::new(),
            delegation_root: Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service",
            )),
            delegated_controllers: ["cpu", "io", "memory", "pids"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            runtime_missing: Vec::new(),
            landlock_abi: Some(7),
            seccomp_supported: true,
            pidfd: true,
            close_range: true,
            init_name: Some("systemd".to_string()),
            kvm: false,
        }
    }

    fn find<'a>(r: &'a DoctorReport, id: &str) -> &'a Check {
        r.checks.iter().find(|c| c.id == id).expect("check id")
    }

    fn remedy_of<'a>(r: &'a DoctorReport, id: &str) -> &'a str {
        find(r, id).remedy.as_deref().expect("remedy present")
    }

    #[test]
    fn healthy_synthetic_env_is_ready() {
        let r = classify(&healthy());
        assert!(
            r.ready(),
            "healthy facts must pass: {:?}",
            r.failed_required()
        );
        assert_eq!(r.overall(), Status::Ok);
    }

    #[test]
    fn apparmor_userns_blocker_has_exact_remedy() {
        let mut f = healthy();
        f.userns_works = false;
        f.apparmor_restrict_userns = Some(1);
        let r = classify(&f);
        let c = find(&r, "userns");
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("AppArmor"), "detail: {}", c.detail);
        let rem = remedy_of(&r, "userns");
        assert!(rem.contains("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"));
        assert!(rem.contains("/etc/sysctl.d/60-apparmor-namespace.conf"));
        assert!(rem.contains(URL_APPARMOR_USERNS));
        assert!(rem.contains("never changes host settings"));
    }

    #[test]
    fn disabled_userns_clone_sysctl_has_exact_remedy() {
        let mut f = healthy();
        f.userns_works = false;
        f.apparmor_restrict_userns = Some(0);
        f.unprivileged_userns_clone = Some(0);
        let r = classify(&f);
        assert_eq!(find(&r, "userns").status, Status::Fail);
        assert!(
            find(&r, "userns")
                .detail
                .contains("unprivileged_userns_clone=0")
        );
        let rem = remedy_of(&r, "userns");
        assert!(rem.contains("sudo sysctl -w kernel.unprivileged_userns_clone=1"));
        assert!(rem.contains("60-cara-userns.conf"));
        assert!(rem.contains(URL_DEBIAN_USERNS_PATCH));
        assert!(rem.contains("Debian-specific"));
    }

    #[test]
    fn zero_max_user_namespaces_has_exact_remedy() {
        let mut f = healthy();
        f.userns_works = false;
        f.apparmor_restrict_userns = None;
        f.unprivileged_userns_clone = None;
        f.max_user_namespaces = Some(0);
        let r = classify(&f);
        assert!(find(&r, "userns").detail.contains("max_user_namespaces=0"));
        let rem = remedy_of(&r, "userns");
        assert!(rem.contains("sudo sysctl -w user.max_user_namespaces=10000"));
        assert!(rem.contains(URL_USER_NAMESPACES));
    }

    #[test]
    fn unknown_userns_denial_names_the_probe_layers() {
        let mut f = healthy();
        f.userns_works = false;
        f.apparmor_restrict_userns = Some(0);
        f.unprivileged_userns_clone = Some(1);
        f.max_user_namespaces = Some(15000);
        let r = classify(&f);
        let rem = remedy_of(&r, "userns");
        assert!(rem.contains("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"));
        assert!(rem.contains("/proc/sys/kernel/unprivileged_userns_clone"));
        assert!(rem.contains("/proc/sys/user/max_user_namespaces"));
    }

    #[test]
    fn cgroup_v1_only_is_detected_with_boot_parameter_remedy() {
        let mut f = healthy();
        f.cgroup2_mounted = false;
        f.cgroup2_controllers.clear();
        f.cgroup_v1_mounts = vec![
            "/sys/fs/cgroup/memory".to_string(),
            "/sys/fs/cgroup/cpu,cpuacct".to_string(),
            "/sys/fs/cgroup/pids".to_string(),
        ];
        let r = classify(&f);
        let c = find(&r, "cgroup2");
        assert_eq!(c.status, Status::Fail);
        assert!(
            c.detail.contains("cgroup v1/hybrid"),
            "detail: {}",
            c.detail
        );
        let rem = remedy_of(&r, "cgroup2");
        assert!(rem.contains("systemd.unified_cgroup_hierarchy=1"));
        assert!(rem.contains("cgroup_no_v1=all"));
        assert!(rem.contains(URL_CGROUP2));
    }

    #[test]
    fn hybrid_without_required_controllers_is_a_blocker() {
        let mut f = healthy();
        f.cgroup2_controllers = vec!["cpuset".to_string(), "pids".to_string()];
        f.cgroup_v1_mounts = vec!["/sys/fs/cgroup/memory".to_string()];
        let r = classify(&f);
        let c = find(&r, "cgroup2");
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("hybrid hierarchy"));
        assert!(c.detail.contains("memory"));
        assert!(remedy_of(&r, "cgroup2").contains("cgroup_no_v1=all"));
    }

    #[test]
    fn hybrid_with_required_controllers_warns_but_runs() {
        let mut f = healthy();
        f.cgroup_v1_mounts = vec!["/sys/fs/cgroup/memory".to_string()];
        let r = classify(&f);
        let c = find(&r, "cgroup2");
        assert_eq!(c.status, Status::Warn);
        assert!(r.ready(), "a usable hybrid host must not be blocked");
        assert!(remedy_of(&r, "cgroup2").contains("No action is needed"));
    }

    #[test]
    fn missing_delegation_has_systemd_remedy() {
        let mut f = healthy();
        f.delegation_root = None;
        f.delegated_controllers.clear();
        let r = classify(&f);
        let c = find(&r, "cgroup-delegation");
        assert_eq!(c.status, Status::Fail);
        let rem = remedy_of(&r, "cgroup-delegation");
        assert!(rem.contains("systemd-run --user --scope --quiet cara doctor"));
        assert!(rem.contains("loginctl enable-linger"));
        assert!(rem.contains("Delegate=cpu memory pids io"));
        assert!(rem.contains(URL_CGROUP_DELEGATION));
    }

    #[test]
    fn missing_required_controllers_names_them_and_the_dropin() {
        let mut f = healthy();
        f.delegated_controllers = vec!["pids".to_string()];
        let r = classify(&f);
        let c = find(&r, "cgroup-delegation");
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("memory"), "detail: {}", c.detail);
        assert!(c.detail.contains("cpu"), "detail: {}", c.detail);
        assert!(remedy_of(&r, "cgroup-delegation").contains("Delegate=cpu memory pids io"));
    }

    #[test]
    fn missing_io_only_warns() {
        let mut f = healthy();
        f.delegated_controllers = vec!["cpu".to_string(), "memory".to_string(), "pids".to_string()];
        let r = classify(&f);
        assert_eq!(find(&r, "cgroup-delegation").status, Status::Warn);
        assert!(r.ready(), "missing io must not block Tier 1");
        assert!(remedy_of(&r, "cgroup-delegation").contains("disk I/O limits"));
    }

    #[test]
    fn delegation_is_not_evaluated_without_cgroup2() {
        let mut f = healthy();
        f.cgroup2_mounted = false;
        let r = classify(&f);
        assert_eq!(find(&r, "cgroup-delegation").status, Status::Info);
        assert!(!r.ready());
    }

    #[test]
    fn non_merged_usr_names_usrmerge() {
        let mut f = healthy();
        f.runtime_missing = vec!["/usr/lib64".to_string()];
        let r = classify(&f);
        let c = find(&r, "runtime-layout");
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("/usr/lib64"));
        let rem = remedy_of(&r, "runtime-layout");
        assert!(rem.contains("sudo apt install usrmerge"));
        assert!(rem.contains("merged-/usr"));
        assert!(rem.contains(URL_USR_MERGE));
    }

    #[test]
    fn missing_landlock_names_kernel_config() {
        let mut f = healthy();
        f.landlock_abi = None;
        let r = classify(&f);
        assert_eq!(find(&r, "landlock").status, Status::Fail);
        let rem = remedy_of(&r, "landlock");
        assert!(rem.contains("CONFIG_SECURITY_LANDLOCK=y"));
        assert!(rem.contains("CONFIG_LSM"));
        assert!(rem.contains(URL_LANDLOCK));
    }

    #[test]
    fn missing_seccomp_names_kernel_config() {
        let mut f = healthy();
        f.seccomp_supported = false;
        let r = classify(&f);
        assert_eq!(find(&r, "seccomp").status, Status::Fail);
        let rem = remedy_of(&r, "seccomp");
        assert!(rem.contains("CONFIG_SECCOMP_FILTER=y"));
        assert!(rem.contains(URL_SECCOMP));
    }

    #[test]
    fn old_kernel_pidfd_and_close_range_are_warnings_with_upgrades() {
        let mut f = healthy();
        f.pidfd = false;
        f.close_range = false;
        let r = classify(&f);
        assert_eq!(find(&r, "pidfd").status, Status::Warn);
        assert_eq!(find(&r, "close-range").status, Status::Warn);
        assert!(r.ready(), "fallbacks exist; these must not block Tier 1");
        assert!(remedy_of(&r, "pidfd").contains("Linux >= 5.3"));
        assert!(remedy_of(&r, "pidfd").contains(URL_PIDFD));
        assert!(remedy_of(&r, "close-range").contains("Linux >= 5.9"));
        assert!(remedy_of(&r, "close-range").contains(URL_CLOSE_RANGE));
    }

    #[test]
    fn every_blocker_remedy_is_print_only_and_cites_upstream() {
        let mut f = healthy();
        f.userns_works = false;
        f.apparmor_restrict_userns = Some(1);
        f.cgroup2_mounted = false;
        f.cgroup_v1_mounts = vec!["/sys/fs/cgroup/memory".to_string()];
        f.landlock_abi = None;
        f.seccomp_supported = false;
        f.runtime_missing = vec!["/usr/bin/sh".to_string()];
        f.pidfd = false;
        f.close_range = false;
        let r = classify(&f);
        assert!(!r.ready());
        for c in &r.checks {
            if matches!(c.status, Status::Fail | Status::Warn) {
                let rem = c
                    .remedy
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} is {:?} without a remedy", c.id, c.status));
                assert!(
                    rem.contains("never changes host settings"),
                    "{} remedy must state it is print-only:\n{rem}",
                    c.id
                );
                assert!(
                    rem.contains("Upstream: https://"),
                    "{} remedy must cite upstream docs:\n{rem}",
                    c.id
                );
            }
        }
    }

    #[test]
    fn all_checks_have_substance() {
        let report = run_checks();
        assert!(report.checks.len() >= 12, "expected a full check suite");
        for c in &report.checks {
            assert!(!c.id.is_empty() && !c.name.is_empty(), "unnamed check");
            assert!(!c.detail.is_empty(), "check {} lacks detail", c.id);
        }
        for c in &report.checks {
            if matches!(c.status, Status::Fail | Status::Warn) {
                assert!(c.remedy.is_some(), "check {} lacks a remedy", c.id);
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
        let landlock = report.checks.iter().find(|c| c.id == "landlock").unwrap();
        assert!(landlock.detail.contains("ABI v7"));
    }

    #[test]
    fn delegation_probe_cleans_up_after_itself() {
        // Run twice; a leftover probe leaf would make the second run's
        // attach fail, so success twice proves cleanup.
        let first = crate::cgroup::attach_capable_root();
        let second = crate::cgroup::attach_capable_root();
        assert_eq!(first.is_some(), second.is_some());
    }
}
