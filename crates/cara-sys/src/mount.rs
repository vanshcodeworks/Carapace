//! Filesystem-type helpers built on `statfs(2)`.

/// `CGROUP2_SUPER_MAGIC` — per `linux/magic.h`: `0x63677270`.
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Returns `true` if `path` is on a cgroup v2 (unified hierarchy) mount,
/// i.e. `/sys/fs/cgroup` is `cgroup2`.
pub fn is_cgroup2_mount(path: &str) -> bool {
    let mut st: libc::statfs = unsafe {
        // SAFETY: statfs output struct is a plain POD C struct; zeroing it
        // produces a valid (if meaningless) value that the syscall overwrites.
        std::mem::zeroed()
    };
    let c_path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let ret = unsafe {
        // SAFETY: statfs(2) with a NUL-terminated path and a valid,
        // zero-initialized out-struct of the matching type.
        libc::statfs(c_path.as_ptr(), &mut st)
    };
    ret == 0 && st.f_type == CGROUP2_SUPER_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_fs_cgroup_is_cgroup2_on_linux_v2_hosts() {
        // Self-consistency: cgroup v2 hosts (the only supported kind) report
        // true; a v1 host reports false, which doctor then flags.
        let is_v2 = is_cgroup2_mount("/sys/fs/cgroup");
        // On the reference dev environment this must be true.
        if std::env::var("CARA_STRICT_ENV_TESTS").is_ok() {
            assert!(is_v2);
        }
    }

    #[test]
    fn nonexistent_path_is_not_cgroup2() {
        assert!(!is_cgroup2_mount("/nonexistent-carapace-probe"));
    }
}
