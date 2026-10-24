//! Seccomp availability probing.
//!
//! Full BPF program construction lives in `carapace-native` (the seccomp
//! profile compiler); this module only answers "does this kernel support
//! seccomp-bpf filters?" — a prerequisite for Tier 1.

/// `SECCOMP_GET_ACTION_AVAIL` operation for the `seccomp(2)` syscall.
/// Per `linux/seccomp.h`: `2`. Used to ask the kernel whether an action
/// (here `SECCOMP_RET_KILL_PROCESS`) is available.
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;

/// `SECCOMP_RET_KILL_PROCESS` action value. Per `linux/seccomp.h`:
/// `0x80000000U`.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Returns `true` if this kernel supports seccomp-bpf filters
/// (`CONFIG_SECCOMP=y` and `CONFIG_SECCOMP_FILTER=y`).
///
/// Probe per `seccomp(2)`: `seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action)`
/// returns 0 iff the kernel knows the given action. Unprivileged-safe.
pub fn filter_support() -> bool {
    let action: u32 = SECCOMP_RET_KILL_PROCESS;
    let ret = unsafe {
        // SAFETY: the documented availability probe. The third argument
        // points to a valid `u32` the kernel reads; flags are 0. No filter
        // is installed and no state is changed.
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0u32,
            std::ptr::from_ref(&action),
        )
    };
    ret == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_env_has_seccomp() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        assert!(filter_support(), "dev environment must support seccomp-bpf");
    }
}
