//! Namespace and process-management syscall probes.
//!
//! These are *probes* (is a feature available?), not the sandbox machinery
//! itself. The sandbox's actual namespace setup lands in `carapace-native`
//! in milestone C1.

/// Probes whether this process may create a **user namespace without
/// privileges**: forks a child that calls `unshare(CLONE_NEWUSER)` and
/// reports success through its exit status.
///
/// This must be done in a forked child: a successful `unshare` in the caller
/// would permanently change the caller's own namespace context.
pub fn unprivileged_userns() -> bool {
    let pid = unsafe {
        // SAFETY: fork(2) in a test/probe context. The child branch below
        // only calls async-signal-safe functions (syscall, _exit) before
        // exiting, so the fork-within-a-multithreaded-process hazard (only
        // one thread survives in the child) does not apply.
        libc::fork()
    };
    match pid {
        -1 => false,
        0 => {
            // Child: try to unshare a user namespace, then signal the result.
            let ret = unsafe {
                // SAFETY: plain unshare(2); CLONE_NEWUSER only touches
                // namespace state of this child process.
                libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER as libc::c_ulong)
            };
            // Exit code 42 = success, 43 = failure (distinct from crashes).
            let code = if ret == 0 { 42 } else { 43 };
            unsafe {
                // SAFETY: _exit is async-signal-safe; calling it immediately
                // after fork in a child that touched no libc state.
                libc::_exit(code);
            }
        }
        child => {
            let mut status: libc::c_int = 0;
            let waited = unsafe {
                // SAFETY: waitpid(2) with a valid status pointer, blocking on
                // a child we just forked.
                libc::waitpid(child, &mut status, 0)
            };
            waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42
        }
    }
}

/// Returns `true` if `pidfd_open(2)` is available (kernel >= 5.3), used for
/// reliable, race-free process-tree signaling.
pub fn pidfd_open_support() -> bool {
    let fd = unsafe {
        // SAFETY: pidfd_open on our own pid with flags 0 is harmless; it
        // returns a new fd referring to this process.
        libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32)
    };
    if fd >= 0 {
        let fd = fd as libc::c_int;
        unsafe {
            // SAFETY: closing an fd we just opened, with no other threads
            // able to race for the number in this brief window (probes run
            // before any thread pool exists).
            libc::close(fd);
        }
        true
    } else {
        false
    }
}

/// Returns `true` if `close_range(2)` is available (kernel >= 5.9), used to
/// sanitize inherited file descriptors before exec'ing untrusted code.
///
/// Probe: `close_range(4, 3, 0)` — an invalid range (last < first) that
/// closes nothing. Kernels with the syscall answer `EINVAL`; kernels without
/// it answer `ENOSYS`.
pub fn close_range_support() -> bool {
    let ret = unsafe {
        // SAFETY: documented no-op range; no fds are closed, nothing is read.
        libc::syscall(libc::SYS_close_range, 4u32, 3u32, 0u32)
    };
    let errno = unsafe {
        // SAFETY: __errno_location returns a valid per-thread errno pointer
        // in a single-threaded probe context; no race window exists.
        *libc::__errno_location()
    };
    ret == -1 && errno == libc::EINVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_agree_with_kernel_version() {
        // On any kernel >= 5.10 (our documented baseline) pidfd_open and
        // close_range must both be present; userns depends on distro policy.
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let major: u32 = release
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if major >= 6 {
            assert!(
                pidfd_open_support(),
                "kernel {release} must have pidfd_open"
            );
            assert!(
                close_range_support(),
                "kernel {release} must have close_range"
            );
        }
    }

    #[test]
    fn strict_env_has_unprivileged_userns() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        assert!(
            unprivileged_userns(),
            "dev environment must allow unprivileged userns"
        );
    }
}
