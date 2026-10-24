//! Landlock syscall bindings.
//!
//! glibc does not wrap the Landlock syscalls, so they are invoked through
//! `syscall(2)` directly. The syscall-number constants come from `libc`
//! (`SYS_landlock_*`); if `libc` ever lags on a new architecture, add the
//! number for that architecture only after verifying it against the
//! architecture's `<asm/unistd.h>` (do not copy numbers between architectures).

/// `LANDLOCK_CREATE_RULESET_VERSION` flag: ask for the highest supported ABI
/// version instead of creating a ruleset. Per `linux/landlock.h`: `(1U << 0)`.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

/// Returns the highest Landlock ABI version supported by the running kernel,
/// or `None` if Landlock is unavailable (syscall not implemented, compiled
/// out, or not listed in the kernel's active LSM stack).
///
/// A kernel with Landlock returns a version >= 1 here. This is the documented
/// feature probe from `landlock(7)`; it creates no ruleset and needs no
/// privileges.
pub fn abi_version() -> Option<u32> {
    let ret = unsafe {
        // SAFETY: the documented ABI-version probe. `ruleset_attr` is NULL
        // and `attr_size` is 0, so no user memory is read; the VERSION flag
        // means no ruleset fd is created. Return value is a small integer.
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if (0..=64).contains(&ret) {
        Some(ret as u32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_consistent() {
        // If the kernel supports Landlock at all, the version is >= 1.
        // (This machine: ABI v7, asserted only under CARA_STRICT_ENV_TESTS.)
        if let Some(v) = abi_version() {
            assert!(v >= 1, "Landlock claimed ABI v{v}, which is nonsense");
        }
    }

    #[test]
    fn strict_env_has_landlock() {
        // Hard environment assertion, but only when the developer opted in
        // via CARA_STRICT_ENV_TESTS (set by scripts/check.sh on the reference
        // dev environment described in docs/agent/ENV.md).
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        assert_eq!(
            abi_version(),
            Some(7),
            "dev environment must have Landlock ABI v7"
        );
    }
}
