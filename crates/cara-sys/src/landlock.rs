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

// ---------------------------------------------------------------- C4 API

/// Filesystem access rights (linux/landlock.h; verified against the
/// Ubuntu 6.8 headers — bit positions are the stable UAPI).
pub mod access_fs {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    /// ABI 2 (kernel 5.19+): cross-directory rename/link.
    pub const REFER: u64 = 1 << 13;
    /// ABI 3 (kernel 6.2+): truncate.
    pub const TRUNCATE: u64 = 1 << 14;
    /// Everything an unprivileged program may plausibly need in /work.
    /// EXECUTE included: compile-and-run workflows exec binaries the
    /// payload itself wrote — no privilege boundary is crossed (caps
    /// dropped, no_new_privs set). Found by the P2 runtime matrix
    /// (rust-binary/gcc EPERM at execve from rw binds).
    pub const RW_ALL: u64 = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_SYM
        | REFER
        | TRUNCATE;
    /// Read-only access.
    pub const RO: u64 = EXECUTE | READ_FILE | READ_DIR;
    /// Read + write files (no creation/removal) — e.g. /dev/null.
    pub const RW_FILES: u64 = READ_FILE | READ_DIR | WRITE_FILE | TRUNCATE;
}

/// The full set of rights this ABI version can handle (and thus
/// restrict). Fail-closed callers treat ABI 0 as unsupported.
pub fn handled_access_for_abi(abi: u32) -> u64 {
    let mut h = access_fs::EXECUTE
        | access_fs::WRITE_FILE
        | access_fs::READ_FILE
        | access_fs::READ_DIR
        | access_fs::REMOVE_DIR
        | access_fs::REMOVE_FILE
        | access_fs::MAKE_CHAR
        | access_fs::MAKE_DIR
        | access_fs::MAKE_REG
        | access_fs::MAKE_SOCK
        | access_fs::MAKE_FIFO
        | access_fs::MAKE_BLOCK
        | access_fs::MAKE_SYM;
    if abi >= 2 {
        h |= access_fs::REFER;
    }
    if abi >= 3 {
        h |= access_fs::TRUNCATE;
    }
    h
}

/// `struct landlock_ruleset_attr` (UAPI, C layout).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr` (UAPI, C layout).
#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
    spare: libc::c_int,
}

/// Creates a ruleset handling `handled` accesses; returns its fd.
pub fn create_ruleset(handled: u64) -> Result<libc::c_int, i32> {
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    let ret = unsafe {
        // SAFETY: landlock_create_ruleset(2) with a valid attr pointer and
        // size, flags 0 (create, not version-probe). Returns an fd or -1.
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::from_ref(&attr),
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        })
    } else {
        Ok(ret as libc::c_int)
    }
}

/// Adds a path-beneath rule: `access` rights on the hierarchy under the
/// O_PATH-opened `parent_fd`.
pub fn add_path_beneath(
    ruleset_fd: libc::c_int,
    access: u64,
    parent_fd: libc::c_int,
) -> Result<(), i32> {
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd,
        spare: 0,
    };
    // LANDLOCK_RULE_PATH_BENEATH = 1 (verified in linux/landlock.h).
    let ret = unsafe {
        // SAFETY: landlock_add_rule(2) with a valid attr pointer.
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd as libc::c_long,
            1 as libc::c_long,
            std::ptr::from_ref(&attr),
            0u32,
        )
    };
    if ret < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        })
    } else {
        Ok(())
    }
}

/// Applies the ruleset to the calling thread (and, through no_new_privs
/// semantics, everything it execs). Requires PR_SET_NO_NEW_PRIVS already
/// set for unprivileged use.
pub fn restrict_self(ruleset_fd: libc::c_int) -> Result<(), i32> {
    let ret = unsafe {
        // SAFETY: landlock_restrict_self(2) with a valid ruleset fd.
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd as libc::c_long,
            0u32,
        )
    };
    if ret < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        })
    } else {
        Ok(())
    }
}
