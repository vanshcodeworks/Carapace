//! The Tier 1 base syscall allowlist (milestone C4).
//!
//! Default-deny. Everything a plain interpreter runtime (python3, dash,
//! coreutils) needs to run ordinary programs is allowed; namespace
//! manipulation, ptrace, module loading, sockets (network syscalls are
//! denied by default — the empty network namespace already prevents
//! egress; this is defense in depth), io_uring, keyrings, and the like
//! are NOT.
//!
//! Developing profiles: set `CARA_SECCOMP_LOG=1` in the parent
//! environment — denied syscalls are then logged by the kernel (dmesg)
//! and allowed, which reveals exactly what a runtime needs without
//! breaking it. Production keeps the strict default.

use carapace_sys::seccomp;
use std::sync::OnceLock;

/// Syscalls allowed for the base runtime profile. Numbers come from
/// `libc::SYS_*` (compiler-checked against the platform).
fn base_allowed() -> &'static [libc::c_long] {
    static LIST: OnceLock<Vec<libc::c_long>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut v: Vec<libc::c_long> = vec![
            // fd & file basics
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_close_range,
            libc::SYS_stat,
            libc::SYS_fstat,
            libc::SYS_lstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_lseek,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_access,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_readlink,
            libc::SYS_readlinkat,
            libc::SYS_getdents,
            libc::SYS_getdents64,
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_fchdir,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_fcntl,
            libc::SYS_flock,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_truncate,
            libc::SYS_ftruncate,
            // file creation/removal (Landlock gates WHERE these may act)
            libc::SYS_creat,
            libc::SYS_rename,
            libc::SYS_renameat,
            libc::SYS_renameat2,
            libc::SYS_mkdir,
            libc::SYS_mkdirat,
            libc::SYS_rmdir,
            libc::SYS_unlink,
            libc::SYS_unlinkat,
            libc::SYS_link,
            libc::SYS_linkat,
            libc::SYS_symlink,
            libc::SYS_symlinkat,
            libc::SYS_chmod,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_fchownat,
            libc::SYS_lchown,
            libc::SYS_umask,
            libc::SYS_utime,
            libc::SYS_utimes,
            libc::SYS_utimensat,
            libc::SYS_copy_file_range,
            libc::SYS_sendfile,
            // memory
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_mremap,
            libc::SYS_msync,
            libc::SYS_madvise,
            libc::SYS_mincore,
            libc::SYS_brk,
            libc::SYS_membarrier,
            libc::SYS_memfd_create,
            // processes & signals (job control inside the sandbox)
            libc::SYS_fork,
            libc::SYS_vfork,
            // SYS_clone has a dedicated BPF block: allowed WITHOUT
            // CLONE_NEW* namespace flags.
            libc::SYS_execve,
            libc::SYS_wait4,
            libc::SYS_waitid,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_kill,
            libc::SYS_tgkill,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigsuspend,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_sigaltstack,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            // scheduling / time / identity
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_gettid,
            // bash-as-pidns-init calls getpgrp during job control setup
            // (P2 runtime matrix); pure read of the caller's own pgid.
            libc::SYS_getpgrp,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_uname,
            libc::SYS_getrlimit,
            libc::SYS_prlimit64,
            libc::SYS_getrusage,
            libc::SYS_sysinfo,
            libc::SYS_times,
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_gettimeofday,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_setaffinity,
            libc::SYS_sched_getscheduler,
            libc::SYS_getcpu,
            // synchronization & waiting
            libc::SYS_futex,
            libc::SYS_epoll_create,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_select,
            libc::SYS_pselect6,
            libc::SYS_pipe,
            libc::SYS_pipe2,
            libc::SYS_eventfd,
            libc::SYS_eventfd2,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
            // xattr reads: coreutils ls -l queries POSIX ACLs via
            // getxattr on every file argument (P2 runtime matrix: ls -l
            // reported EPERM on files while os.stat succeeded). Read-only;
            // the kernel enforces ownership/namespace rules regardless.
            libc::SYS_getxattr,
            libc::SYS_lgetxattr,
            libc::SYS_fgetxattr,
            libc::SYS_listxattr,
            libc::SYS_llistxattr,
            libc::SYS_flistxattr,
            // misc runtime needs
            libc::SYS_ioctl, // isatty & friends
            libc::SYS_getrandom,
            libc::SYS_arch_prctl,
            libc::SYS_prctl, // can only tighten (adding seccomp filters)
        ];
        v.retain(|&s| s != libc::SYS_clone);
        v.sort_unstable();
        v.dedup();
        v
    })
}

/// Socket-family syscalls, allowed ONLY when the policy says the run may
/// use the network (`mode = "full"`; the empty netns already blocks
/// everything in `mode = "none"`).
const NETWORK_ALLOWED: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_shutdown,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_recvmmsg,
    libc::SYS_sendmmsg,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
];

/// Compiles the profile for a network mode. `CARA_SECCOMP_LOG=1` in the
/// parent env switches the default action to log-and-allow (profile
/// development).
pub fn filter_for(network: &carapace_core::NetworkMode) -> seccomp::Filter {
    let log = std::env::var("CARA_SECCOMP_LOG").is_ok_and(|v| v == "1");
    let mut allowed: Vec<libc::c_long> = base_allowed().to_vec();
    let allowlist_connect = matches!(network, carapace_core::NetworkMode::Allowlist(_));
    if matches!(network, carapace_core::NetworkMode::Full) {
        allowed.extend_from_slice(NETWORK_ALLOWED);
        allowed.sort_unstable();
        allowed.dedup();
    }
    seccomp::compile_allowlist(&allowed, log, allowlist_connect)
}

/// The no-network base profile.
pub fn base_filter() -> seccomp::Filter {
    filter_for(&carapace_core::NetworkMode::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_profile_compiles_and_is_sized_sanely() {
        let f = base_filter();
        assert!(f.len() > 100, "expected a real allowlist, got {}", f.len());
        assert!(f.len() <= 4096, "BPF_MAXINSNS");
    }

    #[test]
    fn dangerous_syscalls_are_not_allowed() {
        let v = base_allowed();
        for banned in [
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_reboot,
            libc::SYS_init_module,
            libc::SYS_kexec_load,
            libc::SYS_swapon,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_open_by_handle_at,
            libc::SYS_process_vm_readv,
            libc::SYS_io_uring_setup,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_clone3,
            libc::SYS_pivot_root,
            libc::SYS_name_to_handle_at,
            libc::SYS_setxattr,
            libc::SYS_lsetxattr,
            libc::SYS_fsetxattr,
            libc::SYS_removexattr,
            libc::SYS_lremovexattr,
            libc::SYS_fremovexattr,
        ] {
            assert!(!v.contains(&banned), "syscall {banned} must not be allowed");
        }
    }

    #[test]
    fn essentials_are_allowed() {
        let v = base_allowed();
        for needed in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_execve,
            libc::SYS_futex,
            libc::SYS_getrandom,
            // bash job-control setup as pidns init (ADR-0007 §3).
            libc::SYS_getpgrp,
            // Read-only xattr queries for coreutils (ADR-0007 §4).
            libc::SYS_getxattr,
            libc::SYS_lgetxattr,
            libc::SYS_fgetxattr,
            libc::SYS_listxattr,
            libc::SYS_llistxattr,
            libc::SYS_flistxattr,
        ] {
            assert!(v.contains(&needed));
        }
    }
}
