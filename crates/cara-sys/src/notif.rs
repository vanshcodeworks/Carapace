//! Seccomp user-notification plumbing (linux/seccomp.h, linux/audit.h).
//!
//! This module is deliberately dumb: it does not make policy decisions.
//! It moves the fixed-size kernel structs across the ioctl boundary and
//! copies the target's `sockaddr` with `process_vm_readv`, so the
//! supervisor never dereferences a pointer that belongs to the sandbox.
//!
//! Constant values and struct layouts were checked against Ubuntu 24.04's
//! `linux-libc-dev` headers and are asserted by the tests below.

use std::mem::size_of;

/// `struct seccomp_data` (linux/seccomp.h).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// `struct seccomp_notif`, the classic (v1) 80-byte layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    /// Thread id of the notifying task, in the listener creator's pidns.
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    /// Return value of the syscall when continuing it.
    pub val: i64,
    /// Negative errno for a synchronous denial.
    pub error: i32,
    pub flags: u32,
}

/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`: let the kernel re-run the syscall.
pub const USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// _IOC encoding from linux/ioctl.h (x86_64: dir 2 bits, size 14 bits).
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_READ: u32 = 2;
const IOC_WRITE: u32 = 1;
const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

const fn ioc(dir: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << IOC_DIRSHIFT)
        | (SECCOMP_IOC_MAGIC << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as libc::c_ulong
}

/// `SECCOMP_IOCTL_NOTIF_RECV`.
pub const NOTIF_RECV: libc::c_ulong =
    ioc(IOC_READ | IOC_WRITE, 0, size_of::<SeccompNotif>() as u32);
/// `SECCOMP_IOCTL_NOTIF_SEND`.
pub const NOTIF_SEND: libc::c_ulong = ioc(
    IOC_READ | IOC_WRITE,
    1,
    size_of::<SeccompNotifResp>() as u32,
);
/// `SECCOMP_IOCTL_NOTIF_ID_VALID`.
pub const NOTIF_ID_VALID: libc::c_ulong = ioc(IOC_READ, 2, size_of::<u64>() as u32);

/// Receives one notification. `EINTR` is retried; everything else is an
/// error the caller must treat as fail-closed.
pub fn recv_notif(fd: libc::c_int) -> Result<SeccompNotif, i32> {
    loop {
        let mut notif: SeccompNotif = unsafe {
            // SAFETY: zeroed POD bytes are a valid value for these fixed
            // integer fields; the kernel fills them on success.
            std::mem::zeroed()
        };
        let r = unsafe {
            // SAFETY: ioctl with the documented request and a matching,
            // exclusively owned struct; the kernel writes exactly its size.
            libc::ioctl(fd, NOTIF_RECV, std::ptr::from_mut(&mut notif))
        };
        if r == 0 {
            return Ok(notif);
        }
        let e = unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        };
        if e != libc::EINTR {
            return Err(e);
        }
    }
}

/// Sends the decision for a notification. `EINTR` is retried.
pub fn send_resp(fd: libc::c_int, resp: &SeccompNotifResp) -> Result<(), i32> {
    loop {
        let r = unsafe {
            // SAFETY: ioctl with the documented request and a matching,
            // immutable struct; the kernel only reads its size bytes.
            libc::ioctl(fd, NOTIF_SEND, std::ptr::from_ref(resp))
        };
        if r == 0 {
            return Ok(());
        }
        let e = unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        };
        if e != libc::EINTR {
            return Err(e);
        }
    }
}

/// Checks that a notification id is still live right before responding.
/// This closes the target-exit/PID-reuse race. Any error (including
/// `ENOENT`) means "stale": the caller must not send a response.
pub fn id_valid(fd: libc::c_int, id: u64) -> bool {
    let mut id = id;
    let r = unsafe {
        // SAFETY: ioctl with the documented request and a u64 of the exact
        // size the kernel expects; the kernel only reads it.
        libc::ioctl(fd, NOTIF_ID_VALID, std::ptr::from_mut(&mut id))
    };
    r == 0
}

/// Copies `local.len()` bytes from `remote` in process `pid`.
///
/// This is the ONLY correct way to read a sandbox-address-space pointer:
/// `process_vm_readv` asks the kernel to copy the bytes, with the usual
/// ptrace permission checks. Dereferencing the pointer in the supervisor
/// would read the supervisor's own (unrelated) memory.
pub fn read_process_memory(pid: libc::pid_t, remote: u64, local: &mut [u8]) -> Result<usize, i32> {
    let mut local_iov = libc::iovec {
        iov_base: local.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: local.len(),
    };
    let mut remote_iov = libc::iovec {
        iov_base: (remote as usize) as *mut libc::c_void,
        iov_len: local.len(),
    };
    let n = unsafe {
        // SAFETY: both iovecs describe `local.len()` valid bytes; the
        // kernel checks the remote range and permissions and never lets
        // us read past the local buffer.
        libc::process_vm_readv(
            pid,
            std::ptr::from_mut(&mut local_iov),
            1,
            std::ptr::from_mut(&mut remote_iov),
            1,
            0,
        )
    };
    if n < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        })
    } else {
        Ok(n as usize)
    }
}

/// Marks an fd close-on-exec, in case the kernel did not already.
pub fn set_cloexec(fd: libc::c_int) -> Result<(), i32> {
    let r = unsafe {
        // SAFETY: fcntl(F_GETFD/F_SETFD) on a valid fd we own.
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC)
    };
    if r < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer is valid to read here.
            *libc::__errno_location()
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_struct_layouts_are_kernel_abi() {
        assert_eq!(size_of::<SeccompData>(), 64);
        assert_eq!(size_of::<SeccompNotif>(), 80);
        assert_eq!(size_of::<SeccompNotifResp>(), 24);
        assert_eq!(std::mem::align_of::<SeccompNotif>(), 8);
        assert_eq!(USER_NOTIF_FLAG_CONTINUE, 1);
    }

    #[test]
    fn ioctl_requests_match_linux_headers() {
        // _IOC(READ|WRITE, '!', 0, 80) etc, verified against
        // /usr/include/linux/seccomp.h on the reference host.
        if cfg!(target_arch = "x86_64") {
            assert_eq!(NOTIF_RECV, 0xc050_2100);
            assert_eq!(NOTIF_SEND, 0xc018_2101);
            assert_eq!(NOTIF_ID_VALID, 0x8008_2102);
        }
    }

    #[test]
    fn sockaddr_family_constants_match_libc() {
        assert_eq!(2, libc::AF_INET as u16);
        assert_eq!(10, libc::AF_INET6 as u16);
    }

    /// Proves the safe-copy mechanism on a real child: the parent reads a
    /// stack buffer from the child's address space by pid, getting the
    /// bytes instead of its own unrelated memory.
    #[test]
    fn process_vm_readv_copies_from_a_live_child() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe(2) into a valid 2-int array; the fds are ours.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fork(2) with no arguments; both branches stay simple.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                // SAFETY: post-fork child uses only raw syscalls and its
                // own stack buffer; it never returns to Rust test logic.
                let secret = [0x5au8; 16];
                let addr = secret.as_ptr() as u64;
                let mut left = std::mem::size_of::<u64>();
                let p = std::ptr::from_ref(&addr).cast::<libc::c_char>();
                while left > 0 {
                    let n = libc::write(fds[1], p.cast::<libc::c_void>(), left);
                    if n <= 0 {
                        libc::_exit(2);
                    }
                    left -= n as usize;
                }
                // Stay alive (but inert) until the parent has read us.
                loop {
                    libc::pause();
                }
            }
        }
        assert!(pid > 0);
        // SAFETY: closing our own write end so the child's write is the
        // only source of the address bytes.
        unsafe { libc::close(fds[1]) };
        let mut addr = 0u64;
        let mut off = 0usize;
        while off < 8 {
            let n = unsafe {
                // SAFETY: reading exactly the remaining bytes of a u64.
                libc::read(
                    fds[0],
                    (std::ptr::from_mut(&mut addr).cast::<u8>().add(off)).cast(),
                    8 - off,
                )
            };
            assert!(n > 0, "child must send its buffer address");
            off += n as usize;
        }
        // SAFETY: closing our own read end after the address was read.
        unsafe { libc::close(fds[0]) };
        let mut buf = [0u8; 16];
        let n = read_process_memory(pid, addr, &mut buf).expect("process_vm_readv");
        assert_eq!(n, 16);
        assert_eq!(buf, [0x5a; 16], "must copy the child's bytes, not ours");
        // SAFETY: signaling our own forked child, then reaping it.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut st = 0;
        // SAFETY: blocking waitpid on our own child, which was just killed.
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }
}
