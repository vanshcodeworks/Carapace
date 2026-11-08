//! Seccomp user-notification handler for network allowlist mode.

use libc;
use std::os::unix::io::RawFd;

// SECCOMP_IOCTL_NOTIF_RECV = 0x40809403
const SECCOMP_IOCTL_NOTIF_RECV: u32 = 0x40809403;
// SECCOMP_IOCTL_NOTIF_SEND = 0x40809404
const SECCOMP_IOCTL_NOTIF_SEND: u32 = 0x40809404;
// SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
// SECCOMP_USER_NOTIF_FLAG_KILL = 2
const SECCOMP_USER_NOTIF_FLAG_KILL: u32 = 2;

#[repr(C)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: libc::seccomp_data,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// Seccomp user-notification handler for network allowlist mode.
/// Reads notifications from the seccomp fd, checks if the connect destination
/// is in the allowlist, and replies with allow/deny.
pub fn seccomp_notif_handler(fd: RawFd, allowlist: &[String]) {
    loop {
        let mut notif = SeccompNotif {
            id: 0,
            pid: 0,
            flags: 0,
            data: unsafe { std::mem::zeroed() },
        };

        // SECCOMP_IOCTL_NOTIF_RECV
        let ret = unsafe {
            libc::ioctl(fd, 0x40809403, &mut notif)
        };

        if ret < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // fd closed or error - exit
            eprintln!("seccomp notif handler: ioctl RECV failed: {}", e);
            break;
        }

        // Check if this is a connect(2) syscall
        if notif.data.nr != libc::SYS_connect as u64 {
            // Not a connect - deny by default (shouldn't happen since only connect gets USER_NOTIF)
            let resp = SeccompNotifResp {
                id: notif.id,
                val: 0,
                error: -libc::EPERM,
                flags: 2, // SECCOMP_USER_NOTIF_FLAG_KILL
            };
            unsafe { libc::ioctl(fd, 0x40809404, &resp) };
            continue;
        }

        // Extract connect arguments
        // args[0] = sockfd, args[1] = sockaddr*, args[2] = addrlen
        let sockaddr_ptr = notif.data.args[1] as *const libc::sockaddr;
        let addrlen = notif.data.args[2] as libc::socklen_t;

        // Read the sockaddr
        let allowed = if addrlen >= std::mem::size_of::<libc::sockaddr_in>() as u32 {
            let sockaddr_in = unsafe { &*(sockaddr_ptr as *const libc::sockaddr_in) };
            let ip = libc::ntohl(sockaddr_in.sin_addr.s_addr);
            let port = libc::ntohs(sockaddr_in.sin_port);
            let ip_str = format!(
                "{}.{}.{}.{}",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF
            );
            // Check against allowlist (CIDR not implemented yet - exact match only)
            allowlist.iter().any(|domain| {
                // For now, only support IP:port exact match
                // TODO: CIDR and hostname resolution
                if domain.contains(':') {
                    let parts: Vec<&str> = domain.split(':').collect();
                    if parts.len() == 2 {
                        parts[0] == ip_str && parts[1] == port.to_string()
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
        } else {
            false
        };

        let (error, flags) = if allowed {
            (0, 1) // SECCOMP_USER_NOTIF_FLAG_CONTINUE
        } else {
            (-libc::ECONNREFUSED, 2) // SECCOMP_USER_NOTIF_FLAG_KILL
        };

        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error,
            flags,
        };

        unsafe {
            libc::ioctl(fd, 0x40809404, &resp); // SECCOMP_IOCTL_NOTIF_SEND
        };
    }
}

#[repr(C)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: libc::seccomp_data,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}