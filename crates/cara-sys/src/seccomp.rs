//! seccomp-bpf: availability probing + allowlist filter compiler and
//! installer (milestone C4).
//!
//! The compiler runs PARENT-side (it allocates); the child only installs
//! the already-compiled `sock_filter` array — no allocation post-fork.
//!
//! Constant values verified against Ubuntu 24.04 `linux-libc-dev` headers
//! (`linux/seccomp.h`, `linux/filter.h`, `linux/bpf_common.h`) — see
//! docs/agent/ENV.md.

/// `SECCOMP_SET_MODE_FILTER` per linux/seccomp.h: `1`.
const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// `SECCOMP_RET_ALLOW` = 0x7fff0000.
const RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO` = 0x00050000 (OR'd with the errno).
const RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_LOG` = 0x7ffc0000 (allow but log — profile development).
const RET_LOG: u32 = 0x7ffc_0000;
/// `SECCOMP_RET_KILL_PROCESS` = 0x80000000.
const RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `SECCOMP_GET_ACTION_AVAIL` operation for the `seccomp(2)` syscall.
/// Per `linux/seccomp.h`: `2`.
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// `SECCOMP_RET_KILL_PROCESS` action value. Per `linux/seccomp.h`:
/// `0x80000000`.
const SECCOMP_RET_KILL_PROCESS_PROBE: u32 = 0x8000_0000;

// BPF instruction encoding (linux/bpf_common.h, verified).
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
/// BPF_JA: unconditional jump (op 0x00 within the JMP class). Used by
/// the test-only BPF interpreter.
#[cfg(test)]
const BPF_JA: u16 = 0x00;

/// `AUDIT_ARCH_X86_64` (audit.h): `0xc000003e`.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;

/// `struct seccomp_data` field offsets in bytes: nr=0, arch=4, args=16.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;

/// CLONE_NEW* namespace flags that a sandboxed payload must never pass to
/// clone(2) (it could otherwise re-enter namespace creation; the seccomp
/// filter double-checks what Landlock and the userns already constrain).
#[cfg(target_arch = "x86_64")]
const CLONE_NEW_MASK: u32 = 0x7e02_0000;

/// Returns `true` if this kernel supports seccomp-bpf filters.
pub fn filter_support() -> bool {
    let action: u32 = SECCOMP_RET_KILL_PROCESS_PROBE;
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

/// A compiled filter. Build parent-side with [`compile_allowlist`].
#[derive(Debug, Clone)]
pub struct Filter {
    prog: Vec<libc::sock_filter>,
}

impl Filter {
    pub fn as_slice(&self) -> &[libc::sock_filter] {
        &self.prog
    }

    pub fn len(&self) -> usize {
        self.prog.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prog.is_empty()
    }
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Compiles a default-deny allowlist filter for x86_64.
///
/// - syscalls in `allowed` → `RET_ALLOW`
/// - `clone(2)` with any CLONE_NEW* flag → `RET_ERRNO|EPERM`
/// - everything else → `RET_ERRNO|EPERM`, or `RET_LOG` when
///   `log_denied` is set (profile development: log, then allow — never
///   the default in production)
/// - non-x86_64 architectures → `RET_KILL_PROCESS` (fail closed)
///
/// `clone3` must NOT be in `allowed` (its flags live behind a pointer the
/// filter cannot inspect); debugged empirically — glibc falls back to
/// `clone` when `clone3` fails.
pub fn compile_allowlist(allowed: &[libc::c_long], log_denied: bool) -> Filter {
    let default_action = if log_denied {
        RET_LOG
    } else {
        RET_ERRNO | libc::EPERM as u32
    };
    let mut prog: Vec<libc::sock_filter> = Vec::with_capacity(16 + allowed.len() * 2);

    // Exact instruction layout — jump semantics: a taken branch lands at
    // pc + 1 + offset. Verified instruction-by-instruction by the BPF
    // mini-interpreter test (`filter_semantics_interpreted`):
    //
    //   p0  LD arch
    //   p1  JEQ AUDIT_ARCH  jt=0 (→p2)   jf=6 (→p8 KILL)
    //   p2  LD nr                     ← arch ok
    //   p3  JEQ clone      jt=0 (→p4)   jf=5 (→p9 chain)
    //   p4  LD arg0_lo                ← clone: inspect flags
    //   p5  JSET NEW_MASK  jt=1 (→p7)   jf=0 (→p6)
    //   p6  RET ALLOW                 ← clone without namespace flags
    //   p7  RET ERRNO|EPERM           ← clone with namespace flags
    //   p8  RET KILL_PROCESS          ← wrong architecture
    //   p9+ JEQ nr / RET ALLOW pairs  ← the allowlist chain
    //   last RET default
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH)); // p0
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 0, 6)); // p1

    #[cfg(target_arch = "x86_64")]
    {
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // p2
        prog.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_clone as u32,
            0,
            5,
        )); // p3
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0_LO)); // p4
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_MASK, 1, 0)); // p5
        prog.push(stmt(BPF_RET | BPF_K, RET_ALLOW)); // p6
        prog.push(stmt(BPF_RET | BPF_K, RET_ERRNO | libc::EPERM as u32)); // p7
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Unsupported architecture: no clone handling; every syscall goes
        // to the chain (and the arch mismatch above kills first).
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // p2
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, u32::MAX, 0, 0)); // p3: no-op
        prog.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS)); // unused filler
        prog.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS)); // filler
        prog.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS)); // filler
        prog.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS)); // filler
    }
    prog.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS)); // p8: arch miss

    // Allowlist chain: each allowed nr falls into RET_ALLOW.
    let mut sorted: Vec<u32> = allowed.iter().map(|&n| n as u32).collect();
    sorted.sort_unstable();
    sorted.dedup();
    for nr in sorted {
        if nr == libc::SYS_clone as u32 {
            continue; // handled by the dedicated block above
        }
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, RET_ALLOW));
    }

    // Default.
    prog.push(stmt(BPF_RET | BPF_K, default_action));

    debug_assert!(prog.len() <= 4096, "BPF_MAXINSNS");
    Filter { prog }
}

/// Installs a filter in the CALLING process. Requires
/// `PR_SET_NO_NEW_PRIVS` (set it first — see child setup). Fails closed:
/// an error here must abort the sandbox before exec.
pub fn install(prog: &[libc::sock_filter]) -> Result<(), i32> {
    if prog.is_empty() || prog.len() > 4096 {
        return Err(libc::EINVAL);
    }
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let ret = unsafe {
        // SAFETY: seccomp(2) SET_MODE_FILTER with a valid sock_fprog whose
        // filter array outlives the call (child: leaked config owns it).
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u32,
            &fprog as *const libc::sock_fprog,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_has_sane_shape() {
        let f = compile_allowlist(&[libc::SYS_read, libc::SYS_write], false);
        let p = f.as_slice();
        assert!(p.len() >= 10);
        // First insn loads arch; second is the arch jump.
        assert_eq!(p[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(p[0].k, OFF_ARCH);
        // Default action is the last insn.
        let last = p[p.len() - 1];
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn log_mode_default_is_ret_log() {
        let f = compile_allowlist(&[libc::SYS_read], true);
        let last = f.as_slice()[f.len() - 1];
        assert_eq!(last.k, RET_LOG);
    }

    /// A minimal BPF evaluator over `struct seccomp_data`, used to prove
    /// filter semantics structurally. This is the permanent regression
    /// test for the class of bug where a mislaid jump made the filter
    /// allow everything (caught live by the C4 hardening tests).
    fn eval_filter(prog: &[libc::sock_filter], data: &SeccompData) -> u32 {
        let mut pc: usize = 0;
        let mut acc: u32 = 0;
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps <= 4096, "filter must terminate");
            let insn = prog[pc];
            let code = insn.code;
            match code {
                x if x == (BPF_LD | BPF_W | BPF_ABS) => {
                    let off = insn.k;
                    acc = match off {
                        OFF_NR => data.nr as u32,
                        OFF_ARCH => data.arch,
                        OFF_ARG0_LO => data.args[0] as u32,
                        _ => panic!("unsupported load offset {off}"),
                    };
                    pc += 1;
                }
                x if x == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    pc += if acc == insn.k {
                        insn.jt as usize + 1
                    } else {
                        insn.jf as usize + 1
                    };
                }
                x if x == (BPF_JMP | BPF_JSET | BPF_K) => {
                    pc += if acc & insn.k != 0 {
                        insn.jt as usize + 1
                    } else {
                        insn.jf as usize + 1
                    };
                }
                x if x == (BPF_JMP | BPF_JA) => {
                    // BPF_JA (op 0x00 within the JMP class): pc += k.
                    pc += insn.k as usize;
                }
                x if x == (BPF_RET | BPF_K) => return insn.k,
                _ => panic!("unsupported insn code {code:#x}"),
            }
        }
    }

    #[repr(C)]
    struct SeccompData {
        nr: libc::c_int,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    fn data_for(nr: libc::c_long, arg0: u64) -> SeccompData {
        SeccompData {
            nr: nr as libc::c_int,
            arch: AUDIT_ARCH,
            instruction_pointer: 0,
            args: [arg0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn filter_semantics_interpreted() {
        let f = compile_allowlist(&[libc::SYS_read, libc::SYS_write], false);
        let p = f.as_slice();

        // Allowed syscall -> ALLOW.
        assert_eq!(eval_filter(p, &data_for(libc::SYS_read, 0)), RET_ALLOW);
        assert_eq!(eval_filter(p, &data_for(libc::SYS_write, 0)), RET_ALLOW);

        // NOT-allowed syscall -> ERRNO|EPERM (the bug class this guards:
        // a stray fall-through returning ALLOW).
        for denied in [
            libc::SYS_socket,
            libc::SYS_unshare,
            libc::SYS_mount,
            libc::SYS_ptrace,
            libc::SYS_io_uring_setup,
            9999,
        ] {
            assert_eq!(
                eval_filter(p, &data_for(denied, 0)),
                RET_ERRNO | libc::EPERM as u32,
                "syscall {denied} must be denied"
            );
        }

        // clone: allowed clean, denied with any CLONE_NEW* flag.
        assert_eq!(eval_filter(p, &data_for(libc::SYS_clone, 0)), RET_ALLOW);
        assert_eq!(
            eval_filter(p, &data_for(libc::SYS_clone, libc::CLONE_NEWUSER as u64)),
            RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            eval_filter(p, &data_for(libc::SYS_clone, libc::CLONE_NEWNS as u64 | 11)),
            RET_ERRNO | libc::EPERM as u32
        );

        // Wrong architecture -> KILL_PROCESS (fail closed).
        let mut wrong = data_for(libc::SYS_read, 0);
        wrong.arch = 0x1234_5678;
        assert_eq!(eval_filter(p, &wrong), RET_KILL_PROCESS);
    }

    #[test]
    fn strict_env_has_seccomp() {
        if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
            return;
        }
        assert!(filter_support(), "dev environment must support seccomp-bpf");
    }
}
