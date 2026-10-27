//! `carapace-escape-tests`: the hostile payload catalog (milestone C6).
//!
//! Every security claim Carapace makes maps to a test here. The payloads in
//! [`Catalog::all`] are ONLY ever executed through the real sandbox (by the
//! integration suite in `tests/suite.rs`; never on the host, never via a
//! plain `Command`). The "What Carapace stops" README table is generated
//! from this catalog ([`table::markdown`]) so the docs cannot drift from
//! reality: an entry without a passing test must not appear as a stopped
//! attack.

pub mod table;

pub const MILESTONE: &str = "C6";

/// Which interpreter executes the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// POSIX shell (`/bin/sh -c <payload>`).
    Sh,
    /// Python 3 (`/usr/bin/python3 -c <payload>`).
    Python,
}

/// One hostile payload and the claim it verifies.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct EscapeTest {
    /// Stable snake_case identifier (also the name of the suite case).
    pub id: &'static str,
    /// Human-readable attack name (for docs and tables).
    pub name: &'static str,
    /// Interpreter that runs [`EscapeTest::payload`].
    pub language: Language,
    /// Self-contained payload source. MUST only ever run inside the
    /// sandbox; the suite (`tests/suite.rs`) is the only caller.
    pub payload: &'static str,
    /// What the attack tries to achieve.
    pub attack: &'static str,
    /// The safe outcome Carapace guarantees (asserted by the suite).
    pub expected: &'static str,
}

/// The escape-test catalog: every attack Carapace stops, as a test.
pub struct Catalog;

impl Catalog {
    /// The full catalog, in stable display order.
    pub fn all() -> &'static [EscapeTest] {
        CATALOG
    }

    /// Lookup by id.
    pub fn get(id: &str) -> Option<&'static EscapeTest> {
        CATALOG.iter().find(|t| t.id == id)
    }
}

static CATALOG: &[EscapeTest] = &[
    // Unbounded process creation (`sleep` farm) inside the sandbox.
    EscapeTest {
        id: "fork_bomb",
        name: "Fork bomb",
        language: Language::Sh,
        payload: r#"i=0; while :; do sleep 300 & i=$((i+1)); done 2>/dev/null; echo spawned=$i"#,
        attack: "Fork-bomb the sandbox with unbounded process creation",
        expected: "Capped by pids.max and killed at the timeout; peak process count stays near the cap and no stragglers survive on the host",
    },
    // Allocate far past the cgroup memory limit until the OOM kill fires.
    EscapeTest {
        id: "memory_hog",
        name: "Memory hog",
        language: Language::Python,
        payload: r#"
a = bytearray(256 * 1024 * 1024)
print('SURVIVED')
"#,
        attack: "Exhaust memory far beyond the cgroup limit",
        expected: "OOM-killed at the memory limit (KillReason::MemoryLimit) with peak memory near the cap; the host is unaffected",
    },
    // Busy-loop forever; the wall timeout plus cpu.max quota must bound it.
    EscapeTest {
        id: "cpu_spin",
        name: "CPU spin",
        language: Language::Sh,
        payload: r#"while :; do :; done"#,
        attack: "Burn CPU forever to starve the host",
        expected: "Killed at the wall timeout with cpu_time close to the cpu.max quota (100 percent of one core)",
    },
    // Fill /work and /tmp with zeros until every cap rejects the write.
    EscapeTest {
        id: "disk_filler",
        name: "Disk filler",
        language: Language::Sh,
        payload: r#"dd if=/dev/zero of=/work/big bs=1M count=64 2>&1; echo rc=$?; dd if=/dev/zero of=/tmp/big bs=1M count=64 2>&1; echo rc2=$?"#,
        attack: "Fill both writable areas with 64 MiB of zeros",
        expected: "Writes fail with ENOSPC (8 MiB root tmpfs) or the RLIMIT_FSIZE / scratch-size cap; the host filesystem is untouched",
    },
    // `yes(1)` writes to stdout forever; the byte cap must kill the run.
    EscapeTest {
        id: "output_flood",
        name: "Output flood",
        language: Language::Sh,
        payload: r#"yes"#,
        attack: "Flood stdout forever with yes(1)",
        expected: "Killed with KillReason::OutputOverflow at the output cap; captured output stays capped",
    },
    // Classic recon: host user enumeration via /etc/passwd.
    EscapeTest {
        id: "read_etc_passwd",
        name: "Read /etc/passwd",
        language: Language::Sh,
        payload: r#"cat /etc/passwd"#,
        attack: "Enumerate host users via /etc/passwd",
        expected: "Succeeds but shows the sandbox's own passwd (carapace-sandbox-marker), never host users",
    },
    // Password hash theft: /etc/shadow must not even exist in the sandbox.
    EscapeTest {
        id: "read_shadow",
        name: "Read /etc/shadow",
        language: Language::Sh,
        payload: r#"cat /etc/shadow"#,
        attack: "Steal host password hashes via /etc/shadow",
        expected: "The file does not exist inside the sandbox; cat fails",
    },
    // Host home-directory listing must fail outright.
    EscapeTest {
        id: "read_home",
        name: "Read /home and /root",
        language: Language::Sh,
        payload: r#"ls /home /root"#,
        attack: "List host home directories /home and /root",
        expected: "Neither exists inside the sandbox (No such file or directory)",
    },
    // Try to plant files outside the sandbox on the two interesting mounts.
    EscapeTest {
        id: "write_outside",
        name: "Write outside the sandbox",
        language: Language::Sh,
        payload: r#"echo pwned > /etc/pwned 2>/work/e1; echo rc1=$?; echo pwned > /usr/pwned 2>/work/e2; echo rc2=$?; cat /work/e1 /work/e2"#,
        attack: "Plant files in host-writable locations (/etc, /usr)",
        expected: "Both writes denied: /usr is read-only (EROFS), /etc is denied by Landlock; no host file appears",
    },
    // Write an executable into the scratch area and run it. Landlock's
    // writable grants deny EXECUTE by default (strict), so a payload can
    // stage code but not run it without an explicit policy opt-in.
    EscapeTest {
        id: "write_then_exec",
        name: "Write then execute",
        language: Language::Sh,
        payload: r#"printf '#!/bin/sh\necho CARA-WRITE-THEN-EXEC-ESCAPED\n' > /work/cara-written.sh; chmod +x /work/cara-written.sh; /work/cara-written.sh 2>&1; echo rc=$?"#,
        attack: "Write an executable into the writable scratch area and execute it",
        expected: "The file is created but Landlock denies execve on writable locations: the written program never runs (Permission denied, rc=126)",
    },
    // Symlink from the writable scratch into /etc: the link must resolve
    // inside the Landlock-scoped view, not reach the host.
    EscapeTest {
        id: "symlink_escape",
        name: "Symlink escape",
        language: Language::Sh,
        payload: r#"ln -s /etc/passwd /work/link && cat /work/link"#,
        attack: "Symlink from the writable area into /etc/passwd",
        expected: "The link resolves to the sandbox's own /etc/passwd within the Landlock scope; the host file is untouched",
    },
    // Kernel-interface abuse: read /proc/1 and enumerate pids.
    EscapeTest {
        id: "proc_escape",
        name: "/proc inspection",
        language: Language::Sh,
        payload: r#"echo root=$(readlink /proc/1/root); tr '\0' ' ' < /proc/1/cmdline; echo; ls /proc | grep -E '^[0-9]+$' | sort -n | tail -1"#,
        attack: "Inspect /proc for the host init and host pids",
        expected: "/proc/1 is the sandbox's own shell and the pid space is fresh (max pid <= 10); host processes are invisible",
    },
    // ptrace-attach the sandbox init: the classic injection primitive.
    EscapeTest {
        id: "ptrace_attempt",
        name: "ptrace injection",
        language: Language::Python,
        payload: r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(16, 1, 0, 0)  # PTRACE_ATTACH (16) on pid 1
print('ret', r, 'errno', ctypes.get_errno())
"#,
        attack: "ptrace-attach the sandbox init for code injection",
        expected: "Denied with EPERM: ptrace is not in the seccomp allowlist",
    },
    // Mount a fresh filesystem: would remap the whole view of the world.
    EscapeTest {
        id: "mount_attempt",
        name: "mount(2) attempt",
        language: Language::Python,
        payload: r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
r = libc.mount(b'none', b'/mnt', b'tmpfs', 0, None)
print('ret', r, 'errno', ctypes.get_errno())
"#,
        attack: "Mount a fresh tmpfs to remap the filesystem",
        expected: "Denied with EPERM: mount(2) is not in the seccomp allowlist",
    },
    // User+mount namespace escape attempt with the real unshare(1) tool.
    EscapeTest {
        id: "unshare_attempt",
        name: "unshare(2) escape",
        language: Language::Sh,
        payload: r#"unshare -Ur true 2>&1; echo rc=$?"#,
        attack: "Create a new user+mount namespace to regain privileges",
        expected: "Denied with EPERM: unshare(2) is not in the seccomp allowlist",
    },
    // Network egress to a public address; socket(2) must be denied first.
    EscapeTest {
        id: "socket_egress",
        name: "Network egress",
        language: Language::Python,
        payload: r#"
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('1.1.1.1', 80))
    print('CONNECTED')
except OSError as e:
    print('denied', e.errno)
"#,
        attack: "Open a TCP connection to 1.1.1.1:80",
        expected: "Denied with EPERM on socket(2): no sockets exist (empty netns plus seccomp); the connection is never made",
    },
    // Abstract-namespace AF_UNIX: rendezvous with host processes without
    // any filesystem node.
    EscapeTest {
        id: "abstract_unix_escape",
        name: "Abstract Unix socket",
        language: Language::Python,
        payload: r#"
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind('\0cara-escape-abstract-probe')
    print('BOUND')
except OSError as e:
    print('denied', e.errno)
"#,
        attack: "Bind an abstract-namespace AF_UNIX socket to rendezvous with host processes",
        expected: "Denied with EPERM: socket(2) itself is denied, so the abstract namespace is unreachable",
    },
    // Privilege escalation: uid changes plus a hunt for setuid binaries.
    // The read-only /usr bind may contain setuid-bit files from the host;
    // with CapEff=0 and NoNewPrivs=1 they are provably inert.
    EscapeTest {
        id: "setuid_escalation",
        name: "setuid escalation",
        language: Language::Python,
        payload: r#"
import os, stat
try:
    os.setuid(1)
    print('SETUID1-OK', flush=True)
except PermissionError as e:
    print('setuid1-denied', e.errno, flush=True)
try:
    os.setresuid(1, 1, 1)
    print('SETRES-OK', flush=True)
except PermissionError as e:
    print('setres-denied', e.errno, flush=True)
count = 0
for d, dirs, files in os.walk('/usr/bin'):
    for f in files:
        try:
            if os.stat(d + '/' + f).st_mode & stat.S_ISUID:
                count += 1
        except OSError:
            pass
print('setuid-bit-binaries', count, flush=True)
for line in open('/proc/self/status'):
    if line.startswith(('CapEff', 'NoNewPrivs')):
        print(line.rstrip(), flush=True)
"#,
        attack: "Change uid and abuse setuid binaries for root",
        expected: "Every uid change fails with EPERM (no CAP_SETUID); setuid bits in the read-only /usr bind are inert: CapEff=0000000000000000 and NoNewPrivs=1",
    },
    // Kernel keyring abuse (add_key/keyctl); glibc exposes no symbols, so
    // raw x86_64 syscall numbers are used (add_key=248, keyctl=250).
    EscapeTest {
        id: "keyring_abuse",
        name: "Keyring abuse",
        language: Language::Python,
        payload: r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
r1 = libc.syscall(248, b'user', b'cara-escape-probe', b'v', 1, -2)  # add_key
print('add_key ret', r1, 'errno', ctypes.get_errno())
r2 = libc.syscall(250, 0, 0, 0, 0, 0)  # keyctl(KEYCTL_GET_KEYRING_ID)
print('keyctl ret', r2, 'errno', ctypes.get_errno())
"#,
        attack: "Abuse kernel keyrings via add_key/keyctl to stash or harvest secrets",
        expected: "Denied with EPERM: keyring syscalls are not in the seccomp allowlist",
    },
    // Descriptor leak probing: what fds did the runtime hand the payload?
    EscapeTest {
        id: "fd_leak_scan",
        name: "FD leak scan",
        language: Language::Sh,
        payload: r#"ls /proc/self/fd | sort -n | tr '\n' ' '; echo"#,
        attack: "Enumerate inherited descriptors for leaks into the payload",
        expected: "Exactly 0, 1, 2 plus the scanner's own transient directory fd; nothing else leaks in",
    },
    // Environment harvesting: the child must see only the allowlisted vars.
    EscapeTest {
        id: "env_leak",
        name: "Environment leak",
        language: Language::Python,
        payload: r#"
import os
print(' '.join(sorted(os.environ)))
"#,
        attack: "Harvest inherited environment variables and secrets",
        expected: "The child sees exactly the allowlisted variables the spec set; nothing is inherited from the host",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_21_unique_snake_case_ids() {
        let all = Catalog::all();
        assert_eq!(all.len(), 21, "catalog size drifted; update the suite too");
        for (i, t) in all.iter().enumerate() {
            assert!(
                !t.id.is_empty() && t.id.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "id {:?} is not snake_case",
                t.id
            );
            assert!(
                all[i + 1..].iter().all(|o| o.id != t.id),
                "duplicate id {}",
                t.id
            );
            assert!(!t.name.is_empty() && !t.attack.is_empty() && !t.expected.is_empty());
            assert!(!t.payload.trim().is_empty(), "empty payload in {}", t.id);
        }
    }

    #[test]
    fn catalog_serializes_to_json_and_lookups_work() {
        let json = serde_json::to_string(Catalog::all()).expect("serialize catalog");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v.as_array().map(|a| a.len()), Some(21));
        for t in Catalog::all() {
            assert!(json.contains(t.id), "json is missing {}", t.id);
            assert!(Catalog::get(t.id).is_some(), "get({}) failed", t.id);
        }
        assert!(Catalog::get("no_such_entry").is_none());
    }
}
