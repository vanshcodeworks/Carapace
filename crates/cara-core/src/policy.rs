//! Policy files: what a run is allowed to do, in TOML.
//!
//! Strict by construction: unknown fields are rejected, unknown units are
//! rejected, ambiguous values are errors. A policy file can never
//! silently widen permissions (fail closed).

use crate::spec::{Limits, SandboxSpec};
use serde::Deserialize;
use std::time::Duration;

/// Default `PATH` for policy-driven runs. Kept in sync with the runtime
/// layout baked into the Tier 1 rootfs (`/usr` + merged-usr symlinks) and
/// P2 runtime-matrix findings: compilers, Node, and Python subprocess code
/// all resolve helpers through the inherited `PATH`.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// One outbound destination permitted by `[network] allow`.
///
/// Only literal IPs and CIDR ranges are accepted. Hostnames are refused at
/// parse time: resolving them would make a policy depend on DNS, and doing
/// it in the supervisor would add an unbounded attack surface. Write the
/// resolved address instead. See docs/policy.md and ADR-0004.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AllowlistEntry {
    /// IPv4 host or range: `1.2.3.4:443` or `10.0.0.0/8:443`.
    V4 { ip: [u8; 4], prefix: u8, port: u16 },
    /// IPv6 host or range: `[::1]:443` or `[2001:db8::/32]:443`.
    V6 { ip: [u8; 16], prefix: u8, port: u16 },
}

impl AllowlistEntry {
    /// Parses one `IP:port`, `CIDR:port` or `[IPv6]:port` entry. Anything
    /// else (hostnames, ports out of range, bad prefixes) is an error.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let invalid = |why: &str| {
            PolicyError::Invalid(format!(
                "network.allow entry {s:?}: {why} (use IP:port, CIDR:port or [IPv6]:port)"
            ))
        };
        let (addr_part, port_str, bracketed) = if let Some(inner) = s.strip_prefix('[') {
            let Some(end) = inner.find(']') else {
                return Err(invalid("missing ']'"));
            };
            let (addr, rest) = inner.split_at(end);
            let port = rest
                .strip_prefix(']')
                .ok_or_else(|| invalid("missing ']'"))?
                .strip_prefix(':')
                .ok_or_else(|| invalid("missing :port"))?;
            (addr, port, true)
        } else {
            let (addr, port) = s.rsplit_once(':').ok_or_else(|| invalid("missing :port"))?;
            (addr, port, false)
        };
        if addr_part.is_empty() || (!bracketed && addr_part.contains(':')) {
            return Err(invalid("IPv6 addresses must be written as [addr]:port"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| invalid("port must be a number"))?;
        if port == 0 {
            return Err(invalid("port must be between 1 and 65535"));
        }
        let (ip_str, prefix_str) = match addr_part.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (addr_part, None),
        };
        if ip_str.is_empty() {
            return Err(invalid("empty address"));
        }
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            let prefix = match prefix_str {
                Some(p) => p
                    .parse::<u8>()
                    .map_err(|_| invalid("prefix must be a number"))?,
                None => 32,
            };
            if prefix > 32 {
                return Err(invalid("IPv4 prefix must be between 0 and 32"));
            }
            Ok(Self::V4 {
                ip: ip.octets(),
                prefix,
                port,
            })
        } else if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
            let prefix = match prefix_str {
                Some(p) => p
                    .parse::<u8>()
                    .map_err(|_| invalid("prefix must be a number"))?,
                None => 128,
            };
            if prefix > 128 {
                return Err(invalid("IPv6 prefix must be between 0 and 128"));
            }
            Ok(Self::V6 {
                ip: ip.octets(),
                prefix,
                port,
            })
        } else {
            Err(invalid(
                "hostnames are not supported; resolve to an IP first",
            ))
        }
    }

    /// True when `family`/`addr`/`port` (read from a live `sockaddr`) match
    /// this entry. Ranges are matched by masking the configured network and
    /// the target address with the prefix length.
    pub fn matches(&self, family: u16, addr: &[u8], port: u16) -> bool {
        match self {
            Self::V4 {
                ip,
                prefix,
                port: p,
            } => {
                family == AF_INET
                    && *p == port
                    && addr.len() >= 4
                    && prefix_matches(ip, addr, *prefix)
            }
            Self::V6 {
                ip,
                prefix,
                port: p,
            } => {
                family == AF_INET6
                    && *p == port
                    && addr.len() >= 16
                    && prefix_matches(ip, addr, *prefix)
            }
        }
    }
}

// cara-core is platform-agnostic, so it does not depend on libc. The Linux
// sockaddr family numbers are stable ABI values (socket.h): AF_INET=2,
// AF_INET6=10. cara-sys asserts these against libc in its own tests.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Compares the first `prefix` bits of two addresses.
fn prefix_matches(configured: &[u8], target: &[u8], prefix: u8) -> bool {
    let whole = (prefix as usize) / 8;
    if whole > configured.len() || target.len() < configured.len() {
        return false;
    }
    if configured[..whole] != target[..whole] {
        return false;
    }
    let bits = (prefix as usize) % 8;
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    (configured[whole] & mask) == (target[whole] & mask)
}

/// Network access mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Empty network namespace: no interfaces, nothing reachable.
    #[default]
    None,
    /// Share the host's network namespace (opt-in, loud).
    Full,
    /// Outbound `connect(2)` is brokered by a seccomp user-notification
    /// handler and only reaches the listed IPs/ports. Sockets and the host
    /// network namespace are available so ordinary clients work.
    Allowlist(Vec<AllowlistEntry>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    /// Consumed before this struct is built (see [`Policy::parse`]); kept
    /// as a field so `deny_unknown_fields` accepts it.
    #[allow(dead_code)]
    preset: Option<String>,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    filesystem: RawFs,
    #[serde(default)]
    network: RawNetwork,
    #[serde(default)]
    runtime: RawRuntime,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    memory: Option<String>,
    cpu: Option<String>,
    timeout: Option<String>,
    max_processes: Option<u32>,
    disk: Option<String>,
    max_output: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFs {
    read_only: Option<Vec<String>>,
    read_write: Option<Vec<String>>,
    exec_on_write: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    mode: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    language: Option<String>,
}

/// A validated policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub limits: Limits,
    /// Extra host paths bind-mounted read-only (the runtime /usr is
    /// always present; these are additional).
    pub read_only: Vec<std::path::PathBuf>,
    /// Extra host paths bind-mounted read-write and Landlock-granted.
    pub read_write: Vec<std::path::PathBuf>,
    /// Allow `execve` on files in writable locations (`/work`, `/tmp`,
    /// `/dev/shm`, read-write binds). Off by default and off in `strict`;
    /// `dev` enables it for compile-and-run workflows.
    pub exec_on_write: bool,
    pub network: NetworkMode,
    /// Runtime language hint (informational in v1).
    pub language: Option<String>,
}

/// Everything that can go wrong while loading a policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy file: {0}")]
    Io(String),
    #[error("policy syntax: {0}")]
    Syntax(String),
    #[error("policy invalid: {0}")]
    Invalid(String),
}

/// Known presets (name -> builder). Defaults are the `strict` posture.
pub const PRESETS: &[&str] = &["strict", "dev", "network-light"];

impl Policy {
    /// `strict`: the default posture — tight everything, no network.
    pub fn strict() -> Self {
        Self {
            limits: Limits {
                timeout: Duration::from_secs(10),
                max_output_bytes: 1024 * 1024,
                scratch_bytes: 64 * 1024 * 1024,
                memory_bytes: 256 * 1024 * 1024,
                cpu_percent: 100,
                max_processes: 32,
            },
            read_only: Vec::new(),
            read_write: Vec::new(),
            exec_on_write: false,
            network: NetworkMode::None,
            language: None,
        }
    }

    /// `dev`: room to work, still no network.
    pub fn dev() -> Self {
        Self {
            limits: Limits {
                timeout: Duration::from_secs(60),
                max_output_bytes: 8 * 1024 * 1024,
                scratch_bytes: 512 * 1024 * 1024,
                memory_bytes: 1024 * 1024 * 1024,
                cpu_percent: 200,
                max_processes: 128,
            },
            read_only: Vec::new(),
            read_write: Vec::new(),
            exec_on_write: true,
            network: NetworkMode::None,
            language: None,
        }
    }

    /// `network-light`: dev limits with an empty allowlist, so no outbound
    /// `connect(2)` is permitted until the policy adds entries.
    pub fn network_light() -> Self {
        Self {
            network: NetworkMode::Allowlist(Vec::new()),
            ..Self::dev()
        }
    }

    /// Parses and validates policy text. `preset = "name"` selects the
    /// base posture; other fields override it.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let value: toml::Value =
            toml::from_str(text).map_err(|e| PolicyError::Syntax(e.to_string()))?;

        // preset (must be a known string if present)
        let mut policy = match value.get("preset") {
            None => Self::strict(),
            Some(toml::Value::String(name)) => match name.as_str() {
                "strict" => Self::strict(),
                "dev" => Self::dev(),
                "network-light" => Self::network_light(),
                other => {
                    return Err(PolicyError::Invalid(format!(
                        "unknown preset {other:?} (known: {})",
                        PRESETS.join(", ")
                    )));
                }
            },
            Some(_) => return Err(PolicyError::Invalid("preset must be a string".to_string())),
        };

        // Round-trip through the raw structs for deny_unknown_fields.
        let raw: RawPolicy = value
            .clone()
            .try_into()
            .map_err(|e| PolicyError::Invalid(format!("unknown or malformed field: {e}")))?;

        if let Some(v) = raw.limits.memory {
            policy.limits.memory_bytes = parse_bytes(&v, "limits.memory")?;
        }
        if let Some(v) = raw.limits.cpu {
            policy.limits.cpu_percent = parse_percent(&v, "limits.cpu")?;
        }
        if let Some(v) = raw.limits.timeout {
            policy.limits.timeout = parse_duration(&v, "limits.timeout")?;
        }
        if let Some(v) = raw.limits.max_processes {
            if v == 0 {
                return Err(PolicyError::Invalid(
                    "limits.max_processes must be >= 1".into(),
                ));
            }
            policy.limits.max_processes = v;
        }
        if let Some(v) = raw.limits.disk {
            policy.limits.scratch_bytes = parse_bytes(&v, "limits.disk")?;
        }
        if let Some(v) = raw.limits.max_output {
            policy.limits.max_output_bytes = parse_bytes(&v, "limits.max_output")? as usize;
        }
        if let Some(list) = raw.filesystem.read_only {
            policy.read_only = list
                .iter()
                .map(|p| validate_host_path(p, false))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if let Some(list) = raw.filesystem.read_write {
            policy.read_write = list
                .iter()
                .map(|p| validate_host_path(p, true))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if let Some(allow) = raw.filesystem.exec_on_write {
            policy.exec_on_write = allow;
        }
        if let Some(mode) = raw.network.mode {
            policy.network = match mode.as_str() {
                "none" => NetworkMode::None,
                "full" => NetworkMode::Full,
                "allowlist" => {
                    let mut entries = Vec::with_capacity(raw.network.allow.len());
                    for s in &raw.network.allow {
                        entries.push(AllowlistEntry::parse(s)?);
                    }
                    NetworkMode::Allowlist(entries)
                }
                other => {
                    return Err(PolicyError::Invalid(format!(
                        "unknown network mode {other:?} (none | full | allowlist)"
                    )));
                }
            };
        } else if !raw.network.allow.is_empty() {
            return Err(PolicyError::Invalid(
                "network.allow given without network.mode = \"allowlist\"".into(),
            ));
        }
        if let Some(lang) = raw.runtime.language {
            policy.language = Some(lang);
        }

        Ok(policy)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Builds a spawnable spec for `program` with this policy.
    ///
    /// The environment stays allowlist-only, but policy-driven runs always
    /// get a usable `PATH` and `HOME`: child processes (compilers, package
    /// tooling, shells inside scripts) inherit the child's environment, and
    /// without a PATH they cannot find their own helpers. See the P2 runtime
    /// matrix findings in docs/agent/LOG.md.
    pub fn to_spec(&self, program: &str, args: &[String]) -> SandboxSpec {
        let mut spec = SandboxSpec::new(program).args(args);
        spec.limits = self.limits.clone();
        spec.read_only = self.read_only.clone();
        spec.read_write = self.read_write.clone();
        spec.exec_on_write = self.exec_on_write;
        spec.network = self.network.clone();
        spec.env.insert("PATH".into(), DEFAULT_PATH.into());
        spec.env.insert("HOME".into(), "/work".into());
        spec
    }

    /// Plain-English explanation (the `cara policy explain` output).
    pub fn explain(&self) -> String {
        let mut out = String::new();
        out.push_str("This policy allows:\n");
        out.push_str(&format!(
            "  - run for at most {} (wall clock), then the tree is killed\n",
            human_duration(self.limits.timeout)
        ));
        out.push_str(&format!(
            "  - up to {} of memory; exceeding it is an OOM kill\n",
            human_bytes(self.limits.memory_bytes)
        ));
        out.push_str(&format!(
            "  - about {}% of one CPU core\n",
            self.limits.cpu_percent
        ));
        out.push_str(&format!(
            "  - up to {} processes at once (fork bombs die at the cap)\n",
            self.limits.max_processes
        ));
        out.push_str(&format!(
            "  - {} of writable scratch space in /work (and /tmp)\n",
            human_bytes(self.limits.scratch_bytes)
        ));
        out.push_str(&format!(
            "  - {} of captured output (stdout/stderr each)\n",
            human_bytes(self.limits.max_output_bytes as u64)
        ));
        if self.read_only.is_empty() {
            out.push_str("  - read-only access to the system runtime (/usr, /proc, /etc)\n");
        } else {
            out.push_str("  - read-only access to: /usr, /proc, /etc");
            for p in &self.read_only {
                out.push_str(&format!(", {}", p.display()));
            }
            out.push('\n');
        }
        if self.read_write.is_empty() {
            out.push_str("  - NO write access to any host directory (only sandbox scratch)\n");
        } else {
            out.push_str("  - read-WRITE access to host paths:");
            for p in &self.read_write {
                out.push_str(&format!(" {}", p.display()));
            }
            out.push_str("  (everything else on the host stays invisible)\n");
        }
        if self.exec_on_write {
            out.push_str(
                "  - EXECUTE permission on files written to /work, /tmp, /dev/shm and read-write binds\n",
            );
        } else {
            out.push_str(
                "  - NO execute permission on files written to /work, /tmp, /dev/shm or read-write binds\n",
            );
        }
        match &self.network {
            NetworkMode::None => out.push_str("  - NO network access at all\n"),
            NetworkMode::Full => out.push_str(
                "  - FULL network access (shares the host network — this is the loud option)\n",
            ),
            NetworkMode::Allowlist(list) => {
                out.push_str("  - outbound connects limited to: ");
                if list.is_empty() {
                    out.push_str("(nothing)\n");
                } else {
                    for (i, e) in list.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        match e {
                            AllowlistEntry::V4 { ip, prefix, port } => out.push_str(&format!(
                                "{}.{}.{}.{}/{}/{}",
                                ip[0], ip[1], ip[2], ip[3], prefix, port
                            )),
                            AllowlistEntry::V6 { ip, prefix, port } => {
                                let addr = std::net::Ipv6Addr::from(*ip);
                                out.push_str(&format!("[{addr}]/{prefix}:{port}"));
                            }
                        }
                    }
                    out.push('\n');
                }
                out.push_str(
                    "  - sockets use the host network namespace; only connect(2) to these destinations is allowed\n",
                );
            }
        }
        out.push_str("Everything not listed here is denied. Unlisted host paths are\n");
        out.push_str("invisible; unlisted syscalls return EPERM; unlisted network\n");
        out.push_str("destinations are unreachable.\n");
        out
    }
}

/// Host paths eligible for bind mounts: absolute, no `..`, not shadowing
/// sandbox internals, must exist for read-write (created dirs would
/// surprise the caller).
fn validate_host_path(p: &str, must_exist: bool) -> Result<std::path::PathBuf, PolicyError> {
    let path = std::path::PathBuf::from(p);
    if !path.is_absolute() {
        return Err(PolicyError::Invalid(format!(
            "filesystem path {p:?} must be absolute"
        )));
    }
    let norm = path.components().count();
    let mut has_dotdot = false;
    for c in path.components() {
        if matches!(c, std::path::Component::ParentDir) {
            has_dotdot = true;
        }
    }
    if has_dotdot || norm == 0 {
        return Err(PolicyError::Invalid(format!(
            "filesystem path {p:?} must be normalized (no ..)"
        )));
    }
    for forbidden in ["/proc", "/sys", "/dev", "/etc"] {
        if path.starts_with(forbidden) {
            return Err(PolicyError::Invalid(format!(
                "filesystem path {p:?} may not shadow sandbox internals ({forbidden})"
            )));
        }
    }
    if must_exist && !path.exists() {
        return Err(PolicyError::Invalid(format!(
            "filesystem path {p:?} does not exist"
        )));
    }
    Ok(path)
}

/// Byte sizes: `512`, `64KB`, `8MiB`, `1GB`. Units: B; K/M/G = binary
/// (1024-based, like systemd); KiB/MiB/GiB = binary explicitly;
/// KB/MB/GB = decimal (1000-based). Documented in docs/policy.md.
pub fn parse_bytes(s: &str, what: &str) -> Result<u64, PolicyError> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len()));
    let value: f64 = num
        .trim()
        .parse()
        .map_err(|_| PolicyError::Invalid(format!("{what}: {s:?} is not a size")))?;
    if value < 0.0 {
        return Err(PolicyError::Invalid(format!("{what}: negative size")));
    }
    let mult = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "K" | "KIB" => 1024,
        "M" | "MIB" => 1024 * 1024,
        "G" | "GIB" => 1024 * 1024 * 1024,
        "KB" => 1000,
        "MB" => 1000 * 1000,
        "GB" => 1000 * 1000 * 1000,
        other => {
            return Err(PolicyError::Invalid(format!(
                "{what}: unknown unit {other:?} (B, K/M/G, KiB/MiB/GiB, KB/MB/GB)"
            )));
        }
    };
    let total = value * mult as f64;
    // Cap: 1 TiB. Larger sizes are policy errors (the spec_limits fuzzer
    // showed huge inputs slipping through the old float compare).
    const MAX: f64 = (1u64 << 40) as f64;
    if !total.is_finite() || total > MAX {
        return Err(PolicyError::Invalid(format!(
            "{what}: size exceeds the 1 TiB policy cap"
        )));
    }
    Ok(total as u64)
}

/// Percent: `50%` or `200%` (of one core).
fn parse_percent(s: &str, what: &str) -> Result<u32, PolicyError> {
    let s = s.trim();
    let Some(num) = s.strip_suffix('%') else {
        return Err(PolicyError::Invalid(format!(
            "{what}: {s:?} must be a percent like \"50%\""
        )));
    };
    let v: u32 = num
        .parse()
        .map_err(|_| PolicyError::Invalid(format!("{what}: {s:?} is not a percentage")))?;
    if v == 0 || v > 10_000 {
        return Err(PolicyError::Invalid(format!(
            "{what}: {s:?} out of range (1% .. 10000%)"
        )));
    }
    Ok(v)
}

/// Durations: `500ms`, `10s`, `2m`, `1h`, and sums like `1m30s`.
pub fn parse_duration(s: &str, what: &str) -> Result<Duration, PolicyError> {
    let s = s.trim();
    let mut total = Duration::ZERO;
    let mut rest = s;
    let mut any = false;
    while !rest.is_empty() {
        let split = rest
            .find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| PolicyError::Invalid(format!("{what}: {s:?} is missing a unit")))?;
        let (n, tail) = rest.split_at(split);
        let value: u64 = n
            .parse()
            .map_err(|_| PolicyError::Invalid(format!("{what}: {s:?} is not a duration")))?;
        let unit_len = tail
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(tail.len());
        let (unit, next) = tail.split_at(unit_len);
        let mult = match unit {
            "ms" => 1,
            "s" => 1000,
            "m" => 60_000,
            "h" => 3_600_000,
            other => {
                return Err(PolicyError::Invalid(format!(
                    "{what}: unknown unit {other:?} (ms, s, m, h)"
                )));
            }
        };
        // checked_mul: huge values must error, not silently wrap in
        // release builds (found by the spec_limits fuzz target).
        let millis = value
            .checked_mul(mult)
            .ok_or_else(|| PolicyError::Invalid(format!("{what}: duration too large")))?;
        total += Duration::from_millis(millis);
        rest = next;
        any = true;
    }
    if !any || total.is_zero() {
        return Err(PolicyError::Invalid(format!(
            "{what}: {s:?} must be a positive duration"
        )));
    }
    // Cap: 90 days per duration value (a policy asking for more is a
    // mistake, not a feature).
    const MAX: Duration = Duration::from_secs(90 * 24 * 3600);
    if total > MAX {
        return Err(PolicyError::Invalid(format!(
            "{what}: duration exceeds the 90-day policy cap"
        )));
    }
    Ok(total)
}

fn human_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    if b >= KIB * KIB * KIB && b.is_multiple_of(KIB * KIB * KIB) {
        format!("{}GiB", b / (KIB * KIB * KIB))
    } else if b >= KIB * KIB && b.is_multiple_of(KIB * KIB) {
        format!("{}MiB", b / (KIB * KIB))
    } else if b >= KIB && b.is_multiple_of(KIB) {
        format!("{}KiB", b / KIB)
    } else {
        format!("{b}B")
    }
}

fn human_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1000) {
        let s = ms / 1000;
        if s.is_multiple_of(60) {
            format!("{}m", s / 60)
        } else {
            format!("{}s", s)
        }
    } else {
        format!("{ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: &str = r#"
[limits]
memory = "256MB"
cpu = "100%"
timeout = "10s"
max_processes = 32
disk = "64MB"
max_output = "1MB"

[filesystem]
read_only = ["/usr"]
read_write = []

[network]
mode = "none"

[runtime]
language = "python3.12"
"#;

    #[test]
    fn parses_the_reference_policy() {
        let p = Policy::parse(STRICT).unwrap();
        // "256MB" is decimal (2_500_000_00? no: 256 * 10^6).
        assert_eq!(p.limits.memory_bytes, 256 * 1000 * 1000);
        assert_eq!(p.limits.cpu_percent, 100);
        assert_eq!(p.limits.timeout, Duration::from_secs(10));
        assert_eq!(p.limits.max_processes, 32);
        assert_eq!(p.limits.scratch_bytes, 64 * 1000 * 1000);
        assert_eq!(p.limits.max_output_bytes, 1000 * 1000);
        assert_eq!(p.network, NetworkMode::None);
        assert!(!p.exec_on_write, "strict must not execute written files");
        assert_eq!(p.read_only, vec![std::path::PathBuf::from("/usr")]);
        assert_eq!(p.language.as_deref(), Some("python3.12"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let e = Policy::parse("[limits]\nmemry = \"1MB\"\n").unwrap_err();
        assert!(matches!(e, PolicyError::Invalid(_)), "{e}");
        let e = Policy::parse("[wombat]\nx = 1\n").unwrap_err();
        assert!(matches!(e, PolicyError::Invalid(_)), "{e}");
    }

    #[test]
    fn unknown_preset_and_mode_rejected() {
        assert!(Policy::parse("preset = \"lol\"\n").is_err());
        assert!(Policy::parse("[network]\nmode = \"sneaky\"\n").is_err());
    }

    #[test]
    fn presets_have_distinct_postures() {
        let strict = Policy::strict();
        let dev = Policy::dev();
        assert!(dev.limits.memory_bytes > strict.limits.memory_bytes);
        assert!(dev.limits.timeout > strict.limits.timeout);
        assert!(!strict.exec_on_write, "strict must deny exec-on-write");
        assert!(dev.exec_on_write, "dev enables compile-and-run workflows");
        assert!(
            Policy::network_light().exec_on_write,
            "network-light inherits the dev posture"
        );
        assert_eq!(
            Policy::network_light().network,
            NetworkMode::Allowlist(vec![])
        );
    }

    #[test]
    fn size_units() {
        assert_eq!(parse_bytes("512", "t").unwrap(), 512);
        assert_eq!(parse_bytes("64KB", "t").unwrap(), 64_000);
        assert_eq!(parse_bytes("64K", "t").unwrap(), 65_536);
        assert_eq!(parse_bytes("8MiB", "t").unwrap(), 8 * 1024 * 1024);
        assert!(parse_bytes("8X", "t").is_err());
        assert!(parse_bytes("-8K", "t").is_err());
    }

    #[test]
    fn fuzz_found_inputs_are_rejected() {
        // Regression: the spec_limits fuzzer produced these.
        assert!(parse_duration("8888888888888m", "t").is_err());
        assert!(parse_duration("18446744073709551615s", "t").is_err());
        assert!(parse_bytes("9999999999999999999", "t").is_err());
        assert!(parse_bytes("88888888888888888888", "t").is_err());
    }

    #[test]
    fn duration_forms() {
        assert_eq!(
            parse_duration("500ms", "t").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration("1m30s", "t").unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_duration("2h", "t").unwrap(),
            Duration::from_secs(7200)
        );
        assert!(parse_duration("10", "t").is_err());
        assert!(parse_duration("0s", "t").is_err());
    }

    #[test]
    fn path_validation_blocks_escapes() {
        assert!(validate_host_path("/home/dev/project", false).is_ok());
        assert!(validate_host_path("relative/path", false).is_err());
        assert!(validate_host_path("/home/../etc", false).is_err());
        assert!(validate_host_path("/proc/self", false).is_err());
        assert!(validate_host_path("/nonexistent/thing", true).is_err());
    }

    #[test]
    fn explain_mentions_everything_important() {
        let p = Policy::strict();
        let e = p.explain();
        for needle in [
            "NO network",
            "fork bombs",
            "read-only",
            "NO write access",
            "denied",
        ] {
            assert!(e.contains(needle), "explain must mention {needle}:\n{e}");
        }
    }

    #[test]
    fn allowlist_requires_mode() {
        assert!(Policy::parse("[network]\nallow=[\"x\"]\n").is_err());
        let p = Policy::parse(
            "[network]\nmode=\"allowlist\"\nallow=[\"127.0.0.1:443\", \"10.0.0.0/8:80\", \"[::1]:53\"]\n",
        )
        .unwrap();
        assert_eq!(
            p.network,
            NetworkMode::Allowlist(vec![
                AllowlistEntry::V4 {
                    ip: [127, 0, 0, 1],
                    prefix: 32,
                    port: 443,
                },
                AllowlistEntry::V4 {
                    ip: [10, 0, 0, 0],
                    prefix: 8,
                    port: 80,
                },
                AllowlistEntry::V6 {
                    ip: std::net::Ipv6Addr::LOCALHOST.octets(),
                    prefix: 128,
                    port: 53,
                },
            ])
        );
    }

    #[test]
    fn allowlist_rejects_hostnames_and_malformed_entries() {
        // Fail closed at policy check time: no DNS resolution, no guessing.
        for bad in [
            "pypi.org:443",    // hostname
            "127.0.0.1",       // no port
            "127.0.0.1:0",     // port zero
            "127.0.0.1:65536", // port overflow
            "10.0.0.0/33:443", // prefix out of range
            "[::1]:notaport",  // bad port
            "[::1",            // missing bracket
            "2001:db8::1:443", // IPv6 must be bracketed
            "256.1.1.1:443",   // not an IPv4 address
            "",                // empty
        ] {
            let text = format!("[network]\nmode=\"allowlist\"\nallow=[\"{bad}\"]\n");
            let e = match Policy::parse(&text) {
                Err(e) => e,
                Ok(_) => panic!("{bad:?} must be rejected"),
            };
            assert!(matches!(e, PolicyError::Invalid(_)), "{bad:?}: {e}");
        }
    }

    #[test]
    fn cidr_and_ip_port_matching_is_exact() {
        let host = AllowlistEntry::parse("192.0.2.7:443").unwrap();
        assert!(host.matches(AF_INET, &[192, 0, 2, 7], 443));
        assert!(!host.matches(AF_INET, &[192, 0, 2, 7], 80), "port matters");
        assert!(
            !host.matches(AF_INET, &[192, 0, 2, 8], 443),
            "host bits matter"
        );

        let range = AllowlistEntry::parse("10.0.0.0/8:443").unwrap();
        assert!(range.matches(AF_INET, &[10, 200, 3, 4], 443));
        assert!(!range.matches(AF_INET, &[11, 0, 0, 1], 443));
        assert!(
            !range.matches(AF_INET6, &[10, 0, 0, 1], 443),
            "family matters"
        );

        // A non-byte-aligned prefix masks the remaining bits too.
        let partial = AllowlistEntry::parse("192.0.2.0/25:443").unwrap();
        assert!(partial.matches(AF_INET, &[192, 0, 2, 100], 443));
        assert!(!partial.matches(AF_INET, &[192, 0, 2, 200], 443));

        let v6 = AllowlistEntry::parse("[2001:db8::/32]:443").unwrap();
        let mut addr = [0u8; 16];
        addr[..2].copy_from_slice(&[0x20, 0x01]);
        addr[2..4].copy_from_slice(&[0x0d, 0xb8]);
        addr[15] = 7;
        assert!(v6.matches(AF_INET6, &addr, 443));
        addr[3] = 0xb9;
        assert!(!v6.matches(AF_INET6, &addr, 443));

        // Truncated or unreadable sockaddr bytes never match (fail closed).
        assert!(!host.matches(AF_INET, &[192, 0], 443));
        assert!(!v6.matches(AF_INET6, &[0x20, 0x01], 443));
    }

    #[test]
    fn to_spec_maps_everything() {
        let p = Policy::parse(STRICT).unwrap();
        let spec = p.to_spec("/usr/bin/python3", &["-c".into(), "print(1)".into()]);
        assert_eq!(spec.limits.memory_bytes, 256 * 1000 * 1000);
        assert_eq!(spec.read_only, vec![std::path::PathBuf::from("/usr")]);
        assert_eq!(spec.args.len(), 2);
        assert_eq!(spec.env.get("PATH").unwrap(), DEFAULT_PATH);
        assert_eq!(spec.env.get("HOME").unwrap(), "/work");
        assert!(!spec.exec_on_write);
    }

    #[test]
    fn exec_on_write_is_explicit_and_explained() {
        // Off by default, off in strict, on in dev.
        assert!(!Policy::strict().exec_on_write);
        assert!(Policy::dev().exec_on_write);

        // Explicit opt-in parses; it must be a boolean, not a string.
        let p = Policy::parse("[filesystem]\nexec_on_write = true\n").unwrap();
        assert!(p.exec_on_write);
        assert!(p.explain().contains("EXECUTE permission"));
        assert!(Policy::parse("[filesystem]\nexec_on_write = \"yes\"\n").is_err());

        // The default explanation states the denial explicitly, so a policy
        // reader cannot miss it.
        let e = Policy::strict().explain();
        assert!(
            e.contains("NO execute permission on files written"),
            "strict explain must state exec-on-write denial:\n{e}"
        );
    }
}
