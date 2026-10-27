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

/// Network access mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Empty network namespace: no interfaces, nothing reachable.
    #[default]
    None,
    /// Share the host's network namespace (opt-in, loud).
    Full,
    /// DNS/domain allowlist — designed in ADR-0004, NOT implemented yet:
    /// validating a policy with this mode succeeds, running it fails
    /// closed with a clear error.
    Allowlist(Vec<String>),
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

    /// `network-light`: dev limits with the (not yet implemented)
    /// allowlist network mode — honest fail-closed at run time.
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
                "allowlist" => NetworkMode::Allowlist(raw.network.allow.clone()),
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
                out.push_str(&format!(
                    "  - network access limited to: {} (NOT IMPLEMENTED YET — runs will fail closed until milestone lands)\n",
                    if list.is_empty() { "(nothing)".to_string() } else { list.join(", ") }
                ))
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
        let p = Policy::parse("[network]\nmode=\"allowlist\"\nallow=[\"pypi.org\"]\n").unwrap();
        assert_eq!(
            p.network,
            NetworkMode::Allowlist(vec!["pypi.org".to_string()])
        );
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
