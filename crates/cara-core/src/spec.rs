//! What to run and how it is limited. Platform-agnostic by rule: this crate
//! compiles everywhere, enforcement lives in backends.

use std::collections::BTreeMap;
use std::time::Duration;

/// A request to run one program under sandboxing.
///
/// C1 scope: argv/env/timeout/output caps. Limits grow per milestone
/// (memory/cpu/pids in C3, filesystem in C2/C4, network in C5); the policy
/// file format that *produces* a `SandboxSpec` lands in C5.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Program to exec, argv[0]-style: absolute path, no PATH search
    /// performed by Carapace itself.
    pub program: String,
    /// Arguments after argv[0].
    pub args: Vec<String>,
    /// Exact environment for the child (allowlist by construction:
    /// nothing is inherited from the parent).
    pub env: BTreeMap<String, String>,
    /// Limits applied to this run.
    pub limits: Limits,
}

impl SandboxSpec {
    /// Convenience builder start: empty env, default limits.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            limits: Limits::default(),
        }
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.limits.timeout = d;
        self
    }

    pub fn max_output(mut self, bytes: usize) -> Self {
        self.limits.max_output_bytes = bytes;
        self
    }
}

/// Hard limits for one run. Defaults are deliberately tight.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock time before the tree is killed.
    pub timeout: Duration,
    /// Per-stream (stdout and stderr each) byte cap before the tree is
    /// killed.
    pub max_output_bytes: usize,
    /// Size of the writable /work scratch tmpfs inside the sandbox.
    pub scratch_bytes: u64,
    // C3: memory_bytes, cpu quota, max_processes.
    // C4: fsize/nofile rlimits. C5: network mode.
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_output_bytes: 8 * 1024 * 1024,
            scratch_bytes: 64 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_expected_spec() {
        let s = SandboxSpec::new("/bin/echo")
            .args(["hello"])
            .env("CARA_RUN_ID", "t1")
            .timeout(Duration::from_millis(250))
            .max_output(1024);
        assert_eq!(s.program, "/bin/echo");
        assert_eq!(s.args, vec!["hello"]);
        assert_eq!(s.env.get("CARA_RUN_ID").unwrap(), "t1");
        assert_eq!(s.limits.timeout, Duration::from_millis(250));
        assert_eq!(s.limits.max_output_bytes, 1024);
    }

    #[test]
    fn defaults_are_tight() {
        let l = Limits::default();
        assert!(l.timeout <= Duration::from_secs(10));
        assert!(l.max_output_bytes <= 8 * 1024 * 1024);
    }
}
