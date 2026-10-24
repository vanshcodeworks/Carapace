//! What happened when a sandbox run ended.

use std::time::Duration;

/// Why the sandbox (or the program inside it) terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillReason {
    /// Wall-clock limit exceeded; the tree was killed by the supervisor.
    Timeout,
    /// stdout+stderr exceeded the configured byte cap.
    OutputOverflow,
    /// Carapace-internal failure while setting up or supervising the run.
    /// The code never ran or stopped running: never silently ignored.
    Internal(String),
}

/// The full result of one sandbox run.
#[derive(Debug, Clone)]
pub struct ExitReport {
    /// Program exit code, if it exited on its own.
    pub exit_code: Option<i32>,
    /// Fatal signal number, if the program died by signal (e.g. SIGKILL
    /// from the supervisor or from a rlimit).
    pub signal: Option<i32>,
    /// Set when the supervisor killed the run (or setup failed mid-run).
    pub kill_reason: Option<KillReason>,
    /// Wall time from spawn to termination, measured by the supervisor.
    pub wall_time: Duration,
    /// Captured stdout (already capped).
    pub stdout: Vec<u8>,
    /// Captured stderr (already capped).
    pub stderr: Vec<u8>,
    // C3: cpu_time, peak memory, oom kill flag from cgroups.
}

impl ExitReport {
    /// `true` when the run completed without supervisor intervention or
    /// internal error.
    pub fn ran_to_completion(&self) -> bool {
        self.kill_reason.is_none() && (self.exit_code.is_some() || self.signal.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_semantics() {
        let mut r = ExitReport {
            exit_code: Some(0),
            signal: None,
            kill_reason: None,
            wall_time: Duration::from_millis(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(r.ran_to_completion());
        r.kill_reason = Some(KillReason::Timeout);
        assert!(!r.ran_to_completion());
    }
}
