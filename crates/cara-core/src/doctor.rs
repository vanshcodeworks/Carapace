//! Environment capability model shared by `cara doctor`, the backends, and
//! the test suite.

use serde::{Deserialize, Serialize};

/// Outcome of a single capability check.
///
/// Derived ordering is by severity for `Warn`/`Fail` aggregation
/// (`Ok < Warn < Fail < Info`); `Info` sorts last because it never
/// participates in readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Info,
}

/// One capability check as reported by `cara doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    /// Stable machine identifier (e.g. `userns`), part of the stable CLI JSON.
    pub id: String,
    /// Short human-readable name.
    pub name: String,
    pub status: Status,
    /// What was observed, including versions and measured values.
    pub detail: String,
    /// How to fix or work around a missing capability, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
    /// Whether the native (Tier 1) backend refuses to run without this.
    pub required: bool,
}

impl Check {
    pub fn ok(id: &str, name: &str, detail: impl Into<String>) -> Self {
        Self::new(id, name, Status::Ok, detail, None, true)
    }

    pub fn info(id: &str, name: &str, detail: impl Into<String>) -> Self {
        Self::new(id, name, Status::Info, detail, None, false)
    }

    pub fn warn(
        id: &str,
        name: &str,
        detail: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::new(id, name, Status::Warn, detail, Some(remedy.into()), false)
    }

    pub fn fail(
        id: &str,
        name: &str,
        detail: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::new(id, name, Status::Fail, detail, Some(remedy.into()), true)
    }

    fn new(
        id: &str,
        name: &str,
        status: Status,
        detail: impl Into<String>,
        remedy: Option<String>,
        required: bool,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            status,
            detail: detail.into(),
            remedy,
            required,
        }
    }
}

/// Aggregate environment report. `ready()` is the gate every backend must
/// consult before running untrusted code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
}

impl DoctorReport {
    pub fn new(checks: Vec<Check>) -> Self {
        Self { checks }
    }

    /// The worst status across required checks (a `warn` on a required check
    /// still counts as `ok` for readiness; warnings never block).
    pub fn overall(&self) -> Status {
        let mut overall = Status::Ok;
        for c in &self.checks {
            if c.required && c.status == Status::Fail {
                return Status::Fail;
            }
            if matches!(c.status, Status::Warn | Status::Fail) {
                overall = overall.max(Status::Warn);
            }
        }
        overall
    }

    /// `true` iff no required check failed — the environment can run the
    /// native sandbox. Callers MUST treat `false` as "refuse to run code".
    pub fn ready(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|c| c.required && c.status == Status::Fail)
    }

    pub fn failed_required(&self) -> Vec<&Check> {
        self.checks
            .iter()
            .filter(|c| c.required && c.status == Status::Fail)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(id: &str) -> Check {
        Check::ok(id, id, "fine")
    }

    #[test]
    fn overall_requires_all_required_ok() {
        let r = DoctorReport::new(vec![ok("a"), ok("b")]);
        assert_eq!(r.overall(), Status::Ok);
        assert!(r.ready());
    }

    #[test]
    fn required_fail_blocks() {
        let r = DoctorReport::new(vec![ok("a"), Check::fail("b", "b", "missing", "fix it")]);
        assert_eq!(r.overall(), Status::Fail);
        assert!(!r.ready());
        assert_eq!(r.failed_required().len(), 1);
        assert_eq!(r.failed_required()[0].id, "b");
    }

    #[test]
    fn optional_fail_becomes_warn_not_block() {
        // A non-required check that fails (e.g. KVM absent) must not block.
        let mut kvm = Check::info("kvm", "kvm", "absent");
        kvm.status = Status::Fail;
        let r = DoctorReport::new(vec![ok("a"), kvm]);
        assert_eq!(r.overall(), Status::Warn);
        assert!(r.ready());
    }

    #[test]
    fn warn_does_not_block() {
        let r = DoctorReport::new(vec![
            ok("a"),
            Check::warn("io", "io", "not delegated", "edit systemd"),
        ]);
        assert_eq!(r.overall(), Status::Warn);
        assert!(r.ready());
    }

    #[test]
    fn json_roundtrip() {
        let r = DoctorReport::new(vec![
            ok("kernel"),
            Check::fail(
                "landlock",
                "Landlock",
                "unavailable",
                "install newer kernel",
            ),
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let back: DoctorReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.checks.len(), 2);
        assert_eq!(back.failed_required()[0].id, "landlock");
        assert_eq!(back.checks[0].status, Status::Ok);
    }
}
