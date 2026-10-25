//! `cara run`: policy loading, doctor gate, spawn, report rendering.

use carapace_core::{Backend, ExitReport, KillReason, Policy};
use std::process::ExitCode;

pub(crate) fn run_main(
    policy_path: Option<&str>,
    json: bool,
    timeout_override: Option<&str>,
    argv: &[String],
) -> ExitCode {
    // 1. Policy (strict preset by default).
    let mut policy = match policy_path {
        Some(path) => match Policy::from_file(std::path::Path::new(path)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cara: policy {path}: {e}");
                return ExitCode::from(super::exit_codes::INVALID_POLICY);
            }
        },
        None => Policy::strict(),
    };

    // 2. CLI overrides (explicit flags beat file values).
    if let Some(t) = timeout_override {
        match carapace_core::policy::parse_duration(t, "--timeout") {
            Ok(d) => policy.limits.timeout = d,
            Err(e) => {
                eprintln!("cara: {e}");
                return ExitCode::from(super::exit_codes::INVALID_POLICY);
            }
        }
    }

    // 3. Program sanity: absolute path required (we are the executor).
    let program = &argv[0];
    if !program.starts_with('/') {
        eprintln!(
            "cara: program must be an absolute path (got {program:?}); \
             e.g. `cara run -- /bin/sh -c '...'`"
        );
        return ExitCode::from(super::exit_codes::INVALID_POLICY);
    }

    // 4. Spawn through the native backend (doctor gate inside).
    let backend = carapace_native::NativeBackend::new();
    let spec = policy.to_spec(program, &argv[1..]);
    let mut handle = match backend.spawn(&spec) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cara: {e}");
            return ExitCode::from(super::exit_codes::ENV_NOT_READY);
        }
    };
    let report = match handle.wait() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cara: supervision error: {e}");
            return ExitCode::from(super::exit_codes::ENV_NOT_READY);
        }
    };

    // 5. Report.
    if json {
        println!("{}", json_report(&report));
    } else {
        print!("{}", human_report(&report));
        use std::io::Write;
        let _ = std::io::stdout().write_all(&report.stdout);
        if !report.stderr.is_empty() {
            eprintln!("\n--- stderr ---");
            let _ = std::io::stderr().write_all(&report.stderr);
        }
        eprintln!("\n{}", human_summary(&report));
    }

    match (&report.kill_reason, report.exit_code) {
        (None, Some(code)) => ExitCode::from(code as u8),
        _ => ExitCode::from(1),
    }
}

fn json_report(r: &ExitReport) -> String {
    let reason = match &r.kill_reason {
        None => serde_json::Value::Null,
        Some(KillReason::Timeout) => serde_json::json!("timeout"),
        Some(KillReason::OutputOverflow) => serde_json::json!("output_overflow"),
        Some(KillReason::MemoryLimit) => serde_json::json!("memory_limit"),
        Some(KillReason::CpuLimit) => serde_json::json!("cpu_limit"),
        Some(KillReason::Internal(m)) => serde_json::json!(format!("internal: {m}")),
    };
    serde_json::json!({
        "exit_code": r.exit_code,
        "signal": r.signal,
        "kill_reason": reason,
        "wall_time_ms": r.wall_time.as_millis() as u64,
        "cpu_time_ms": r.cpu_time.map(|d| d.as_millis() as u64),
        "peak_memory_bytes": r.peak_memory_bytes,
        "peak_processes": r.peak_processes,
        // Documented lossy: invalid UTF-8 becomes U+FFFD.
        "stdout": String::from_utf8_lossy(&r.stdout),
        "stderr": String::from_utf8_lossy(&r.stderr),
    })
    .to_string()
}

fn human_report(r: &ExitReport) -> String {
    let mut out = String::new();
    if let Some(reason) = &r.kill_reason {
        out.push_str(&format!("cara: run terminated: {}\n", kill_text(reason)));
    }
    out
}

fn human_summary(r: &ExitReport) -> String {
    format!(
        "cara: wall {:?}, cpu {:?}, peak mem {}{}\n",
        r.wall_time,
        r.cpu_time.unwrap_or_default(),
        r.peak_memory_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "?".into()),
        match (&r.exit_code, r.signal) {
            (Some(c), _) => format!(", exit code {c}"),
            (None, Some(s)) => format!(", killed by signal {s}"),
            _ => String::new(),
        }
    )
}

fn kill_text(reason: &KillReason) -> String {
    match reason {
        KillReason::Timeout => "wall-clock limit exceeded".into(),
        KillReason::OutputOverflow => "output limit exceeded".into(),
        KillReason::MemoryLimit => "memory limit exceeded (OOM)".into(),
        KillReason::CpuLimit => "CPU limit exceeded".into(),
        KillReason::Internal(m) => format!("internal error: {m}"),
    }
}

fn human_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    if b >= KIB * KIB && b.is_multiple_of(KIB * KIB) {
        format!("{}MiB", b / (KIB * KIB))
    } else if b >= KIB && b.is_multiple_of(KIB) {
        format!("{}KiB", b / KIB)
    } else {
        format!("{b}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_core::policy::PolicyError;
    use carapace_core::report::KillReason;
    use std::time::Duration;

    fn sample() -> ExitReport {
        ExitReport {
            exit_code: Some(0),
            signal: None,
            kill_reason: None,
            wall_time: Duration::from_millis(5),
            stdout: b"hi".to_vec(),
            stderr: Vec::new(),
            cpu_time: Some(Duration::from_millis(3)),
            peak_memory_bytes: Some(9 * 1024 * 1024),
            peak_processes: Some(2),
        }
    }

    #[test]
    fn json_has_stable_shape() {
        let j = json_report(&sample());
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["exit_code"], 0);
        assert_eq!(v["stdout"], "hi");
        assert_eq!(v["peak_memory_bytes"], 9 * 1024 * 1024);
        assert!(v["kill_reason"].is_null());
    }

    #[test]
    fn json_kill_reasons_are_stable_strings() {
        let mut r = sample();
        r.kill_reason = Some(KillReason::MemoryLimit);
        let v: serde_json::Value = serde_json::from_str(&json_report(&r)).unwrap();
        assert_eq!(v["kill_reason"], "memory_limit");
        r.kill_reason = Some(KillReason::Timeout);
        let v: serde_json::Value = serde_json::from_str(&json_report(&r)).unwrap();
        assert_eq!(v["kill_reason"], "timeout");
    }

    #[test]
    fn human_output_mentions_reason() {
        let mut r = sample();
        r.kill_reason = Some(KillReason::OutputOverflow);
        assert!(human_report(&r).contains("output limit"));
    }

    #[test]
    fn parse_errors_are_policy_errors() {
        assert!(matches!(
            carapace_core::policy::parse_duration("x", "--timeout"),
            Err(PolicyError::Invalid(_))
        ));
    }
}
