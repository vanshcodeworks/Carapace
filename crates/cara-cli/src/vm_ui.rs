//! `cara vm`: Tier 3 microVM run. The VM backend fails closed without KVM.

use carapace_core::{Backend, ExitReport, KillReason, Policy};
use std::process::ExitCode;

/// Runs one program in a Tier 3 microVM.
///
/// Wired from `Cmd::Vm { policy, json, argv }` in main.rs. The signature is
/// fixed: `vm_ui::vm_main(policy.as_deref(), json, &argv)`.
pub(crate) fn vm_main(policy_path: Option<&str>, json: bool, argv: &[String]) -> ExitCode {
    // 1. Policy. Strict by default; a supplied file is parsed fail-closed.
    let policy = match policy_path {
        Some(path) => match Policy::from_file(std::path::Path::new(path)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cara: policy {path}: {e}");
                return ExitCode::from(super::exit_codes::INVALID_POLICY);
            }
        },
        None => Policy::strict(),
    };

    // 2. Program sanity: the guest exec path must be absolute.
    let Some(program) = argv.first() else {
        eprintln!("cara vm: no program given");
        return ExitCode::from(super::exit_codes::USAGE);
    };
    if !program.starts_with('/') {
        eprintln!(
            "cara vm: program must be an absolute guest path (got {program:?}); \
             e.g. `cara vm -- /usr/bin/echo hello`"
        );
        return ExitCode::from(super::exit_codes::INVALID_POLICY);
    }

    // 3. Spawn through the microVM backend (KVM gate + setup inside).
    let spec = policy.to_spec(program, &argv[1..]);
    let backend = carapace_vm::VmBackend::new();
    let mut handle = match backend.spawn(&spec) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cara vm: {e}");
            return ExitCode::from(super::exit_codes::ENV_NOT_READY);
        }
    };

    // 4. Wait for the report.
    let report = match handle.wait() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cara vm: supervision error: {e}");
            return ExitCode::from(super::exit_codes::ENV_NOT_READY);
        }
    };

    // 5. Render.
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
        "stdout": String::from_utf8_lossy(&r.stdout),
        "stderr": String::from_utf8_lossy(&r.stderr),
    })
    .to_string()
}

fn human_report(r: &ExitReport) -> String {
    let mut out = String::new();
    if let Some(reason) = &r.kill_reason {
        out.push_str(&format!("cara vm: run terminated: {}\n", kill_text(reason)));
    }
    out
}

fn human_summary(r: &ExitReport) -> String {
    let status = match (&r.kill_reason, r.exit_code) {
        (None, Some(code)) => format!("exit {code}"),
        (Some(reason), _) => kill_text(reason),
        (None, None) => "no status".to_string(),
    };
    format!(
        "cara vm: {status}; wall {} ms; stdout {} bytes; stderr {} bytes",
        r.wall_time.as_millis(),
        r.stdout.len(),
        r.stderr.len()
    )
}

fn kill_text(reason: &KillReason) -> String {
    match reason {
        KillReason::Timeout => "timeout".to_string(),
        KillReason::OutputOverflow => "output overflow".to_string(),
        KillReason::MemoryLimit => "memory limit".to_string(),
        KillReason::CpuLimit => "cpu limit".to_string(),
        KillReason::Internal(m) => format!("internal error: {m}"),
    }
}
