//! `cara session`: create, use, and close persistent sandbox sessions.

use carapace_core::Policy;
use carapace_native::session::{
    Entry, ExecResult, MAX_TRANSFER_BYTES, SessionClient, SessionError, SessionManager,
    SessionPolicy,
};
use std::io::{Read, Write};
use std::process::ExitCode;

pub(crate) fn start_main(policy_path: Option<&str>, json: bool) -> ExitCode {
    let policy = match policy_path {
        Some(path) => match Policy::from_file(std::path::Path::new(path)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cara session: policy {path}: {e}");
                return ExitCode::from(super::exit_codes::INVALID_POLICY);
            }
        },
        None => Policy::strict(),
    };
    let session_policy = match SessionPolicy::from_policy(&policy) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let manager = match SessionManager::new() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    match manager.start(session_policy, 0) {
        Ok(meta) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&meta).expect("session meta serializes")
                );
            } else {
                println!("{}", meta.id);
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn exec_main(id: &str, timeout: Option<&str>, json: bool, argv: &[String]) -> ExitCode {
    let program = &argv[0];
    if !program.starts_with('/') {
        eprintln!(
            "cara session exec: program must be an absolute path (got {program:?}); \
             e.g. `cara session exec {id} -- /bin/sh -c '...'`"
        );
        return ExitCode::from(super::exit_codes::INVALID_POLICY);
    }
    let timeout_ms = match timeout {
        Some(text) => match carapace_core::policy::parse_duration(text, "--timeout") {
            Ok(d) => Some(d.as_millis() as u64),
            Err(e) => {
                eprintln!("cara session exec: {e}");
                return ExitCode::from(super::exit_codes::INVALID_POLICY);
            }
        },
        None => None,
    };
    let manager = match SessionManager::new() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    let mut client = match manager.connect(id) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match client.exec(program, &argv[1..], timeout_ms) {
        Ok(result) => {
            if json {
                println!("{}", exec_json(id, &result));
            } else {
                let stdout = result.stdout();
                let stderr = result.stderr();
                let mut out = std::io::stdout();
                let _ = out.write_all(&stdout);
                let _ = out.flush();
                if !stderr.is_empty() {
                    let mut err = std::io::stderr();
                    let _ = err.write_all(&stderr);
                    let _ = err.flush();
                }
                eprintln!("{}", exec_summary(&result));
            }
            match (&result.kill_reason, result.exit_code) {
                (None, Some(code)) => ExitCode::from(code as u8),
                _ => ExitCode::from(1),
            }
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn put_main(id: &str, local: &str, remote: &str) -> ExitCode {
    let data = if local == "-" {
        let mut buf = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
            eprintln!("cara session put: stdin: {e}");
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read(local) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("cara session put: {local}: {e}");
                return ExitCode::from(1);
            }
        }
    };
    if data.len() as u64 > MAX_TRANSFER_BYTES {
        eprintln!(
            "cara session put: {local} exceeds the {MAX_TRANSFER_BYTES}-byte session transfer cap"
        );
        return ExitCode::from(super::exit_codes::INVALID_POLICY);
    }
    let mut client = match connect(id) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.put(remote, &data, 0o644) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

pub(crate) fn get_main(id: &str, remote: &str, local: &str) -> ExitCode {
    let mut client = match connect(id) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let data = match client.get(remote) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if local == "-" {
        let mut out = std::io::stdout();
        if let Err(e) = out.write_all(&data) {
            eprintln!("cara session get: stdout: {e}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    match std::fs::File::create(local) {
        Ok(mut file) => match file.write_all(&data) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cara session get: {local}: {e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("cara session get: {local}: {e}");
            ExitCode::from(1)
        }
    }
}

pub(crate) fn ls_main(id: &str, path: &str, json: bool) -> ExitCode {
    let mut client = match connect(id) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.list(path) {
        Ok(entries) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "session_id": id,
                        "path": path,
                        "entries": entries,
                    })
                );
            } else {
                for entry in entries {
                    println!("{}", entry_line(&entry));
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn list_main(json: bool) -> ExitCode {
    let manager = match SessionManager::new() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    match manager.list() {
        Ok(sessions) => {
            if json {
                println!("{}", serde_json::json!({ "sessions": sessions }));
            } else if sessions.is_empty() {
                eprintln!("cara session: no sessions");
            } else {
                for s in sessions {
                    println!(
                        "{}  {:<5}  age {:>8}  keeper {:<8}  net {:<4}  timeout {}ms",
                        s.meta.id,
                        if s.alive { "alive" } else { "dead" },
                        age_text(s.meta.created_at_ms),
                        s.meta.keeper_pid,
                        s.meta.policy.network,
                        s.meta.policy.timeout_ms
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn close_main(id: &str) -> ExitCode {
    let manager = match SessionManager::new() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    match manager.close(id) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

pub(crate) fn prune_main(json: bool) -> ExitCode {
    let manager = match SessionManager::new() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    match manager.prune() {
        Ok(removed) => {
            if json {
                println!("{}", serde_json::json!({ "removed": removed }));
            } else {
                println!("removed {removed} dead session(s)");
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn connect(id: &str) -> Result<SessionClient, ExitCode> {
    let manager = SessionManager::new().map_err(fail)?;
    manager.connect(id).map_err(fail)
}

fn fail(e: SessionError) -> ExitCode {
    eprintln!("cara session: {e}");
    let code = match &e {
        SessionError::Invalid(_) | SessionError::NotFound(_) => super::exit_codes::INVALID_POLICY,
        SessionError::Environment(_) => super::exit_codes::ENV_NOT_READY,
        _ => 1,
    };
    ExitCode::from(code)
}

fn age_text(created_at_ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let secs = now.saturating_sub(created_at_ms) / 1000;
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h{}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d", secs / 86400),
    }
}

fn entry_line(entry: &Entry) -> String {
    let size = entry
        .size
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!("{:<7} {:>10}  {}", entry.kind, size, entry.name)
}

fn exec_json(id: &str, r: &ExecResult) -> String {
    serde_json::json!({
        "session_id": id,
        "exit_code": r.exit_code,
        "signal": r.signal,
        "kill_reason": r.kill_reason,
        "wall_time_ms": r.wall_time_ms,
        "cpu_time_ms": r.cpu_usec.map(|u| u / 1000),
        "peak_memory_bytes": r.peak_memory_bytes,
        "peak_processes": r.peak_processes,
        // Documented lossy: invalid UTF-8 becomes U+FFFD.
        "stdout": String::from_utf8_lossy(&r.stdout()),
        "stderr": String::from_utf8_lossy(&r.stderr()),
    })
    .to_string()
}

fn exec_summary(r: &ExecResult) -> String {
    let status = match (&r.exit_code, r.signal) {
        (Some(c), _) => format!("exit code {c}"),
        (None, Some(s)) => format!("killed by signal {s}"),
        _ => "unknown status".to_string(),
    };
    let reason = r
        .kill_reason
        .as_deref()
        .map(|k| format!(", {k}"))
        .unwrap_or_default();
    format!(
        "cara session: wall {}ms, cpu {}ms, peak mem {}{reason}, {status}",
        r.wall_time_ms,
        r.cpu_usec.map(|u| u / 1000).unwrap_or(0),
        r.peak_memory_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "?".into()),
    )
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
