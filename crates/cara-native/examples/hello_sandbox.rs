//! Library quick-start: run a program inside the Carapace sandbox.
//!
//! Run with: cargo run -p carapace-native --example hello_sandbox
//! (inside the Linux dev environment — see scripts/check.sh for the
//! cgroup-delegation bridge; `cara doctor` tells you if this host can
//! run the native tier).

use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::Duration;

fn main() -> std::process::ExitCode {
    let backend = NativeBackend::new();

    // The doctor gate: fail closed when this host cannot isolate.
    let env = backend.environment();
    for check in &env.checks {
        println!(
            "{:>5}  {}",
            match check.status {
                carapace_core::Status::Ok => "ok",
                carapace_core::Status::Warn => "warn",
                carapace_core::Status::Fail => "FAIL",
                carapace_core::Status::Info => "info",
            },
            check.name
        );
    }
    if !env.ready() {
        eprintln!("\nThis host cannot run the native sandbox safely (see above).");
        return std::process::ExitCode::FAILURE;
    }

    // Define what to run and how to limit it.
    let spec = SandboxSpec::new("/bin/sh")
        .args([
            "-c",
            "echo hello from inside the sandbox; id -u; df -h /work | tail -1",
        ])
        .env("PATH", "/usr/bin:/bin")
        .timeout(Duration::from_secs(10));

    // Run it. If any isolation step fails, spawn() returns an error and
    // the payload never ran (fail closed).
    let mut handle = match backend.spawn(&spec) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sandbox refused to start: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let report = handle.wait().expect("wait");

    println!("--- stdout ---");
    print!("{}", String::from_utf8_lossy(&report.stdout));
    println!("--- report ---");
    println!("exit code: {:?}", report.exit_code);
    println!("wall time: {:?}", report.wall_time);
    if let Some(cpu) = report.cpu_time {
        println!("cpu time:  {cpu:?}");
    }
    if let Some(mem) = report.peak_memory_bytes {
        println!("peak mem:  {mem} bytes");
    }
    match &report.kill_reason {
        Some(reason) => println!("KILLED: {reason:?}"),
        None => println!("completed normally"),
    }

    if report.exit_code == Some(0) {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
