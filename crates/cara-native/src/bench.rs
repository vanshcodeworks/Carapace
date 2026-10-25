//! The honest benchmark (milestone C8, cold path; warm numbers come with
//! the ADR-0005 zygote pool).
//!
//! Everything here measures the REAL spawn→exit path. Numbers are only
//! meaningful with the machine context printed alongside (kernel + OS).

use crate::NativeBackend;
use carapace_core::{Backend, SandboxSpec};
use std::time::{Duration, Instant};

fn percentile(mut v: Vec<Duration>, p: f64) -> Duration {
    v.sort();
    let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[idx]
}

fn bench_one(
    backend: &NativeBackend,
    spec: &SandboxSpec,
    n: usize,
) -> Result<(Duration, Duration), String> {
    let mut walls = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let mut h = backend
            .spawn(spec)
            .map_err(|e| format!("spawn failed: {e}"))?;
        let r = h.wait().map_err(|e| format!("wait failed: {e}"))?;
        walls.push(t0.elapsed());
        if r.exit_code != Some(0) {
            return Err(format!(
                "payload exited {:?} (stderr: {})",
                r.exit_code,
                String::from_utf8_lossy(&r.stderr)
            ));
        }
    }
    let median = percentile(walls.clone(), 0.5);
    let p95 = percentile(walls, 0.95);
    Ok((median, p95))
}

/// Runs the full benchmark and returns the human-readable report (with
/// machine context). `n` runs per case.
pub fn run_benchmark(n: usize) -> Result<String, String> {
    let backend = NativeBackend::new();
    if !backend.environment().ready() {
        return Err("environment not ready for the native sandbox — run `cara doctor`".to_string());
    }
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let os = std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("PRETTY_NAME"))
        .unwrap_or("")
        .trim_start_matches("PRETTY_NAME=")
        .trim()
        .trim_matches('"')
        .to_string();

    let cases: [(&str, SandboxSpec); 3] = [
        (
            "/bin/true",
            SandboxSpec::new("/bin/true").env("PATH", "/usr/bin:/bin"),
        ),
        (
            "/bin/sh -c exit",
            SandboxSpec::new("/bin/sh")
                .args(["-c", "exit 0"])
                .env("PATH", "/usr/bin:/bin"),
        ),
        (
            "/usr/bin/python3 -c pass",
            SandboxSpec::new("/usr/bin/python3")
                .args(["-c", "pass"])
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/work"),
        ),
    ];

    let mut out = format!("carapace cold-start benchmark, n={n} runs each\n");
    out.push_str(&format!("kernel: {kernel}\nos:     {os}\n\n"));
    for (name, spec) in &cases {
        if std::fs::metadata(spec.program.split(' ').next().unwrap_or("/bin/true")).is_err() {
            out.push_str(&format!("{name:<28} SKIPPED (binary missing)\n"));
            continue;
        }
        let (median, p95) = bench_one(&backend, spec, n)?;
        out.push_str(&format!(
            "{name:<28} median {:>8.2?}  p95 {:>8.2?}\n",
            median, p95
        ));
    }
    out.push_str("\nQuote these numbers only with the kernel/OS lines above.\n");
    Ok(out)
}
