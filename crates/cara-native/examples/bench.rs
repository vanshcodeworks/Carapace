//! Honest cold/warm start benchmark (milestone C8).
//!
//! Usage: cargo run -p carapace-native --release --example bench
//! Reports median + p95 over N runs of full sandbox spawn→exit for /bin/true
//! and /bin/sh, plus interpreter startup for python3. Machine specs are
//! printed from docs/agent/ENV.md's reference environment probe (uname +
//! os-release). NEVER quote these numbers without the machine context.

use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;
use std::time::{Duration, Instant};

fn percentile(mut v: Vec<Duration>, p: f64) -> Duration {
    v.sort();
    let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[idx]
}

fn bench(name: &str, spec: &SandboxSpec, n: usize) -> Option<(Duration, Duration, f64)> {
    let backend = NativeBackend::new();
    if !backend.environment().ready() {
        eprintln!("environment not ready; skipping {name}");
        return None;
    }
    let mut walls = Vec::with_capacity(n);
    let mut cpu_ratios = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let mut h = backend.spawn(spec).expect("spawn");
        let r = h.wait().expect("wait");
        walls.push(t0.elapsed());
        if let Some(cpu) = r.cpu_time {
            cpu_ratios.push(cpu.as_secs_f64() / r.wall_time.as_secs_f64().max(1e-9));
        }
        if r.exit_code != Some(0) {
            eprintln!(
                "WARNING: {name} exited {:?} (stderr: {})",
                r.exit_code,
                String::from_utf8_lossy(&r.stderr)
            );
        }
    }
    let median = percentile(walls.clone(), 0.5);
    let p95 = percentile(walls, 0.95);
    let cpu_ratio = cpu_ratios.last().copied().unwrap_or(f64::NAN);
    Some((median, p95, cpu_ratio))
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100);
    println!("carapace cold-start benchmark, n={n} runs each");
    println!(
        "kernel: {}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    println!(
        "os:     {}",
        std::fs::read_to_string("/etc/os-release")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("PRETTY_NAME"))
            .unwrap_or("")
            .trim_start_matches("PRETTY_NAME=")
            .trim()
            .trim_matches('"')
    );
    println!();

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

    let mut results = Vec::new();
    for (name, spec) in &cases {
        if let Some((median, p95, cpu)) = bench(name, spec, n) {
            println!(
                "{name:<28} median {:>8.2?}  p95 {:>8.2?}  cpu/wall {:.2}",
                median, p95, cpu
            );
            results.push((name, median, p95));
        }
    }
    if results.is_empty() {
        std::process::exit(1);
    }
    println!("\nQuote these numbers only with the kernel/OS lines above.");
}
