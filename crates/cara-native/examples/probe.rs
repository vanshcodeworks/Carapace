//! Manual probe: run one program through the backend and print the report.
//! Usage: cargo run -p carapace-native --example probe -- /bin/true

use carapace_core::{Backend, SandboxSpec};
use carapace_native::NativeBackend;

fn main() {
    let prog = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/bin/true".into());
    let b = NativeBackend::new();
    let spec = SandboxSpec::new(prog.clone())
        .env("PATH", "/usr/bin:/bin")
        .timeout(std::time::Duration::from_secs(5));
    let t0 = std::time::Instant::now();
    let mut h = match b.spawn(&spec) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("spawn error: {e}");
            std::process::exit(1);
        }
    };
    match h.wait() {
        Ok(r) => {
            println!(
                "prog={prog} exit={:?} signal={:?} reason={:?} wall={:?} (supervised {:?})",
                r.exit_code,
                r.signal,
                r.kill_reason,
                r.wall_time,
                t0.elapsed()
            );
            println!(
                "stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&r.stdout),
                String::from_utf8_lossy(&r.stderr)
            );
        }
        Err(e) => eprintln!("wait error: {e}"),
    }
}
