//! C9 parity tests: the Wasm tier enforces the same policy semantics as
//! the native tier. Modules are inline WAT (assembled via the `wat` crate
//! at test time — no external toolchain).

use carapace_core::report::KillReason;
use carapace_core::{Backend, SandboxSpec};
use carapace_wasm::WasmBackend;
use std::time::Duration;

fn backend() -> WasmBackend {
    WasmBackend::new()
}

/// Writes a module to a unique temp file (parallel tests must not share
/// paths — learned when concurrent writes produced truncated parses).
fn write_module(wat: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cara-wat-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("mod.wat");
    std::fs::write(&p, wat).unwrap();
    p
}

fn run(spec: SandboxSpec) -> carapace_core::ExitReport {
    let mut h = backend().spawn(&spec).expect("spawn");
    h.wait().expect("wait")
}

const HELLO: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "hello wasm\n")
  (func (export "_start")
    (i32.store (i32.const 16) (i32.const 64))
    (i32.store (i32.const 20) (i32.const 11))
    (drop (call $fd_write
      (i32.const 1)   ;; stdout
      (i32.const 16)  ;; iov base
      (i32.const 1)   ;; iov count
      (i32.const 0))) ;; ignored retptr
  )
)
"#;

const EXIT_N: &str = r#"
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  ;; the preview1 shim requires an exported memory
  (memory (export "memory") 1)
  (func (export "_start") (call $proc_exit (i32.const 7)))
)
"#;

const INFINITE_LOOP: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (loop br 0))
)
"#;

const MEMORY_GROWER: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $grow
      (drop (memory.grow (i32.const 16)))  ;; +1 page per iteration
      ;; store past the old end: traps OOB as soon as the limiter
      ;; denies a grow (guest "forgets" to check for -1)
      (i32.store (i32.mul (memory.size) (i32.const 65536)) (i32.const 1))
      (br $grow))
  )
)
"#;

const FLOODER: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "0123456789abcdef0123456789abcdef")
  (func (export "_start")
    ;; iov[0] = { base = 64, len = 32 } at address 16 (no overlap).
    (i32.store (i32.const 16) (i32.const 64))
    (i32.store (i32.const 20) (i32.const 32))
    (loop $flood
      (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 0)))
      (br $flood))
  )
)
"#;

#[test]
fn wasm_hello_world_captures_output() {
    let p = write_module(HELLO);
    let r = run(SandboxSpec::new(p.to_str().unwrap()).timeout(Duration::from_secs(15)));
    assert_eq!(
        r.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&r.stdout), "hello wasm\n");
    assert_eq!(r.kill_reason, None);
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_exit_code_propagates() {
    let p = write_module(EXIT_N);
    let r = run(SandboxSpec::new(p.to_str().unwrap()).timeout(Duration::from_secs(15)));
    assert_eq!(r.exit_code, Some(7));
    assert_eq!(r.kill_reason, None);
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_infinite_loop_hits_cpu_limit() {
    let p = write_module(INFINITE_LOOP);
    let mut spec = SandboxSpec::new(p.to_str().unwrap())
        .timeout(Duration::from_secs(30))
        .max_output(4096);
    // Tiny CPU budget: fuel (2e7 per percent-second * 1% * 30s = 6e8)
    // exhausts well before the 30s wall clock, so CpuLimit binds.
    spec.limits.cpu_percent = 1;
    let r = run(spec);
    assert_eq!(
        r.kill_reason,
        Some(KillReason::CpuLimit),
        "fuel must run out first (fuel=2e9/s vs loop); got {r:?}"
    );
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_wall_timeout_beats_huge_fuel() {
    let p = write_module(INFINITE_LOOP);
    let mut spec = SandboxSpec::new(p.to_str().unwrap()).timeout(Duration::from_millis(400));
    // Huge fuel so the wall clock is the binding constraint.
    spec.limits.cpu_percent = 10_000;
    let r = run(spec);
    assert_eq!(
        r.kill_reason,
        Some(KillReason::Timeout),
        "epoch interruption must kill at the wall deadline: {r:?}"
    );
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_memory_limiter_kills_grower() {
    let p = write_module(MEMORY_GROWER);
    let mut spec = SandboxSpec::new(p.to_str().unwrap()).timeout(Duration::from_secs(20));
    spec.limits.memory_bytes = 8 * 1024 * 1024; // 8 MiB => ~128 pages
    let r = run(spec);
    assert_eq!(
        r.kill_reason,
        Some(KillReason::MemoryLimit),
        "store limiter must stop the grower: {r:?}"
    );
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_output_flood_reported_and_capped() {
    let p = write_module(FLOODER);
    let r = run(SandboxSpec::new(p.to_str().unwrap())
        .timeout(Duration::from_secs(60))
        .max_output(64 * 1024));
    // The flooder fills the 8 MiB WASI pipe (dropped writes), then keeps
    // running until SOME bound kills it (fuel, wall clock — whichever is
    // binding). Hard invariants: termination + capped capture.
    assert!(
        r.stdout.len() <= 64 * 1024,
        "output must be capped: {}",
        r.stdout.len()
    );
    assert!(
        r.kill_reason.is_some(),
        "a flooder must be killed by some limit: {r:?}"
    );
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wasm_rejects_relative_module_paths() {
    let err = match backend().spawn(&SandboxSpec::new("mod.wat")) {
        Err(e) => e,
        Ok(_) => panic!("relative module path must fail"),
    };
    assert!(matches!(err, carapace_core::BackendError::Setup(_)));
}

#[test]
fn wasm_rejects_nonexistent_modules() {
    let err = match backend().spawn(&SandboxSpec::new("/nonexistent/mod.wat")) {
        Err(e) => e,
        Ok(_) => panic!("missing module must fail"),
    };
    assert!(matches!(err, carapace_core::BackendError::Setup(_)));
}

/// Parity with Tier 1: the same kill-reason JSON strings.
#[test]
fn wasm_kill_reasons_match_native_strings() {
    let p = write_module(INFINITE_LOOP);
    let mut spec = SandboxSpec::new(p.to_str().unwrap())
        .timeout(Duration::from_secs(30))
        .max_output(4096);
    spec.limits.cpu_percent = 1;
    let r = run(spec);
    let reason = format!("{:?}", r.kill_reason);
    assert!(reason.contains("CpuLimit"), "{reason}");
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}
