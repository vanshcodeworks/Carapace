//! Tier 2 backend: Wasmtime with fuel metering (CPU), epoch interruption
//! (wall time), a store memory limiter, and WASI capability grants.
//!
//! Isolation model (threat-model §3): the guest cannot issue host syscalls
//! at all — it sees only the WASI functions the host explicitly provides.
//! Grants per run: stdout/stderr = capacity-bounded memory pipes, args/env
//! from the spec (allowlist), ONE fresh scratch directory preopened at
//! /work, no stdin, no network (WASI sockets are not provided), no other
//! filesystem access.

use carapace_core::report::{ExitReport, KillReason};
use carapace_core::spec::SandboxSpec;
use carapace_core::{Backend, BackendError, SandboxHandle};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Module, Store};

/// Fuel units per CPU-percent-second of the policy budget. Documented,
/// deliberately round: fuel is a deterministic proxy for CPU work, not a
/// wall-clock measure (epoch interruption covers wall time).
const FUEL_PER_CPU_PERCENT_SECOND: u64 = 2_000_000_000 / 100;

/// Byte capacity of the WASI stdout/stderr memory pipes. When a stream
/// fills, further writes are dropped (WASI write still "succeeds") and the
/// run is reported as OutputOverflow.
const WASM_STREAM_CAP: usize = 8 * 1024 * 1024;

/// Store state: WASI(p1) + memory limits. `add_to_linker_sync` for the
/// preview1 shim requires `&mut WasiP1Ctx` from the state, hence the
/// explicit accessor in the linker closure.
struct WasmState {
    wasi: wasmtime_wasi::p1::WasiP1Ctx,
    limits: wasmtime::StoreLimits,
}

/// The Wasm tier backend.
#[derive(Debug, Clone, Default)]
pub struct WasmBackend;

impl WasmBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for WasmBackend {
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError> {
        // The "program" is a Wasm (or Wat) module path — absolute, existing.
        if !spec.program.starts_with('/') {
            return Err(BackendError::Setup(format!(
                "wasm module path must be absolute (got {:?})",
                spec.program
            )));
        }
        let bytes = std::fs::read(&spec.program)
            .map_err(|e| BackendError::Setup(format!("read module: {e}")))?;
        let module_bytes: Vec<u8> = if bytes.starts_with(b"\0asm") {
            bytes
        } else {
            // Wat text form: assemble it (wat is a wasmtime dependency).
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| BackendError::Setup("module is binary-like but not wasm".into()))?;
            wat::parse_str(text).map_err(|e| BackendError::Setup(format!("not wasm/wat: {e}")))?
        };

        // Engine: fuel for CPU, epochs for wall time.
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).map_err(|e| BackendError::Setup(format!("engine: {e}")))?;
        let module = Module::from_binary(&engine, &module_bytes)
            .map_err(|e| BackendError::Setup(format!("compile module: {e}")))?;

        // Scratch dir: ONE fresh directory (mkdtemp), preopened at /work,
        // removed when the handle drops. Wasmtime has no filesystem quota —
        // the scratch byte cap is TODO(wasm-tier), documented honestly.
        let scratch = mk_scratch_dir().map_err(|e| BackendError::Setup(format!("scratch: {e}")))?;

        // WASI context: capped capture pipes, allowlist args/env, scratch
        // preopen. No stdin, no sockets, nothing else.
        let stdout = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(WASM_STREAM_CAP);
        let stderr = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(WASM_STREAM_CAP);
        let args: Vec<String> = std::iter::once(spec.program.clone())
            .chain(spec.args.iter().cloned())
            .collect();
        let envs: Vec<(String, String)> = spec
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();
        wasi.stdout(stdout.clone())
            .stderr(stderr.clone())
            .args(&args)
            .envs(&envs)
            .preopened_dir(scratch.path(), "/work", wasmtime_wasi::FsPerms::ReadWrite)
            .map_err(|e| BackendError::Setup(format!("preopen scratch: {e}")))?;
        // p1 adapter around the preview2 ctx (built once, per run).
        let wasi_p1 = wasi.build_p1();

        // Fuel budget: cpu_percent applied to the wall-time seconds.
        let fuel = FUEL_PER_CPU_PERCENT_SECOND
            .saturating_mul(u64::from(spec.limits.cpu_percent.max(1)))
            .saturating_mul(spec.limits.timeout.as_secs().max(1));
        let mem_bytes = spec.limits.memory_bytes.min(i64::MAX as u64) as usize;

        // The run happens on a worker thread; wait() joins it.
        let engine_t = engine.clone();
        let timeout = spec.limits.timeout;
        let max_output = spec.limits.max_output_bytes;
        let guard = ScratchGuard {
            path: scratch.into_path(),
        };

        let worker = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || -> ExitReport {
                let start = Instant::now();
                let mut linker: wasmtime::Linker<WasmState> = wasmtime::Linker::new(&engine_t);
                if let Err(e) = wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s| &mut s.wasi)
                {
                    return internal(format!("linker: {e}"), start);
                }
                let mut store = Store::new(
                    &engine_t,
                    WasmState {
                        wasi: wasi_p1,
                        limits: wasmtime::StoreLimitsBuilder::new()
                            .memory_size(mem_bytes)
                            .memories(1)
                            .tables(4)
                            .build(),
                    },
                );
                store.limiter(|s| &mut s.limits);
                if let Err(e) = store.set_fuel(fuel) {
                    return internal(format!("fuel: {e}"), start);
                }
                // Wall clock: epoch deadline; ticker advances the epoch at
                // the deadline (kill from another thread = external kill).
                let ticker = {
                    let e = engine_t.clone();
                    std::thread::spawn(move || {
                        let deadline = Instant::now() + timeout;
                        loop {
                            let now = Instant::now();
                            if now >= deadline {
                                e.increment_epoch();
                                return;
                            }
                            std::thread::sleep(std::cmp::min(
                                Duration::from_millis(10),
                                deadline - now,
                            ));
                        }
                    })
                };
                store.set_epoch_deadline(1);

                let run = (|| -> Result<i32, wasmtime::Error> {
                    let instance = linker.instantiate(&mut store, &module)?;
                    let start_fn = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
                    match start_fn.call(&mut store, ()) {
                        Ok(()) => Ok(0),
                        Err(e) => {
                            // proc_exit surfaces anywhere in the anyhow
                            // chain; root_cause reaches it.
                            let exit = e
                                .chain()
                                .find_map(|c| c.downcast_ref::<wasmtime_wasi::I32Exit>())
                                .map(|x| x.0);
                            match exit {
                                Some(code) => Ok(code),
                                None => Err(e),
                            }
                        }
                    }
                })();

                // Do NOT join the ticker: it exits at the deadline and the
                // run may finish much earlier (joining here pinned every
                // report to the full timeout). Detach; a late increment is
                // harmless with no store alive.
                drop(ticker);
                let wall = start.elapsed();
                // Trap classification by STATE, not message strings:
                // fuel exhausted -> CpuLimit; fuel remaining but the wall
                // deadline passed -> Timeout. (wasmtime 50 has no public
                // Trap enum; messages alone are ambiguous.)
                let fuel_left = store.get_fuel().ok();
                let wall_deadline_hit = wall + Duration::from_millis(50) >= timeout;

                // Capture + overflow: MemoryOutputPipe drops writes past its
                // capacity, so full-to-capacity marks overflow.
                let stdout_full = stdout.contents().len() >= WASM_STREAM_CAP;
                let stderr_full = stderr.contents().len() >= WASM_STREAM_CAP;
                let overflow = stdout_full || stderr_full;

                let mut kill_reason = None;
                match &run {
                    Ok(_) => {
                        if overflow {
                            kill_reason = Some(KillReason::OutputOverflow);
                        }
                    }
                    Err(e) => {
                        if std::env::var("CARA_WASM_DEBUG").is_ok() {
                            eprintln!("cara-wasm: trap chain:");
                            for (i, c) in e.chain().enumerate() {
                                eprintln!("  [{i}] {}", c);
                            }
                        }
                        // The top-level error is just the wasm backtrace;
                        // the real cause (trap kind) lives in the chain.
                        let msg = e
                            .chain()
                            .map(|c| c.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase();
                        kill_reason = Some(if msg.contains("memory") && msg.contains("limit") {
                            KillReason::MemoryLimit
                        } else if msg.contains("out of bounds") {
                            // Store/load beyond memory.size: with a
                            // grow-checking guest this is a guest bug;
                            // with a greedy guest it is the memory cap
                            // manifesting (grow denied -> OOB).
                            KillReason::MemoryLimit
                        } else if fuel_left == Some(0) {
                            KillReason::CpuLimit
                        } else if wall_deadline_hit {
                            KillReason::Timeout
                        } else if overflow {
                            KillReason::OutputOverflow
                        } else {
                            KillReason::Internal(short_msg(e))
                        });
                    }
                }

                let mut out = stdout.contents().to_vec();
                out.truncate(max_output);
                let mut err = stderr.contents().to_vec();
                err.truncate(max_output);

                ExitReport {
                    exit_code: match (&run, &kill_reason) {
                        (Ok(c), None) | (Ok(c), Some(KillReason::OutputOverflow)) => Some(*c),
                        _ => None,
                    },
                    signal: None,
                    kill_reason,
                    wall_time: wall,
                    stdout: out,
                    stderr: err,
                    cpu_time: None,          // TODO(wasm-tier): fuel→time estimate
                    peak_memory_bytes: None, // TODO(wasm-tier): store usage
                    peak_processes: None,
                }
            })
            .map_err(|e| BackendError::Setup(format!("worker thread: {e}")))?;

        Ok(Box::new(WasmHandle {
            worker: Mutex::new(Some(worker)),
            _guard: guard,
        }))
    }
}

fn internal(msg: String, start: Instant) -> ExitReport {
    ExitReport {
        exit_code: None,
        signal: None,
        kill_reason: Some(KillReason::Internal(msg)),
        wall_time: start.elapsed(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        cpu_time: None,
        peak_memory_bytes: None,
        peak_processes: None,
    }
}

fn short_msg(e: &wasmtime::Error) -> String {
    let mut s = e.to_string();
    if s.len() > 200 {
        s.truncate(200);
    }
    s
}

fn mk_scratch_dir() -> std::io::Result<ScratchDir> {
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let mut tmpl = format!("{}/cara-wasm.XXXXXX\0", base).into_bytes();
    let p = unsafe {
        // SAFETY: mkdtemp(3) with a mutable NUL-terminated template of the
        // documented form; returns NULL on failure.
        libc::mkdtemp(tmpl.as_mut_ptr().cast::<libc::c_char>())
    };
    if p.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    tmpl.truncate(tmpl.len() - 1);
    let path = std::path::PathBuf::from(
        String::from_utf8(tmpl).map_err(|_| std::io::Error::other("unreachable NUL"))?,
    );
    Ok(ScratchDir { path })
}

struct ScratchDir {
    path: std::path::PathBuf,
}

impl ScratchDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
    fn into_path(self) -> std::path::PathBuf {
        self.path
    }
}

/// Removes the run's scratch dir when the handle drops.
struct ScratchGuard {
    path: std::path::PathBuf,
}
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct WasmHandle {
    worker: Mutex<Option<std::thread::JoinHandle<ExitReport>>>,
    /// Keeps the scratch dir alive for the run's duration; removes it after.
    _guard: ScratchGuard,
}

impl SandboxHandle for WasmHandle {
    fn wait(&mut self) -> Result<ExitReport, BackendError> {
        let worker = self
            .worker
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| BackendError::Supervision("wait called twice".into()))?;
        worker
            .join()
            .map_err(|e| BackendError::Supervision(format!("worker panicked: {e:?}")))
    }

    fn kill(&mut self, _reason: KillReason) {
        // The run is bounded by fuel (CPU) and the epoch deadline (wall);
        // both already guarantee termination. An explicit external kill
        // hook (engine-shared epoch bump) lands with engine sharing.
        // TODO(wasm-tier): share one Engine per backend to enable kill().
    }
}
