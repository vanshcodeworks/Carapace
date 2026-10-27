use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod doctor_ui;
mod exit_codes;
mod run_ui;
mod session_ui;

#[derive(Parser)]
#[command(name = "cara", version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check whether this machine can run the Tier 1 native sandbox.
    Doctor {
        /// Emit machine-readable JSON (stable schema: DoctorReport).
        #[arg(long)]
        json: bool,
    },

    /// Run a command inside the sandbox.
    Run {
        /// Policy file (TOML). Without one, the `strict` preset applies.
        #[arg(long)]
        policy: Option<String>,

        /// Machine-readable JSON report on stdout.
        #[arg(long)]
        json: bool,

        /// Override the wall-clock timeout (e.g. "30s").
        #[arg(long)]
        timeout: Option<String>,

        /// The program and its arguments (after --).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },

    /// Validate or explain a policy file.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },

    /// Measure sandbox cold-start latency (median + p95, machine context
    /// printed alongside — quote numbers only together with it).
    Bench {
        /// Runs per case.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },

    /// Serve the MCP (Model Context Protocol) server on stdio.
    Mcp,

    /// Manage persistent sandbox sessions (persistent /work, no daemon).
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },

    /// Internal: session keeper process. Not a public command.
    #[command(name = "__session-keeper", hide = true)]
    SessionKeeper { spec: String },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate a policy file (exit 0 = valid, 3 = invalid).
    Check {
        file: String,
        #[arg(long)]
        json: bool,
    },
    /// Print what the policy allows in plain English.
    Explain { file: String },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Create a session (prints its id). Detached from this process.
    Start {
        /// Policy file (TOML). Without one, the `strict` preset applies.
        #[arg(long)]
        policy: Option<String>,
        /// Machine-readable metadata on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Run one program inside a session (stdout/stderr are streamed back).
    Exec {
        /// Session id.
        id: String,
        /// Override the per-exec wall-clock timeout (e.g. "30s").
        #[arg(long)]
        timeout: Option<String>,
        /// Machine-readable JSON report on stdout.
        #[arg(long)]
        json: bool,
        /// The program and its arguments (after --).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Upload a host file into the session work dir.
    Put {
        id: String,
        local: String,
        remote: String,
    },
    /// Download a session file to the host.
    Get {
        id: String,
        remote: String,
        local: String,
    },
    /// List a directory inside the session work dir.
    Ls {
        id: String,
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        json: bool,
    },
    /// List sessions known to this user.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Close a session and remove its work dir and cgroup leaf.
    Close { id: String },
    /// Remove dead sessions (never touches a live keeper).
    Prune {
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor { json } => doctor_main(json),
        Cmd::Run {
            policy,
            json,
            timeout,
            argv,
        } => run_ui::run_main(policy.as_deref(), json, timeout.as_deref(), &argv),
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Check { file, json } => policy_check(&file, json),
            PolicyCmd::Explain { file } => policy_explain(&file),
        },
        Cmd::Mcp => mcp_main(),
        Cmd::Session { cmd } => match cmd {
            SessionCmd::Start { policy, json } => session_ui::start_main(policy.as_deref(), json),
            SessionCmd::Exec {
                id,
                timeout,
                json,
                argv,
            } => session_ui::exec_main(&id, timeout.as_deref(), json, &argv),
            SessionCmd::Put { id, local, remote } => session_ui::put_main(&id, &local, &remote),
            SessionCmd::Get { id, remote, local } => session_ui::get_main(&id, &remote, &local),
            SessionCmd::Ls { id, path, json } => session_ui::ls_main(&id, &path, json),
            SessionCmd::List { json } => session_ui::list_main(json),
            SessionCmd::Close { id } => session_ui::close_main(&id),
            SessionCmd::Prune { json } => session_ui::prune_main(json),
        },
        Cmd::SessionKeeper { spec } => {
            carapace_native::session::keeper_main(std::path::Path::new(&spec));
        }
        Cmd::Bench { runs } => match carapace_native::bench::run_benchmark(runs) {
            Ok(report) => {
                print!("{report}");
                ExitCode::from(exit_codes::OK)
            }
            Err(e) => {
                eprintln!("cara bench: {e}");
                ExitCode::from(exit_codes::ENV_NOT_READY)
            }
        },
    }
}

fn mcp_main() -> ExitCode {
    use std::io::BufReader;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut server = carapace_mcp::McpServer::new(BufReader::new(stdin.lock()), stdout.lock());
    match server.serve() {
        Ok(()) => ExitCode::from(exit_codes::OK),
        Err(e) => {
            eprintln!("cara mcp: {e}");
            ExitCode::from(exit_codes::ENV_NOT_READY)
        }
    }
}

fn doctor_main(json: bool) -> ExitCode {
    let report = carapace_native::doctor::run_checks();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report serializes")
        );
    } else {
        print!("{}", doctor_ui::render_human(&report));
    }
    if report.ready() {
        ExitCode::from(exit_codes::OK)
    } else {
        ExitCode::from(exit_codes::ENV_NOT_READY)
    }
}

fn policy_check(file: &str, json: bool) -> ExitCode {
    match carapace_core::Policy::from_file(std::path::Path::new(file)) {
        Ok(p) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "preset_summary": preset_summary(&p),
                    })
                );
            } else {
                println!("{file}: valid. {}", preset_summary(&p));
            }
            ExitCode::from(exit_codes::OK)
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "valid": false, "error": e.to_string() })
                );
            } else {
                eprintln!("{file}: {e}");
            }
            ExitCode::from(exit_codes::INVALID_POLICY)
        }
    }
}

fn policy_explain(file: &str) -> ExitCode {
    match carapace_core::Policy::from_file(std::path::Path::new(file)) {
        Ok(p) => {
            print!("{}", p.explain());
            ExitCode::from(exit_codes::OK)
        }
        Err(e) => {
            eprintln!("{file}: {e}");
            ExitCode::from(exit_codes::INVALID_POLICY)
        }
    }
}

fn preset_summary(p: &carapace_core::Policy) -> String {
    use carapace_core::NetworkMode;
    let net = match p.network {
        NetworkMode::None => "no network",
        NetworkMode::Full => "full network",
        NetworkMode::Allowlist(_) => "allowlisted network (unimplemented)",
    };
    format!("{net}; timeout {:?}", p.limits.timeout)
}
