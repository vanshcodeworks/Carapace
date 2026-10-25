use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod doctor_ui;
mod exit_codes;
mod run_ui;

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
