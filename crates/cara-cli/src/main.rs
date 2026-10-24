use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod doctor_ui;
mod exit_codes;

/// cara — run untrusted code inside a locked-down sandbox.
///
/// Carapace executes arbitrary (often AI-generated) programs with hard
/// limits on CPU, memory, processes, time, filesystem access and network,
/// without Docker or a daemon. It fails closed: if any isolation step
/// cannot be applied, the code does not run.
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor { json } => {
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
    }
}
