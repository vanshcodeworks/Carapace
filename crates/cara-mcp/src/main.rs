//! `cara-mcp` binary: the Model Context Protocol server over stdio.
//!
//! One JSON-RPC request per stdin line, one response per stdout line. The
//! response is flushed after every write so interactive clients see it
//! immediately. EOF on stdin ends the server cleanly.

use std::io::BufReader;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Simple CLI flags for humans. MCP clients spawn us with no arguments,
    // so these never interfere with the stdio protocol.
    match std::env::args().nth(1).as_deref() {
        Some("-V" | "--version") => {
            println!("cara-mcp {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("-h" | "--help") => {
            println!("cara-mcp - Carapace MCP server (JSON-RPC 2.0 over stdio)");
            println!();
            println!("Usage: cara-mcp");
            println!();
            println!("The server reads one JSON-RPC request per stdin line and writes");
            println!("one response per stdout line. EOF on stdin ends the server.");
            println!();
            println!("Options:");
            println!("  -V, --version  Print version and exit");
            println!("  -h, --help     Print this help and exit");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    // Hidden session keeper entry point (spawned by the session manager).
    if std::env::args().nth(1).as_deref() == Some(carapace_native::session::KEEPER_ARG) {
        carapace_native::session::keeper_main_from_args();
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut server = carapace_mcp::McpServer::new(BufReader::new(stdin.lock()), stdout.lock());
    match server.serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cara-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}
