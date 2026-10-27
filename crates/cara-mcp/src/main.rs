//! `cara-mcp` binary: the Model Context Protocol server over stdio.
//!
//! One JSON-RPC request per stdin line, one response per stdout line. The
//! response is flushed after every write so interactive clients see it
//! immediately. EOF on stdin ends the server cleanly.

use std::io::BufReader;
use std::process::ExitCode;

fn main() -> ExitCode {
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
