//! `cara-mcp` binary: the Model Context Protocol server over stdio.
//!
//! One JSON-RPC request per stdin line, one response per stdout line. The
//! response is flushed after every write so interactive clients see it
//! immediately. EOF on stdin ends the server cleanly.

use std::io::BufReader;
use std::process::ExitCode;

fn main() -> ExitCode {
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
