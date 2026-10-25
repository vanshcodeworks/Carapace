//! End-to-end test: drives the real `cara-mcp` binary over stdio.
//!
//! Environment-gated (sandbox spawns need cgroup delegation): the runner
//! scripts set `CARA_STRICT_ENV_TESTS` inside the user cgroup slice
//! (.wsl/ws-test.sh, scripts/check.sh). Threads + timeouts everywhere so a
//! hang fails the test instead of blocking CI.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Longest wait for one response line from the server.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

fn recv_response(rx: &mpsc::Receiver<String>, child: &mut Child, what: &str) -> serde_json::Value {
    match rx.recv_timeout(RESPONSE_TIMEOUT) {
        Ok(line) => serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("{what}: not valid JSON ({e}): {line}")),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for {what}");
        }
    }
}

#[test]
fn mcp_runs_code_end_to_end() {
    if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
        eprintln!("skipping: CARA_STRICT_ENV_TESTS is not set (needs the user cgroup slice)");
        return;
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_cara-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the cara-mcp binary");

    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");

    // Reader thread: every server line lands on the channel.
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Writer thread: the whole session, then close stdin (EOF ends the server).
    let writer = std::thread::spawn(move || {
        let python_code = concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.connect((\"127.0.0.1\", 59999))\n",
            "print(\"connected\")\n",
        );
        let python_json =
            serde_json::to_string(python_code).expect("python code serializes to a JSON string");
        let lines = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.to_string(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_code","arguments":{"code":"echo mcp-ok","language":"sh"}}}"#.to_string(),
            format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"run_code","arguments":{{"code":{python_json},"language":"python3"}}}}}}"#
            ),
        ];
        for mut line in lines {
            line.push('\n');
            stdin
                .write_all(line.as_bytes())
                .expect("write one request line to cara-mcp");
        }
        stdin.flush().expect("flush requests");
        drop(stdin); // EOF: the server must exit after the last response
    });

    // 1. initialize
    let init = recv_response(&rx, &mut child, "initialize response");
    assert_eq!(init["id"], 1, "{init}");
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05", "{init}");
    assert_eq!(init["result"]["serverInfo"]["name"], "carapace", "{init}");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );

    // 2. run_code sh: echo mcp-ok
    let resp = recv_response(&rx, &mut child, "run_code sh response");
    assert_eq!(resp["id"], 2, "{resp}");
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("run_code must return text content: {resp}"));
    let report: serde_json::Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("run_code text must be a report JSON: {e}: {text}"));
    assert_eq!(report["exit_code"], 0, "{report}");
    assert!(
        report["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("mcp-ok"),
        "{report}"
    );
    assert!(report["kill_reason"].is_null(), "{report}");
    assert!(report["wall_time_ms"].is_number(), "{report}");

    // 3. run_code python3: networking must fail closed (empty network
    //    namespace), so isError or a non-zero exit.
    let resp = recv_response(&rx, &mut child, "run_code python3 response");
    assert_eq!(resp["id"], 3, "{resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("run_code must return text content: {resp}"));
    let report: serde_json::Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("run_code text must be a report JSON: {e}: {text}"));
    assert!(
        resp["result"]["isError"] == true || report["exit_code"] != 0,
        "a network attempt must fail inside the sandbox: {resp}"
    );

    // stdin was closed: the server must exit cleanly on EOF.
    writer.join().expect("writer thread");
    let mut exited = None;
    for _ in 0..100 {
        if let Ok(Some(status)) = child.try_wait() {
            exited = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = exited.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("cara-mcp did not exit after stdin EOF");
    });
    assert!(status.success(), "cara-mcp exited with {status}");
    reader.join().expect("reader thread");
}
