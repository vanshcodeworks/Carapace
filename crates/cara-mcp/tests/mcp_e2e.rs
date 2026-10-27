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

// ------------------------------------------------------------- sessions

/// A live `cara-mcp` child with request/response plumbing.
struct Server {
    child: Child,
    stdin: std::process::ChildStdin,
    rx: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cara-mcp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the cara-mcp binary");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
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
        Self {
            child,
            stdin,
            rx,
            reader: Some(reader),
        }
    }

    fn send(&mut self, request: &serde_json::Value, what: &str) -> serde_json::Value {
        let mut line = serde_json::to_string(request).expect("request serializes");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("write one request line");
        self.stdin.flush().expect("flush request");
        recv_response(&self.rx, &mut self.child, what)
    }

    fn call(&mut self, id: u64, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let response = self.send(
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }),
            name,
        );
        assert_eq!(response["id"], id, "{response}");
        response
    }

    fn finish(mut self) {
        drop(self.stdin);
        let mut exited = None;
        for _ in 0..100 {
            if let Ok(Some(status)) = self.child.try_wait() {
                exited = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let status = exited.unwrap_or_else(|| {
            let _ = self.child.kill();
            panic!("cara-mcp did not exit after stdin EOF");
        });
        assert!(status.success(), "cara-mcp exited with {status}");
        if let Some(reader) = self.reader.take() {
            reader.join().expect("reader thread");
        }
    }
}

/// Parses a tool result's `content[0].text` as JSON (our tools return JSON
/// text bodies).
fn tool_json(response: &serde_json::Value) -> serde_json::Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool must return text content: {response}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("tool text must be JSON ({e}): {text}"))
}

fn tool_text(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool must return text content: {response}"))
        .to_string()
}

#[test]
fn mcp_sessions_persist_files_and_close() {
    if std::env::var("CARA_STRICT_ENV_TESTS").is_err() {
        eprintln!("skipping: CARA_STRICT_ENV_TESTS is not set (needs the user cgroup slice)");
        return;
    }
    let mut server = Server::start();
    let init = server.send(
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        "initialize",
    );
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05", "{init}");

    // 1. Create a session with a small footprint.
    let created = server.call(
        2,
        "session_create",
        serde_json::json!({"policy": {"memory_mb": 128, "disk_mb": 8, "timeout_ms": 5000}}),
    );
    let created = tool_json(&created);
    let id = created["session_id"]
        .as_str()
        .unwrap_or_else(|| panic!("session_create must return an id: {created}"))
        .to_string();
    assert_eq!(id.len(), 32, "{created}");
    assert_eq!(created["policy"]["network"], "none", "{created}");

    // 2. Write a file in one exec...
    let written = server.call(
        3,
        "session_exec",
        serde_json::json!({"session_id": id, "code": "echo persisted > /work/f; echo made"}),
    );
    let report = tool_json(&written);
    assert_eq!(report["exit_code"], 0, "{report}");
    assert_eq!(report["stdout"], "made\n", "{report}");

    // 3. ...and read it in the next (separate sandbox, same /work).
    let read = server.call(
        4,
        "session_exec",
        serde_json::json!({"session_id": id, "code": "cat /work/f"}),
    );
    let report = tool_json(&read);
    assert_eq!(report["stdout"], "persisted\n", "{report}");

    // 4. Upload + download round-trip (base64 of "uploaded\n").
    let up = server.call(
        5,
        "session_upload",
        serde_json::json!({"session_id": id, "path": "in/u.txt", "content_base64": "dXBsb2FkZWQK"}),
    );
    let up = tool_json(&up);
    assert_eq!(up["size"], 9, "{up}");
    let read = server.call(
        6,
        "session_exec",
        serde_json::json!({"session_id": id, "code": "cat /work/in/u.txt"}),
    );
    assert_eq!(tool_json(&read)["stdout"], "uploaded\n", "{read}");
    let down = server.call(
        7,
        "session_download",
        serde_json::json!({"session_id": id, "path": "in/u.txt"}),
    );
    let down = tool_json(&down);
    assert_eq!(down["size"], 9, "{down}");
    assert_eq!(down["content_base64"], "dXBsb2FkZWQK", "{down}");

    // 5. Listing shows only this server's session.
    let listed = server.call(8, "session_list", serde_json::json!({}));
    let listed = tool_json(&listed);
    let sessions = listed["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 1, "{listed}");
    assert_eq!(sessions[0]["session_id"], id.as_str(), "{listed}");
    assert_eq!(sessions[0]["alive"], true, "{listed}");

    // 6. A session id this server did not create is refused outright.
    let foreign = server.call(
        9,
        "session_exec",
        serde_json::json!({
            "session_id": "deadbeefdeadbeefdeadbeefdeadbeef",
            "code": "true",
        }),
    );
    assert_eq!(foreign["result"]["isError"], true, "{foreign}");

    // 7. Close, then the session is gone and unusable.
    let closed = server.call(10, "session_close", serde_json::json!({"session_id": id}));
    let closed = tool_json(&closed);
    assert_eq!(closed["closed"], true, "{closed}");
    let after = server.call(
        11,
        "session_exec",
        serde_json::json!({"session_id": id, "code": "true"}),
    );
    assert_eq!(after["result"]["isError"], true, "{after}");
    assert!(tool_text(&after).contains("only accepts session ids it created"));

    server.finish();
}
