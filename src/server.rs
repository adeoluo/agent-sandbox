//! JSON Lines over stdio, so agents written in any language can call the sandbox.
//!
//! One request per line, one response per line, in order:
//!
//! ```text
//! -> {"id":1,"op":"check","argv":["ls","-la"]}
//! <- {"id":1,"ok":true,"result":{"allowed":true,"rule":"exec[ls]",...}}
//! -> {"id":2,"op":"run","argv":["cat","notes.txt"]}
//! -> {"id":3,"op":"read_file","path":"notes.txt"}
//! -> {"id":4,"op":"write_file","path":"scratch/out.txt","contents":"hello"}
//! -> {"id":5,"op":"check_read","path":"~/.ssh/id_ed25519"}
//! -> {"id":6,"op":"policy"}
//! ```

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::engine::Request;
use crate::sandbox::{RunOptions, Sandbox};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Op {
    Check {
        #[serde(default)]
        id: Value,
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    CheckRead {
        #[serde(default)]
        id: Value,
        path: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    CheckWrite {
        #[serde(default)]
        id: Value,
        path: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    Run {
        #[serde(default)]
        id: Value,
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<PathBuf>,
        #[serde(default)]
        stdin: Option<String>,
        #[serde(default)]
        dry_run: bool,
    },
    ReadFile {
        #[serde(default)]
        id: Value,
        path: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    WriteFile {
        #[serde(default)]
        id: Value,
        path: String,
        contents: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    Policy {
        #[serde(default)]
        id: Value,
    },
}

/// Handles one request line and returns the response value.
pub fn handle_line(sandbox: &Sandbox, line: &str) -> Value {
    let op: Op = match serde_json::from_str(line) {
        Ok(op) => op,
        Err(e) => {
            let id = serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or(Value::Null);
            return json!({ "id": id, "ok": false, "error": format!("bad request: {e}") });
        }
    };
    let (id, result) = match op {
        Op::Check { id, argv, cwd } => (
            id,
            sandbox
                .check(&Request::Exec { argv, cwd })
                .map(|d| json!(d)),
        ),
        Op::CheckRead { id, path, cwd } => (
            id,
            sandbox
                .check(&Request::Read { path, cwd })
                .map(|d| json!(d)),
        ),
        Op::CheckWrite { id, path, cwd } => (
            id,
            sandbox
                .check(&Request::Write { path, cwd })
                .map(|d| json!(d)),
        ),
        Op::Run {
            id,
            argv,
            cwd,
            stdin,
            dry_run,
        } => {
            let opts = RunOptions {
                cwd,
                stdin,
                dry_run,
            };
            (id, sandbox.run(&argv, &opts).map(|o| json!(o)))
        }
        Op::ReadFile { id, path, cwd } => (
            id,
            sandbox.read_file(&path, cwd.as_deref()).map(|o| json!(o)),
        ),
        Op::WriteFile {
            id,
            path,
            contents,
            cwd,
        } => (
            id,
            sandbox
                .write_file(&path, contents.as_bytes(), cwd.as_deref())
                .map(|o| json!(o)),
        ),
        Op::Policy { id } => {
            let p = sandbox.policy();
            (
                id,
                Ok(json!({
                    "name": p.name(),
                    "policy_hash": p.policy_hash,
                    "workspace": p.workspace,
                    "scratch": p.scratch,
                    "read_roots": p.read_roots,
                    "writable_roots": p.writable_roots,
                    "denied_paths": p.denied_paths,
                    "executables": p.policy.exec.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
                    "network": p.policy.network.mode,
                    "limits": p.policy.limits,
                })),
            )
        }
    };
    match result {
        Ok(value) => json!({ "id": id, "ok": true, "result": value }),
        Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
    }
}

/// Serves requests until EOF. Blank lines are ignored.
pub fn serve<R: BufRead, W: Write>(
    sandbox: &Sandbox,
    reader: R,
    mut writer: W,
) -> std::io::Result<u64> {
    let mut handled = 0;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(sandbox, &line);
        writeln!(writer, "{response}")?;
        writer.flush()?;
        handled += 1;
    }
    Ok(handled)
}
