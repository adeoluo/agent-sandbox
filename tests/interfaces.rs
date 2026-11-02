//! The CLI binary and the JSON Lines stdio protocol.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use agent_sandbox::server::{handle_line, serve};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-sandbox");

struct Cli {
    fx: common::Fixture,
    policy: std::path::PathBuf,
    audit: std::path::PathBuf,
}

fn cli(extra: &str) -> Cli {
    let fx = common::fixture(extra);
    let policy = fx.workspace.join("policy.toml");
    std::fs::write(&policy, common::policy_text(extra)).unwrap();
    let audit = fx.scratch().join("audit.jsonl");
    Cli { fx, policy, audit }
}

impl Cli {
    fn cmd(&self, sub: &str) -> Command {
        let mut c = Command::new(BIN);
        c.arg(sub)
            .arg("--policy")
            .arg(&self.policy)
            .arg("--workspace")
            .arg(&self.fx.workspace)
            .arg("--audit")
            .arg(&self.audit)
            .env("HOME", &self.fx.home);
        c
    }
}

#[test]
fn run_passes_output_and_exit_code_through() {
    let c = cli("[[exec]]\nname = \"sh\"\n");
    let out = c.cmd("run").args(["--", "echo", "hello"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello\n");
    let out = c
        .cmd("run")
        .args(["--", "sh", "-c", "echo err >&2; exit 3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
}

#[test]
fn run_denied_exits_126_with_reason() {
    let c = cli("");
    let out = c
        .cmd("run")
        .args(["--", "curl", "https://example.com"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&out.stderr).contains("network.deny"));
}

#[test]
fn run_timeout_and_truncation_messages() {
    let c = cli(
        "[[exec]]\nname = \"sleep\"\n\n[[exec]]\nname = \"yes\"\n\n[limits]\ntimeout_ms = 200\nmax_output_bytes = 16\n",
    );
    let out = c.cmd("run").args(["--", "sleep", "10"]).output().unwrap();
    assert_eq!(out.status.code(), Some(124));
    assert!(String::from_utf8_lossy(&out.stderr).contains("timeout"));
    let out = c.cmd("run").args(["--", "yes"]).output().unwrap();
    assert_eq!(out.stdout.len(), 16);
    assert!(String::from_utf8_lossy(&out.stderr).contains("truncated"));
}

#[test]
fn run_json_and_dry_run() {
    let c = cli("");
    let out = c
        .cmd("run")
        .args(["--json", "--dry-run", "--", "touch", "scratch/x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"]["allowed"], true);
    assert_eq!(v["executed"], false);
    assert!(!c.fx.scratch().join("x").exists());
    let out = c
        .cmd("run")
        .args(["--dry-run", "--", "ls"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("dry run"));
}

#[test]
fn check_variants() {
    let c = cli("");
    let out = c.cmd("check").args(["--", "ls"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ALLOW exec[ls]"));
    let out = c
        .cmd("check")
        .args(["--read", "~/.ssh/id_ed25519"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("DENY filesystem.denied_paths"));
    let out = c
        .cmd("check")
        .args(["--json", "--write", "scratch/a"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["allowed"], true);
    let out = c.cmd("check").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn audit_verify_detects_tampering() {
    let c = cli("");
    for argv in [["ls"], ["pwd"]] {
        c.cmd("check").arg("--").args(argv).output().unwrap();
    }
    let out = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&c.audit)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("OK 2 records"));
    let json = Command::new(BIN)
        .args(["audit", "verify", "--json"])
        .arg(&c.audit)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    let head = report["head_hash"].as_str().unwrap().to_string();
    let ok = Command::new(BIN)
        .args(["audit", "verify", "--expect-head", &head])
        .arg(&c.audit)
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));

    let text = std::fs::read_to_string(&c.audit)
        .unwrap()
        .replace("\"ls\"", "\"rm\"");
    std::fs::write(&c.audit, text).unwrap();
    let out = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&c.audit)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("TAMPERED at line 1"));
}

#[test]
fn inspect_reports_enforcement() {
    let c = cli("");
    let out = c.cmd("inspect").output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["name"], "test");
    assert!(v["enforcement"]["backend"].is_string());
    assert!(v["executables"].as_array().unwrap().len() >= 5);
}

#[test]
fn bad_policy_is_a_usage_error() {
    let out = Command::new(BIN)
        .args(["check", "--policy", "/nonexistent.toml", "--", "ls"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("loading policy"));
}

#[test]
fn serve_over_stdio_from_another_process() {
    let c = cli("");
    let mut child = c
        .cmd("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = concat!(
        r#"{"id":1,"op":"check","argv":["ls"]}"#,
        "\n",
        r#"{"id":2,"op":"run","argv":["echo","hi"]}"#,
        "\n",
        "\n",
        r#"{"id":3,"op":"check_read","path":"~/.ssh/id_ed25519"}"#,
        "\n",
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["result"]["allowed"], true);
    assert_eq!(lines[1]["result"]["stdout"], "hi\n");
    assert_eq!(lines[2]["result"]["allowed"], false);
    assert_eq!(lines[2]["id"], 3);
}

#[test]
fn protocol_operations() {
    let fx = common::fixture("");
    let call = |line: &str| -> Value { handle_line(&fx.sandbox, line) };
    let r = call(r#"{"id":"a","op":"check","argv":["rm","-rf","/"]}"#);
    assert_eq!(r["ok"], true);
    assert_eq!(r["result"]["allowed"], false);
    assert_eq!(r["id"], "a");
    let r = call(r#"{"id":2,"op":"check_write","path":"scratch/x"}"#);
    assert_eq!(r["result"]["allowed"], true);
    let r = call(r#"{"id":3,"op":"write_file","path":"scratch/note.txt","contents":"hello"}"#);
    assert_eq!(r["result"]["decision"]["allowed"], true);
    assert_eq!(r["result"]["bytes"], 5);
    let r = call(r#"{"id":4,"op":"read_file","path":"scratch/note.txt"}"#);
    assert_eq!(r["result"]["content"], "hello");
    let r = call(r#"{"id":5,"op":"run","argv":["cat"],"stdin":"piped"}"#);
    assert_eq!(r["result"]["stdout"], "piped");
    let r = call(r#"{"id":6,"op":"run","argv":["ls"],"dry_run":true}"#);
    assert_eq!(r["result"]["executed"], false);
    let r = call(r#"{"id":7,"op":"policy"}"#);
    assert_eq!(r["result"]["name"], "test");
    assert_eq!(r["result"]["network"], "deny");
    let r = call(r#"{"id":8,"op":"explode"}"#);
    assert_eq!(r["ok"], false);
    assert_eq!(r["id"], 8);
    assert!(r["error"].as_str().unwrap().contains("bad request"));
    let r = call("not json");
    assert_eq!(r["ok"], false);
    assert_eq!(r["id"], Value::Null);
    let r = call(r#"{"id":9,"op":"read_file","path":"scratch/missing.txt"}"#);
    assert_eq!(r["ok"], false, "I/O errors are reported, not panicked on");
}

#[test]
fn serve_counts_requests() {
    let fx = common::fixture("");
    let input = b"{\"op\":\"check\",\"argv\":[\"ls\"]}\n\n{\"op\":\"policy\"}\n";
    let mut output = Vec::new();
    let n = serve(&fx.sandbox, &input[..], &mut output).unwrap();
    assert_eq!(n, 2);
    assert_eq!(String::from_utf8_lossy(&output).lines().count(), 2);
}
