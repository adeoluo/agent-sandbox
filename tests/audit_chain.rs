//! Hash-chain integrity and tamper detection for the audit log.

mod common;

use std::path::Path;

use agent_sandbox::audit::{AuditRecord, GENESIS_HASH, write_canonical};
use agent_sandbox::{AuditLog, Request, verify};
use serde_json::{Value, json};

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

fn sample_log(dir: &Path, n: u64) -> std::path::PathBuf {
    let path = dir.join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for i in 0..n {
        log.append(json!({ "type": "test", "i": i, "argv": ["rm", "-rf", format!("file{i}")] }))
            .unwrap();
    }
    path
}

#[test]
fn intact_chain_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let report = verify(&path, None).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.records, 5);
    let recs: Vec<AuditRecord> = lines(&path)
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs[0].prev_hash, GENESIS_HASH);
    for pair in recs.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
        assert_eq!(pair[1].seq, pair[0].seq + 1);
    }
    assert_eq!(report.head_hash, recs[4].hash);
    assert!(verify(&path, Some(&recs[4].hash)).unwrap().ok);
}

#[test]
fn empty_log_verifies_to_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/dir/audit.jsonl");
    let log = AuditLog::open(&path).unwrap();
    assert_eq!(log.path(), path);
    let report = verify(&path, None).unwrap();
    assert!(report.ok);
    assert_eq!(report.records, 0);
    assert_eq!(report.head_hash, GENESIS_HASH);
}

#[test]
fn modified_event_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let mut l = lines(&path);
    l[2] = l[2].replace("file2", "file9");
    write_lines(&path, &l);
    let report = verify(&path, None).unwrap();
    assert!(!report.ok);
    assert_eq!(report.line, Some(3));
    assert_eq!(report.records, 2);
    assert!(report.error.unwrap().contains("hash does not match"));
}

#[test]
fn recomputed_hash_breaks_the_next_link() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let mut l = lines(&path);
    let mut rec: AuditRecord = serde_json::from_str(&l[1]).unwrap();
    rec.event["i"] = json!(99);
    rec.hash = AuditRecord::compute_hash(rec.seq, rec.ts_ms, &rec.prev_hash, &rec.event);
    l[1] = serde_json::to_string(&rec).unwrap();
    write_lines(&path, &l);
    let report = verify(&path, None).unwrap();
    assert!(!report.ok);
    assert_eq!(report.line, Some(3));
    assert!(report.error.unwrap().contains("prev_hash"));
}

#[test]
fn deleted_record_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let mut l = lines(&path);
    l.remove(1);
    write_lines(&path, &l);
    let report = verify(&path, None).unwrap();
    assert!(!report.ok);
    assert_eq!(report.line, Some(2));
    assert!(report.error.unwrap().contains("seq"));
}

#[test]
fn reordered_records_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let mut l = lines(&path);
    l.swap(2, 3);
    write_lines(&path, &l);
    assert!(!verify(&path, None).unwrap().ok);
}

#[test]
fn inserted_and_malformed_records_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 3);
    let mut l = lines(&path);
    l.insert(1, "not json".into());
    write_lines(&path, &l);
    let report = verify(&path, None).unwrap();
    assert!(!report.ok);
    assert!(report.error.unwrap().contains("malformed"));
}

#[test]
fn truncation_is_detected_with_an_expected_head() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 5);
    let head = verify(&path, None).unwrap().head_hash;
    let mut l = lines(&path);
    l.truncate(3);
    write_lines(&path, &l);
    assert!(
        verify(&path, None).unwrap().ok,
        "a truncated chain is still internally valid"
    );
    let report = verify(&path, Some(&head)).unwrap();
    assert!(!report.ok);
    assert!(report.error.unwrap().contains("truncated"));
}

#[test]
fn appends_continue_the_chain_across_reopen_and_threads() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path(), 2);
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut log = AuditLog::open(&path).unwrap();
                for i in 0..25 {
                    log.append(json!({ "thread": t, "i": i })).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let report = verify(&path, None).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.records, 102);
}

#[test]
fn canonical_encoding_sorts_keys() {
    let a: Value = serde_json::from_str(r#"{"b":1,"a":{"d":[1,{"z":0,"y":1}],"c":null}}"#).unwrap();
    let mut out = String::new();
    write_canonical(&a, &mut out);
    assert_eq!(out, r#"{"a":{"c":null,"d":[1,{"y":1,"z":0}]},"b":1}"#);
}

#[test]
fn sandbox_writes_every_decision() {
    let fx = common::fixture("");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let sandbox = agent_sandbox::Sandbox::new(fx.sandbox.policy().clone())
        .with_audit(AuditLog::open(&path).unwrap());
    sandbox
        .check(&Request::Exec {
            argv: common::argv_of(&["curl", "x"]),
            cwd: None,
        })
        .unwrap();
    sandbox
        .run(&common::argv_of(&["echo", "hi"]), &Default::default())
        .unwrap();
    sandbox
        .run(&common::argv_of(&["python3"]), &Default::default())
        .unwrap();
    sandbox.read_file("README.md", None).unwrap();
    sandbox.write_file("scratch/x", b"x", None).unwrap();
    let recs: Vec<AuditRecord> = lines(&path)
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let types: Vec<&str> = recs
        .iter()
        .map(|r| r.event["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["check", "exec", "exec", "read_file", "write_file"]);
    assert_eq!(recs[0].event["decision"]["rule"], "network.deny");
    assert_eq!(recs[1].event["outcome"]["exit_code"], 0);
    assert_eq!(recs[2].event["executed"], false);
    assert!(
        recs.iter()
            .all(|r| r.event["policy_hash"].as_str().unwrap().len() == 64)
    );
    assert!(verify(&path, None).unwrap().ok);
}

#[test]
fn float_values_survive_the_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for x in [
        0.1 + 0.2,
        1.0 / 3.0,
        1_234.567_890_123_4,
        2.302_281_000_000_000_3,
        1e-300,
    ] {
        log.append(json!({ "x": x })).unwrap();
    }
    assert!(verify(&path, None).unwrap().ok);
}
