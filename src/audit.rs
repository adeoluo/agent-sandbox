//! Append-only JSON Lines audit log with a SHA-256 hash chain.
//!
//! Each record stores the hash of the previous record. The record hash covers the sequence
//! number, timestamp, previous hash, and a canonical (sorted-key) encoding of the event, so
//! editing, deleting, inserting, or reordering any record breaks verification from that
//! point on. Truncating the tail is only detectable against a head hash stored elsewhere,
//! which is what `verify --expect-head` is for.
//!
//! Events should avoid floating-point values: integers and strings re-serialize identically
//! after a parse, which the verifier relies on.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Result, SandboxError};
use crate::policy::hex;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts_ms: u64,
    pub prev_hash: String,
    pub event: Value,
    pub hash: String,
}

impl AuditRecord {
    pub fn compute_hash(seq: u64, ts_ms: u64, prev_hash: &str, event: &Value) -> String {
        let mut canonical = String::new();
        write_canonical(event, &mut canonical);
        let mut hasher = Sha256::new();
        hasher.update(format!("{seq}\n{ts_ms}\n{prev_hash}\n").as_bytes());
        hasher.update(canonical.as_bytes());
        hex(&hasher.finalize())
    }
}

/// Serializes JSON with object keys sorted, independent of serde_json feature flags.
pub fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// An open audit log. Appends take an exclusive `flock` and re-read the tail, so several
/// processes can share one log without forking the chain.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends an event and returns the written record.
    pub fn append(&mut self, event: Value) -> Result<AuditRecord> {
        let _lock = FileLock::exclusive(&self.file)?;
        let (seq, prev_hash) = match last_record(&mut self.file)? {
            Some(last) => (last.seq + 1, last.hash),
            None => (0, GENESIS_HASH.to_string()),
        };
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let hash = AuditRecord::compute_hash(seq, ts_ms, &prev_hash, &event);
        let record = AuditRecord {
            seq,
            ts_ms,
            prev_hash,
            event,
            hash,
        };
        let mut line = serde_json::to_string(&record)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        Ok(record)
    }
}

/// Holds an exclusive `flock` until dropped. The descriptor must outlive the guard.
struct FileLock(std::os::fd::RawFd);

impl FileLock {
    fn exclusive(file: &File) -> Result<Self> {
        let fd = file.as_raw_fd();
        // SAFETY: flock on a valid descriptor.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(fd))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: unlocking a descriptor we locked and that is still open.
        unsafe { libc::flock(self.0, libc::LOCK_UN) };
    }
}

/// Reads the last complete record without scanning the whole file.
fn last_record(file: &mut File) -> Result<Option<AuditRecord>> {
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    let mut window = 64 * 1024u64;
    loop {
        let start = len.saturating_sub(window);
        file.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::with_capacity((len - start) as usize);
        file.take(len - start).read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        let trimmed = text.trim_end_matches('\n');
        if let Some(idx) = trimmed.rfind('\n') {
            return parse_line(&trimmed[idx + 1..]).map(Some);
        }
        if start == 0 {
            return parse_line(trimmed).map(Some);
        }
        window *= 4;
    }
}

fn parse_line(line: &str) -> Result<AuditRecord> {
    serde_json::from_str(line)
        .map_err(|e| SandboxError::Audit(format!("cannot parse the last audit record: {e}")))
}

/// The result of verifying a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub records: u64,
    /// Hash of the last valid record (the genesis hash for an empty log).
    pub head_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 1-based line number of the first problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

/// Verifies the chain. If `expect_head` is given, the final hash must equal it, which
/// detects truncation of the tail.
pub fn verify(path: impl AsRef<Path>, expect_head: Option<&str>) -> Result<VerifyReport> {
    let file = File::open(path.as_ref())?;
    let mut report = VerifyReport {
        ok: true,
        records: 0,
        head_hash: GENESIS_HASH.to_string(),
        error: None,
        line: None,
    };
    let fail = |mut report: VerifyReport, line: u64, msg: String| {
        report.ok = false;
        report.error = Some(msg);
        report.line = Some(line);
        report
    };
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let lineno = index as u64 + 1;
        let line = line?;
        let record: AuditRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => return Ok(fail(report, lineno, format!("malformed record: {e}"))),
        };
        if record.seq != report.records {
            return Ok(fail(
                report.clone(),
                lineno,
                format!("expected seq {} but found {}", report.records, record.seq),
            ));
        }
        if record.prev_hash != report.head_hash {
            return Ok(fail(
                report,
                lineno,
                "prev_hash does not match the previous record".into(),
            ));
        }
        let expected =
            AuditRecord::compute_hash(record.seq, record.ts_ms, &record.prev_hash, &record.event);
        if expected != record.hash {
            return Ok(fail(
                report,
                lineno,
                "record hash does not match its contents".into(),
            ));
        }
        report.records += 1;
        report.head_hash = record.hash;
    }
    if let Some(expected) = expect_head
        && expected != report.head_hash
    {
        let line = report.records;
        return Ok(fail(
            report,
            line,
            format!(
                "head hash differs from the expected {expected}; the log may have been truncated"
            ),
        ));
    }
    Ok(report)
}
