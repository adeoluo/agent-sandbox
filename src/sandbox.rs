//! The sandbox: decides, executes under the policy, supervises, and audits.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;

use crate::audit::AuditLog;
use crate::engine::{Decision, Engine, Request};
use crate::error::{Result, SandboxError};
use crate::isolation::{self, Enforcement, Prepared};
use crate::limits;
use crate::policy::{CompiledPolicy, NetworkMode, sha256_hex};

/// Environment variables removed whenever the network policy is `deny`.
pub const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "socks_proxy",
    "rsync_proxy",
];

/// Default cap on a single `write_file` when `limits.max_file_size_bytes` is unset.
pub const DEFAULT_MAX_WRITE_BYTES: u64 = 16 << 20;

/// How long to wait for output pipes to close after the process group is gone.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunOptions {
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub stdin: Option<String>,
    /// Evaluate and audit, but do not execute.
    #[serde(default)]
    pub dry_run: bool,
}

fn lossy<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&String::from_utf8_lossy(bytes))
}

/// Everything known about one `run` request.
#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub decision: Decision,
    pub executed: bool,
    pub dry_run: bool,
    /// Process id of the command, which is also its process-group id.
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub memory_exceeded: bool,
    pub output_limit_hit: bool,
    #[serde(serialize_with = "lossy")]
    pub stdout: Vec<u8>,
    #[serde(serialize_with = "lossy")]
    pub stderr: Vec<u8>,
    /// Bytes the process wrote, including any beyond the capture limit.
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: f64,
    pub enforcement: Option<Enforcement>,
}

impl RunOutcome {
    fn not_executed(decision: Decision, dry_run: bool) -> Self {
        Self {
            decision,
            executed: false,
            dry_run,
            pid: None,
            exit_code: None,
            signal: None,
            timed_out: false,
            memory_exceeded: false,
            output_limit_hit: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 0.0,
            enforcement: None,
        }
    }

    /// Allowed, executed, and exited with status 0.
    pub fn success(&self) -> bool {
        self.executed && self.exit_code == Some(0)
    }

    fn summary(&self) -> serde_json::Value {
        json!({
            "pid": self.pid,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "timed_out": self.timed_out,
            "memory_exceeded": self.memory_exceeded,
            "output_limit_hit": self.output_limit_hit,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_sha256": sha256_hex(&self.stdout),
            "stderr_sha256": sha256_hex(&self.stderr),
            "duration_us": (self.duration_ms * 1000.0).round() as u64,
            "enforcement": self.enforcement,
        })
    }
}

/// Result of a sandboxed file operation.
#[derive(Debug, Clone, Serialize)]
pub struct FileOutcome {
    pub decision: Decision,
    #[serde(serialize_with = "lossy")]
    pub content: Vec<u8>,
    pub bytes: u64,
    pub truncated: bool,
}

/// A policy plus an optional audit log. Methods take `&self`; the log is mutex-guarded.
#[derive(Debug)]
pub struct Sandbox {
    policy: CompiledPolicy,
    audit: Option<Mutex<AuditLog>>,
}

impl Sandbox {
    pub fn new(policy: CompiledPolicy) -> Self {
        Self {
            policy,
            audit: None,
        }
    }

    pub fn with_audit(mut self, log: AuditLog) -> Self {
        self.audit = Some(Mutex::new(log));
        self
    }

    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    pub fn engine(&self) -> Engine<'_> {
        Engine::new(&self.policy)
    }

    fn record(&self, kind: &str, mut event: serde_json::Value) -> Result<()> {
        let Some(audit) = &self.audit else {
            return Ok(());
        };
        event["type"] = json!(kind);
        event["policy"] = json!(self.policy.name());
        event["policy_hash"] = json!(self.policy.policy_hash);
        let mut log = audit
            .lock()
            .map_err(|_| SandboxError::Audit("audit log mutex poisoned".into()))?;
        log.append(event)?;
        Ok(())
    }

    /// Evaluates a request without executing it, and audits the decision.
    pub fn check(&self, request: &Request) -> Result<Decision> {
        let decision = self.engine().decide(request);
        self.record("check", json!({ "request": request, "decision": decision }))?;
        Ok(decision)
    }

    /// Evaluates and, if allowed, executes `argv` under the policy.
    pub fn run(&self, argv: &[String], opts: &RunOptions) -> Result<RunOutcome> {
        let request = Request::Exec {
            argv: argv.to_vec(),
            cwd: opts.cwd.clone(),
        };
        let decision = self.engine().decide(&request);
        if !decision.allowed || opts.dry_run {
            let outcome = RunOutcome::not_executed(decision, opts.dry_run);
            self.record(
                "exec",
                json!({ "request": request, "decision": outcome.decision, "dry_run": opts.dry_run, "executed": false }),
            )?;
            return Ok(outcome);
        }
        let result = self.execute(&decision, &argv[1..], opts.stdin.as_deref());
        match result {
            Ok(outcome) => {
                self.record(
                    "exec",
                    json!({ "request": request, "decision": outcome.decision, "dry_run": false, "executed": true, "outcome": outcome.summary() }),
                )?;
                Ok(outcome)
            }
            Err(err) => {
                self.record(
                    "exec",
                    json!({ "request": request, "decision": decision, "dry_run": false, "executed": false, "error": err.to_string() }),
                )?;
                Err(err)
            }
        }
    }

    /// The environment passed to every child: allowlisted variables, policy-set values,
    /// the policy `PATH`, and `TMPDIR` pointing at the scratch directory.
    pub fn child_env(&self) -> BTreeMap<OsString, OsString> {
        let p = &self.policy;
        let mut env = BTreeMap::new();
        for (key, value) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if p.policy.env.allow.iter().any(|g| g.matches(&name)) {
                env.insert(key, value);
            }
        }
        let path = std::env::join_paths(&p.path_dirs).unwrap_or_default();
        env.insert("PATH".into(), path);
        if let Some(scratch) = &p.scratch {
            env.insert("TMPDIR".into(), scratch.clone().into_os_string());
        }
        for (key, value) in &p.policy.env.set {
            env.insert(key.into(), p.placeholders.expand_text(value).into());
        }
        if p.policy.network.mode == NetworkMode::Deny {
            env.retain(|key, _| {
                let lower = key.to_string_lossy().to_ascii_lowercase();
                !PROXY_VARS.contains(&lower.as_str())
            });
        }
        env
    }

    fn execute(
        &self,
        decision: &Decision,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<RunOutcome> {
        let program = decision
            .program
            .clone()
            .ok_or_else(|| SandboxError::Audit("allowed exec decision lacks a program".into()))?;
        let cwd = decision
            .resolved
            .clone()
            .unwrap_or_else(|| self.policy.workspace.clone());
        let lim = self.policy.limits();
        let plan = limits::plan(lim);
        let (prepared, mut enforcement) = isolation::prepare(&self.policy, &program)?;
        enforcement.memory = plan.memory.clone();
        enforcement.cpu = plan.cpu.clone();
        enforcement.processes = plan.processes.clone();
        enforcement.notes.extend(plan.notes.iter().cloned());

        let mut cmd = match &prepared {
            Prepared::Seatbelt { profile } => {
                let mut c = Command::new(isolation::macos::SANDBOX_EXEC);
                c.arg("-p").arg(profile).arg(&program);
                c
            }
            _ => Command::new(&program),
        };
        cmd.args(args)
            .env_clear()
            .envs(self.child_env())
            .current_dir(&cwd)
            .process_group(0)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let rlimits = plan.rlimits.clone();
        #[cfg(target_os = "linux")]
        let landlock_fd = match &prepared {
            Prepared::Landlock(ruleset) => Some(ruleset.raw_fd()),
            _ => None,
        };
        // SAFETY: the closure runs between fork and exec and only makes async-signal-safe
        // syscalls (setrlimit, prctl, landlock_restrict_self) on data prepared in the parent.
        unsafe {
            cmd.pre_exec(move || {
                limits::apply(&rlimits)?;
                #[cfg(target_os = "linux")]
                if let Some(fd) = landlock_fd {
                    crate::isolation::linux::restrict_self(fd)?;
                }
                Ok(())
            });
        }

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|source| SandboxError::Spawn {
            program: program.display().to_string(),
            source,
        })?;
        drop(prepared);
        let pgid = child.id() as libc::pid_t;
        let overflow = Arc::new(AtomicBool::new(false));
        if let (Some(data), Some(mut pipe)) =
            (stdin.map(|s| s.as_bytes().to_vec()), child.stdin.take())
        {
            thread::spawn(move || {
                let _ = pipe.write_all(&data);
            });
        }
        let cap = lim.max_output_bytes;
        let kill = lim.kill_on_output_limit;
        let out_rx = read_capped(child.stdout.take(), cap, kill, pgid, overflow.clone());
        let err_rx = read_capped(child.stderr.take(), cap, kill, pgid, overflow.clone());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait());
        });

        let deadline = start + Duration::from_millis(lim.timeout_ms);
        let poll = if plan.rss_watchdog_bytes.is_some() {
            Duration::from_millis(5)
        } else {
            Duration::from_secs(3600)
        };
        let mut timed_out = false;
        let mut memory_exceeded = false;
        let status = loop {
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                kill_group(pgid);
                break rx
                    .recv()
                    .map_err(|_| SandboxError::Audit("wait thread vanished".into()))?;
            }
            match rx.recv_timeout((deadline - now).min(poll)) {
                Ok(status) => break status,
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(max) = plan.rss_watchdog_bytes
                        && limits::group_rss_bytes(pgid) > max
                    {
                        memory_exceeded = true;
                        kill_group(pgid);
                        break rx
                            .recv()
                            .map_err(|_| SandboxError::Audit("wait thread vanished".into()))?;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(SandboxError::Audit("wait thread vanished".into()));
                }
            }
        }?;
        sweep_group(pgid);
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        let (stdout, stdout_bytes) = collect(&out_rx.0, &out_rx.1, DRAIN_GRACE);
        let (stderr, stderr_bytes) = collect(&err_rx.0, &err_rx.1, DRAIN_GRACE);
        Ok(RunOutcome {
            decision: decision.clone(),
            executed: true,
            dry_run: false,
            pid: Some(pgid as u32),
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            memory_exceeded,
            output_limit_hit: overflow.load(Ordering::SeqCst),
            stdout_truncated: stdout_bytes > stdout.len() as u64,
            stderr_truncated: stderr_bytes > stderr.len() as u64,
            stdout,
            stderr,
            stdout_bytes,
            stderr_bytes,
            duration_ms,
            enforcement: Some(enforcement),
        })
    }

    /// Reads a file the policy allows, up to `limits.max_output_bytes`. The final path
    /// component is opened with `O_NOFOLLOW`, so a symlink swapped in after the check fails.
    pub fn read_file(&self, path: &str, cwd: Option<&Path>) -> Result<FileOutcome> {
        let request = Request::Read {
            path: path.to_string(),
            cwd: cwd.map(Path::to_path_buf),
        };
        let decision = self.engine().decide(&request);
        let mut outcome = FileOutcome {
            decision,
            content: Vec::new(),
            bytes: 0,
            truncated: false,
        };
        if let (true, Some(resolved)) =
            (outcome.decision.allowed, outcome.decision.resolved.clone())
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&resolved)?;
            let cap = self.policy.limits().max_output_bytes as u64;
            file.take(cap + 1).read_to_end(&mut outcome.content)?;
            outcome.truncated = outcome.content.len() as u64 > cap;
            outcome.content.truncate(cap as usize);
            outcome.bytes = outcome.content.len() as u64;
        }
        self.record(
            "read_file",
            json!({ "request": request, "decision": outcome.decision, "bytes": outcome.bytes, "truncated": outcome.truncated }),
        )?;
        Ok(outcome)
    }

    /// Writes a file the policy allows. Refuses content above `limits.max_file_size_bytes`.
    pub fn write_file(
        &self,
        path: &str,
        contents: &[u8],
        cwd: Option<&Path>,
    ) -> Result<FileOutcome> {
        let request = Request::Write {
            path: path.to_string(),
            cwd: cwd.map(Path::to_path_buf),
        };
        let mut decision = self.engine().decide(&request);
        let max = self
            .policy
            .limits()
            .max_file_size_bytes
            .unwrap_or(DEFAULT_MAX_WRITE_BYTES);
        if decision.allowed && contents.len() as u64 > max {
            decision = Decision {
                allowed: false,
                rule: "limits.max_file_size_bytes".into(),
                reason: format!(
                    "{} bytes exceeds the {max}-byte write limit",
                    contents.len()
                ),
                program: None,
                resolved: decision.resolved,
            };
        }
        let mut written = 0u64;
        if let (true, Some(resolved)) = (decision.allowed, decision.resolved.clone()) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&resolved)?;
            file.write_all(contents)?;
            written = contents.len() as u64;
        }
        self.record(
            "write_file",
            json!({ "request": request, "decision": decision, "bytes": written, "sha256": sha256_hex(contents) }),
        )?;
        Ok(FileOutcome {
            decision,
            content: Vec::new(),
            bytes: written,
            truncated: false,
        })
    }
}

fn kill_group(pgid: libc::pid_t) {
    // SAFETY: killpg with a positive group id; ESRCH (already gone) is ignored.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// How long cleanup keeps signalling a process group whose members are still forking.
const SWEEP_LIMIT: Duration = Duration::from_secs(5);

/// Kills a process group repeatedly until it is empty. A single `killpg` can miss a child
/// created by a `fork` that was in flight, which matters for fork bombs.
fn sweep_group(pgid: libc::pid_t) {
    let deadline = Instant::now() + SWEEP_LIMIT;
    // SAFETY: killpg with a positive group id; ESRCH means the group is empty.
    while unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
}

/// Bytes captured from one output stream so far, and the total number of bytes seen.
type Captured = Arc<Mutex<(Vec<u8>, u64)>>;

/// Reads a child's output stream on a background thread, keeping at most `cap` bytes.
///
/// Captured bytes are published to shared state as they arrive, so the caller can collect
/// them even when the stream does not reach end of file within the drain grace period
/// (for example on a slow machine after the process group is killed).
fn read_capped<R: Read + Send + 'static>(
    pipe: Option<R>,
    cap: usize,
    kill_on_overflow: bool,
    pgid: libc::pid_t,
    overflow: Arc<AtomicBool>,
) -> (Receiver<()>, Captured) {
    let (tx, rx) = mpsc::channel();
    let captured: Captured = Arc::new(Mutex::new((Vec::new(), 0)));
    let shared = Arc::clone(&captured);
    thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let total = {
                            let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
                            let (kept, total) = &mut *guard;
                            *total += n as u64;
                            if kept.len() < cap {
                                let take = (cap - kept.len()).min(n);
                                kept.extend_from_slice(&chunk[..take]);
                            }
                            *total
                        };
                        if total > cap as u64
                            && !overflow.swap(true, Ordering::SeqCst)
                            && kill_on_overflow
                        {
                            kill_group(pgid);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
        let _ = tx.send(());
    });
    (rx, captured)
}

/// Waits up to `grace` for the reader to reach end of file, then returns whatever it captured.
fn collect(done: &Receiver<()>, captured: &Captured, grace: Duration) -> (Vec<u8>, u64) {
    let _ = done.recv_timeout(grace);
    let guard = captured.lock().unwrap_or_else(|e| e.into_inner());
    (guard.0.clone(), guard.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that yields one chunk and then blocks, never reaching end of file.
    struct StallsAfterFirstChunk {
        sent: bool,
    }

    impl Read for StallsAfterFirstChunk {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.sent {
                thread::sleep(Duration::from_secs(30));
                return Ok(0);
            }
            self.sent = true;
            let n = 32.min(buf.len());
            buf[..n].fill(b'y');
            Ok(n)
        }
    }

    #[test]
    fn captured_output_survives_a_late_end_of_file() {
        let overflow = Arc::new(AtomicBool::new(false));
        let (done, captured) = read_capped(
            Some(StallsAfterFirstChunk { sent: false }),
            16,
            false,
            0,
            Arc::clone(&overflow),
        );
        thread::sleep(Duration::from_millis(50));
        let (kept, total) = collect(&done, &captured, Duration::from_millis(100));
        assert_eq!(kept, vec![b'y'; 16]);
        assert_eq!(total, 32);
        assert!(overflow.load(Ordering::SeqCst));
    }
}
