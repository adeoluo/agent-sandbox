//! Resource limits applied in the child between `fork` and `exec`, plus the process
//! accounting helpers they need.

use std::io;

use crate::policy::Limits;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

/// One `setrlimit` call, computed in the parent so the child only makes syscalls.
#[derive(Debug, Clone, Copy)]
pub struct Rlimit {
    resource: Resource,
    soft: libc::rlim_t,
    hard: libc::rlim_t,
    pub name: &'static str,
}

/// Every rlimit to apply, plus a description of how each configured limit is enforced.
#[derive(Debug, Clone, Default)]
pub struct RlimitPlan {
    pub rlimits: Vec<Rlimit>,
    pub memory: String,
    pub cpu: String,
    pub processes: String,
    pub notes: Vec<String>,
    /// Resident-set ceiling enforced by the parent's watchdog (macOS only).
    pub rss_watchdog_bytes: Option<u64>,
    /// The configured `max_processes`, when set.
    pub process_max: Option<u64>,
    /// The mechanism expected to enforce `process_max` on this host.
    pub process_cap: ProcessCap,
}

/// How a configured `max_processes` is enforced. Every variant except `Unenforceable` is
/// decided by the kernel before a new task exists; there is no polling fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcessCap {
    /// The policy sets no process limit.
    #[default]
    None,
    /// `RLIMIT_NPROC`, which the kernel enforces for every user except root.
    Rlimit,
    /// cgroup v2 `pids.max` on a leaf cgroup the child joins before `exec`.
    Cgroup,
    /// The seccomp fork gate (`forkgate`), for root without a writable cgroup.
    ForkGate,
    /// Root with neither mechanism. The sandbox refuses to run rather than start a command
    /// whose process limit nothing enforces.
    Unenforceable,
}

/// Why a root caller cannot have `max_processes` enforced, for the refusal error.
pub const UNENFORCEABLE_PROCESS_CAP: &str = "the kernel ignores RLIMIT_NPROC for uid 0, cgroup v2 pids.max is not writable here, and a seccomp user-notification listener is unavailable; run as a non-root user, make the pids cgroup controller writable, or remove limits.max_processes from the policy";

fn current_hard(resource: Resource) -> libc::rlim_t {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid, initialized struct.
    let rc = unsafe { libc::getrlimit(resource, &mut cur) };
    if rc == 0 {
        cur.rlim_max
    } else {
        libc::RLIM_INFINITY
    }
}

fn limit(resource: Resource, name: &'static str, soft: u64, hard: u64) -> Rlimit {
    let max = current_hard(resource);
    let hard = (hard as libc::rlim_t).min(max);
    let soft = (soft as libc::rlim_t).min(hard);
    Rlimit {
        resource,
        soft,
        hard,
        name,
    }
}

/// Plans the rlimits for a policy. Called in the parent before spawning.
pub fn plan(limits: &Limits) -> RlimitPlan {
    let mut plan = RlimitPlan {
        memory: "unlimited".into(),
        cpu: "unlimited".into(),
        processes: "unlimited".into(),
        ..Default::default()
    };
    if let Some(cpu) = limits.cpu_seconds {
        plan.rlimits.push(limit(
            libc::RLIMIT_CPU as Resource,
            "RLIMIT_CPU",
            cpu,
            cpu.saturating_add(1),
        ));
        plan.cpu = format!("RLIMIT_CPU {cpu}s (SIGXCPU, then SIGKILL one second later)");
    }
    if let Some(bytes) = limits.max_file_size_bytes {
        plan.rlimits.push(limit(
            libc::RLIMIT_FSIZE as Resource,
            "RLIMIT_FSIZE",
            bytes,
            bytes,
        ));
    }
    if let Some(n) = limits.max_open_files {
        plan.rlimits.push(limit(
            libc::RLIMIT_NOFILE as Resource,
            "RLIMIT_NOFILE",
            n,
            n,
        ));
    }
    if let Some(bytes) = limits.memory_bytes {
        if cfg!(target_os = "macos") {
            plan.rss_watchdog_bytes = Some(bytes);
            plan.memory = format!(
                "resident-set watchdog {bytes} bytes over the process group (macOS rejects RLIMIT_AS)"
            );
        } else {
            plan.rlimits.push(limit(
                libc::RLIMIT_AS as Resource,
                "RLIMIT_AS",
                bytes,
                bytes,
            ));
            plan.memory = format!("RLIMIT_AS {bytes} bytes per process");
        }
    }
    if let Some(extra) = limits.max_processes {
        // SAFETY: getuid has no failure modes.
        let uid = unsafe { libc::getuid() };
        let existing = count_user_processes(uid).unwrap_or(0);
        let total = existing.saturating_add(extra);
        plan.rlimits.push(limit(
            libc::RLIMIT_NPROC as Resource,
            "RLIMIT_NPROC",
            total,
            total,
        ));
        plan.process_max = Some(extra);
        let cgroup = cgroup_v2_pids_available();
        plan.process_cap = if uid != 0 {
            ProcessCap::Rlimit
        } else if cgroup {
            ProcessCap::Cgroup
        } else if crate::forkgate::available() {
            ProcessCap::ForkGate
        } else {
            ProcessCap::Unenforceable
        };
        plan.processes =
            describe_process_cap(plan.process_cap, extra, total, existing, uid, cgroup);
        if plan.process_cap == ProcessCap::Unenforceable {
            plan.notes.push(format!(
                "max_processes cannot be enforced, so commands are refused: {UNENFORCEABLE_PROCESS_CAP}"
            ));
        }
    }
    plan
}

/// The audit-log description of how a process limit of `extra` tasks is enforced.
pub fn describe_process_cap(
    cap: ProcessCap,
    extra: u64,
    total: u64,
    existing: u64,
    uid: libc::uid_t,
    cgroup_also: bool,
) -> String {
    match cap {
        ProcessCap::None => String::new(),
        ProcessCap::Rlimit if cgroup_also => format!(
            "cgroup v2 pids.max {extra} + RLIMIT_NPROC {total} ({existing} owned by uid {uid} plus {extra})"
        ),
        ProcessCap::Rlimit => {
            format!("RLIMIT_NPROC {total} ({existing} already owned by uid {uid} plus {extra})")
        }
        ProcessCap::Cgroup => format!(
            "cgroup v2 pids.max {extra}, joined before exec (the kernel ignores RLIMIT_NPROC for uid 0)"
        ),
        ProcessCap::ForkGate => format!(
            "seccomp fork gate: at most {extra} tasks in the process group, every clone/fork approved by the supervisor (the kernel ignores RLIMIT_NPROC for uid 0; cgroup v2 pids.max not writable); setsid and setpgid are refused"
        ),
        ProcessCap::Unenforceable => format!(
            "max_processes {extra} is not enforceable on this host (RLIMIT_NPROC is ignored for uid 0); commands are refused"
        ),
    }
}

/// Applies the plan. Runs in the forked child, so it only calls `setrlimit`.
pub fn apply(plan: &[Rlimit]) -> io::Result<()> {
    for r in plan {
        let value = libc::rlimit {
            rlim_cur: r.soft,
            rlim_max: r.hard,
        };
        // SAFETY: setrlimit is async-signal-safe and reads a valid struct.
        if unsafe { libc::setrlimit(r.resource, &value) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Counts what the kernel compares against `RLIMIT_NPROC` for this user: processes on macOS,
/// threads (tasks) on Linux.
#[cfg(target_os = "linux")]
pub fn count_user_processes(uid: libc::uid_t) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0u64;
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.uid() != uid {
            continue;
        }
        let tasks = std::fs::read_dir(entry.path().join("task"))
            .map(|d| d.count() as u64)
            .unwrap_or(1);
        total += tasks.max(1);
    }
    Ok(total)
}

#[cfg(target_os = "macos")]
pub fn count_user_processes(uid: libc::uid_t) -> io::Result<u64> {
    const PROC_RUID_ONLY: u32 = 5;
    Ok(macos_list_pids(PROC_RUID_ONLY, uid)?.len() as u64)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn count_user_processes(_uid: libc::uid_t) -> io::Result<u64> {
    Ok(0)
}

#[cfg(target_os = "macos")]
fn macos_list_pids(kind: u32, info: u32) -> io::Result<Vec<libc::pid_t>> {
    let mut capacity = 1024usize;
    loop {
        let mut buf: Vec<libc::pid_t> = vec![0; capacity];
        let bytes = (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: the buffer is valid for `bytes` bytes.
        let n = unsafe { libc::proc_listpids(kind, info, buf.as_mut_ptr().cast(), bytes) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = n as usize / std::mem::size_of::<libc::pid_t>();
        if count < capacity {
            buf.truncate(count);
            buf.retain(|p| *p > 0);
            return Ok(buf);
        }
        capacity *= 2;
    }
}

/// Sum of resident-set sizes of every process in a process group (macOS watchdog).
#[cfg(target_os = "macos")]
pub fn group_rss_bytes(pgid: libc::pid_t) -> u64 {
    const PROC_PGRP_ONLY: u32 = 2;
    let Ok(pids) = macos_list_pids(PROC_PGRP_ONLY, pgid as u32) else {
        return 0;
    };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    pids.into_iter()
        .map(|pid| {
            // SAFETY: proc_taskinfo is plain data; zeroed is a valid initial value.
            let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
            // SAFETY: the buffer is valid for `size` bytes.
            let n = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTASKINFO,
                    0,
                    (&mut info as *mut libc::proc_taskinfo).cast(),
                    size,
                )
            };
            if n == size { info.pti_resident_size } else { 0 }
        })
        .sum()
}

#[cfg(not(target_os = "macos"))]
pub fn group_rss_bytes(_pgid: libc::pid_t) -> u64 {
    0
}

/// Number of live tasks (threads included) in process group `pgid`. The fork gate calls
/// this while the task that wants to fork is still blocked in the kernel.
#[cfg(target_os = "linux")]
pub fn group_process_count(pgid: libc::pid_t) -> u64 {
    let mut count = 0u64;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some(rparen) = stat.rfind(')') {
            let mut fields = stat[rparen + 1..].split_whitespace();
            let _state = fields.next();
            let _ppid = fields.next();
            if let Some(pgrp_str) = fields.next()
                && pgrp_str.parse::<libc::pid_t>().ok() == Some(pgid)
            {
                let tasks = std::fs::read_dir(entry.path().join("task"))
                    .map(|d| d.count() as u64)
                    .unwrap_or(1);
                count += tasks.max(1);
            }
        }
    }
    count
}

#[cfg(target_os = "macos")]
pub fn group_process_count(pgid: libc::pid_t) -> u64 {
    const PROC_PGRP_ONLY: u32 = 2;
    macos_list_pids(PROC_PGRP_ONLY, pgid as u32)
        .map(|v| v.len() as u64)
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn group_process_count(_pgid: libc::pid_t) -> u64 {
    0
}

/// Whether a leaf cgroup with a working `pids.max` can be created under this process's
/// cgroup v2 directory. Probed by creating one and removing it again.
#[cfg(target_os = "linux")]
pub fn cgroup_v2_pids_available() -> bool {
    PidsCgroup::create(1).is_some()
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_v2_pids_available() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn current_cgroup_v2_dir() -> Option<std::path::PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in content.lines() {
        if let Some(rel) = line.strip_prefix("0::") {
            let trimmed = rel.trim().trim_start_matches('/');
            let root = std::path::Path::new("/sys/fs/cgroup");
            let dir = if trimmed.is_empty() {
                root.to_path_buf()
            } else {
                root.join(trimmed)
            };
            if dir.is_dir() {
                return Some(dir);
            }
        }
    }
    None
}

/// RAII handle for a per-invocation cgroup v2 leaf with `pids.max` set. The leaf exists
/// before the command is spawned and the forked child joins it before `exec`, so no task of
/// the command ever runs outside it.
pub struct PidsCgroup {
    #[cfg(target_os = "linux")]
    dir: std::path::PathBuf,
    #[cfg(target_os = "linux")]
    procs: std::fs::File,
}

impl PidsCgroup {
    /// Creates the leaf and sets `pids.max`. `None` when the controller is not usable here.
    ///
    /// The leaf is tried under this process's own cgroup and then beside it, under the
    /// parent, and is used only if the kernel reports it as an ordinary `domain` cgroup with
    /// a `pids.max` file. This never edits `cgroup.subtree_control` of a cgroup that holds
    /// processes: enabling `pids` there would turn the caller's own cgroup into a threaded
    /// domain, whose children cannot accept processes at all. The one cgroup allowed to
    /// hold processes and delegate is the real root, which is the only place it is enabled.
    #[cfg(target_os = "linux")]
    pub fn create(max_pids: u64) -> Option<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let own = current_cgroup_v2_dir()?;
        let mount = std::path::Path::new("/sys/fs/cgroup");
        let beside = own.parent().filter(|p| p.starts_with(mount));
        // Only the real root cgroup has no `cgroup.type` file.
        if !own.join("cgroup.type").exists() {
            let _ = std::fs::write(own.join("cgroup.subtree_control"), "+pids");
        }
        let name = format!(
            "agent-sandbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        for base in std::iter::once(own.as_path()).chain(beside) {
            let leaf = base.join(&name);
            if std::fs::create_dir(&leaf).is_err() {
                continue;
            }
            let domain = std::fs::read_to_string(leaf.join("cgroup.type"))
                .is_ok_and(|kind| kind.trim() == "domain");
            let capped = domain
                && std::fs::OpenOptions::new()
                    .write(true)
                    .open(leaf.join("pids.max"))
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(max_pids.to_string().as_bytes())
                    })
                    .is_ok();
            let procs = std::fs::OpenOptions::new()
                .write(true)
                .open(leaf.join("cgroup.procs"));
            match (capped, procs) {
                (true, Ok(procs)) => return Some(Self { dir: leaf, procs }),
                _ => {
                    let _ = std::fs::remove_dir(&leaf);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(_max_pids: u64) -> Option<Self> {
        None
    }

    /// The descriptor the forked child writes to in order to join the leaf.
    #[cfg(target_os = "linux")]
    pub fn procs_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.procs.as_raw_fd()
    }

    /// Moves the calling process into the leaf. Runs in the forked child; one `write`.
    #[cfg(target_os = "linux")]
    pub fn join(procs_fd: std::os::fd::RawFd) -> io::Result<()> {
        // SAFETY: writes one byte from a static buffer to a descriptor opened in the parent.
        let n = unsafe { libc::write(procs_fd, b"0".as_ptr().cast(), 1) };
        if n == 1 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for PidsCgroup {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::fs::write(self.dir.join("cgroup.kill"), "1");
            // The kernel removes a cgroup only once its last task has been reaped.
            for _ in 0..200 {
                if std::fs::remove_dir(&self.dir).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_describes_each_limit() {
        let limits = Limits {
            cpu_seconds: Some(2),
            memory_bytes: Some(64 << 20),
            max_processes: Some(8),
            max_file_size_bytes: Some(1 << 20),
            max_open_files: Some(64),
            ..Limits::default()
        };
        let plan = plan(&limits);
        assert!(plan.cpu.contains("RLIMIT_CPU"));
        assert!(plan.processes.contains("RLIMIT_NPROC"));
        assert_eq!(plan.process_max, Some(8));
        // SAFETY: getuid has no failure modes.
        let root = unsafe { libc::getuid() } == 0;
        assert_eq!(plan.process_cap == ProcessCap::Rlimit, !root);
        assert_ne!(plan.process_cap, ProcessCap::None);
        assert_ne!(plan.memory, "unlimited");
        let names: Vec<_> = plan.rlimits.iter().map(|r| r.name).collect();
        assert!(names.contains(&"RLIMIT_FSIZE"));
        assert!(names.contains(&"RLIMIT_NOFILE"));
        for r in &plan.rlimits {
            assert!(r.soft <= r.hard);
        }
    }

    #[test]
    fn unlimited_by_default() {
        let plan = plan(&Limits::default());
        assert!(plan.rlimits.is_empty());
        assert_eq!(plan.memory, "unlimited");
        assert!(apply(&plan.rlimits).is_ok());
    }

    #[test]
    fn counts_own_processes() {
        // SAFETY: getuid has no failure modes.
        let uid = unsafe { libc::getuid() };
        assert!(count_user_processes(uid).unwrap() >= 1);
    }
}
