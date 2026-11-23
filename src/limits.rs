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
    /// Process-group task ceiling enforced by cgroup v2 `pids.max` (Linux when writable)
    /// and a 5 ms parent watchdog fallback (when running as root without writable cgroups).
    pub process_watchdog_max: Option<u64>,
}

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
        plan.process_watchdog_max = Some(extra);
        if uid == 0 {
            if cgroup_v2_pids_available() {
                plan.processes = format!(
                    "cgroup v2 pids.max {extra} + process-group watchdog (RLIMIT_NPROC {total} set; uid 0)"
                );
            } else {
                plan.processes = format!(
                    "process-group watchdog {extra} tasks (RLIMIT_NPROC {total} ignored by kernel for uid 0; cgroup v2 unavailable)"
                );
                plan.notes.push(
                    "running as root without writable cgroup v2: process cap enforced by parent watchdog rather than kernel pids.max".into(),
                );
            }
        } else if cgroup_v2_pids_available() {
            plan.processes = format!(
                "cgroup v2 pids.max {extra} + RLIMIT_NPROC {total} ({existing} owned by uid {uid} plus {extra})"
            );
        } else {
            plan.processes = format!(
                "RLIMIT_NPROC {total} ({existing} already owned by uid {uid} plus {extra})"
            );
        }
    }
    plan
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

/// Number of live tasks belonging to process group `pgid` (used by the parent watchdog
/// when running as root without writable cgroup v2 `pids.max`).
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

/// Whether Linux cgroup v2 `pids` controller is writable by this process.
#[cfg(target_os = "linux")]
pub fn cgroup_v2_pids_available() -> bool {
    let Some(base) = current_cgroup_v2_dir() else {
        return false;
    };
    let Ok(controllers) = std::fs::read_to_string(base.join("cgroup.controllers")) else {
        return false;
    };
    if !controllers.split_whitespace().any(|c| c == "pids") {
        return false;
    }
    // Check writability without leaving artifacts behind.
    let probe = base.join(format!("agent-sandbox-probe-{}", std::process::id()));
    if std::fs::create_dir(&probe).is_ok() {
        let _ = std::fs::remove_dir(&probe);
        true
    } else {
        false
    }
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

/// RAII handle for a transient per-invocation cgroup v2 leaf enforcing `pids.max`.
pub struct PidsCgroup {
    #[cfg(target_os = "linux")]
    dir: Option<std::path::PathBuf>,
}

impl PidsCgroup {
    #[cfg(target_os = "linux")]
    pub fn attach(pid: u32, max_pids: Option<u64>) -> Self {
        let Some(max) = max_pids else {
            return Self { dir: None };
        };
        let Some(parent) = current_cgroup_v2_dir() else {
            return Self { dir: None };
        };
        // Best-effort enable +pids on parent subtree_control when running in a root cgroup.
        let _ = std::fs::write(parent.join("cgroup.subtree_control"), "+pids");
        let leaf = parent.join(format!("agent-sandbox-{}-{pid}", std::process::id()));
        if std::fs::create_dir(&leaf).is_err() {
            return Self { dir: None };
        }
        if std::fs::write(leaf.join("pids.max"), max.to_string()).is_err()
            || std::fs::write(leaf.join("cgroup.procs"), pid.to_string()).is_err()
        {
            let _ = std::fs::remove_dir(&leaf);
            return Self { dir: None };
        }
        Self { dir: Some(leaf) }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attach(_pid: u32, _max_pids: Option<u64>) -> Self {
        Self {}
    }

    pub fn active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.dir.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Drop for PidsCgroup {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::write(dir.join("cgroup.kill"), "1");
            let _ = std::fs::remove_dir(&dir);
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
