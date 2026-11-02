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
        plan.processes =
            format!("RLIMIT_NPROC {total} ({existing} already owned by uid {uid} plus {extra})");
        if uid == 0 {
            plan.notes.push(
                "running as root: the kernel does not apply RLIMIT_NPROC to privileged users"
                    .into(),
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
