//! Resource limits: wall-clock timeout, output caps, CPU, memory, processes, file size,
//! and process-group cleanup.

mod common;

use std::time::{Duration, Instant};

use agent_sandbox::RunOptions;
use common::{argv_of, fixture};

const SH: &str = "[[exec]]\nname = \"sh\"\n\n[[exec]]\nname = \"sleep\"\n\n[[exec]]\nname = \"yes\"\n\n[[exec]]\nname = \"perl\"\n";

fn with_limits(limits: &str) -> String {
    format!("{SH}\n[limits]\n{limits}\n")
}

#[test]
fn timeout_kills_a_sleeping_process() {
    let fx = fixture(&with_limits("timeout_ms = 300"));
    let start = Instant::now();
    let out = fx.run(&["sleep", "30"]);
    assert!(out.executed);
    assert!(out.timed_out);
    assert_eq!(out.signal, Some(libc::SIGKILL));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn timeout_kills_the_whole_process_group() {
    let fx = fixture(&with_limits("timeout_ms = 300"));
    let start = Instant::now();
    // The shell waits on a child; both must die, and output pipes must close.
    let out = fx.run(&["sh", "-c", "sleep 30; echo never"]);
    assert!(out.timed_out);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("never"));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn background_processes_are_reaped_after_exit() {
    let fx = fixture(&with_limits("timeout_ms = 5000"));
    let start = Instant::now();
    let out = fx.run(&["sh", "-c", "sleep 30 & echo $!"]);
    assert_eq!(out.exit_code, Some(0));
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "a background child held the pipes open"
    );
    let pid: libc::pid_t = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    // SAFETY: signal 0 only checks for existence.
    while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: as above.
    assert_ne!(
        unsafe { libc::kill(pid, 0) },
        0,
        "background sleep {pid} survived"
    );
}

#[test]
fn output_is_truncated_and_the_producer_stopped() {
    let fx = fixture(&with_limits("timeout_ms = 10000\nmax_output_bytes = 1000"));
    let start = Instant::now();
    let out = fx.run(&["yes"]);
    assert!(out.output_limit_hit);
    assert!(out.stdout_truncated);
    assert_eq!(out.stdout.len(), 1000);
    assert!(out.stdout_bytes > 1000);
    assert!(
        !out.timed_out,
        "yes should be killed by the output limit, not the timeout"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn output_truncation_without_kill_drains_to_exit() {
    let fx = fixture(&with_limits(
        "max_output_bytes = 10\nkill_on_output_limit = false",
    ));
    let out = fx.run(&[
        "sh",
        "-c",
        "i=0; while [ $i -lt 100 ]; do echo line$i; i=$((i+1)); done; echo done >&2",
    ]);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.output_limit_hit);
    assert_eq!(out.stdout.len(), 10);
    assert!(out.stdout_bytes > 500);
    assert_eq!(String::from_utf8_lossy(&out.stderr), "done\n");
}

#[test]
fn cpu_limit_stops_a_busy_loop() {
    // CPU time, not wall time, is limited; on a loaded machine one CPU second can take
    // several wall seconds, so the timeout is generous and must not be what fires.
    let fx = fixture(&with_limits("timeout_ms = 60000\ncpu_seconds = 1"));
    let out = fx.run(&["sh", "-c", "while :; do :; done"]);
    assert!(!out.timed_out, "{out:?}");
    assert!(
        matches!(out.signal, Some(s) if s == libc::SIGXCPU || s == libc::SIGKILL),
        "{out:?}"
    );
}

#[test]
fn memory_limit_contains_a_large_allocation() {
    let fx = fixture(&with_limits("timeout_ms = 20000\nmemory_bytes = 134217728"));
    // Build a 1 GiB string; the process must not succeed.
    let out = fx.run(&[
        "perl",
        "-e",
        "my $x = 'a' x (1024*1024*1024); print length($x)",
    ]);
    assert!(out.executed);
    assert_ne!(out.exit_code, Some(0), "{out:?}");
    assert!(!out.timed_out);
    if cfg!(target_os = "macos") {
        assert!(out.memory_exceeded, "macOS watchdog should fire: {out:?}");
    }
    let small = fx.run(&["perl", "-e", "my $x = 'a' x (1024*1024); print length($x)"]);
    assert_eq!(small.exit_code, Some(0), "{small:?}");
    assert_eq!(String::from_utf8_lossy(&small.stdout), "1048576");
}

/// Whether this host can enforce `max_processes` for the current user. It cannot for root
/// with neither a writable pids cgroup nor a seccomp listener, and then the sandbox refuses.
fn process_cap_enforceable() -> bool {
    let limits = agent_sandbox::policy::Limits {
        max_processes: Some(16),
        ..Default::default()
    };
    agent_sandbox::limits::plan(&limits).process_cap
        != agent_sandbox::limits::ProcessCap::Unenforceable
}

/// CI runs this suite as root in containers built to exercise one mechanism each and names
/// the one it expects, so a silent fall-through to another path fails the build.
#[test]
fn process_cap_mechanism_matches_the_environment() {
    use agent_sandbox::limits::ProcessCap;
    let Ok(expected) = std::env::var("AGENT_SANDBOX_EXPECT_PROCESS_CAP") else {
        return;
    };
    let limits = agent_sandbox::policy::Limits {
        max_processes: Some(16),
        ..Default::default()
    };
    let actual = agent_sandbox::limits::plan(&limits).process_cap;
    let wanted = match expected.as_str() {
        "rlimit" => ProcessCap::Rlimit,
        "cgroup" => ProcessCap::Cgroup,
        "forkgate" => ProcessCap::ForkGate,
        "refused" => ProcessCap::Unenforceable,
        other => panic!("unknown AGENT_SANDBOX_EXPECT_PROCESS_CAP {other:?}"),
    };
    assert_eq!(actual, wanted);
}

#[test]
fn fork_bomb_is_bounded() {
    let fx = fixture(&with_limits("timeout_ms = 3000\nmax_processes = 16"));
    if !process_cap_enforceable() {
        // Nothing in this environment can cap processes for root, so the command must not
        // start at all: an unenforced limit is refused, never silently dropped.
        let err = fx
            .sandbox
            .run(
                &argv_of(&["sh", "-c", "echo started"]),
                &RunOptions::default(),
            )
            .unwrap_err();
        assert!(
            matches!(err, agent_sandbox::SandboxError::LimitUnenforceable(_)),
            "{err}"
        );
        return;
    }
    let start = Instant::now();
    // The same exponential bomb for every user and mechanism: RLIMIT_NPROC, a pids cgroup,
    // or the seccomp fork gate must each stop it in the kernel.
    let out = fx.run(&[
        "sh",
        "-c",
        "bomb() { bomb | bomb & }; bomb; sleep 1; echo survived",
    ]);
    assert!(out.executed);
    assert!(start.elapsed() < Duration::from_secs(12));
    // The bomb's process group is emptied once run() returns. On Linux this is exact. On
    // macOS, under load, a few SIGKILLed members can sit in the kernel exit path for
    // seconds; they are no longer forking, and their number is bounded by the limit.
    let pgid = out.pid.unwrap() as libc::pid_t;
    let deadline = Instant::now() + Duration::from_secs(10);
    // SAFETY: signal 0 only checks for existence.
    while unsafe { libc::killpg(pgid, 0) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let survivors = group_members(pgid);
    if cfg!(target_os = "linux") {
        assert!(
            survivors.is_empty(),
            "bomb processes survived: {survivors:#?}"
        );
    } else {
        assert!(
            survivors.len() <= 64,
            "bomb was not bounded: {} members",
            survivors.len()
        );
        if !survivors.is_empty() {
            eprintln!("note: {} killed members still exiting", survivors.len());
        }
    }
    let enforcement = out.enforcement.unwrap();
    eprintln!("fork bomb stopped by: {}", enforcement.processes);
    assert!(
        enforcement.processes.contains("RLIMIT_NPROC")
            || enforcement.processes.contains("cgroup v2")
            || enforcement.processes.contains("seccomp fork gate"),
        "unexpected processes enforcement string: {}",
        enforcement.processes
    );
}

/// For root the cap is a hard ceiling, not a reaction: a command that tries to hold 48 tasks
/// under a limit of 8 is sampled from outside while it runs and never holds more than 8,
/// whether the limit comes from a pids cgroup or the seccomp fork gate. (For other users
/// `RLIMIT_NPROC` counts every process of the uid, so the group ceiling is not exact.)
#[cfg(target_os = "linux")]
#[test]
fn root_process_cap_is_never_exceeded() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    // SAFETY: geteuid has no failure modes.
    if unsafe { libc::geteuid() } != 0 || !process_cap_enforceable() {
        return;
    }
    let fx = fixture(&with_limits("timeout_ms = 8000\nmax_processes = 8"));
    let marker = fx.scratch().join("pgid");
    let release = fx.scratch().join("release");
    let done = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU64::new(0));
    let (done2, peak2, marker2) = (done.clone(), peak.clone(), marker.clone());
    let sampler = std::thread::spawn(move || {
        while !done2.load(Ordering::SeqCst) {
            if let Some(pgid) = std::fs::read_to_string(&marker2)
                .ok()
                .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
            {
                let n = agent_sandbox::limits::group_process_count(pgid);
                peak2.fetch_max(n, Ordering::SeqCst);
                if n >= 2 {
                    let _ = std::fs::write(&release, b"seen");
                }
            }
            std::thread::yield_now();
        }
    });
    // The sandbox makes the command a process-group leader, so `$$` is the group id. The
    // spawner runs in a subshell because `sh` exits on a refused fork, and the sandbox kills
    // the group as soon as the leader exits. The leader then spins on builtins (no forks)
    // until the sampler has counted the group, so the observation does not depend on the
    // sampler thread being scheduled inside the few milliseconds the spawner needs.
    let out = fx.run(&[
        "sh",
        "-c",
        "echo $$ > scratch/pgid; \
         ( i=0; while [ $i -lt 48 ]; do sleep 5 & i=$((i+1)); done ) 2>/dev/null; \
         while [ ! -e scratch/release ]; do :; done",
    ]);
    done.store(true, Ordering::SeqCst);
    sampler.join().unwrap();
    assert!(out.executed);
    let seen = peak.load(Ordering::SeqCst);
    assert!(seen >= 2, "the sampler never observed the spawner: {seen}");
    assert!(
        seen <= 8,
        "process group held {seen} tasks under a cap of 8"
    );
    let enforcement = out.enforcement.unwrap();
    eprintln!(
        "peak {seen} tasks under a cap of 8, enforced by: {} {:?}",
        enforcement.processes, enforcement.notes
    );
    assert!(
        enforcement.processes.contains("cgroup v2")
            || enforcement.processes.contains("seccomp fork gate"),
        "{}",
        enforcement.processes
    );
}

fn group_members(pgid: libc::pid_t) -> Vec<String> {
    let ps = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,pgid=,stat=,comm="])
        .output()
        .unwrap();
    String::from_utf8_lossy(&ps.stdout)
        .lines()
        .filter(|l| l.split_whitespace().nth(1) == Some(&pgid.to_string()))
        .map(String::from)
        .collect()
}

#[test]
fn file_size_limit_applies_to_children() {
    let fx = fixture(&with_limits("max_file_size_bytes = 1024"));
    let out = fx.run(&[
        "sh",
        "-c",
        "yes | head -c 100000 > scratch/big.bin; echo $?",
    ]);
    assert!(out.executed);
    let size = std::fs::metadata(fx.scratch().join("big.bin"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(size <= 1024, "file grew to {size}");
}

#[test]
fn stdin_is_delivered() {
    let fx = fixture(SH);
    let out = fx
        .sandbox
        .run(
            &argv_of(&["cat"]),
            &RunOptions {
                stdin: Some("from the agent".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from the agent");
}

#[test]
fn environment_is_scrubbed() {
    let text = common::policy_text(SH).replace(
        "[env]\n",
        "[env]\nallow = [\"LANG\", \"HTTPS_PROXY\"]\nset = { HOME = \"{scratch}\", GREETING = \"hi\" }\n",
    );
    let fx = common::fixture_with(&text);
    let env = fx.sandbox.child_env();
    let keys: Vec<String> = env
        .keys()
        .map(|k| k.to_string_lossy().into_owned())
        .collect();
    assert!(keys.contains(&"PATH".to_string()));
    assert!(keys.contains(&"TMPDIR".to_string()));
    assert!(keys.contains(&"GREETING".to_string()));
    assert!(!keys.iter().any(|k| k.eq_ignore_ascii_case("https_proxy")));
    assert!(!keys.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
    let out = fx.run(&["sh", "-c", "echo $HOME:$GREETING"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("{}:hi", fx.scratch().display())
    );
}

#[test]
fn exit_codes_and_dry_run() {
    let fx = fixture(SH);
    let out = fx.run(&["sh", "-c", "exit 7"]);
    assert_eq!(out.exit_code, Some(7));
    assert!(!out.success());
    assert!(fx.run(&["sh", "-c", "true"]).success());
    let dry = fx
        .sandbox
        .run(
            &argv_of(&["sh", "-c", "touch scratch/dry"]),
            &RunOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(dry.decision.allowed && dry.dry_run && !dry.executed);
    assert!(!fx.scratch().join("dry").exists());
}
