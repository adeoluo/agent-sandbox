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

#[test]
fn fork_bomb_is_bounded() {
    let fx = fixture(&with_limits("timeout_ms = 3000\nmax_processes = 16"));
    let start = Instant::now();
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
    assert!(enforcement.processes.contains("RLIMIT_NPROC"));
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
