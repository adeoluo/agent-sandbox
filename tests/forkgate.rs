//! The seccomp fork gate, driven directly. It needs no privilege (only `no_new_privs`), so
//! this runs for the ordinary CI user as well as for root, on x86-64 and arm64.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_sandbox::forkgate::{self, Gate};
use agent_sandbox::limits::group_process_count;

/// Spawns `sh -c script` as a process-group leader behind a gate allowing `max` tasks and
/// returns (exit code, peak tasks seen in the group while it ran, refused forks).
fn run_gated(script: &str, max: u64) -> (Option<i32>, u64, u64) {
    let gate = Gate::new().unwrap();
    let side = gate.child_side();
    let mut cmd = Command::new("sh");
    cmd.args(["-c", script])
        .process_group(0)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `arm` only makes async-signal-safe system calls on data built in the parent.
    unsafe { cmd.pre_exec(move || side.arm()) };
    let mut child = cmd.spawn().unwrap();
    let pgid = child.id() as libc::pid_t;
    let supervisor = gate.supervise(pgid, max).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut peak = 0;
    let status = loop {
        peak = peak.max(group_process_count(pgid));
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "gated command did not finish");
        std::thread::yield_now();
    };
    // Background children outlive the shell, so count once more before cleaning up.
    peak = peak.max(group_process_count(pgid));
    // SAFETY: killpg with a positive group id; ESRCH is fine.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
    (status.code(), peak, supervisor.refusals())
}

#[test]
fn gate_holds_the_group_at_the_limit() {
    if !forkgate::available() {
        eprintln!("skipped: no seccomp user-notification listener on this host");
        return;
    }
    let (_, peak, refused) = run_gated(
        "i=0; while [ $i -lt 24 ]; do sleep 1 & i=$((i+1)); done; wait",
        6,
    );
    assert!(peak >= 2, "the spawner was never observed: {peak}");
    assert!(peak <= 6, "group held {peak} tasks under a limit of 6");
    assert!(refused >= 1, "no fork was refused");
}

#[test]
fn gate_lets_a_command_under_the_limit_run_normally() {
    if !forkgate::available() {
        return;
    }
    let (code, peak, refused) = run_gated("for i in 1 2 3 4 5; do /bin/true; done; exit 3", 4);
    assert_eq!(code, Some(3));
    assert!(peak <= 4);
    assert_eq!(refused, 0, "sequential children must never be refused");
}

#[test]
fn gate_refuses_leaving_the_counted_group() {
    if !forkgate::available() {
        return;
    }
    // Outside the gate a non-leader may always start its own group; inside, it may not.
    let own_group = "perl -e 'exit(setpgrp(0, 0) ? 0 : 7)'";
    assert_eq!(
        Command::new("sh")
            .args(["-c", own_group])
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    let (code, _, _) = run_gated(own_group, 4);
    assert_eq!(code, Some(7), "setpgid succeeded inside the gate");
}
