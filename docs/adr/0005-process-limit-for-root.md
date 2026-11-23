# ADR 0005: A process limit for root is kernel-enforced or the command is refused

- Status: accepted
- Date: 2026-11-23

## Context

`limits.max_processes` is implemented with `RLIMIT_NPROC`. The kernel does not apply that
limit to `uid 0` (Linux checks it only for users other than the initial root user without
`CAP_SYS_RESOURCE` or `CAP_SYS_ADMIN`; XNU skips it for root). Agents commonly run as root
inside containers, where cgroups are mounted read-only, so the configured limit did nothing.

After the 0.1.2 release, two fallbacks were added on `main`: a `pids.max` cgroup attached after the command had been
spawned, and a parent thread that polled `/proc` every millisecond and killed the process
group once it had grown past the limit. Both were wrong:

- The cgroup was joined after `exec`, so the command could fork before it was moved, and the
  leaf was created under the caller's own cgroup after enabling `pids` in that cgroup's
  `cgroup.subtree_control`. A cgroup that holds processes becomes a threaded domain when that
  is done, its children are `domain invalid`, and moving a process into one fails with
  `EOPNOTSUPP`. The path never engaged outside the real root cgroup.
- The watchdog reacts after the limit is exceeded and depends on how quickly the host
  answers `/proc`. An external reviewer ran the suite as root in a container without writable
  cgroups and saw a spawner of 48 processes finish under a limit of 8.

## Decision

For root, use the first of these that works, decided before the command exists:

1. A `pids.max` leaf cgroup, created under the caller's cgroup or beside it and accepted only
   if the kernel reports it as type `domain`. The forked child writes itself into the leaf
   before `exec`. `cgroup.subtree_control` is edited only in the real root cgroup.
2. A seccomp filter installed in the child that returns `SECCOMP_RET_USER_NOTIF` for `clone`,
   `clone3`, `fork` and `vfork`. A supervisor thread in the sandbox receives each request
   while the caller is blocked, counts the live tasks of the process group, and answers
   continue or `EAGAIN`. The filter returns `EPERM` for `setsid` and `setpgid` so a task
   cannot leave the group being counted, and refuses system calls of any other architecture
   (and the x32 ABI) because their numbers would bypass it.
3. Otherwise refuse: `run` returns `SandboxError::LimitUnenforceable` without spawning.

The polling watchdog is removed.

## Consequences

- The limit is a ceiling, not a reaction. Sampled from outside, a spawner asking for 48 tasks
  under a limit of 8 peaked at 8 with either mechanism.
- After approving a fork the supervisor waits up to 5 ms for the new task to appear before
  handling the next request, so concurrent forkers are not each checked against a stale
  count. Each task creation costs one `/proc` scan under the gate.
- Commands that call `setsid` or `setpgid` (daemonizing, interactive job control) fail under
  the gate. They are unaffected under a cgroup or as a non-root user.
- On macOS as root, on Linux before 5.5, and in runtimes without seccomp listeners, a policy
  that sets `max_processes` cannot run commands as root. The operator has to run as another
  user or drop the limit knowingly; the sandbox no longer drops it silently.
- If the supervisor thread stops, the kernel fails every pending and later task creation with
  `ENOSYS`, so the failure mode is "cannot fork", not "unlimited".
- The gate is not used for non-root users, where `RLIMIT_NPROC` already applies. That limit
  stays per user and therefore approximate for one sandbox.
