# ADR 0004: Seatbelt on macOS, Landlock on Linux, no namespaces in v0.1

- Status: accepted
- Date: 2026-11-01

## Context

The core must work on macOS and Linux without root. Options considered:

| Option | Unprivileged | Filesystem | Network | Notes |
|---|---|---|---|---|
| Linux user + mount + net namespaces | often blocked | yes (bind mounts) | yes (empty netns) | Ubuntu (since 24.04) restricts unprivileged user namespaces through AppArmor by default; many containers block `unshare` via seccomp |
| Linux Landlock | yes | yes (allow-list of trees) | TCP bind/connect from ABI 4 (kernel 6.7) | no root, no setup, inherited by children, cannot be undone by the child |
| Linux seccomp-bpf | yes | no (paths are not visible to BPF) | coarse (block `socket`) | needs an architecture-specific filter |
| macOS `sandbox-exec` (Seatbelt) | yes | yes | yes | marked deprecated by Apple, still shipped and used by major tools; cannot nest |
| macOS App Sandbox / Endpoint Security | no | yes | yes | requires entitlements or signing |

## Decision

- **macOS:** wrap the program with `sandbox-exec -p <profile>`. The generated profile is
  `allow default` minus: all network operations (when the policy denies network), all
  file writes outside the writable roots and a few device files, and all reads and writes
  under denied paths. Reads outside the read roots are not denied at the OS level, because
  a dynamic macOS binary touches many system paths (dyld cache, frameworks, preferences)
  that would make the profile fragile; the engine checks reads instead.
- **Linux:** build a Landlock ruleset in the parent (read roots get execute/read rights,
  writable roots get all handled rights, plus `/dev/null` and the urandom devices), then
  call `prctl(PR_SET_NO_NEW_PRIVS)` and `landlock_restrict_self` in the child between
  `fork` and `exec`. On ABI 4 and newer, TCP bind and connect are denied when the network
  policy is deny. Landlock rules are allow-only, so `denied_paths` inside a read root are
  enforced by the engine, not the kernel.
- **Namespaces:** not used in v0.1. They are the stronger tool where available and are on
  the roadmap as an optional backend, but making them the core would fail on the default
  configuration of the most common CI runner and on macOS.
- `isolation.mode` is `auto` (use the backend if the probe succeeds, report otherwise),
  `required` (refuse to run without it), or `off`.

## Consequences

- Kernel-level write confinement and network denial on both platforms without root.
- Clear, documented gaps: UDP and non-TCP sockets on Linux; reads outside the read roots
  on macOS; `denied_paths` inside a read root on Linux. Each is listed in the README.
- `sandbox-exec` adds about 8.4 ms per spawn on the development machine; Landlock adds no measurable cost (see README).
