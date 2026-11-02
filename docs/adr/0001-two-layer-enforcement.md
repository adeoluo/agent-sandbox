# ADR 0001: Two enforcement layers, a decision engine and an OS backend

- Status: accepted
- Date: 2026-11-01

## Context

An agent tool call arrives as an argv vector. Two different questions need answers:

1. Should this request run at all? This needs a readable reason ("`rm` may only write
   inside the scratch directory") that can be returned to the agent and logged.
2. If it runs, what can the process actually do? An allowed interpreter (`sh -c`, `python
   -c`) can do anything its argument string says, which no argv inspection can see.

A single mechanism does not answer both. Kernel sandboxes give strong guarantees but
report failures as `EPERM` deep inside the child, with no rule name. Argv inspection gives
good explanations but is bypassed by any interpreter or by a tool with an unexpected flag.

## Decision

Use both layers, each for what it is good at:

- The **decision engine** (`engine.rs`) evaluates every request before spawning. It owns
  the allowlist, argument patterns, path checks, and network-client heuristics, and returns
  the matching rule and a reason. It is pure (apart from `stat`/`readlink` during path
  resolution), fast, and fully unit tested.
- The **OS backend** (`isolation/`) constrains the process that does run: Seatbelt via
  `sandbox-exec` on macOS, Landlock on Linux. It enforces the filesystem and network
  rules the engine cannot see through interpreters.
- **Resource limits** (rlimits, wall-clock timeout, output caps, process-group kill) apply
  in both cases.

Every execution reports an `Enforcement` record stating which layer enforced what, so the
audit log never implies a guarantee that was not in place.

## Consequences

- Denials are explainable and cheap (no process is created).
- When the OS backend is unavailable (nested sandbox, old kernel, container seccomp), the
  engine still applies; `isolation.mode = "required"` turns that situation into a refusal.
- Policies have two kinds of rules to reason about. The README and `inspect` output state
  plainly which rules each OS enforces at the kernel level.
