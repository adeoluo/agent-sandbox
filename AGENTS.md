# AGENTS.md

Working notes for coding agents and contributors in **Agent Sandbox**. The [README](README.md)
explains what the project does and why; this file explains how to change it safely.

## Project

A policy-based sandbox for AI agent tool calls: declarative rules for commands, arguments, paths, environment, network, and resources, with explained decisions, OS-level enforcement where available, and a tamper-evident audit log.

## Layout

- `benches/`: Criterion benchmarks
- `docs/`: documentation, architecture diagram source and render, design records
- `examples/`: runnable examples and sample configuration
- `policies/`: sandbox policy files used by examples and tests
- `scripts/`: maintenance scripts (release, assets, data)
- `src/`: library and service source
- `tests/`: test suite

Key modules:

- `src/audit.rs`: Append-only JSON Lines audit log with a SHA-256 hash chain.
- `src/engine.rs`: The decision engine: evaluates a request against a compiled policy and returns an allow/deny decision naming the rule that produced it.
- `src/error.rs`
- `src/isolation/linux.rs`: Landlock ruleset construction (Linux 5.13+), using raw syscalls.
- `src/isolation/macos.rs`: Seatbelt profile generation for `sandbox-exec` (macOS).
- `src/isolation/mod.rs`: OS-level isolation backends.
- `src/lib.rs`: # agent-sandbox A policy-based sandbox for running AI agent tool calls.
- `src/limits.rs`: Resource limits applied in the child between `fork` and `exec`, plus the process accounting helpers they need.
- `src/main.rs`
- `src/paths.rs`: Path handling: deceptive-character checks, placeholder expansion, and symlink-aware resolution that defeats `..` and symlink escapes.
- `src/pattern.rs`: A small, linear-time glob matcher used for argument and environment patterns.
- `src/policy.rs`: Declarative policy: the on-disk schema (`Policy`) and its resolved form (`CompiledPolicy`).
- `src/sandbox.rs`: The sandbox: decides, executes under the policy, supervises, and audits.
- `src/server.rs`: JSON Lines over stdio, so agents written in any language can call the sandbox.

## Commands

| Command | Purpose |
|---|---|
| `make help` | Show this help |
| `make build` | Debug build |
| `make release` | Optimized build at target/release/agent-sandbox |
| `make fmt` | Format the code |
| `make lint` | Format check and clippy (warnings are errors) |
| `make test` | Run every test |
| `make coverage` | Line coverage with an 85 percent gate (needs cargo-llvm-cov) |
| `make bench` | Criterion benchmarks |
| `make latency` | Percentile table used in the README |
| `make inspect` | Show what this OS enforces for the sample policy |
| `make demo` | Python client over the stdio protocol |
| `make diagram` | Render the architecture diagram to SVG (needs mmdc) |
| `make clean` | Remove build output and scratch directories |
| `make all` | Local gate (mirrors CI) |
| `make changelog` | Regenerate CHANGELOG.md from Conventional Commits (git-cliff) |
| `make cut-release` | Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional) |

Run the full local gate (`make all`) before committing; CI runs the same checks.

## Conventions

- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`).
  The changelog and the next version number are derived from them.
- Every number quoted in the README is produced by a command in this repository. When behavior
  changes, rerun that command and update the number in the same commit.
- When a component is added, removed or renamed, update `docs/architecture/architecture.mmd`
  and re-render `architecture.svg` so the diagram matches the code.
- README sections keep their fixed order. Prose avoids em and en dashes and promotional wording.
- Tests accompany behavior changes; a bug fix comes with a test that fails without it.
- Releases are cut with `make cut-release`.

## Rust notes

- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.
- No `unwrap()` in library code paths that can fail at runtime; return a typed error.
- Unsafe code is limited to the places that need a syscall and carries a `SAFETY:` comment.
