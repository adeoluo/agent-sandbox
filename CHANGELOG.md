# Changelog

## v0.1.0 (2026-11-01)

First release.

- Declarative TOML or JSON policies: executable allowlist with argument patterns, global
  denied arguments and executables, read, writable, and denied paths, scratch directory,
  environment allowlist, network mode, resource limits, isolation mode.
- Decision engine returning the deciding rule and a reason; symlink-aware path
  resolution; rejection of deceptive Unicode.
- Execution with rlimits (CPU, address space on Linux, processes, file size, open files),
  wall-clock timeout, output caps, process-group cleanup, and an RSS watchdog on macOS.
- OS backends: Seatbelt via `sandbox-exec` on macOS; Landlock (filesystem, and TCP from
  ABI 4) on Linux.
- Hash-chained JSON Lines audit log with `audit verify` and `--expect-head`.
- CLI (`run`, `check`, `audit verify`, `serve`, `inspect`), Rust library, JSON Lines
  stdio protocol, and a Python client example.
- 92 tests including property tests and an adversarial suite; benchmarks.
