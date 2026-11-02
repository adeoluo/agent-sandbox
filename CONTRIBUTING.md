# Contributing

## Development setup

You need a stable Rust toolchain (1.85 or newer) on macOS or Linux.

```bash
make build     # debug build
make all       # local gate: fmt check, clippy with warnings as errors, all tests
make coverage  # needs cargo-llvm-cov; see below
make latency   # regenerate the benchmark table
make diagram   # re-render docs/architecture/architecture.svg (needs Node.js for npx)
```

The Makefile points `TMPDIR` at `target/tmp` so test fixtures stay inside the project.

Coverage uses `cargo-llvm-cov`. With `rustup`, install the `llvm-tools-preview` component.
With a Homebrew toolchain, install `llvm` and `cargo-llvm-cov` and point the tool at it:

```bash
export LLVM_COV=$(brew --prefix llvm)/bin/llvm-cov
export LLVM_PROFDATA=$(brew --prefix llvm)/bin/llvm-profdata
make coverage
```

## Workflow

1. Branch from `main` (`feat/...`, `fix/...`, `docs/...`).
2. Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
3. Keep pull requests focused. CI must be green on both Ubuntu and macOS before merge.

## Standards

- Every new rule in the engine comes with rows in the allow/deny matrix
  (`tests/policy_engine.rs`), and every new escape class with a test in
  `tests/path_escape.rs` or `tests/adversarial.rs`.
- Code between `fork` and `exec` (the `pre_exec` closure) must stay async-signal-safe:
  no allocation, no locks, only syscalls on data prepared in the parent.
- Any change to what is enforced on an OS updates the per-OS table in the README and the
  `Enforcement` strings, so documentation and audit records never overstate a guarantee.
- Non-obvious design choices get an ADR in `docs/adr/`.
