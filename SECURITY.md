# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub (Security, then "Report a
vulnerability") or by email to the maintainer at adeoluo@hotmail.com. Do not open public
issues for sandbox escapes.

A useful report includes the policy file, the request (argv or file operation), the OS and
kernel version, the output of `agent-sandbox inspect --policy <file>`, and what the request
achieved that the policy should have prevented.

## Scope

In scope:

- A request the engine allows that the policy, as documented, should deny.
- A path, symlink, or Unicode form that escapes the filesystem rules.
- A way for a command running under an active OS backend to write outside the writable
  roots, or (macOS) use the network, or (Linux, Landlock ABI 4+) open a TCP connection.
- Audit log modifications that `audit verify` does not detect, other than tail truncation
  without `--expect-head` and full-chain rewrites (both documented).
- Resource limits that do not apply as documented.

Out of scope, because they are documented limitations: anything an allowed interpreter can
do that the per-OS table in the README lists as not enforced; behavior with no OS backend;
`setsid` escapes from the process group; running as root.

## Controls in this repository

- **SAST:** CodeQL for Rust (`.github/workflows/codeql.yml`).
- **Dependencies:** versions are pinned in `Cargo.lock`; updates are reviewed and applied by hand.
- **Lints:** `cargo clippy --all-targets -D warnings` on Linux and macOS.
- **Unsafe code:** limited to libc and syscall wrappers in `limits.rs`, `audit.rs`,
  `sandbox.rs`, and `isolation/linux.rs`, each with a `SAFETY` comment.
