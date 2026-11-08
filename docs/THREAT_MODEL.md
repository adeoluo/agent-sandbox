# Threat Model - Agent Sandbox

The sandbox sits between an AI agent and the operating system. It assumes the agent can be
manipulated (by prompt injection in anything it reads, a poisoned tool, or a plain model error)
and limits what a manipulated agent can do. It does not try to detect the manipulation itself.

## Assets

- Files outside the workspace, above all credentials (`~/.ssh`, `~/.aws`, `.env`, tokens in the
  environment) and the source tree the agent works on.
- The host's availability: CPU time, memory, the process table, disk and output buffers.
- Network reachability, which is both an exfiltration channel and a path to other systems.
- The audit log: the record of what the agent asked for and what happened.

## Trust boundaries

1. **Agent to sandbox.** Every argv string, path, stdin byte and file body is untrusted. Any
   argument that can name a file is resolved fully (symlinks, `..`, `~`) before it is checked.
2. **Policy file.** Trusted but validated: unknown keys, relative pinned paths, empty names, zero
   limits, deceptive characters and a writable root of `/` are load errors.
3. **Sandbox to child.** The child gets a resolved absolute program path, an allowlisted
   environment, its own process group, rlimits and, where available, a kernel sandbox it cannot
   remove. The parent never runs a shell.
4. **Audit log.** Written only by the sandbox; anyone with the file can verify the chain, and an
   externally stored head hash also detects truncation.

## Threats

| Threat | Vector | Impact | Mitigation |
|---|---|---|---|
| Destructive commands | `rm -rf`, `find -delete`, writes over source files | Data loss | Executable allowlist with argument patterns; global denied arguments; writes outside writable roots blocked by Seatbelt or Landlock even inside `sh -c` |
| Credential reads | `cat ~/.ssh/id_ed25519`, `cat .env`, environment variables | Credential theft | `denied_paths` checked after resolution; environment allowlist; kernel read confinement on Linux, kernel denial of `denied_paths` on macOS |
| Network exfiltration | `curl -d @file`, `nc`, sockets from an allowed interpreter | Data leaves the host | Engine network heuristics; macOS denies all network in the kernel; Linux denies TCP bind and connect (Landlock ABI 4 and later); proxy variables removed |
| Interpreter pivot | An allowed `sh`, `python3`, `git -c core.sshCommand=...` | The engine cannot see inner actions | Interpreters are off the shipped profiles' allowlists; pivot flags such as `git -c` and `--upload-pack` are denied; the OS backend still confines writes and network |
| Path disguises | Symlinks, `..`, Unicode look-alikes, bidi controls, `--opt=PATH` | Policy bypass | Full resolution with `lstat` and `readlink`; deceptive characters rejected; `O_NOFOLLOW` on the final component of in-process file operations |
| Resource exhaustion | Fork bombs, `yes`, large allocations, busy loops | Host denial of service | rlimits, a 5 ms RSS watchdog on macOS, wall-clock timeout with process-group kill, output caps, a process-group sweep after exit |
| Escape from supervision | `setsid`, daemonizing, a sandboxed caller that disables `sandbox-exec` | The process outlives cleanup or runs without a backend | Partly: Landlock and Seatbelt still apply after `setsid`; `required` mode refuses to run without a backend |
| Audit tampering | Editing, reordering or truncating the log | Hidden actions | SHA-256 hash chain; `audit verify --expect-head` detects truncation; heads are not signed |
| Over-permissive policy | Allowing an interpreter or a broad writable root | Silent over-permission | Strict policy validation; `inspect` and `check` print the deciding rule and the enforcement level |
| Time-of-check to time-of-use | A path swapped between the check and the open | Bypass of a path rule | `O_NOFOLLOW` in the file API; the OS backends re-check writes in the kernel; hard links are not detected |
| Malicious dependency | A compromised crate | Code execution | Versions pinned in `Cargo.lock`; CodeQL for Rust; `clippy -D warnings` |

## Standards mapping

Agents are the subject of this project, so each threat is mapped to the OWASP Top 10 for Agentic
Applications 2026 as well as the OWASP Top 10 for LLM Applications 2026 and MITRE ATLAS
v2026.10. ATLAS IDs and names were checked against `ATLAS.yaml` from the
[v2026.10 release of mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data/releases).

| Threat | OWASP LLM 2026 | OWASP Agentic 2026 | MITRE ATLAS v2026.10 | Role of this project |
|---|---|---|---|---|
| A hijacked or misbehaving agent issues the requests (the upstream cause) | LLM01:2026 Prompt Injection; LLM03:2026 Excessive Agency | ASI01 Agent Goal Hijack; ASI10 Rogue Agents | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0112.000 Machine Compromise: Local AI Agent | Limits the blast radius; does not detect the hijack |
| Destructive commands | LLM03:2026 Excessive Agency; LLM10:2026 Improper Output Handling | ASI02 Tool Misuse and Exploitation; ASI05 Unexpected Code Execution | AML.T0053 AI Agent Tool Invocation; AML.T0101 Data Destruction via AI Agent Tool Invocation; AML.T0050 Command and Scripting Interpreter | Prevents (engine and kernel) |
| Credential reads | LLM02:2026 Sensitive Information Disclosure | ASI03 Identity and Privilege Abuse | AML.T0037 Data from Local System; AML.T0055 Unsecured Credentials | Prevents (engine; kernel on Linux and for `denied_paths` on macOS) |
| Network exfiltration | LLM02:2026 Sensitive Information Disclosure | ASI02 Tool Misuse and Exploitation | AML.T0086 Exfiltration via AI Agent Tool Invocation | Prevents where a backend is active (all network on macOS, TCP on Linux) |
| Interpreter pivot | LLM03:2026 Excessive Agency | ASI05 Unexpected Code Execution | AML.T0050 Command and Scripting Interpreter; AML.T0102 Generate Malicious Commands | Partly: confined by the OS backend only |
| Path disguises | LLM03:2026 Excessive Agency | ASI02 Tool Misuse and Exploitation | AML.T0107 Exploitation for Defense Evasion | Prevents; 15 path escape tests |
| Resource exhaustion | LLM06:2026 Unbounded Consumption | ASI02 Tool Misuse and Exploitation | AML.T0034.002 Cost Harvesting: Agentic Resource Consumption; AML.T0029 Denial of AI Service | Prevents with limits (AML.M0036 Limit AI Workload Resource Consumption) |
| Escape from supervision | | ASI05 Unexpected Code Execution | AML.T0105 Escape to Host; AML.T0097 Virtualization/Sandbox Evasion | Partly; see Limitations in the README |
| Audit tampering | | ASI10 Rogue Agents | AML.T0138 Indicator Removal | Detects (AML.M0024 AI Telemetry Logging and Monitoring) |
| Malicious dependency | LLM04:2026 Supply Chain | ASI04 Agentic Supply Chain Vulnerabilities | AML.T0010.001 Supply Chain Compromise: Software | Mitigates with a lockfile and CodeQL |

The sandbox implements AML.M0028 Enforce Access Controls for AI Agent Tools (the per-profile
allowlist), AML.M0032 Segmentation of AI Agent Components (the child process boundary and the
OS backend), AML.M0036 Limit AI Workload Resource Consumption and AML.M0024 AI Telemetry Logging
and Monitoring (the audit log). It does not implement AML.M0029 Human In-the-Loop for AI Agent
Actions: there is no approval prompt. It does not address ASI06 Memory and Context Poisoning,
ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures or ASI09 Human-Agent Trust
Exploitation, which concern the agent's context, its peers and its users rather than its
access to the host. In NIST AI 600-1
(Generative AI Profile) terms it addresses the Information Security risk.

## Residual risk

- An allowed interpreter can do anything the OS backend does not confine; with no backend it
  can do anything the user can.
- Reads outside the read roots are not confined on macOS, and UDP and raw sockets are not
  confined on Linux.
- The audit log is tamper-evident relative to a stored head hash, not tamper-proof.
- The per-OS enforcement table and the full list of limitations are in the
  [README](../README.md#limitations).
