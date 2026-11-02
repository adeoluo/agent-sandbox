use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use agent_sandbox::isolation;
use agent_sandbox::{
    AuditLog, CompileOptions, CompiledPolicy, Request, RunOptions, Sandbox, server, verify,
};

/// Exit status when the policy denies a request.
const EXIT_DENIED: u8 = 126;
/// Exit status when the wall-clock timeout fires (same as coreutils `timeout`).
const EXIT_TIMEOUT: u8 = 124;

#[derive(Parser)]
#[command(
    name = "agent-sandbox",
    version,
    about = "Run AI agent tool calls under a declarative policy."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct PolicyArgs {
    /// Policy file (.toml or .json).
    #[arg(long, short)]
    policy: PathBuf,
    /// Workspace directory used for relative paths and `{workspace}` (default: current dir).
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Append every decision and execution to this hash-chained JSON Lines log.
    #[arg(long)]
    audit: Option<PathBuf>,
}

impl PolicyArgs {
    fn sandbox(&self) -> Result<Sandbox> {
        let opts = CompileOptions::from_env(self.workspace.clone())?;
        let policy = CompiledPolicy::load(&self.policy, &opts)
            .with_context(|| format!("loading policy {}", self.policy.display()))?;
        let mut sandbox = Sandbox::new(policy);
        if let Some(path) = &self.audit {
            sandbox = sandbox.with_audit(AuditLog::open(path)?);
        }
        Ok(sandbox)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate and run a command under the policy.
    Run {
        #[command(flatten)]
        policy: PolicyArgs,
        /// Working directory for the command.
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Decide and audit, but do not execute.
        #[arg(long)]
        dry_run: bool,
        /// Print the full outcome as JSON instead of passing output through.
        #[arg(long)]
        json: bool,
        /// Command and arguments (after `--`).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Evaluate a request and print the decision (exit 0 if allowed, 1 if denied).
    Check {
        #[command(flatten)]
        policy: PolicyArgs,
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Check reading this path instead of a command.
        #[arg(long, conflicts_with_all = ["write", "argv"])]
        read: Option<String>,
        /// Check writing this path instead of a command.
        #[arg(long, conflicts_with = "argv")]
        write: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Audit log operations.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Serve JSON Lines requests on stdin/stdout.
    Serve {
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Show the resolved policy and what this OS enforces for it.
    Inspect {
        #[command(flatten)]
        policy: PolicyArgs,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify the hash chain of an audit log.
    Verify {
        log: PathBuf,
        /// Fail unless the final record hash equals this value (detects truncation).
        #[arg(long)]
        expect_head: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("agent-sandbox: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Run {
            policy,
            cwd,
            dry_run,
            json,
            argv,
        } => {
            let sandbox = policy.sandbox()?;
            let outcome = sandbox.run(
                &argv,
                &RunOptions {
                    cwd,
                    stdin: None,
                    dry_run,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                std::io::stdout().write_all(&outcome.stdout)?;
                std::io::stderr().write_all(&outcome.stderr)?;
                if !outcome.decision.allowed {
                    eprintln!(
                        "agent-sandbox: denied by {}: {}",
                        outcome.decision.rule, outcome.decision.reason
                    );
                } else if dry_run {
                    eprintln!(
                        "agent-sandbox: dry run, allowed by {}",
                        outcome.decision.rule
                    );
                }
                if outcome.timed_out {
                    eprintln!(
                        "agent-sandbox: killed after the {} ms timeout",
                        sandbox.policy().limits().timeout_ms
                    );
                }
                if outcome.memory_exceeded {
                    eprintln!("agent-sandbox: killed for exceeding the memory limit");
                }
                if outcome.stdout_truncated || outcome.stderr_truncated {
                    eprintln!(
                        "agent-sandbox: output truncated at {} bytes per stream",
                        sandbox.policy().limits().max_output_bytes
                    );
                }
            }
            let code = if !outcome.decision.allowed {
                EXIT_DENIED
            } else if outcome.timed_out {
                EXIT_TIMEOUT
            } else if let Some(code) = outcome.exit_code {
                code as u8
            } else if let Some(signal) = outcome.signal {
                128u8.saturating_add(signal as u8)
            } else {
                0
            };
            Ok(ExitCode::from(code))
        }
        Command::Check {
            policy,
            cwd,
            read,
            write,
            json,
            argv,
        } => {
            let sandbox = policy.sandbox()?;
            let request = match (read, write) {
                (Some(path), _) => Request::Read { path, cwd },
                (_, Some(path)) => Request::Write { path, cwd },
                _ if argv.is_empty() => {
                    anyhow::bail!("give a command after `--`, or --read/--write PATH")
                }
                _ => Request::Exec { argv, cwd },
            };
            let decision = sandbox.check(&request)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                let verdict = if decision.allowed { "ALLOW" } else { "DENY" };
                println!("{verdict} {}: {}", decision.rule, decision.reason);
            }
            Ok(if decision.allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Audit {
            command:
                AuditCommand::Verify {
                    log,
                    expect_head,
                    json,
                },
        } => {
            let report = verify(&log, expect_head.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if report.ok {
                println!("OK {} records, head {}", report.records, report.head_hash);
            } else {
                println!(
                    "TAMPERED at line {}: {} ({} valid records before it)",
                    report.line.unwrap_or(0),
                    report.error.as_deref().unwrap_or("unknown"),
                    report.records
                );
            }
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Serve { policy } => {
            let sandbox = policy.sandbox()?;
            let stdin = std::io::stdin();
            server::serve(&sandbox, stdin.lock(), std::io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Inspect { policy } => {
            let sandbox = policy.sandbox()?;
            let p = sandbox.policy();
            let probe = p
                .path_dirs
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("/usr/bin"));
            let (_, mut enforcement) = isolation::prepare(p, &probe.join("true"))?;
            let plan = agent_sandbox::limits::plan(p.limits());
            enforcement.memory = plan.memory;
            enforcement.cpu = plan.cpu;
            enforcement.processes = plan.processes;
            enforcement.notes.extend(plan.notes);
            let view = serde_json::json!({
                "name": p.name(),
                "policy_hash": p.policy_hash,
                "workspace": p.workspace,
                "scratch": p.scratch,
                "read_roots": p.read_roots,
                "writable_roots": p.writable_roots,
                "denied_paths": p.denied_paths,
                "path": p.path_dirs,
                "executables": p.policy.exec.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
                "limits": p.policy.limits,
                "enforcement": enforcement,
            });
            println!("{}", serde_json::to_string_pretty(&view)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}
