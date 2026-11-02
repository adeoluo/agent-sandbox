//! # agent-sandbox
//!
//! A policy-based sandbox for running AI agent tool calls. A declarative policy names the
//! executables an agent may run, the arguments they may take, the filesystem roots they may
//! read and write, the environment they see, whether they may use the network, and the
//! resources they may consume. Every request is evaluated by a decision engine that returns
//! the rule that decided it, executed (when allowed) under rlimits and an OS isolation
//! backend where one is available, and recorded in a hash-chained audit log.
//!
//! ```no_run
//! use agent_sandbox::{CompileOptions, CompiledPolicy, RunOptions, Sandbox};
//!
//! let opts = CompileOptions::from_env(None).unwrap();
//! let policy = CompiledPolicy::load("policy.toml".as_ref(), &opts).unwrap();
//! let sandbox = Sandbox::new(policy);
//! let outcome = sandbox.run(&["ls".into(), "-la".into()], &RunOptions::default()).unwrap();
//! println!("{} {}", outcome.decision.rule, String::from_utf8_lossy(&outcome.stdout));
//! ```

#[cfg(not(unix))]
compile_error!("agent-sandbox supports Unix platforms (Linux and macOS) only");

pub mod audit;
pub mod engine;
pub mod error;
pub mod isolation;
pub mod limits;
pub mod paths;
pub mod pattern;
pub mod policy;
pub mod sandbox;
pub mod server;

pub use audit::{AuditLog, AuditRecord, VerifyReport, verify};
pub use engine::{Decision, Engine, Request};
pub use error::{Result, SandboxError};
pub use isolation::Enforcement;
pub use policy::{CompileOptions, CompiledPolicy, Policy};
pub use sandbox::{FileOutcome, RunOptions, RunOutcome, Sandbox};
