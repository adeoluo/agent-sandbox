//! OS-level isolation backends. The decision engine checks a request before it runs; these
//! backends constrain the process while it runs, so a command that is allowed (for example
//! an interpreter) still cannot write outside the writable roots or open network sockets.
//!
//! * macOS: `sandbox-exec` with a generated Seatbelt profile.
//! * Linux: Landlock (filesystem from ABI 1, TCP bind/connect from ABI 4).
//! * Elsewhere, or when unavailable: engine-only enforcement, reported as such.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SandboxError};
use crate::policy::{CompiledPolicy, IsolationMode, NetworkMode};

#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;

/// What is enforced, and by what, for one execution. Written to the audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    pub backend: String,
    pub filesystem: String,
    pub network: String,
    pub memory: String,
    pub cpu: String,
    pub processes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Backend state prepared in the parent before spawning.
#[derive(Debug)]
pub enum Prepared {
    None,
    /// Run the program through `sandbox-exec -p <profile>`.
    Seatbelt {
        profile: String,
    },
    #[cfg(target_os = "linux")]
    Landlock(linux::Ruleset),
}

const ENGINE_FS: &str = "engine: path arguments checked before spawn";

fn engine_network(policy: &CompiledPolicy) -> String {
    match policy.policy.network.mode {
        NetworkMode::Allow => "allowed".into(),
        NetworkMode::Deny => {
            "engine: network clients and URL arguments denied; proxy variables removed".into()
        }
    }
}

/// Prepares the OS backend for one execution of `program`.
pub fn prepare(policy: &CompiledPolicy, program: &Path) -> Result<(Prepared, Enforcement)> {
    let mut report = Enforcement {
        backend: "none".into(),
        filesystem: ENGINE_FS.into(),
        network: engine_network(policy),
        ..Default::default()
    };
    let mode = policy.policy.isolation.mode;
    if mode == IsolationMode::Off {
        report.notes.push("isolation.mode is off".into());
        return Ok((Prepared::None, report));
    }
    match backend(policy, program, &mut report) {
        Ok(prepared) => Ok((prepared, report)),
        Err(why) if mode == IsolationMode::Required => Err(SandboxError::IsolationUnavailable(why)),
        Err(why) => {
            report
                .notes
                .push(format!("OS isolation unavailable: {why}"));
            Ok((Prepared::None, report))
        }
    }
}

#[cfg(target_os = "macos")]
fn backend(
    policy: &CompiledPolicy,
    _program: &Path,
    report: &mut Enforcement,
) -> std::result::Result<Prepared, String> {
    if !macos::available() {
        return Err("sandbox-exec is missing or cannot apply a profile in this context".into());
    }
    report.backend = "sandbox-exec".into();
    report.filesystem = "os: writes confined to writable roots, denied paths unreadable; reads outside read roots checked by the engine only".into();
    if policy.policy.network.mode == NetworkMode::Deny {
        report.network = "os: all network operations denied".into();
    }
    Ok(Prepared::Seatbelt {
        profile: macos::profile(policy),
    })
}

#[cfg(target_os = "linux")]
fn backend(
    policy: &CompiledPolicy,
    program: &Path,
    report: &mut Enforcement,
) -> std::result::Result<Prepared, String> {
    let ruleset = linux::Ruleset::build(policy, program).map_err(|e| e.to_string())?;
    report.backend = format!("landlock-abi-{}", ruleset.abi);
    report.filesystem = "os: reads limited to read roots, writes to writable roots; denied paths inside an allowed root checked by the engine only".into();
    if policy.policy.network.mode == NetworkMode::Deny {
        if ruleset.network {
            report.network = "os: TCP bind and connect denied (UDP and other families not covered by Landlock); engine checks also apply".into();
        } else {
            report
                .notes
                .push("Landlock ABI < 4: network is not enforced by the kernel".into());
        }
    }
    Ok(Prepared::Landlock(ruleset))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn backend(
    _policy: &CompiledPolicy,
    _program: &Path,
    _report: &mut Enforcement,
) -> std::result::Result<Prepared, String> {
    Err("no OS isolation backend for this platform".into())
}
