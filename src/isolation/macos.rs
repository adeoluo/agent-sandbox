//! Seatbelt profile generation for `sandbox-exec` (macOS).
//!
//! `sandbox-exec` is marked deprecated by Apple but remains the only user-space way to apply
//! a custom sandbox profile to an arbitrary process. The profile starts from `allow default`
//! and subtracts: all network operations (when denied), all file writes outside the
//! writable roots, and all access to denied paths. Later rules take precedence in SBPL.

use std::fmt::Write as _;
use std::path::Path;

use crate::policy::{CompiledPolicy, NetworkMode};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Device files every process may write.
const WRITABLE_DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper"];

/// Quotes a path as an SBPL string literal.
pub fn quote(path: &Path) -> String {
    let mut out = String::from("\"");
    for c in path.to_string_lossy().chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn profile(policy: &CompiledPolicy) -> String {
    let mut p = String::from("(version 1)\n(allow default)\n");
    if policy.policy.network.mode == NetworkMode::Deny {
        p.push_str("(deny network*)\n");
    }
    p.push_str("(deny file-write*)\n(allow file-write*");
    for root in &policy.writable_roots {
        let _ = write!(p, "\n  (subpath {})", quote(root));
    }
    for dev in WRITABLE_DEVICES {
        let _ = write!(p, "\n  (literal {})", quote(Path::new(dev)));
    }
    p.push_str(")\n");
    for denied in &policy.denied_paths {
        let _ = writeln!(
            p,
            "(deny file-read* file-write* (subpath {}))",
            quote(denied)
        );
    }
    p
}

/// True when `sandbox-exec` exists and can apply a profile here. Nested sandboxes are not
/// permitted, so this fails when the caller is itself sandboxed.
pub fn available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::process::Command::new(SANDBOX_EXEC)
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_specials() {
        assert_eq!(quote(Path::new("/a\"b\\c")), "\"/a\\\"b\\\\c\"");
    }
}
