//! The decision engine: evaluates a request against a compiled policy and returns an
//! allow/deny decision naming the rule that produced it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::pattern::Glob;
use crate::policy::{CompiledPolicy, ExecRule, NetworkMode};

/// Executables treated as network clients when the network mode is `deny`.
pub const NETWORK_CLIENTS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "ssh",
    "rsync", "ping", "ping6", "dig", "nslookup", "host", "aria2c", "http", "https", "xh",
];

/// Upper bound on the total size of argv, well below typical `ARG_MAX`.
pub const MAX_ARGV_BYTES: usize = 128 * 1024;

/// A request from an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Execute `argv[0]` with arguments `argv[1..]` in `cwd` (default: workspace).
    Exec {
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    /// Read a file.
    Read {
        path: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    /// Create, overwrite, or delete a file.
    Write {
        path: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
}

/// The outcome of evaluating a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    /// The rule that decided, e.g. `exec[ls]`, `filesystem.denied_paths[/home/u/.ssh]`.
    pub rule: String,
    pub reason: String,
    /// The resolved executable for allowed `Exec` requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<PathBuf>,
    /// The resolved working directory or file path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<PathBuf>,
}

impl Decision {
    fn deny(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            rule: rule.into(),
            reason: reason.into(),
            program: None,
            resolved: None,
        }
    }

    fn allow(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            rule: rule.into(),
            reason: reason.into(),
            program: None,
            resolved: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

/// Evaluates requests against one compiled policy. Cheap to construct; holds no state.
#[derive(Debug, Clone, Copy)]
pub struct Engine<'p> {
    policy: &'p CompiledPolicy,
}

type Deny = Box<Decision>;

impl<'p> Engine<'p> {
    pub fn new(policy: &'p CompiledPolicy) -> Self {
        Self { policy }
    }

    pub fn decide(&self, request: &Request) -> Decision {
        let result = match request {
            Request::Exec { argv, cwd } => self.decide_exec(argv, cwd.as_deref()),
            Request::Read { path, cwd } => self.decide_file(path, cwd.as_deref(), Access::Read),
            Request::Write { path, cwd } => self.decide_file(path, cwd.as_deref(), Access::Write),
        };
        result.unwrap_or_else(|deny| *deny)
    }

    fn cwd(&self, cwd: Option<&Path>) -> Result<PathBuf, Deny> {
        let raw = cwd.unwrap_or(&self.policy.workspace);
        if let Err(issue) = paths::check_path_text(&raw.to_string_lossy()) {
            return Err(Box::new(Decision::deny(
                "filesystem.text",
                format!("working directory {issue}"),
            )));
        }
        let resolved = paths::resolve(raw, &self.policy.workspace).map_err(|e| {
            Box::new(Decision::deny(
                "filesystem.resolve",
                format!("cannot resolve working directory: {e}"),
            ))
        })?;
        self.check_path(&resolved, Access::Read, "working directory")?;
        Ok(resolved)
    }

    fn decide_file(&self, raw: &str, cwd: Option<&Path>, access: Access) -> Result<Decision, Deny> {
        let cwd = self.cwd(cwd)?;
        let resolved = self.check_raw_path(raw, &cwd, access)?;
        let rule = match access {
            Access::Read => "filesystem.read",
            Access::Write => "filesystem.write",
        };
        let mut decision = Decision::allow(
            rule,
            format!("{} is within an allowed root", resolved.display()),
        );
        decision.resolved = Some(resolved);
        Ok(decision)
    }

    fn check_raw_path(&self, raw: &str, cwd: &Path, access: Access) -> Result<PathBuf, Deny> {
        if let Err(issue) = paths::check_path_text(raw) {
            return Err(Box::new(Decision::deny(
                "filesystem.text",
                format!("path {raw:?} {issue}"),
            )));
        }
        let expanded = paths::expand_tilde(raw, self.policy.home.as_deref());
        let resolved = paths::resolve(&expanded, cwd).map_err(|e| {
            Box::new(Decision::deny(
                "filesystem.resolve",
                format!("cannot resolve {raw:?}: {e}"),
            ))
        })?;
        self.check_path(&resolved, access, raw)?;
        Ok(resolved)
    }

    fn check_path(&self, resolved: &Path, access: Access, label: &str) -> Result<(), Deny> {
        let p = self.policy;
        if let Some(denied) = p
            .denied_paths
            .iter()
            .find(|d| paths::is_within(resolved, d))
        {
            return Err(Box::new(Decision::deny(
                format!("filesystem.denied_paths[{}]", denied.display()),
                format!("{label} resolves to {} which is denied", resolved.display()),
            )));
        }
        let writable = p
            .writable_roots
            .iter()
            .any(|r| paths::is_within(resolved, r));
        match access {
            Access::Write if !writable => Err(Box::new(Decision::deny(
                "filesystem.writable_roots",
                format!(
                    "{label} resolves to {} which is outside every writable root",
                    resolved.display()
                ),
            ))),
            Access::Read
                if !writable && !p.read_roots.iter().any(|r| paths::is_within(resolved, r)) =>
            {
                Err(Box::new(Decision::deny(
                    "filesystem.read_roots",
                    format!(
                        "{label} resolves to {} which is outside every readable root",
                        resolved.display()
                    ),
                )))
            }
            _ => Ok(()),
        }
    }

    fn decide_exec(&self, argv: &[String], cwd: Option<&Path>) -> Result<Decision, Deny> {
        let p = self.policy;
        let Some(program) = argv.first() else {
            return Err(Box::new(Decision::deny("exec.argv", "argv is empty")));
        };
        let total: usize = argv.iter().map(|a| a.len() + 1).sum();
        if total > MAX_ARGV_BYTES {
            return Err(Box::new(Decision::deny(
                "exec.argv",
                format!("argv is {total} bytes; the limit is {MAX_ARGV_BYTES}"),
            )));
        }
        for arg in argv {
            if let Err(issue) = paths::check_arg_text(arg) {
                return Err(Box::new(Decision::deny(
                    "exec.text",
                    format!("argument {arg:?} {issue}"),
                )));
            }
        }
        if let Err(issue) = paths::check_path_text(program) {
            return Err(Box::new(Decision::deny(
                "exec.text",
                format!("program {program:?} {issue}"),
            )));
        }
        let cwd = self.cwd(cwd)?;
        let invoked_path = if program.contains('/') {
            Some(paths::resolve(Path::new(program), &cwd).map_err(|e| {
                Box::new(Decision::deny(
                    "exec.resolve",
                    format!("cannot resolve {program:?}: {e}"),
                ))
            })?)
        } else {
            None
        };
        let base = match &invoked_path {
            Some(path) => path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            None => program.clone(),
        };

        if p.policy
            .deny
            .executables
            .iter()
            .any(|d| d == &base || d == program)
        {
            return Err(Box::new(Decision::deny(
                format!("deny.executables[{base}]"),
                format!("{base} is explicitly denied"),
            )));
        }
        if p.policy.network.mode == NetworkMode::Deny
            && (NETWORK_CLIENTS.contains(&base.as_str())
                || p.policy.network.clients.iter().any(|c| c == &base))
        {
            return Err(Box::new(Decision::deny(
                "network.deny",
                format!("{base} is a network client and the network policy is deny"),
            )));
        }

        let rule = self.find_rule(program, &base, invoked_path.as_deref())?;
        let expected = self.locate(rule)?;
        if let Some(invoked) = &invoked_path
            && invoked != &expected
        {
            return Err(Box::new(Decision::deny(
                format!("exec[{}]", rule.name),
                format!(
                    "{} is not the allowlisted binary {}",
                    invoked.display(),
                    expected.display()
                ),
            )));
        }

        let args = &argv[1..];
        if let Some(max) = rule.max_args
            && args.len() > max
        {
            return Err(Box::new(Decision::deny(
                format!("exec[{}].max_args", rule.name),
                format!("{} arguments given; at most {max} allowed", args.len()),
            )));
        }
        for arg in args {
            self.check_arg(rule, arg)?;
        }
        let mut options_ended = false;
        for arg in args {
            for candidate in path_candidates(arg, rule.writes, options_ended, &cwd) {
                let access = if rule.writes && candidate.operand {
                    Access::Write
                } else {
                    Access::Read
                };
                self.check_raw_path(&candidate.text, &cwd, access)?;
            }
            if arg == "--" {
                options_ended = true;
            }
        }

        let mut decision = Decision::allow(
            format!("exec[{}]", rule.name),
            format!(
                "{} is allowlisted and every argument passed the policy",
                rule.name
            ),
        );
        decision.program = Some(expected);
        decision.resolved = Some(cwd);
        Ok(decision)
    }

    fn find_rule(
        &self,
        program: &str,
        base: &str,
        invoked: Option<&Path>,
    ) -> Result<&'p ExecRule, Deny> {
        let p = self.policy;
        let rule = p.policy.exec.iter().find(|r| {
            r.name == base
                || match (invoked, &r.path) {
                    (Some(invoked), Some(pinned)) => {
                        paths::resolve(Path::new(pinned), Path::new("/"))
                            .ok()
                            .as_deref()
                            == Some(invoked)
                    }
                    _ => false,
                }
        });
        rule.ok_or_else(|| {
            Box::new(Decision::deny(
                "default-deny",
                format!("{program} is not in the executable allowlist"),
            ))
        })
    }

    /// Finds the binary an allow rule refers to: its pinned path, or the first match on the
    /// policy `PATH`.
    pub fn locate(&self, rule: &ExecRule) -> Result<PathBuf, Box<Decision>> {
        let not_found = || {
            Box::new(Decision::deny(
                format!("exec[{}]", rule.name),
                format!("{} was not found on the policy PATH", rule.name),
            ))
        };
        let candidate = match &rule.path {
            Some(pinned) => paths::resolve(Path::new(pinned), Path::new("/")).ok(),
            None => self.policy.path_dirs.iter().find_map(|dir| {
                let path = dir.join(&rule.name);
                is_executable(&path)
                    .then(|| paths::resolve(&path, dir).ok())
                    .flatten()
            }),
        };
        match candidate {
            Some(path) if is_executable(&path) => Ok(path),
            _ => Err(not_found()),
        }
    }

    fn check_arg(&self, rule: &ExecRule, arg: &str) -> Result<(), Deny> {
        let p = self.policy;
        let hit = |globs: &[Glob]| {
            globs
                .iter()
                .find(|g| g.matches(arg))
                .map(|g| g.as_str().to_string())
        };
        if let Some(g) = hit(&p.policy.deny.args) {
            return Err(Box::new(Decision::deny(
                format!("deny.args[{g}]"),
                format!("argument {arg:?} matches a globally denied pattern"),
            )));
        }
        if let Some(g) = hit(&rule.args_deny) {
            return Err(Box::new(Decision::deny(
                format!("exec[{}].args_deny[{g}]", rule.name),
                format!("argument {arg:?} is denied for {}", rule.name),
            )));
        }
        if !rule.args_allow.is_empty() && hit(&rule.args_allow).is_none() {
            return Err(Box::new(Decision::deny(
                format!("exec[{}].args_allow", rule.name),
                format!(
                    "argument {arg:?} matches no allowed pattern for {}",
                    rule.name
                ),
            )));
        }
        if p.policy.network.mode == NetworkMode::Deny && looks_like_remote(arg) {
            return Err(Box::new(Decision::deny(
                "network.deny",
                format!("argument {arg:?} names a network location and the network policy is deny"),
            )));
        }
        Ok(())
    }
}

fn looks_like_remote(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.contains("://")
        || lower.starts_with("git@")
        || lower.contains("/dev/tcp/")
        || lower.contains("/dev/udp/")
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    text: String,
    /// A positional operand (as opposed to the value of an option).
    operand: bool,
}

fn looks_like_path(text: &str) -> bool {
    text.starts_with('/')
        || text.starts_with('~')
        || text.starts_with("./")
        || text.starts_with("../")
        || text == "."
        || text == ".."
        || text.contains('/')
        || paths::has_lookalike(text)
}

/// Extracts the parts of an argument that may name a file. Flags are inspected for
/// `--opt=value` and `-Xvalue` forms. Positional operands are checked when they look like a
/// path, when they exist relative to the working directory (a bare name may be a symlink),
/// or always for commands marked `writes`.
fn path_candidates(arg: &str, writes: bool, options_ended: bool, cwd: &Path) -> Vec<Candidate> {
    let mut out = Vec::new();
    if arg.is_empty() || arg == "--" && !options_ended {
        return out;
    }
    if arg.starts_with('-') && arg != "-" && !options_ended {
        let value = if let Some((_, value)) = arg.split_once('=') {
            Some(value)
        } else if !arg.starts_with("--") && arg.len() > 2 {
            arg.get(2..)
        } else {
            None
        };
        if let Some(value) = value
            && looks_like_path(value)
        {
            out.push(Candidate {
                text: value.to_string(),
                operand: false,
            });
        }
        return out;
    }
    if arg == "-" {
        return out;
    }
    let exists = std::fs::symlink_metadata(cwd.join(arg)).is_ok();
    if writes || looks_like_path(arg) || exists {
        out.push(Candidate {
            text: arg.to_string(),
            operand: true,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_cover_flag_forms() {
        let cwd = Path::new("/nonexistent-cwd");
        let texts = |arg: &str, writes: bool| -> Vec<String> {
            path_candidates(arg, writes, false, cwd)
                .into_iter()
                .map(|c| c.text)
                .collect()
        };
        assert_eq!(texts("--output=/etc/passwd", false), vec!["/etc/passwd"]);
        assert_eq!(texts("-o/etc/passwd", false), vec!["/etc/passwd"]);
        assert!(texts("-la", false).is_empty());
        assert!(texts("--color=auto", false).is_empty());
        assert!(texts("pattern", false).is_empty());
        assert_eq!(texts("file.txt", true), vec!["file.txt"]);
        assert_eq!(texts("~/.ssh", false), vec!["~/.ssh"]);
        assert!(texts("-", true).is_empty());
        assert!(texts("--", true).is_empty());
        assert_eq!(
            path_candidates("-rf", true, true, cwd).len(),
            1,
            "after -- a dash-prefixed word is an operand"
        );
        assert!(looks_like_remote("https://example.com"));
        assert!(looks_like_remote("git@github.com:a/b"));
        assert!(looks_like_remote("/dev/tcp/1.2.3.4/80"));
        assert!(!looks_like_remote("src/main.rs"));
    }
}
