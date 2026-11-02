//! Declarative policy: the on-disk schema (`Policy`) and its resolved form (`CompiledPolicy`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, SandboxError};
use crate::paths::{self, Placeholders};
use crate::pattern::Glob;

/// The policy file schema. Unknown keys are rejected so a typo cannot silently weaken a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub env: EnvPolicy,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub isolation: IsolationPolicy,
    #[serde(default)]
    pub deny: DenyPolicy,
    #[serde(default)]
    pub exec: Vec<ExecRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Trees the agent may read (and execute from). Writable roots are readable too.
    #[serde(default)]
    pub read_roots: Vec<String>,
    /// Trees the agent may create, modify, and delete files in.
    #[serde(default)]
    pub writable_roots: Vec<String>,
    /// Paths that are never readable or writable, even inside an allowed root.
    #[serde(default)]
    pub denied_paths: Vec<String>,
    /// A per-profile scratch directory, created if missing and added to the writable roots.
    #[serde(default)]
    pub scratch_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: NetworkMode,
    /// Additional executable names treated as network clients when the mode is `deny`.
    #[serde(default)]
    pub clients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvPolicy {
    /// Names (glob patterns) copied from the caller's environment.
    #[serde(default = "default_env_allow")]
    pub allow: Vec<Glob>,
    /// Variables set explicitly. Values may use `{scratch}`, `{workspace}`, `{home}`.
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    /// Directories searched for allowlisted executables and exported as `PATH`.
    #[serde(default = "default_path")]
    pub path: Vec<String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            allow: default_env_allow(),
            set: BTreeMap::new(),
            path: default_path(),
        }
    }
}

fn default_env_allow() -> Vec<Glob> {
    ["LANG", "LC_*", "TERM", "TZ"]
        .into_iter()
        .map(Glob::new)
        .collect()
}

fn default_path() -> Vec<String> {
    ["/usr/bin", "/bin"].into_iter().map(String::from).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Wall-clock timeout; the whole process group is killed when it expires.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// CPU seconds (`RLIMIT_CPU`).
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    /// Address-space limit on Linux (`RLIMIT_AS`); resident-set watchdog on macOS.
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// Bytes captured per stream (stdout and stderr each).
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    /// Kill the process group once a stream exceeds `max_output_bytes`.
    #[serde(default = "default_true")]
    pub kill_on_output_limit: bool,
    /// Additional processes the command may create (`RLIMIT_NPROC`, set relative to the
    /// caller's current process count because the kernel counts per user).
    #[serde(default)]
    pub max_processes: Option<u64>,
    /// Largest file the command may write (`RLIMIT_FSIZE`).
    #[serde(default)]
    pub max_file_size_bytes: Option<u64>,
    /// Open file descriptors (`RLIMIT_NOFILE`).
    #[serde(default)]
    pub max_open_files: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            cpu_seconds: None,
            memory_bytes: None,
            max_output_bytes: default_max_output(),
            kill_on_output_limit: true,
            max_processes: None,
            max_file_size_bytes: None,
            max_open_files: None,
        }
    }
}

fn default_timeout_ms() -> u64 {
    30_000
}
fn default_max_output() -> usize {
    1 << 20
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationMode {
    /// Use the OS backend when available; fall back to engine-only enforcement otherwise.
    #[default]
    Auto,
    /// Refuse to run if the OS backend is unavailable.
    Required,
    /// Never use the OS backend (rlimits, environment, and timeouts still apply).
    Off,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationPolicy {
    #[serde(default)]
    pub mode: IsolationMode,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyPolicy {
    /// Argument patterns denied for every executable.
    #[serde(default)]
    pub args: Vec<Glob>,
    /// Executable names denied even if an allow rule matches.
    #[serde(default)]
    pub executables: Vec<String>,
}

/// One allowlisted executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRule {
    /// The command name as the agent invokes it (`ls`, `git`).
    pub name: String,
    /// Pin the binary to an absolute path instead of searching `env.path`.
    #[serde(default)]
    pub path: Option<String>,
    /// If non-empty, every argument must match at least one pattern.
    #[serde(default)]
    pub args_allow: Vec<Glob>,
    /// Any argument matching one of these patterns denies the request.
    #[serde(default)]
    pub args_deny: Vec<Glob>,
    /// The command modifies its operands: every non-flag argument must be a writable path.
    #[serde(default)]
    pub writes: bool,
    #[serde(default)]
    pub max_args: Option<usize>,
}

impl Policy {
    pub fn from_toml_str(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| SandboxError::PolicyParse(e.to_string()))
    }

    pub fn from_json_str(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| SandboxError::PolicyParse(e.to_string()))
    }

    /// Loads a `.toml` or `.json` policy file and returns it with the SHA-256 of its bytes.
    pub fn from_file(path: &Path) -> Result<(Self, String)> {
        let text = std::fs::read_to_string(path).map_err(|source| SandboxError::PolicyRead {
            path: path.to_path_buf(),
            source,
        })?;
        let policy = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Self::from_json_str(&text)?,
            _ => Self::from_toml_str(&text)?,
        };
        Ok((policy, sha256_hex(text.as_bytes())))
    }

    pub fn validate(&self) -> Result<()> {
        let invalid = |msg: String| Err(SandboxError::PolicyInvalid(msg));
        if self.name.trim().is_empty() {
            return invalid("policy name must not be empty".into());
        }
        if self.limits.timeout_ms == 0 {
            return invalid("limits.timeout_ms must be greater than zero".into());
        }
        if self.limits.max_output_bytes == 0 {
            return invalid("limits.max_output_bytes must be greater than zero".into());
        }
        for rule in &self.exec {
            if rule.name.is_empty() || rule.name.contains('/') {
                return invalid(format!(
                    "exec rule name {:?} must be a bare command name; use `path` to pin a binary",
                    rule.name
                ));
            }
            if let Some(path) = &rule.path
                && !path.starts_with('/')
            {
                return invalid(format!("exec[{}].path must be absolute", rule.name));
            }
        }
        for raw in self
            .filesystem
            .read_roots
            .iter()
            .chain(&self.filesystem.writable_roots)
            .chain(&self.filesystem.denied_paths)
            .chain(&self.env.path)
        {
            if let Err(issue) = paths::check_path_text(raw) {
                return invalid(format!("path {raw:?}: {issue}"));
            }
        }
        Ok(())
    }
}

/// Context needed to turn a policy into concrete paths.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub workspace: PathBuf,
    pub home: Option<PathBuf>,
}

impl CompileOptions {
    pub fn from_env(workspace: Option<PathBuf>) -> std::io::Result<Self> {
        let workspace = match workspace {
            Some(w) => w,
            None => std::env::current_dir()?,
        };
        Ok(Self {
            workspace,
            home: std::env::var_os("HOME").map(PathBuf::from),
        })
    }
}

/// A validated policy with every path expanded and resolved.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    pub policy_hash: String,
    pub workspace: PathBuf,
    pub home: Option<PathBuf>,
    pub scratch: Option<PathBuf>,
    pub read_roots: Vec<PathBuf>,
    pub writable_roots: Vec<PathBuf>,
    pub denied_paths: Vec<PathBuf>,
    pub path_dirs: Vec<PathBuf>,
    pub placeholders: Placeholders,
}

impl CompiledPolicy {
    /// Validates and resolves a policy. The scratch directory is created if missing. Read and
    /// writable roots that do not exist are dropped (a policy can list `/lib64` and still
    /// load on macOS); denied paths are kept even if missing so they cannot be created.
    pub fn compile(policy: Policy, policy_hash: String, opts: &CompileOptions) -> Result<Self> {
        policy.validate()?;
        let workspace = paths::resolve(&opts.workspace, Path::new("/"))?;
        let mut placeholders = Placeholders {
            workspace: workspace.clone(),
            home: opts.home.clone(),
            scratch: None,
        };
        let scratch = match &policy.filesystem.scratch_dir {
            Some(raw) => {
                let dir = placeholders.expand_path(raw);
                std::fs::create_dir_all(&dir)?;
                let dir = paths::resolve(&dir, &workspace)?;
                placeholders.scratch = Some(dir.clone());
                Some(dir)
            }
            None => None,
        };
        let resolve_existing = |raws: &[String]| -> Result<Vec<PathBuf>> {
            let mut out = Vec::new();
            for raw in raws {
                let resolved = paths::resolve(&placeholders.expand_path(raw), &workspace)?;
                if resolved.exists() && !out.contains(&resolved) {
                    out.push(resolved);
                }
            }
            Ok(out)
        };
        let read_roots = resolve_existing(&policy.filesystem.read_roots)?;
        let mut writable_roots = resolve_existing(&policy.filesystem.writable_roots)?;
        if let Some(dir) = &scratch
            && !writable_roots.contains(dir)
        {
            writable_roots.push(dir.clone());
        }
        if let Some(root) = writable_roots.iter().find(|r| r.parent().is_none()) {
            return Err(SandboxError::PolicyInvalid(format!(
                "writable root {} would allow writing anywhere",
                root.display()
            )));
        }
        let mut denied_paths = Vec::new();
        for raw in &policy.filesystem.denied_paths {
            let resolved = paths::resolve(&placeholders.expand_path(raw), &workspace)?;
            if !denied_paths.contains(&resolved) {
                denied_paths.push(resolved);
            }
        }
        let path_dirs = resolve_existing(&policy.env.path)?;
        Ok(Self {
            policy,
            policy_hash,
            workspace,
            home: opts.home.clone(),
            scratch,
            read_roots,
            writable_roots,
            denied_paths,
            path_dirs,
            placeholders,
        })
    }

    /// Loads, validates, and compiles a policy file.
    pub fn load(path: &Path, opts: &CompileOptions) -> Result<Self> {
        let (policy, hash) = Policy::from_file(path)?;
        Self::compile(policy, hash, opts)
    }

    /// Compiles a policy given as TOML text (hash computed over the text).
    pub fn from_toml(text: &str, opts: &CompileOptions) -> Result<Self> {
        let policy = Policy::from_toml_str(text)?;
        Self::compile(policy, sha256_hex(text.as_bytes()), opts)
    }

    pub fn name(&self) -> &str {
        &self.policy.name
    }

    pub fn limits(&self) -> &Limits {
        &self.policy.limits
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xf) as usize] as char);
    }
    out
}
