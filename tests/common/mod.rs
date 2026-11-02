#![allow(dead_code)]

use std::path::{Path, PathBuf};

use agent_sandbox::{CompileOptions, CompiledPolicy, RunOptions, RunOutcome, Sandbox};
use tempfile::TempDir;

/// System trees for both macOS and Linux; missing ones are skipped by the compiler.
pub const SYSTEM_ROOTS: &str = r#""/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/System", "/opt/homebrew", "/Library/Frameworks""#;

/// A temporary workspace, a separate fake home directory, and a compiled policy.
pub struct Fixture {
    pub _dir: TempDir,
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub outside: PathBuf,
    pub sandbox: Sandbox,
}

impl Fixture {
    pub fn scratch(&self) -> PathBuf {
        self.sandbox.policy().scratch.clone().expect("scratch")
    }

    pub fn run(&self, argv: &[&str]) -> RunOutcome {
        self.sandbox
            .run(&argv_of(argv), &RunOptions::default())
            .expect("run")
    }
}

pub fn argv_of(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| s.to_string()).collect()
}

/// The standard test policy body: `{extra}` is appended verbatim (more `[[exec]]` rules,
/// a `[limits]` table, and so on).
pub fn policy_text(extra: &str) -> String {
    format!(
        r#"
name = "test"

[filesystem]
read_roots = ["{{workspace}}", {SYSTEM_ROOTS}]
scratch_dir = "{{workspace}}/scratch"
denied_paths = ["~/.ssh", "~/.aws", "/etc/shadow", "{{workspace}}/.env", "{{workspace}}/secrets"]

[env]
path = ["/usr/bin", "/bin"]

[deny]
args = ["--no-preserve-root"]
executables = ["sudo"]

[[exec]]
name = "ls"

[[exec]]
name = "cat"

[[exec]]
name = "echo"

[[exec]]
name = "grep"

[[exec]]
name = "rm"
writes = true

[[exec]]
name = "touch"
writes = true

[[exec]]
name = "find"
args_deny = ["-delete", "-exec*"]

[[exec]]
name = "git"
args_allow = ["status", "log", "diff", "-*"]
args_deny = ["push", "-c", "--upload-pack*", "--exec-path*"]
max_args = 4

{extra}
"#
    )
}

pub fn fixture(extra: &str) -> Fixture {
    fixture_with(&policy_text(extra))
}

pub fn fixture_with(text: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(dir.path()).expect("canonicalize");
    let workspace = root.join("ws");
    let home = root.join("home");
    let outside = root.join("outside");
    for d in [
        &workspace,
        &home,
        &outside,
        &home.join(".ssh"),
        &workspace.join("src"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    std::fs::write(workspace.join("README.md"), "hello\n").unwrap();
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=secret").unwrap();
    std::fs::write(outside.join("victim.txt"), "do not touch").unwrap();
    let opts = CompileOptions {
        workspace: workspace.clone(),
        home: Some(home.clone()),
    };
    let policy = CompiledPolicy::from_toml(text, &opts).expect("policy compiles");
    Fixture {
        _dir: dir,
        workspace,
        home,
        outside,
        sandbox: Sandbox::new(policy),
    }
}

pub fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// True when this platform has an OS isolation backend that works here.
pub fn os_isolation_available(fx: &Fixture) -> bool {
    let program = PathBuf::from("/bin/sh");
    match agent_sandbox::isolation::prepare(fx.sandbox.policy(), &program) {
        Ok((_, report)) => report.backend != "none",
        Err(_) => false,
    }
}
