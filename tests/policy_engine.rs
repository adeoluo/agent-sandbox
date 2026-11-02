//! Allow/deny matrix for the decision engine, plus policy parsing and validation.

mod common;

use agent_sandbox::policy::{IsolationMode, NetworkMode, Policy};
use agent_sandbox::{CompileOptions, CompiledPolicy, Request, SandboxError};
use common::{argv_of, fixture};

fn exec(argv: &[&str]) -> Request {
    Request::Exec {
        argv: argv_of(argv),
        cwd: None,
    }
}

/// (argv, allowed, expected rule prefix)
const MATRIX: &[(&[&str], bool, &str)] = &[
    (&["ls"], true, "exec[ls]"),
    (&["ls", "-la", "src"], true, "exec[ls]"),
    (&["cat", "README.md"], true, "exec[cat]"),
    (&["cat", "./src/main.rs"], true, "exec[cat]"),
    (&["grep", "-r", "fn main", "src"], true, "exec[grep]"),
    (&["echo", "hello world"], true, "exec[echo]"),
    (&["git", "status"], true, "exec[git]"),
    (&["git", "log", "--oneline"], true, "exec[git]"),
    (&["git", "push"], false, "exec[git].args_deny[push]"),
    (
        &["git", "-c", "core.pager=sh", "log"],
        false,
        "exec[git].args_deny[-c]",
    ),
    (&["git", "commit"], false, "exec[git].args_allow"),
    (
        &["git", "log", "-1", "-2", "-3", "-4"],
        false,
        "exec[git].max_args",
    ),
    (&["touch", "scratch/new.txt"], true, "exec[touch]"),
    (&["touch", "new.txt"], false, "filesystem.writable_roots"),
    (&["rm", "-rf", "scratch/tmp"], true, "exec[rm]"),
    (&["rm", "-rf", "src"], false, "filesystem.writable_roots"),
    (
        &["rm", "-rf", "--no-preserve-root", "/"],
        false,
        "deny.args[--no-preserve-root]",
    ),
    (&["find", ".", "-name", "*.rs"], true, "exec[find]"),
    (
        &["find", ".", "-delete"],
        false,
        "exec[find].args_deny[-delete]",
    ),
    (
        &["find", ".", "-exec", "sh", ";"],
        false,
        "exec[find].args_deny[-exec*]",
    ),
    (&["python3", "-c", "print(1)"], false, "default-deny"),
    (&["bash"], false, "default-deny"),
    (&["sudo", "ls"], false, "deny.executables[sudo]"),
    (&["curl", "https://example.com"], false, "network.deny"),
    (&["wget", "http://example.com"], false, "network.deny"),
    (&["ssh", "host"], false, "network.deny"),
    (&["cat", "https://example.com/x"], false, "network.deny"),
    (&["cat", "/dev/tcp/1.2.3.4/80"], false, "network.deny"),
    (&["cat", ".env"], false, "filesystem.denied_paths"),
    (&["cat", "secrets/key"], false, "filesystem.denied_paths"),
    (
        &["cat", "~/.ssh/id_ed25519"],
        false,
        "filesystem.denied_paths",
    ),
    (
        &["cat", "--file=~/.ssh/id_ed25519"],
        false,
        "filesystem.denied_paths",
    ),
    (
        &["grep", "-f/etc/../root/x", "a"],
        false,
        "filesystem.read_roots",
    ),
    (&["ls", "/"], false, "filesystem.read_roots"),
    (&[], false, "exec.argv"),
];

#[test]
fn allow_deny_matrix() {
    let fx = fixture("");
    let engine = fx.sandbox.engine();
    let mut failures = Vec::new();
    for (argv, allowed, rule) in MATRIX {
        let d = engine.decide(&exec(argv));
        if d.allowed != *allowed || !d.rule.starts_with(rule) {
            failures.push(format!(
                "{argv:?}: got allowed={} rule={} ({})",
                d.allowed, d.rule, d.reason
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "matrix failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn allowed_exec_reports_program_and_cwd() {
    let fx = fixture("");
    let d = fx.sandbox.engine().decide(&exec(&["ls"]));
    assert!(d.allowed);
    let program = d.program.unwrap();
    assert!(program.is_absolute());
    assert_eq!(program.file_name().unwrap(), "ls");
    assert_eq!(d.resolved.unwrap(), fx.workspace);
}

#[test]
fn file_requests() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    let read = |p: &str| {
        e.decide(&Request::Read {
            path: p.into(),
            cwd: None,
        })
    };
    let write = |p: &str| {
        e.decide(&Request::Write {
            path: p.into(),
            cwd: None,
        })
    };
    assert!(read("README.md").allowed);
    assert_eq!(read("README.md").rule, "filesystem.read");
    assert!(read("scratch/anything").allowed);
    assert!(!read(".env").allowed);
    assert!(!read("~/.aws/credentials").allowed);
    assert!(write("scratch/out.txt").allowed);
    assert_eq!(write("scratch/out.txt").rule, "filesystem.write");
    assert!(!write("README.md").allowed);
    assert!(!write("/etc/hosts").allowed);
}

#[test]
fn cwd_must_be_readable() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    let d = e.decide(&Request::Exec {
        argv: argv_of(&["ls"]),
        cwd: Some(fx.outside.clone()),
    });
    assert!(!d.allowed);
    assert_eq!(d.rule, "filesystem.read_roots");
    let d = e.decide(&Request::Exec {
        argv: argv_of(&["ls"]),
        cwd: Some("src".into()),
    });
    assert!(d.allowed);
    assert_eq!(d.resolved.unwrap(), fx.workspace.join("src"));
}

#[test]
fn network_allow_mode_permits_clients_if_listed() {
    let fx = fixture("[network]\nmode = \"allow\"\n\n[[exec]]\nname = \"curl\"\n");
    let d = fx
        .sandbox
        .engine()
        .decide(&exec(&["curl", "https://example.com"]));
    // curl may be absent on a minimal system; the network rule must not be what denies it.
    assert_ne!(d.rule, "network.deny");
}

#[test]
fn custom_network_clients_are_denied() {
    let fx = fixture("[network]\nclients = [\"ls\"]\n");
    let d = fx.sandbox.engine().decide(&exec(&["ls"]));
    assert_eq!(d.rule, "network.deny");
}

#[test]
fn absolute_program_must_match_the_allowlisted_binary() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    let ls = e.decide(&exec(&["ls"])).program.unwrap();
    let d = e.decide(&exec(&[ls.to_str().unwrap()]));
    assert!(d.allowed, "{d:?}");
    // A copy named `ls` in the scratch directory is not the allowlisted binary.
    let fake = fx.scratch().join("ls");
    std::fs::copy(&ls, &fake).unwrap();
    let d = e.decide(&exec(&["./scratch/ls"]));
    assert!(!d.allowed);
    assert_eq!(d.rule, "exec[ls]");
    assert!(d.reason.contains("not the allowlisted binary"));
}

#[test]
fn pinned_path_rule() {
    let fx = fixture("[[exec]]\nname = \"list\"\npath = \"/bin/ls\"\n");
    let e = fx.sandbox.engine();
    assert!(e.decide(&exec(&["list"])).allowed);
    assert!(e.decide(&exec(&["/bin/ls"])).allowed);
}

#[test]
fn missing_binary_is_denied() {
    let fx = fixture("[[exec]]\nname = \"definitely-not-installed-xyz\"\n");
    let d = fx
        .sandbox
        .engine()
        .decide(&exec(&["definitely-not-installed-xyz"]));
    assert!(!d.allowed);
    assert!(d.reason.contains("not found"));
}

#[test]
fn oversized_argv_is_denied() {
    let fx = fixture("");
    let big = "a".repeat(200 * 1024);
    let d = fx.sandbox.engine().decide(&exec(&["echo", &big]));
    assert_eq!(d.rule, "exec.argv");
}

#[test]
fn parse_and_validation_errors() {
    let opts = CompileOptions {
        workspace: std::env::temp_dir(),
        home: None,
    };
    let err = |text: &str| CompiledPolicy::from_toml(text, &opts).unwrap_err();
    assert!(matches!(
        err("name = \"x\"\nunknown_key = 1"),
        SandboxError::PolicyParse(_)
    ));
    assert!(matches!(err("name = \"\""), SandboxError::PolicyInvalid(_)));
    assert!(matches!(
        err("name = \"x\"\n[limits]\ntimeout_ms = 0"),
        SandboxError::PolicyInvalid(_)
    ));
    assert!(matches!(
        err("name = \"x\"\n[limits]\nmax_output_bytes = 0"),
        SandboxError::PolicyInvalid(_)
    ));
    assert!(matches!(
        err("name = \"x\"\n[[exec]]\nname = \"/bin/ls\""),
        SandboxError::PolicyInvalid(_)
    ));
    assert!(matches!(
        err("name = \"x\"\n[[exec]]\nname = \"ls\"\npath = \"ls\""),
        SandboxError::PolicyInvalid(_)
    ));
    assert!(matches!(
        err("name = \"x\"\n[filesystem]\nread_roots = [\"/usr\u{2215}lib\"]"),
        SandboxError::PolicyInvalid(_)
    ));
    assert!(matches!(
        err("name = \"x\"\n[filesystem]\nwritable_roots = [\"/\"]"),
        SandboxError::PolicyInvalid(_)
    ));
    for e in [err("name = \"\""), err("x = ")] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn defaults_are_conservative() {
    let p = Policy::from_toml_str("name = \"min\"").unwrap();
    assert_eq!(p.network.mode, NetworkMode::Deny);
    assert_eq!(p.isolation.mode, IsolationMode::Auto);
    assert!(p.exec.is_empty());
    assert!(p.limits.kill_on_output_limit);
    assert_eq!(p.limits.timeout_ms, 30_000);
}

#[test]
fn json_and_toml_files_load() {
    let root = env!("CARGO_MANIFEST_DIR");
    let opts = CompileOptions {
        workspace: root.into(),
        home: None,
    };
    for file in [
        "policies/coding-agent.toml",
        "policies/readonly.toml",
        "policies/readonly.json",
    ] {
        let p = CompiledPolicy::load(&std::path::Path::new(root).join(file), &opts).unwrap();
        assert_eq!(p.policy_hash.len(), 64);
        assert!(!p.read_roots.is_empty());
    }
    let missing = CompiledPolicy::load("does/not/exist.toml".as_ref(), &opts).unwrap_err();
    assert!(matches!(missing, SandboxError::PolicyRead { .. }));
    let bad = Policy::from_json_str("{").unwrap_err();
    assert!(matches!(bad, SandboxError::PolicyParse(_)));
}

#[test]
fn every_decision_names_a_rule_and_reason() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    for (argv, _, _) in MATRIX {
        let d = e.decide(&exec(argv));
        assert!(!d.rule.is_empty() && !d.reason.is_empty(), "{argv:?}");
    }
}
