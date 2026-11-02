//! Path-escape attacks: `..`, symlinks, absolute paths, and Unicode tricks.

mod common;

use std::os::unix::fs::symlink;
use std::path::Path;

use agent_sandbox::paths::resolve;
use agent_sandbox::{Request, RunOptions};
use common::{argv_of, exists, fixture};
use proptest::prelude::*;

fn write_req(path: &str) -> Request {
    Request::Write {
        path: path.into(),
        cwd: None,
    }
}

fn read_req(path: &str) -> Request {
    Request::Read {
        path: path.into(),
        cwd: None,
    }
}

#[test]
fn dotdot_escapes_are_denied() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    for p in [
        "scratch/../README.md",
        "scratch/../../outside/victim.txt",
        "scratch/./../scratch/../../outside/x",
        "scratch/a/b/../../../../outside/x",
        "../outside/victim.txt",
        "scratch/../../../../../../../../etc/passwd",
    ] {
        let d = e.decide(&write_req(p));
        assert!(!d.allowed, "{p} should be denied: {d:?}");
    }
    assert!(e.decide(&write_req("scratch/a/../b.txt")).allowed);
    assert!(e.decide(&write_req("scratch/a/b/../../c.txt")).allowed);
}

#[test]
fn absolute_paths_outside_roots_are_denied() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    let victim = fx.outside.join("victim.txt");
    assert!(!e.decide(&read_req(victim.to_str().unwrap())).allowed);
    assert!(!e.decide(&write_req(victim.to_str().unwrap())).allowed);
    assert!(!e.decide(&write_req("/etc/passwd")).allowed);
    let inside = fx.scratch().join("ok.txt");
    assert!(e.decide(&write_req(inside.to_str().unwrap())).allowed);
    // `//` and `/./` do not confuse resolution.
    let doubled = format!("{}//./ok.txt", fx.scratch().display());
    assert!(e.decide(&write_req(&doubled)).allowed);
}

#[test]
fn symlink_in_scratch_pointing_outside_is_followed() {
    let fx = fixture("");
    let scratch = fx.scratch();
    symlink(&fx.outside, scratch.join("escape-dir")).unwrap();
    symlink(fx.outside.join("victim.txt"), scratch.join("escape-file")).unwrap();
    symlink(fx.home.join(".ssh/id_ed25519"), scratch.join("key")).unwrap();
    let e = fx.sandbox.engine();
    assert!(
        !e.decide(&write_req("scratch/escape-dir/victim.txt"))
            .allowed
    );
    assert!(!e.decide(&write_req("scratch/escape-file")).allowed);
    assert!(!e.decide(&read_req("scratch/escape-dir/victim.txt")).allowed);
    let d = e.decide(&read_req("scratch/key"));
    assert!(d.rule.starts_with("filesystem.denied_paths"), "{d:?}");
    // A bare name that is a symlink is checked even for a read-only command.
    let d = e.decide(&Request::Exec {
        argv: argv_of(&["cat", "key"]),
        cwd: Some(scratch.clone()),
    });
    assert!(d.rule.starts_with("filesystem.denied_paths"), "{d:?}");
    // The write path really is refused by the sandbox file API too.
    let out = fx
        .sandbox
        .write_file("scratch/escape-file", b"pwned", None)
        .unwrap();
    assert!(!out.decision.allowed);
    assert_eq!(
        std::fs::read_to_string(fx.outside.join("victim.txt")).unwrap(),
        "do not touch"
    );
}

#[test]
fn dangling_symlink_cannot_redirect_a_write() {
    let fx = fixture("");
    let target = fx.outside.join("created-by-agent.txt");
    symlink(&target, fx.scratch().join("dangling")).unwrap();
    let out = fx
        .sandbox
        .write_file("scratch/dangling", b"x", None)
        .unwrap();
    assert!(!out.decision.allowed);
    assert!(!exists(&target));
}

#[test]
fn symlinked_directory_then_dotdot() {
    let fx = fixture("");
    // scratch/deep -> outside/a/b ; scratch/deep/../../x resolves under outside, not scratch.
    std::fs::create_dir_all(fx.outside.join("a/b")).unwrap();
    symlink(fx.outside.join("a/b"), fx.scratch().join("deep")).unwrap();
    let d = fx
        .sandbox
        .engine()
        .decide(&write_req("scratch/deep/../../x"));
    assert!(!d.allowed, "{d:?}");
}

#[test]
fn symlink_loops_are_denied() {
    let fx = fixture("");
    let s = fx.scratch();
    symlink(s.join("loop-b"), s.join("loop-a")).unwrap();
    symlink(s.join("loop-a"), s.join("loop-b")).unwrap();
    let d = fx.sandbox.engine().decide(&write_req("scratch/loop-a"));
    assert!(!d.allowed);
    assert_eq!(d.rule, "filesystem.resolve");
}

#[test]
fn unicode_tricks_are_denied() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    for p in [
        "scratch/..\u{2215}..\u{2215}outside", // division slash
        "scratch/..\u{FF0F}README.md",         // fullwidth solidus
        "scratch/\u{2024}\u{2024}/x",          // one dot leaders
        "scratch/\u{FF0E}\u{FF0E}/x",          // fullwidth full stops
        "scratch/file\u{202E}txt.sh",          // right-to-left override
        "scratch/a\u{200B}b",                  // zero-width space
        "scratch/a\u{0000}b",                  // NUL
        "scratch/a\nb",                        // newline
    ] {
        let d = e.decide(&write_req(p));
        assert!(!d.allowed, "{p:?}");
        assert_eq!(d.rule, "filesystem.text", "{p:?}");
    }
    // Lookalikes inside an exec argument are treated as paths and rejected.
    let d = e.decide(&Request::Exec {
        argv: argv_of(&["cat", "..\u{FF0F}..\u{FF0F}etc\u{FF0F}passwd"]),
        cwd: None,
    });
    assert_eq!(d.rule, "filesystem.text");
    // Invisible characters anywhere in argv are rejected.
    let d = e.decide(&Request::Exec {
        argv: argv_of(&["echo", "safe\u{202E}"]),
        cwd: None,
    });
    assert_eq!(d.rule, "exec.text");
    // Legitimate non-ASCII names are fine.
    assert!(
        e.decide(&write_req("scratch/caf\u{00e9}-\u{6587}\u{4ef6}.txt"))
            .allowed
    );
}

#[test]
fn tilde_is_expanded_like_a_shell() {
    let fx = fixture("");
    let e = fx.sandbox.engine();
    assert!(
        e.decide(&read_req("~/.ssh/id_ed25519"))
            .rule
            .starts_with("filesystem.denied_paths")
    );
    assert!(
        e.decide(&read_req("~/.ssh"))
            .rule
            .starts_with("filesystem.denied_paths")
    );
    assert!(!e.decide(&read_req("~")).allowed);
}

#[test]
fn denied_path_prefix_does_not_overmatch() {
    let fx = fixture("");
    std::fs::create_dir_all(fx.workspace.join("secrets-public")).unwrap();
    let e = fx.sandbox.engine();
    assert!(e.decide(&read_req("secrets-public/readme")).allowed);
    assert!(!e.decide(&read_req("secrets/readme")).allowed);
    assert!(e.decide(&read_req(".envrc")).allowed);
}

#[test]
fn file_api_round_trip_and_limits() {
    let fx = fixture("[limits]\nmax_output_bytes = 4\nmax_file_size_bytes = 8\n");
    let w = fx
        .sandbox
        .write_file("scratch/a.txt", b"12345678", None)
        .unwrap();
    assert!(w.decision.allowed);
    let r = fx.sandbox.read_file("scratch/a.txt", None).unwrap();
    assert_eq!(r.content, b"1234");
    assert!(r.truncated);
    let big = fx
        .sandbox
        .write_file("scratch/b.txt", b"123456789", None)
        .unwrap();
    assert_eq!(big.decision.rule, "limits.max_file_size_bytes");
    assert!(!exists(&fx.scratch().join("b.txt")));
    let denied = fx.sandbox.read_file(".env", None).unwrap();
    assert!(!denied.decision.allowed);
    assert!(denied.content.is_empty());
}

#[test]
fn exec_cwd_escape_is_denied() {
    let fx = fixture("");
    let out = fx
        .sandbox
        .run(
            &argv_of(&["ls"]),
            &RunOptions {
                cwd: Some("scratch/../../outside".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!out.executed);
    assert_eq!(out.decision.rule, "filesystem.read_roots");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For every path that exists, the resolver agrees with the kernel's realpath.
    #[test]
    fn resolver_matches_realpath(parts in proptest::collection::vec(
        prop_oneof![Just("a"), Just("b"), Just(".."), Just("."), Just("up"), Just("loop-free")], 0..8)) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("a/b/a/b")).unwrap();
        symlink("..", root.join("a/up")).unwrap();
        symlink(root.join("a/b"), root.join("loop-free")).unwrap();
        let rel: std::path::PathBuf = parts.iter().collect();
        let joined = root.join("a").join(&rel);
        if let Ok(real) = std::fs::canonicalize(&joined) {
            prop_assert_eq!(resolve(&rel, &root.join("a")).unwrap(), real);
        }
    }

    /// Whatever the agent sends, an allowed write resolves inside a writable root.
    #[test]
    fn allowed_writes_stay_in_scratch(parts in proptest::collection::vec(
        prop_oneof![Just("scratch"), Just(".."), Just("."), Just("x"), Just("link"), Just("outside")], 1..8)) {
        let fx = fixture("");
        let _ = symlink(&fx.outside, fx.scratch().join("link"));
        let path: std::path::PathBuf = parts.iter().collect();
        let d = fx.sandbox.engine().decide(&Request::Write { path: path.to_string_lossy().into(), cwd: None });
        if d.allowed {
            let resolved = d.resolved.unwrap();
            prop_assert!(resolved.starts_with(fx.scratch()), "{} escaped", resolved.display());
            prop_assert!(!resolved.starts_with(&fx.outside));
        }
    }

    /// The engine never panics on arbitrary argv.
    #[test]
    fn engine_total_on_arbitrary_argv(argv in proptest::collection::vec(".{0,24}", 0..6)) {
        let fx = fixture("");
        let d = fx.sandbox.engine().decide(&Request::Exec { argv, cwd: None });
        prop_assert!(!d.rule.is_empty());
    }
}

#[test]
fn resolve_handles_root_and_relative_base() {
    assert_eq!(
        resolve(Path::new("/"), Path::new("/")).unwrap(),
        Path::new("/")
    );
    assert_eq!(
        resolve(Path::new("/.."), Path::new("/")).unwrap(),
        Path::new("/")
    );
}
