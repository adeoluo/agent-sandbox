//! Criterion benchmarks: decision latency and spawn overhead versus a bare `Command`.

use std::hint::black_box;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use agent_sandbox::{CompileOptions, CompiledPolicy, Request, RunOptions, Sandbox};
use criterion::{Criterion, criterion_group, criterion_main};

fn sandbox(isolation: &str) -> Sandbox {
    let workspace = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bench-ws");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/policies/coding-agent.toml"
    ))
    .unwrap()
    .replace("mode = \"auto\"", &format!("mode = \"{isolation}\""));
    let opts = CompileOptions {
        workspace,
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    Sandbox::new(CompiledPolicy::from_toml(&text, &opts).unwrap())
}

fn exec(argv: &[&str]) -> Request {
    Request::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: None,
    }
}

fn decisions(c: &mut Criterion) {
    let sb = sandbox("off");
    let engine = sb.engine();
    let allow = exec(&["ls", "-la", "src"]);
    let deny_unlisted = exec(&["python3", "-c", "print(1)"]);
    let deny_path = exec(&["cat", "~/.ssh/id_ed25519"]);
    let many = exec(&[
        "cat",
        "src/main.rs",
        "src/a",
        "src/b",
        "src/c",
        "src/d",
        "src/e",
        "src/f",
        "src/g",
        "src/h",
    ]);
    c.bench_function("decide/allow ls -la src", |b| {
        b.iter(|| black_box(engine.decide(black_box(&allow))))
    });
    c.bench_function("decide/deny unlisted", |b| {
        b.iter(|| black_box(engine.decide(black_box(&deny_unlisted))))
    });
    c.bench_function("decide/deny ~/.ssh", |b| {
        b.iter(|| black_box(engine.decide(black_box(&deny_path))))
    });
    c.bench_function("decide/allow 9 path args", |b| {
        b.iter(|| black_box(engine.decide(black_box(&many))))
    });
}

fn spawns(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn echo");
    group.sample_size(30);
    group.bench_function("bare Command", |b| {
        b.iter(|| {
            Command::new("/bin/echo")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        })
    });
    for mode in ["off", "auto"] {
        let sb = sandbox(mode);
        let argv = vec!["echo".to_string()];
        group.bench_function(format!("sandbox isolation={mode}"), |b| {
            b.iter(|| sb.run(&argv, &RunOptions::default()).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, decisions, spawns);
criterion_main!(benches);
