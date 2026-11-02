//! Prints a Markdown table of decision latency and spawn overhead percentiles.
//!
//! `cargo run --release --example latency [iterations]`

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use agent_sandbox::{CompileOptions, CompiledPolicy, Request, RunOptions, Sandbox};

fn sandbox(workspace: &Path, isolation: &str) -> Sandbox {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/policies/coding-agent.toml"
    ))
    .unwrap()
    .replace("mode = \"auto\"", &format!("mode = \"{isolation}\""));
    let opts = CompileOptions {
        workspace: workspace.to_path_buf(),
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    Sandbox::new(CompiledPolicy::from_toml(&text, &opts).unwrap())
}

fn percentiles(mut samples: Vec<f64>) -> (f64, f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q).round() as usize];
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    (at(0.50), at(0.95), at(0.99), mean)
}

fn measure(n: usize, mut f: impl FnMut()) -> Vec<f64> {
    for _ in 0..n.min(50) {
        f();
    }
    (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect()
}

fn row(name: &str, unit: &str, samples: Vec<f64>) {
    let scale = if unit == "ms" { 1e-3 } else { 1.0 };
    let (p50, p95, p99, mean) = percentiles(samples);
    println!(
        "| {name} | {:.2} | {:.2} | {:.2} | {:.2} | {unit} |",
        p50 * scale,
        p95 * scale,
        p99 * scale,
        mean * scale
    );
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(2000);
    let workspace = std::env::current_dir().unwrap().join("target/latency-ws");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    let off = sandbox(&workspace, "off");
    let auto = sandbox(&workspace, "auto");
    let engine = off.engine();
    let req = |argv: &[&str]| Request::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: None,
    };

    println!("| Operation | p50 | p95 | p99 | mean | unit |");
    println!("|---|---:|---:|---:|---:|---|");
    for (name, r) in [
        ("decide: allow `ls -la src`", req(&["ls", "-la", "src"])),
        (
            "decide: deny unlisted `python3`",
            req(&["python3", "-c", "1"]),
        ),
        (
            "decide: deny `cat ~/.ssh/id_ed25519`",
            req(&["cat", "~/.ssh/id_ed25519"]),
        ),
        (
            "decide: allow `cat` with 9 path args",
            req(&[
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
            ]),
        ),
    ] {
        row(
            name,
            "us",
            measure(n * 10, || {
                std::hint::black_box(engine.decide(&r));
            }),
        );
    }
    let spawn_n = (n / 4).max(50);
    row(
        "spawn: bare `Command::output` of /bin/echo",
        "ms",
        measure(spawn_n, || {
            Command::new("/bin/echo")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
        }),
    );
    let argv = vec!["echo".to_string()];
    row(
        "spawn: sandbox run, isolation off",
        "ms",
        measure(spawn_n, || {
            off.run(&argv, &RunOptions::default()).unwrap();
        }),
    );
    let backend = auto
        .run(&argv, &RunOptions::default())
        .unwrap()
        .enforcement
        .unwrap()
        .backend;
    row(
        &format!("spawn: sandbox run, isolation auto ({backend})"),
        "ms",
        measure(spawn_n, || {
            auto.run(&argv, &RunOptions::default()).unwrap();
        }),
    );
    println!(
        "\n{n} x10 decision samples, {spawn_n} spawn samples; {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
}
