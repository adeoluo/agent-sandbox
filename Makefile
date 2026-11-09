.PHONY: help build release fmt lint test coverage bench latency inspect demo diagram clean all changelog cut-release

# Keep test temp directories inside the project.
export TMPDIR := $(CURDIR)/target/tmp

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Debug build
	cargo build

release: ## Optimized build at target/release/agent-sandbox
	cargo build --release

fmt: ## Format the code
	cargo fmt --all

lint: ## Format check and clippy (warnings are errors)
	cargo fmt --all --check
	cargo clippy --all-targets -- -D warnings

test: ## Run every test
	@mkdir -p $(TMPDIR)
	cargo test --all-targets

coverage: ## Line coverage with an 85 percent gate (needs cargo-llvm-cov)
	@mkdir -p $(TMPDIR)
	cargo llvm-cov --summary-only --fail-under-lines 85

bench: ## Criterion benchmarks
	cargo bench --bench sandbox

latency: ## Percentile table used in the README
	cargo run --release --example latency 2000

inspect: ## Show what this OS enforces for the sample policy
	cargo run --quiet -- inspect --policy policies/coding-agent.toml

demo: release ## Python client over the stdio protocol
	python3 examples/python_client.py target/release/agent-sandbox policies/coding-agent.toml

diagram: ## Render every diagram in docs/architecture to SVG (house theme, white background)
	@for f in docs/architecture/*.mmd; do \
		npx -y @mermaid-js/mermaid-cli -q -i "$$f" -o "$${f%.mmd}.svg" -c mermaid.config.json -b white || exit 1; \
	done

clean: ## Remove build output and scratch directories
	cargo clean
	rm -rf .sandbox-scratch

all: lint test ## Local gate (mirrors CI)

changelog: ## Regenerate CHANGELOG.md from Conventional Commits (git-cliff)
	git cliff --output CHANGELOG.md && perl -0pi -e 's/\n+\z/\n/' CHANGELOG.md

cut-release: ## Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional)
	scripts/release.sh $(RELEASE_VERSION)
