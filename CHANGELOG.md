# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## [0.1.2] 2026-11-08

### Documentation

- Vertical layered architecture diagram
- Horizontal layered architecture diagram
- Compact horizontal architecture diagram
- Recorded terminal demo of a real run, with its vhs tape
- Remove authorship statements from docs and scripts
- Recorded demos of more commands, with their vhs tapes (#2)
- Recorded demos of the HTTP service and more commands (#3)
- Complete citation metadata and bump it on release (#5)
- Add a threat model mapped to OWASP Agentic 2026, OWASP LLM 2026 and MITRE ATLAS v2026.10 (#7)
- Add standards keywords to the citation metadata (#8)

### Build and CI

- Build release archives for Linux and macOS on arm64 and amd64 (#1)

### Maintenance

- Add release automation, AGENTS.md, llms.txt and contributor docs
- Classify squash merges in the changelog by the commits they contain
- Latest toolchain and CI versions (#4)
- Release script keeps hard-coded version strings in step (#6)

## [0.1.0] 2026-11-02

### Features

- Agent-sandbox v0.1.0 (#1)

### Build and CI

- Run CodeQL on main and on a weekly schedule only

### Maintenance

- Initial commit with license and readme stub
