#!/usr/bin/env bash
# Build the release archive for the host platform plus checksums.txt for scripts/release.sh.
# Platforms without a prebuilt archive install from source (scripts/install.sh falls back to cargo).
set -euo pipefail
version="${1:?usage: build-assets.sh vX.Y.Z}"
binary=agent-sandbox
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) arch="$(uname -m)" ;; esac
out=dist/release
name="${binary}_${version}_${os}_${arch}"
rm -rf "$out" && mkdir -p "$out/$name"
cargo build --release --locked
cp "target/release/$binary" LICENSE README.md "$out/$name/"
COPYFILE_DISABLE=1 tar -C "$out" -czf "$out/$name.tar.gz" "$name"
rm -rf "${out:?}/$name"
(cd "$out" && shasum -a 256 ./*.tar.gz | sed 's# \./# #' > checksums.txt)
echo "assets in $out"
