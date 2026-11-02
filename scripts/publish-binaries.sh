#!/usr/bin/env bash
# Build every platform archive in CI, then upload them to the release as the maintainer.
#   scripts/publish-binaries.sh v0.1.0
# Runs the "Release binaries" workflow for the tag, waits for it, downloads the artifacts,
# writes checksums.txt for all archives, and uploads with --clobber (replacing a
# host-only checksums file from an earlier upload).
set -euo pipefail
tag="${1:?usage: publish-binaries.sh vX.Y.Z}"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
gh release view "$tag" -R "$repo" >/dev/null
gh workflow run binaries.yml -R "$repo" -f tag="$tag"
sleep 8
run_id="$(gh run list -R "$repo" -w binaries.yml -L 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$run_id" -R "$repo" --exit-status >/dev/null
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
gh run download "$run_id" -R "$repo" -D "$out"
mkdir -p "$out/upload"
find "$out" -name '*.tar.gz' -exec cp {} "$out/upload/" \;
(cd "$out/upload" && shasum -a 256 ./*.tar.gz | sed 's# \./# #' > checksums.txt)
gh release upload "$tag" -R "$repo" --clobber "$out"/upload/*
echo "uploaded $(ls "$out/upload" | wc -l | tr -d ' ') files to $tag"
