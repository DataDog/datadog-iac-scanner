#!/usr/bin/env bash
# Builds a {version, sha256: {platform: hash}} JSON blob from a GitHub
# release's checksums.txt asset (published by GoReleaser).
#
# Usage: scripts/gen-checksums.sh [tag]
#   tag defaults to the latest release if omitted.
set -euo pipefail

REPO="DataDog/datadog-iac-scanner"
TAG="${1:-}"

if [[ -z "$TAG" ]]; then
  TAG=$(gh release view --repo "$REPO" --json tagName -q .tagName)
fi

gh release download "$TAG" --repo "$REPO" \
  -p 'datadog-iac-scanner_checksums.txt' -O - \
  | awk '{print $2, $1}' \
  | jq -R -n --arg version "$TAG" '
      [inputs | split(" ")]
      | map(select(.[0] | test("darwin|linux")))
      | map({(.[0] | capture("datadog-iac-scanner_(?<plat>darwin_arm64|darwin_amd64|linux_arm64|linux_amd64)").plat): .[1]})
      | add as $sha256
      | {version: $version, sha256: $sha256}
    '
