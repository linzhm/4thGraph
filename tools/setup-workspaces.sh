#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$root/workspace"/{build,cache,logs}
for project in "$root"/projects/*; do
  [[ -f "$project/README.md" ]] || continue
  mkdir -p "$project/workspace"/{build,cache,logs}
done
