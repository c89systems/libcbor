#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
for target in x86_64-linux-gnu x86_64-linux-musl aarch64-linux-gnu aarch64-linux-musl armhf-linux-gnu armhf-linux-musl arm64-apple-darwin; do
  scripts/build.sh core "$target" Release "${1:-}"
  if [[ $target != arm64-apple-darwin || $(uname -s) == Darwin ]]; then
    scripts/build.sh test "$target" Release
  fi
  scripts/build.sh lua "$target" Release
  if [[ $target != arm64-apple-darwin || $(uname -s) == Darwin ]]; then
    scripts/build.sh lua-test "$target" Release
  fi
  scripts/package.sh "$target" Release "${1:-}"
  scripts/verify-package.sh "$target" Release "${1:-}"
done
