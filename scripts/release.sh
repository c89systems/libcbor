#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
[[ -z ${1:-} && -z ${C89CBOR_VERSION_OVERRIDE:-} ]] || { printf 'Candidate overrides are forbidden for release\n' >&2; exit 1; }
branch=$(git branch --show-current)
default=$(git symbolic-ref refs/remotes/origin/HEAD)
default=${default#refs/remotes/origin/}
[[ $branch == "$default" ]] || { printf 'Release requires the resolved default branch %s\n' "$default" >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { printf 'Release requires a clean committed worktree\n' >&2; exit 1; }
git verify-commit HEAD
version=$(scripts/version.sh)
[[ $version != 0.0.0 && $(git cat-file -t "refs/tags/v$version") == commit && $(git rev-parse "refs/tags/v$version") == $(git rev-parse HEAD) ]]
make clean
make prerelease
printf 'Local release gate passed for %s. No refs were pushed or published.\n' "$version"
