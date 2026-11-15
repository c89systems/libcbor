#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [[ -n "${1:-}" ]]; then
  [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Invalid candidate version\n' >&2; exit 1; }
  printf '%s\n' "$1"
elif [[ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || :)" == "$root" ]]; then
  selected=
  while IFS= read -r tag; do
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [[ $(git -C "$root" cat-file -t "refs/tags/$tag") == commit ]] || continue
    [[ -z $selected ]] || { printf 'Ambiguous release tags\n' >&2; exit 1; }
    selected=${tag#v}
  done < <(git -C "$root" tag --points-at HEAD)
  printf '%s\n' "${selected:-0.0.0}"
else
  [[ -f "$root/VERSION" && -f "$root/RELEASE_MANIFEST" ]] || { printf 'Extracted source requires VERSION and RELEASE_MANIFEST\n' >&2; exit 1; }
  version=$(cat "$root/VERSION")
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
  printf '%s\n' "$version"
fi
