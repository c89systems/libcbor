#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
files=()
for target in x86_64-linux-gnu x86_64-linux-musl aarch64-linux-gnu aarch64-linux-musl armhf-linux-gnu armhf-linux-musl arm64-apple-darwin; do
  files+=("libcbor-$version-$target.tar.gz")
done
files+=("libcbor-$version.tar.gz" "libcbor-lua-$version.tar.gz" "libcbor-$version-1.rockspec" "libcbor-$version-1.src.rock")
for file in "${files[@]}"; do [[ -f dist/$file ]] || { printf 'Missing artifact: %s\n' "$file" >&2; exit 1; }; done
shopt -s dotglob nullglob
for file in dist/*; do
  [[ ${file##*/} == "libcbor-$version-CHECKSUMS" ]] && continue
  matched=false
  for expected in "${files[@]}"; do [[ ${file##*/} != "$expected" ]] || matched=true; done
  $matched || { printf 'Unexpected artifact: %s\n' "$file" >&2; exit 1; }
done
(cd dist; sha256sum "${files[@]}" > "libcbor-$version-CHECKSUMS"; sha256sum -c "libcbor-$version-CHECKSUMS")
