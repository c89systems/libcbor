#!/usr/bin/env bash
set -euo pipefail
umask 022
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
name=libcbor-$version
stage=build/source/$name
c89_owned_path "$stage"; c89_owned_path "dist/$name.tar.gz"
mkdir -p build/source dist
rm -rf -- "$stage"
mkdir -p "$stage"
# Source inventory comes from this owning checkout's index; callers stage new
# source files before preparation. Generated/cache files are never enumerated.
[[ $(git rev-parse --show-toplevel) == "$PWD" ]]
git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$stage"
printf '%s\n' "$version" > "$stage/VERSION"
git ls-files > "$stage/RELEASE_MANIFEST"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C build/source -cf - "$name" | gzip -n > "dist/$name.tar.gz"
