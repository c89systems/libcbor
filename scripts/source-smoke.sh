#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
c89_owned_path "build/source-smoke/libcbor-$version"
mkdir -p build/source-smoke
rm -rf -- "build/source-smoke/libcbor-$version"
tar -xzf "dist/libcbor-$version.tar.gz" -C build/source-smoke
cd -- "build/source-smoke/libcbor-$version"
# No parent checkout build, extracted SDK, tool collection or local cache reuse.
scripts/build.sh core x86_64-linux-gnu Release
scripts/build.sh test x86_64-linux-gnu Release
scripts/build.sh lua x86_64-linux-gnu Release
scripts/build.sh lua-test x86_64-linux-gnu Release
