#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
owner=$root
c89_owned_path "build/source-smoke/libcbor-$version"
mkdir -p build/source-smoke
rm -rf -- "build/source-smoke/libcbor-$version"
tar -xzf "dist/libcbor-$version.tar.gz" -C build/source-smoke
cd -- "build/source-smoke/libcbor-$version"
# No parent checkout build, extracted SDK, tool collection or local cache reuse.
if [[ -n ${CPKT_DEPENDENCY_CACHE:-} && $CPKT_DEPENDENCY_CACHE == /* ]]; then
  dependency_cache=$(realpath -m -- "$CPKT_DEPENDENCY_CACHE")
  case "$dependency_cache/" in
    "$owner/build/"*|"$owner/.cache/"*) export CPKT_DEPENDENCY_CACHE=$PWD/.cache/shared ;;
  esac
fi
scripts/build.sh core x86_64-linux-gnu Release
scripts/build.sh test x86_64-linux-gnu Release
scripts/build.sh lua x86_64-linux-gnu Release
scripts/build.sh lua-test x86_64-linux-gnu Release
scripts/package.sh x86_64-linux-gnu Release
scripts/verify-package.sh x86_64-linux-gnu Release
# Export only the verified public bytes and their binary-scope checksum.
mkdir -p "$owner/build/package/x86_64-linux-gnu-release"
cp "dist/libcbor-$version-x86_64-linux-gnu.tar.gz" "$owner/dist/"
cp build/package/x86_64-linux-gnu-release/SHA256 "$owner/build/package/x86_64-linux-gnu-release/"
