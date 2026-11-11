#!/usr/bin/env bash
set -euo pipefail
umask 022
source "$(dirname -- "$0")/workspace.sh"
target=${1:?target required}; config=${2:-Release}
version=$(scripts/version.sh "${3:-}")
name=libcbor-$version-$target
stage=build/package/$target-${config,,}
c89_target "$target"; c89_config "$config"
c89_owned_path "$stage/$name"
c89_owned_path "dist/$name.tar.gz"
[[ -d build/$target-${config,,} ]] || { printf 'Build target first\n' >&2; exit 1; }
mkdir -p "$stage" dist
rm -rf -- "$stage/$name"
cmake --install "build/$target-${config,,}" --prefix "$PWD/$stage/$name"
# Strip only installed copies, never the development build or prerequisite SDK.
strip_tool=$(sed -n 's/^CMAKE_STRIP:FILEPATH=//p' "build/$target-${config,,}/CMakeCache.txt")
if [[ $target == arm64-apple-darwin ]]; then
  "$strip_tool" -S "$stage/$name/lib/libcbor.a" "$stage/$name/lib/libcbor.$version.dylib"
else
  "$strip_tool" -g -D "$stage/$name/lib/libcbor.a" "$stage/$name/lib/libcbor.so.$version"
fi
printf 'version=%s\ntarget=%s\nabi=0\n' "$version" "$target" > "$stage/$name/share/doc/C89Cbor/package.txt"
epoch=${SOURCE_DATE_EPOCH:-0}
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$name" | gzip -n > "dist/$name.tar.gz"
sha256sum "dist/$name.tar.gz" > "$stage/SHA256"
