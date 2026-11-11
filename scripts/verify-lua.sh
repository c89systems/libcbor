#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
target=x86_64-linux-gnu
sdk=$root/build/verify/$target-release/relocated/libcbor-$version-$target
lua_sdk=$root/build/lua-sdk-$target-release
[[ -f "$sdk/lib/libcbor.so" ]] || { printf 'Verify the extracted native Release SDK first\n' >&2; exit 1; }
[[ -f "$lua_sdk/lib/liblua.so" ]] || { printf 'Prepare the pinned Lua 5.5.1 runtime first\n' >&2; exit 1; }
name=libcbor-lua-$version
scratch=$root/build/verify-lua
c89_owned_path build/verify-lua
rm -rf -- "$scratch"
mkdir -p "$scratch"/extracted "$scratch"/tmp
archive=$root/dist/$name.tar.gz
rock=$root/dist/libcbor-$version-1.src.rock
spec=libcbor-$version-1.rockspec
mapfile -t members < <(unzip -Z1 "$rock")
[[ ${#members[@]} == 2 && ${members[0]} == "$spec" && ${members[1]} == "$name.tar.gz" ]]
unzip -p "$rock" "$spec" | cmp - "dist/$spec"
unzip -p "$rock" "$name.tar.gz" | cmp - "$archive"
tar -xzf "$archive" -C "$scratch/extracted"
if rg -a -l -F -- "$HOME/" "$scratch/extracted" "dist/$spec"; then
  printf 'Workstation path in Lua source artifacts\n' >&2; exit 1
fi
lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
description=$("$lifecycle/cpkt-toolchains.sh" discover "$target")
cc=$(sed -n 's/^cc=//p' <<< "$description")
[[ -x $cc ]]
args=(-G Ninja "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake"
  "-DC89CBOR_TARGET=$target" "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" -DCMAKE_BUILD_TYPE=Release
  "-DC89Cbor_DIR=$sdk/lib/cmake/C89Cbor" "-DLUA_INCLUDE_DIR=$lua_sdk/include" "-DLUA_LIBRARY=$lua_sdk/lib/liblua.so")
args+=("-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.49.0-$target/lib/cmake/lonejson")
args+=("-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-$target/lib/cmake/CpktCore")
cmake -S "$scratch/extracted/$name" -B "$scratch/facade" "${args[@]}"
cmake --build "$scratch/facade" --parallel "${BUILD_JOBS:-2}"
cmake -S lua -B "$scratch/runner" "${args[@]}"
cmake --build "$scratch/runner" --target lua_test --parallel "${BUILD_JOBS:-2}"
TMPDIR="$scratch/tmp" luarocks --tree "$scratch/tree" --lua-version=5.5 \
  install --deps-mode=none "$rock" "CBOR_DIR=$sdk" "CC=$cc" "LD=$cc" \
  "LONEJSON_DIR=$root/.cache/deps/liblonejson-0.49.0-$target" \
  "CRYPTO_DIR=$root/.cache/deps/cpkt-0.7.0-$target" \
  "LUA_INCDIR=$lua_sdk/include" "LUA_LIBDIR=$lua_sdk/lib" \
  'CFLAGS=-O2 -fPIC -std=c89 -Wall -Wextra -Werror -Wpedantic -Wno-long-long'
runner=$scratch/runner/lua_test
nm_tool=$(sed -n 's/^nm=//p' <<< "$description")
inspect=$(sed -n 's/^readelf=//p' <<< "$description")
for module in "$scratch/facade/lua/cbor.so" "$scratch/tree/lib/lua/5.5/cbor.so"; do
  "$runner" "$module" "$root/tests/lua_test.lua"
  cmake "-DNM=$nm_tool" "-DINSPECT=$inspect" "-DMODULE=$module" \
    "-DHEADER=$root/include/c89cbor/lua.h" -P "$root/tests/lua_exports.cmake"
done
printf 'Verified Lua source archive and source rock against the extracted SDK\n'
