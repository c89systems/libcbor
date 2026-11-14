#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
target=x86_64-linux-gnu
lua_sdk=$root/build/lua-sdk-$target-release
sha256sum -c "build/package/$target-release/SHA256"
name=libcbor-lua-$version
scratch=$root/build/verify-lua
c89_owned_path build/verify-lua
rm -rf -- "$scratch"
mkdir -p "$scratch"/extracted "$scratch"/tmp "$scratch"/sdk
tar -xzf "dist/libcbor-$version-$target.tar.gz" -C "$scratch/sdk"
sdk=$scratch/sdk/libcbor-$version-$target
scripts/build.sh lua-runtime "$target" Release
archive=$root/dist/$name.tar.gz
rock=$root/dist/libcbor-$version-1.src.rock
spec=libcbor-$version-1.rockspec
mapfile -t members < <(unzip -Z1 "$rock")
[[ ${#members[@]} == 2 && ${members[0]} == "$spec" && ${members[1]} == "$name.tar.gz" ]]
unzip -p "$rock" "$spec" | cmp - "dist/$spec"
unzip -p "$rock" "$name.tar.gz" | cmp - "$archive"
tar -xzf "$archive" -C "$scratch/extracted"
cmake "-DROOT=$scratch/extracted/$name" -P cmake/CheckDocLinks.cmake
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
args+=("-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.50.0-$target/lib/cmake/lonejson")
args+=("-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-$target/lib/cmake/CpktCore")
cmake -S "$scratch/extracted/$name" -B "$scratch/facade" "${args[@]}"
cmake --build "$scratch/facade" --parallel "${BUILD_JOBS:-2}"
TMPDIR="$scratch/tmp" luarocks --tree "$scratch/tree" --lua-version=5.5 \
  install --deps-mode=none "$rock" "CBOR_DIR=$sdk" "CC=$cc" "LD=$cc" \
  "LONEJSON_DIR=$root/.cache/deps/liblonejson-0.50.0-$target" \
  "CRYPTO_DIR=$root/.cache/deps/cpkt-0.7.0-$target" \
  "LUA_INCDIR=$lua_sdk/include" "LUA_LIBDIR=$lua_sdk/lib" \
  'CFLAGS=-O2 -fPIC -std=c89 -Wall -Wextra -Werror -Wpedantic -Wno-long-long'
for module in "$scratch/facade/lua/cbor.so" "$scratch/tree/lib/lua/5.5/cbor.so"; do
  cmake -S lua -B "$scratch/runner" "${args[@]}" "-DC89CBOR_LUA_TEST_MODULE=$module"
  cmake --build "$scratch/runner" --parallel "${BUILD_JOBS:-2}"
  ctest --test-dir "$scratch/runner" --output-on-failure --stop-on-failure --no-tests=error
done
printf 'Verified Lua source archive and source rock against the extracted SDK\n'
