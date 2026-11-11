#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
root=$PWD; target=${1:?target required}; config=${2:-Release}
version=$(scripts/version.sh "${3:-}")
name=libcbor-$version-$target
stage=build/verify/$target-${config,,}
c89_target "$target"; c89_config "$config"
c89_owned_path "$stage/relocated"; c89_owned_path "$stage/consumer"
sha256sum -c "build/package/$target-${config,,}/SHA256"
mkdir -p "$stage"
rm -rf -- "$stage/relocated" "$stage/consumer"
mkdir -p "$stage/relocated"
tar -xzf "dist/$name.tar.gz" -C "$stage/relocated"
sdk=$root/$stage/relocated/$name
[[ -f "$sdk/LICENSE" || -f "$sdk/share/doc/C89Cbor/LICENSE" ]]
[[ -f "$sdk/include/c89cbor/cbor.h" && -f "$sdk/include/c89cbor/io.h" && -f "$sdk/lib/libcbor.a" ]]
[[ -f "$sdk/include/c89cbor/lua.h" && ! -e "$sdk/include/c89" && ! -e "$sdk/include/cbor" ]]
if rg -a -l '/home/|/tmp/|\.cache/|fsanitize=|GLIBC_TUNABLES' "$sdk"; then
  printf 'Private path or test instrumentation in SDK\n' >&2; exit 1
fi
cache=build/$target-${config,,}/CMakeCache.txt
nm_tool=$(sed -n 's/^CMAKE_NM:FILEPATH=//p' "$cache")
if [[ $target == arm64-apple-darwin ]]; then
  shared=$sdk/lib/libcbor.$version.dylib
  "$nm_tool" -gU "$shared" | awk '{sub(/^_/,"",$NF); print $NF}' | sort > "$stage/exports"
  otool=$(sed -n 's/^CMAKE_OTOOL:FILEPATH=//p' "$cache")
  "$otool" -hv "$shared" > "$stage/headers"
  "$otool" -L "$shared" | sed '1d' > "$stage/dependencies"
  rg -q 'ARM64' "$stage/headers"
  rg -q '@rpath/libcbor.0.dylib' "$stage/dependencies"
  if rg '/home/|/tmp/|\.cache/' "$stage/dependencies"; then exit 1; fi
else
  shared=$sdk/lib/libcbor.so.$version
  "$nm_tool" -D --defined-only "$shared" | awk '{print $NF}' | sort > "$stage/exports"
  readelf=$(sed -n 's/^CMAKE_READELF:FILEPATH=//p' "$cache")
  "$readelf" -h "$shared" > "$stage/headers"
  "$readelf" -d "$shared" > "$stage/dependencies"
  case "$target" in x86_64*) machine='Advanced Micro Devices X86-64';; aarch64*) machine=AArch64;; armhf*) machine=ARM;; esac
  rg -q "$machine" "$stage/headers"
  rg -q 'SONAME.*libcbor.so.0' "$stage/dependencies"
  if rg 'RPATH|RUNPATH' "$stage/dependencies"; then printf 'Unexpected SDK RPATH\n' >&2; exit 1; fi
fi
rg --no-filename -o 'c89cbor_[a-zA-Z0-9_]+\(' include/c89cbor/cbor.h include/c89cbor/io.h include/c89cbor/lonejson.h | sed 's/($//' | sort -u > "$stage/expected-exports"
diff -u "$stage/expected-exports" "$stage/exports"
lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
cmake -S tests/consumer -B "$stage/consumer" -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" "-DC89CBOR_TARGET=$target" \
  "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" "-DC89Cbor_DIR=$sdk/lib/cmake/C89Cbor" \
  "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.49.0-$target/lib/cmake/lonejson" \
  "-DSDK_PREFIX=$sdk" "-DEXPECTED_VERSION=$version" "-DRUNTIME_HELPER=$root/cmake/Runtime.cmake" \
  "-DAPI_SURFACE_SOURCE=$root/build/$target-${config,,}/api_surface.c" \
  "-DAPI_SURFACE_STACK=$root/tests/stack.c"
cmake --build "$stage/consumer" --parallel "${BUILD_JOBS:-2}"
if [[ $target != arm64-apple-darwin || $(uname -s) == Darwin ]]; then
  ctest --test-dir "$stage/consumer" --output-on-failure --stop-on-failure --no-tests=error
else
  printf 'Darwin: target compile/link/Mach-O/exports verified; execution deferred\n'
fi
pc_version=$(PKG_CONFIG_LIBDIR="$sdk/lib/pkgconfig:$root/.cache/deps/liblonejson-0.49.0-$target/lib/pkgconfig" pkg-config --modversion c89cbor)
[[ $pc_version == "$version" ]]
printf 'Verified %s\n' "dist/$name.tar.gz"
