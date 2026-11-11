#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
root=$PWD
action=${1:?usage: build.sh core|test|lua|lua-test TARGET Debug|Release [VERSION]}
target=${2:-x86_64-linux-gnu}
config=${3:-Debug}
version=${4:-}
c89_config "$config"
lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
[[ -x "$lifecycle/cpkt-toolchains.sh" ]] || { printf 'Set CPKT_LIFECYCLE_SCRIPTS_DIR to the lifecycle scripts directory\n' >&2; exit 1; }
c89_target "$target"
build=build/$target-${config,,}
c89_owned_path "$build"
args=(-G Ninja "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake"
  "-DC89CBOR_TARGET=$target" "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle"
  "-DCMAKE_BUILD_TYPE=$config" "-DCMAKE_INSTALL_LIBDIR=lib")
case "$action" in
core)
  scripts/deps.sh "$target" lonejson
  cmake -S . -B "$build" "${args[@]}" "-DC89CBOR_VERSION_OVERRIDE=$version" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.49.0-$target/lib/cmake/lonejson" "${@:5}"
  cmake --build "$build" --parallel "${BUILD_JOBS:-2}"
  ;;
test)
  [[ $target != arm64-apple-darwin || $(uname -s) == Darwin ]] || { printf 'Darwin execution requires a native Darwin runner\n' >&2; exit 1; }
  ctest --test-dir "$build" --output-on-failure --stop-on-failure --no-tests=error
  ;;
lua)
  scripts/deps.sh "$target"
  sdk=$root/build/sdk-$target-${config,,}
  cmake --install "$build" --prefix "$sdk"
  cmake -S lua -B "build/lua-$target-${config,,}" "${args[@]}" \
    "-DC89Cbor_DIR=$sdk/lib/cmake/C89Cbor" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.49.0-$target/lib/cmake/lonejson" \
    "-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-$target/lib/cmake/CpktCore"
  cmake --build "build/lua-$target-${config,,}" --parallel "${BUILD_JOBS:-2}"
  ;;
lua-test)
  [[ $target != arm64-apple-darwin || $(uname -s) == Darwin ]] || { printf 'Darwin execution requires a native Darwin runner\n' >&2; exit 1; }
  ctest --test-dir "build/lua-$target-${config,,}" --output-on-failure --stop-on-failure --no-tests=error
  ;;
*) printf 'Unknown build operation: %s\n' "$action" >&2; exit 1;;
esac
