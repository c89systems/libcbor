#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
case ${1:?valgrind or fuzz} in
valgrind)
  command -v valgrind >/dev/null
  scripts/build.sh core x86_64-linux-gnu Debug "${2:-}"
  for test in codec io transport; do
    valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
      "build/x86_64-linux-gnu-debug/${test}_test"
  done
  ;;
fuzz)
  root=$PWD
  scripts/deps.sh x86_64-linux-gnu lonejson
  lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
  description=$("$lifecycle/cpkt-aflpp.sh" discover)
  afl=$(sed -n 's/^afl_fuzz=//p' <<< "$description")
  [[ -x "$afl" ]] || { printf 'Prepare pinned native AFL++ before fuzzing\n' >&2; exit 1; }
  cmake -S . -B build/fuzz -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" \
    -DC89CBOR_TARGET=x86_64-linux-gnu "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" \
    -DC89CBOR_AFL=ON -DC89CBOR_DISABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug \
    "-DC89CBOR_VERSION_OVERRIDE=${2:-}" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.49.0-x86_64-linux-gnu/lib/cmake/lonejson"
  cmake --build build/fuzz --parallel "${BUILD_JOBS:-2}"
  AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
    AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-1}" \
    "$afl" -i tests/fuzz-corpus -o build/fuzz/results -V "${FUZZ_SECONDS:-10}" \
      -- "$root/build/fuzz/codec_fuzz"
  findings=$(find build/fuzz/results/default/crashes build/fuzz/results/default/hangs -type f ! -name README.txt -print -quit)
  if [[ -n $findings ]]; then
    printf 'Fuzzing found a crash or hang; inspect build/fuzz/results\n' >&2; exit 1
  fi
  ;;
*) exit 1;;
esac
