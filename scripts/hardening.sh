#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
case ${1:?valgrind or fuzz} in
valgrind)
  command -v valgrind >/dev/null
  scripts/build.sh core x86_64-linux-gnu Debug "${2:-}"
  for test in codec io transport receiver_static receiver_shared conversion_static conversion_shared map_static map_shared api_static api_shared concurrency_static concurrency_shared cose_static cose_shared cose_rng; do
    valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
      "build/x86_64-linux-gnu-debug/${test}_test"
  done
  for kind in static shared; do
    valgrind --tool=helgrind --error-exitcode=99 "build/x86_64-linux-gnu-debug/concurrency_${kind}_test"
    valgrind --tool=helgrind --error-exitcode=99 "build/x86_64-linux-gnu-debug/cose_${kind}_test"
  done
  scripts/build.sh lua x86_64-linux-gnu Debug
  valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
    build/lua-x86_64-linux-gnu-debug/lua_test "$root/build/lua-x86_64-linux-gnu-debug/cbor.so" "$root/tests/lua_test.lua"
  ;;
fuzz)
  root=$PWD
  scripts/deps.sh x86_64-linux-gnu lonejson
  scripts/deps.sh x86_64-linux-gnu cpkt
  lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
  description=$("$lifecycle/cpkt-aflpp.sh" discover)
  afl=$(sed -n 's/^afl_fuzz=//p' <<< "$description")
  [[ -x "$afl" ]] || { printf 'Prepare pinned native AFL++ before fuzzing\n' >&2; exit 1; }
  cmake -S . -B build/fuzz -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" \
    -DC89CBOR_TARGET=x86_64-linux-gnu "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" \
    -DC89CBOR_AFL=ON -DC89CBOR_DISABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug \
    "-DC89CBOR_VERSION_OVERRIDE=${2:-}" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.50.0-x86_64-linux-gnu/lib/cmake/lonejson" \
    "-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-x86_64-linux-gnu/lib/cmake/CpktCore"
  cmake --build build/fuzz --parallel "${BUILD_JOBS:-2}"
  read -ra fuzz_cases <<< "${FUZZ_CASES:-codec json cbor map cose cose-stream}"
  for case_name in "${fuzz_cases[@]}"; do
    case "$case_name" in codec|json|cbor|map|cose|cose-stream) ;; *) printf 'Unknown fuzz case: %s\n' "$case_name" >&2; exit 1;; esac
    result=build/fuzz/results-$case_name
    c89_owned_path "$result"
    rm -rf -- "$result"
    if [[ $case_name == codec ]]; then
      command=("$root/build/fuzz/codec_fuzz")
      corpus=tests/fuzz-corpus
    elif [[ $case_name == cose* ]]; then
      command=("$root/build/fuzz/cose_fuzz" "$case_name")
      corpus=build/fuzz/corpus-$case_name
      mkdir -p "$corpus"
      build/fuzz/cose_fuzz "seed-$case_name" < /dev/null > "$corpus/valid"
      build/fuzz/cose_fuzz "seed-$case_name-kw" < /dev/null > "$corpus/wrapped"
      build/fuzz/cose_fuzz "seed-$case_name-x" < /dev/null > "$corpus/public"
      cp tests/fuzz-corpus/* "$corpus/"
    else
      command=("$root/build/fuzz/bridge_fuzz" "$case_name")
      corpus=tests/bridge-corpus
    fi
    AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
    AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-1}" \
      "$afl" -i "$corpus" -o "$result" -V "${FUZZ_SECONDS:-10}" -- "${command[@]}"
    findings=$(find "$result/default/crashes" "$result/default/hangs" -type f ! -name README.txt -print -quit)
    if [[ -n $findings ]]; then
      printf 'Fuzzing found a crash or hang; inspect %s\n' "$result" >&2; exit 1
    fi
  done
  ;;
*) exit 1;;
esac
