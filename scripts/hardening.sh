#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
check_findings() {
  local result=$1 findings
  c89_owned_path "$result"
  [[ -d $result ]] || return 0
  findings=$(find "$result" -type f \( -path '*/crashes/*' -o -path '*/crashes.*/*' \
    -o -path '*/hangs/*' -o -path '*/hangs.*/*' \) ! -name README.txt -print -quit)
  if [[ -n $findings ]]; then
    printf 'Fuzzing found a saved crash or hang; inspect %s\n' "$result" >&2
    return 1
  fi
}
case ${1:?valgrind, fuzz or fuzz-long} in
findings)
  check_findings "${2:?owned result path required}"
  ;;
sanitize)
  [[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || exit 1
  scripts/deps.sh x86_64-linux-gnu lonejson
  scripts/deps.sh x86_64-linux-gnu cpkt
  lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
  cmake -S . -B build/sanitize -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" \
    -DC89CBOR_TARGET=x86_64-linux-gnu "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" \
    -DC89CBOR_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug \
    "-DC89CBOR_VERSION_OVERRIDE=${2:-}" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.50.0-x86_64-linux-gnu/lib/cmake/lonejson" \
    "-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-x86_64-linux-gnu/lib/cmake/CpktCore"
  cmake --build build/sanitize --parallel "${BUILD_JOBS:-2}"
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    ctest --test-dir build/sanitize --output-on-failure --stop-on-failure --no-tests=error -E '^reference-peer$'
  ;;
valgrind)
  command -v valgrind >/dev/null
  scripts/build.sh core x86_64-linux-gnu Debug "${2:-}"
  for test in codec io transport receiver_static receiver_shared conversion_static conversion_shared map_static map_shared api_static api_shared concurrency_static concurrency_shared cose_static cose_shared cose_rng datagram_static datagram_shared cwt_reuse_static cwt_reuse_shared; do
    valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
      "build/x86_64-linux-gnu-debug/${test}_test"
  done
  for kind in static shared; do
    valgrind --tool=helgrind --error-exitcode=99 --suppressions=tests/openssl-helgrind.supp "build/x86_64-linux-gnu-debug/concurrency_${kind}_test"
    valgrind --tool=helgrind --error-exitcode=99 --suppressions=tests/openssl-helgrind.supp "build/x86_64-linux-gnu-debug/cose_${kind}_test"
    valgrind --tool=helgrind --error-exitcode=99 --suppressions=tests/openssl-helgrind.supp "build/x86_64-linux-gnu-debug/cwt_reuse_${kind}_test"
  done
  scripts/build.sh lua x86_64-linux-gnu Debug
  valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
    build/lua-x86_64-linux-gnu-debug/lua_test "$root/build/lua-x86_64-linux-gnu-debug/cbor.so" "$root/tests/lua_test.lua"
  ;;
fuzz|fuzz-long)
  mode=$1
  seconds=${FUZZ_SECONDS:-10}
  if [[ $mode == fuzz-long ]]; then seconds=${FUZZ_SECONDS:-120}; fi
  [[ $seconds =~ ^[1-9][0-9]*$ ]] || { printf 'FUZZ_SECONDS must be positive\n' >&2; exit 1; }
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
  read -ra fuzz_cases <<< "${FUZZ_CASES:-codec json cbor map cose cose-stream cose-sign1 cose-sign1-stream cose-mac0 cose-mac0-stream cwt}"
  for case_name in "${fuzz_cases[@]}"; do
    case "$case_name" in codec|json|cbor|map|cose|cose-stream|cose-sign1|cose-sign1-stream|cose-mac0|cose-mac0-stream|cwt) ;; *) printf 'Unknown fuzz case: %s\n' "$case_name" >&2; exit 1;; esac
    result=build/fuzz/results-$case_name
    if [[ $mode == fuzz-long ]]; then result=build/fuzz/long-$case_name; fi
    c89_owned_path "$result"
    if [[ $mode != fuzz-long ]]; then rm -rf -- "$result"; fi
    check_findings "$result"
    if [[ $case_name == codec ]]; then
      command=("$root/build/fuzz/codec_fuzz")
      corpus=tests/fuzz-corpus
    elif [[ $case_name == cose* || $case_name == cwt ]]; then
      command=("$root/build/fuzz/cose_fuzz" "$case_name")
      corpus=build/fuzz/corpus-$case_name
      mkdir -p "$corpus"
      build/fuzz/cose_fuzz "seed-$case_name" < /dev/null > "$corpus/valid"
      build/fuzz/cose_fuzz "seed-$case_name-kw" < /dev/null > "$corpus/wrapped"
      build/fuzz/cose_fuzz "seed-$case_name-x" < /dev/null > "$corpus/public"
      build/fuzz/cose_fuzz "seed-$case_name-p256" < /dev/null > "$corpus/p256"
      build/fuzz/cose_fuzz "seed-$case_name-hmac" < /dev/null > "$corpus/hmac"
      cp tests/fuzz-corpus/* "$corpus/"
    else
      command=("$root/build/fuzz/bridge_fuzz" "$case_name")
      corpus=tests/bridge-corpus
    fi
    if [[ -d $result/default/queue ]]; then corpus=-; fi
    AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
    AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-1}" \
      "$afl" -i "$corpus" -o "$result" -V "$seconds" -- "${command[@]}"
    check_findings "$result"
  done
  ;;
*) exit 1;;
esac
