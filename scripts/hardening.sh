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
    ctest --test-dir build/sanitize --output-on-failure --stop-on-failure --no-tests=error -LE podman
  scripts/build.sh lua-runtime x86_64-linux-gnu Debug
  cmake --install build/sanitize --prefix "$root/build/sdk-sanitize"
  cmake -S lua -B build/lua-sanitize -G Ninja \
    "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" -DC89CBOR_TARGET=x86_64-linux-gnu \
    "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" -DCMAKE_BUILD_TYPE=Debug -DC89CBOR_SANITIZE=ON \
    "-DC89Cbor_DIR=$root/build/sdk-sanitize/lib/cmake/C89Cbor" \
    "-Dlonejson_DIR=$root/.cache/deps/liblonejson-0.50.0-x86_64-linux-gnu/lib/cmake/lonejson" \
    "-DCpktCore_DIR=$root/.cache/deps/cpkt-0.7.0-x86_64-linux-gnu/lib/cmake/CpktCore" \
    "-DLUA_INCLUDE_DIR=$root/build/lua-sdk-x86_64-linux-gnu-debug/include" \
    "-DLUA_LIBRARY=$root/build/lua-sdk-x86_64-linux-gnu-debug/lib/liblua.so"
  cmake --build build/lua-sanitize --parallel "${BUILD_JOBS:-2}"
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    ctest --test-dir build/lua-sanitize --output-on-failure --stop-on-failure --no-tests=error
  ;;
valgrind)
  command -v valgrind >/dev/null
  scripts/build.sh core x86_64-linux-gnu Debug "${2:-}"
  checker=$(command -v valgrind)
  memory_args=(--overwrite "MemoryCheckCommand=$checker" --overwrite MemoryCheckType=Valgrind)
  ctest --test-dir build/x86_64-linux-gnu-debug -T MemCheck "${memory_args[@]}" \
    --overwrite 'MemoryCheckCommandOptions=--error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all' \
    -R '^(codec|io|transport-.*|((receiver|conversion|map|api|concurrency|cose|datagram|cwt-reuse)-(static|shared))|cose-rng)$' \
    --output-on-failure --stop-on-failure --no-tests=error
  ctest --test-dir build/x86_64-linux-gnu-debug -T MemCheck "${memory_args[@]}" \
    --overwrite "MemoryCheckCommandOptions=--tool=helgrind --error-exitcode=99 --suppressions=$root/tests/openssl-helgrind.supp" \
    -R '^(concurrency|cose|cwt-reuse)-(static|shared)$' \
    --output-on-failure --stop-on-failure --no-tests=error
  scripts/build.sh lua x86_64-linux-gnu Debug
  ctest --test-dir build/lua-x86_64-linux-gnu-debug -R '^lua-test-inventory$' \
    --output-on-failure --no-tests=error
  ctest --test-dir build/lua-x86_64-linux-gnu-debug -T MemCheck "${memory_args[@]}" \
    --overwrite 'MemoryCheckCommandOptions=--error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all' \
    -L lua --output-on-failure --stop-on-failure --no-tests=error
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
