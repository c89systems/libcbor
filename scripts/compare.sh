#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
root=$PWD
archive=.cache/archives/pjk-libcbor-0.14.0.tar.gz
mkdir -p .cache/archives .cache/reference build/bench
bash scripts/archive.sh https://codeload.github.com/PJK/libcbor/tar.gz/refs/tags/v0.14.0 \
  a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae "$archive"
if [[ ! -d .cache/reference/libcbor-0.14.0 ]]; then tar -xzf "$archive" -C .cache/reference; fi
lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
cmake -S .cache/reference/libcbor-0.14.0 -B build/reference -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$root/cmake/toolchain.cmake" -DC89CBOR_TARGET=x86_64-linux-gnu \
  "-DCPKT_LIFECYCLE_SCRIPTS_DIR=$lifecycle" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_STANDARD=99 \
  -DWITH_EXAMPLES=OFF -DWITH_TESTS=OFF -DSANITIZE=OFF -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_POLICY_DEFAULT_CMP0137=NEW -DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF \
  "-DCMAKE_INSTALL_PREFIX=$root/.cache/reference/sdk"
cmake --build build/reference --parallel "${BUILD_JOBS:-2}"
cmake --install build/reference
scripts/build.sh core x86_64-linux-gnu Release "${1:-}" -DC89CBOR_BENCHMARKS=ON "-DC89CBOR_REFERENCE_PREFIX=$root/.cache/reference/sdk"
for executable in reference_benchmark reference_mapped_benchmark; do
  if nm "build/x86_64-linux-gnu-release/$executable" | rg 'c89cbor_'; then
    printf 'Native libcbor symbols leaked into independent reference executable\n' >&2; exit 1
  fi
done
for executable in codec_benchmark profile_benchmark; do
  if nm "build/x86_64-linux-gnu-release/$executable" | rg ' cbor_stream_decode$'; then
    printf 'Reference symbols leaked into native executable\n' >&2; exit 1
  fi
done
ctest --test-dir build/x86_64-linux-gnu-release -R 'benchmark-.*-smoke|interop-reference' --output-on-failure --stop-on-failure
{
  uname -srm
  git rev-parse HEAD
  git status --short
  sha256sum "$archive"
  for executable in codec_benchmark profile_benchmark reference_benchmark reference_mapped_benchmark; do
    sha256sum "build/x86_64-linux-gnu-release/$executable"
  done
  sed -n '/^CMAKE_C_COMPILER:FILEPATH=/p; /^CMAKE_C_FLAGS_RELEASE:STRING=/p' build/x86_64-linux-gnu-release/CMakeCache.txt
  awk -F: '/model name/ {print; exit}' /proc/cpuinfo
  printf 'profile_repetitions=%s chunk=2048\n' "${BENCH_REPETITIONS:-10000}"
} > build/bench/comparison-context.txt
for mode in decode encode; do
  build/x86_64-linux-gnu-release/codec_benchmark "$mode" | tee "build/bench/$mode.jsonl"
  build/x86_64-linux-gnu-release/reference_benchmark "$mode" | tee "build/bench/reference-$mode.jsonl"
done
for mode in encode decode; do
  build/x86_64-linux-gnu-release/profile_benchmark "mapped-$mode" "${BENCH_REPETITIONS:-10000}" | tee "build/bench/mapped-$mode.jsonl"
  build/x86_64-linux-gnu-release/reference_mapped_benchmark "$mode" "${BENCH_REPETITIONS:-10000}" | tee "build/bench/reference-mapped-$mode.jsonl"
done
