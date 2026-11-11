#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
root=$PWD
archive=.cache/archives/pjk-libcbor-0.14.0.tar.gz
mkdir -p .cache/archives .cache/reference build/bench
if [[ ! -f $archive ]]; then
  curl --fail --location --retry 3 https://codeload.github.com/PJK/libcbor/tar.gz/refs/tags/v0.14.0 -o "$archive.part"
  printf '%s  %s\n' a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae "$archive.part" | sha256sum -c -
  mv -- "$archive.part" "$archive"
fi
printf '%s  %s\n' a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae "$archive" | sha256sum -c -
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
if nm build/x86_64-linux-gnu-release/reference_benchmark | rg 'c89cbor_'; then
  printf 'Native libcbor symbols leaked into independent reference executable\n' >&2; exit 1
fi
if nm build/x86_64-linux-gnu-release/codec_benchmark | rg ' cbor_stream_decode$'; then
  printf 'Reference symbols leaked into native executable\n' >&2; exit 1
fi
for mode in decode encode; do
  build/x86_64-linux-gnu-release/codec_benchmark "$mode" | tee "build/bench/$mode.jsonl"
  build/x86_64-linux-gnu-release/reference_benchmark "$mode" | tee "build/bench/reference-$mode.jsonl"
done
