#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
scripts/build.sh core x86_64-linux-gnu Release "${1:-}" -DC89CBOR_BENCHMARKS=ON
scripts/build.sh lua x86_64-linux-gnu Release
mkdir -p build/bench
{
  uname -srm
  git rev-parse HEAD
  git status --short
  sha256sum build/x86_64-linux-gnu-release/codec_benchmark build/lua-x86_64-linux-gnu-release/cbor.so
  sha256sum build/x86_64-linux-gnu-release/profile_benchmark
  sed -n '/^CMAKE_C_COMPILER:FILEPATH=/p; /^CMAKE_C_FLAGS_RELEASE:STRING=/p' build/x86_64-linux-gnu-release/CMakeCache.txt
  awk -F: '/model name/ {print; exit}' /proc/cpuinfo
  printf 'profile_repetitions=%s chunk=%s\n' "${BENCH_REPETITIONS:-10000}" "${BENCH_CHUNK:-0}"
} > build/bench/context.txt
for mode in decode encode; do
  build/x86_64-linux-gnu-release/codec_benchmark "$mode" | tee "build/bench/$mode.jsonl"
done
for mode in mapped-encode mapped-decode json-control-encode json-control-decode json-to-cbor cbor-to-json; do
  build/x86_64-linux-gnu-release/profile_benchmark "$mode" "${BENCH_REPETITIONS:-10000}" "${BENCH_CHUNK:-0}" | tee "build/bench/$mode.jsonl"
done
for transport in unix tcp udp pipe unix-dgram; do
  report=build/bench/$transport.jsonl
  : > "$report"
  for round in 0 1 2 3 4 5; do
    result=$(build/x86_64-linux-gnu-release/transport_test "$transport" 8388608)
    if [[ $round != 0 ]]; then printf '%s\n' "$result" | tee -a "$report"; fi
  done
done
for transport in unix tcp pipe; do
  report=build/bench/$transport-indefinite.jsonl
  : > "$report"
  for round in 0 1 2 3 4 5; do
    result=$(build/x86_64-linux-gnu-release/transport_test "$transport" 8388608 indefinite)
    if [[ $round != 0 ]]; then printf '%s\n' "$result" | tee -a "$report"; fi
  done
done
for round in 0 1 2 3 4 5; do
  result=$(build/lua-x86_64-linux-gnu-release/lua_test "$PWD/build/lua-x86_64-linux-gnu-release/cbor.so" "$PWD/tests/lua_benchmark.lua")
  if [[ $round != 0 ]]; then printf '%s\n' "$result"; fi
done | tee build/bench/lua.jsonl
for round in 0 1 2 3 4 5; do
  result=$(build/lua-x86_64-linux-gnu-release/lua_test "$PWD/build/lua-x86_64-linux-gnu-release/cbor.so" --native)
  if [[ $round != 0 ]]; then printf '%s\n' "$result"; fi
done | tee build/bench/c-native.jsonl
