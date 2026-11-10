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
} > build/bench/context.txt
for mode in decode encode; do
  build/x86_64-linux-gnu-release/codec_benchmark "$mode" | tee "build/bench/$mode.jsonl"
done
for transport in unix tcp udp pipe unix-dgram; do
  report=build/bench/$transport.jsonl
  : > "$report"
  for round in 0 1 2 3 4 5; do
    result=$(build/x86_64-linux-gnu-release/transport_test "$transport" 8388608)
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
