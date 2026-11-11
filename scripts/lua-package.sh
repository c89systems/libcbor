#!/usr/bin/env bash
set -euo pipefail
umask 022
source "$(dirname -- "$0")/workspace.sh"
version=$(scripts/version.sh "${1:-}")
name=libcbor-lua-$version
stage=build/lua-source/$name
c89_owned_path "$stage"; c89_owned_path "dist/$name.tar.gz"
mkdir -p build/lua-source dist
rm -rf -- "$stage"
mkdir -p "$stage"/lua "$stage"/include/c89cbor "$stage"/cmake "$stage"/docs
cp lua/cbor.c lua/cbor.lua lua/CMakeLists.txt lua/exports.map "$stage/lua/"
cp include/c89cbor/lua.h "$stage/include/c89cbor/"
cp cmake/Runtime.cmake cmake/FindLua.cmake "$stage/cmake/"
cp LICENSE "$stage/"
cp docs/lua.md docs/delivery.md "$stage/docs/"
cat > "$stage/README.md" <<'README'
# libcbor Lua facade

This source package builds against the installed c89.systems CBOR SDK and Lua
5.5.1 public headers. See the [Lua API](docs/lua.md) and [delivery guide](docs/delivery.md).
README
printf '%s\n' "$version" > "$stage/VERSION"
# Lua source package builds the facade only against installed SDKs.
cat > "$stage/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.21)
project(CborLuaSource LANGUAGES C)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(lua)
CMAKE
find "$stage" -type f -printf '%P\n' | sort > "$stage/RELEASE_MANIFEST"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C build/lua-source -cf - "$name" | gzip -n > "dist/$name.tar.gz"
cat > "dist/libcbor-$version-1.rockspec" <<ROCK
package = "libcbor"
version = "$version-1"
source = {
  url = "https://github.com/c89systems/libcbor/releases/download/v$version/$name.tar.gz",
  dir = "$name"
}
description = { summary = "Native streaming c89.systems CBOR facade", license = "MIT" }
dependencies = { "lua >= 5.5, < 5.6" }
external_dependencies = {
  CBOR = { header = "c89cbor/lonejson.h", library = "cbor" },
  LONEJSON = { header = "lonejson.h", library = "lonejson" }
}
build = {
  type = "builtin",
  modules = {
    cbor = {
      sources = { "lua/cbor.c" },
      libraries = { "cbor", "lonejson" },
      defines = { "_POSIX_C_SOURCE=200809L" },
      incdirs = { "include", "\$(CBOR_INCDIR)", "\$(LONEJSON_INCDIR)" },
      libdirs = { "\$(CBOR_LIBDIR)", "\$(LONEJSON_LIBDIR)" }
    }
  }
}
ROCK
# A source rock is a ZIP containing its exact rockspec and public source archive.
# Fixed timestamps and sorted members make the package independent of staging mtimes.
mkdir -p build/lua-rock
cp "dist/libcbor-$version-1.rockspec" "dist/$name.tar.gz" build/lua-rock/
rm -f -- "dist/libcbor-$version-1.src.rock"
(cd build/lua-rock; touch -t 198001010000 "libcbor-$version-1.rockspec" "$name.tar.gz"; \
  zip -X -q "../../dist/libcbor-$version-1.src.rock" "libcbor-$version-1.rockspec" "$name.tar.gz")
