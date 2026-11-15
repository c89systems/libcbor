# Development

## Tools and dependencies

Use Bash >=4.4, CMake >=3.21, Ninja, Make, Git, curl, GNU tar/gzip, SHA-256 tools,
pkg-config, flock, clang-format and clangd. The pkt-systems-cmake-lifecycle skill
supplies the pinned Bootlin/osxcross resolvers. Set `CPKT_LIFECYCLE_SCRIPTS_DIR`
when those helpers are outside the usual Codex skill directory.

The build prepares lonejson 0.50.0, cpkt 0.8.0/OpenSSL 3.6.5 and Lua 5.5.1.
Extracted dependencies belong to this checkout's `.cache/`; verified archives
can be shared through the cpkt cache. `CPKT_DEPENDENCY_CACHE` selects checkout-owned
`build/` or `.cache/` storage, or the standard global cache. Acquisition verifies
SHA-256 and uses a per-digest lock. Corrupt inputs and missing toolchains fail
with an actionable error.

CMake consumers provide `lonejson_DIR` and `CpktCore_DIR`. The selected cpkt SDK
also selects OpenSSL, replacing stale provider cache entries. The core links
libcrypto directly. Lua builds use target/configuration-local
`build/lua-runtime-*` and `build/lua-sdk-*` directories, retaining Lua's 64-bit
integer ABI on every target.

## Build and test

```sh
make build VERSION=0.1.0
make check-native VERSION=0.1.0
make matrix VERSION=0.1.0
make valgrind VERSION=0.1.0
make fuzz-smoke VERSION=0.1.0
```

`VERSION` overrides preparation identity. Exact lightweight release tags supply
release versions; an untagged checkout defaults to 0.0.0. Extracted source carries
`VERSION` and `RELEASE_MANIFEST`. Select `TARGET=<triple>` and
`CONFIG=Debug|Release` for individual builds. `check-native` always selects
x86_64 Linux glibc Debug. `BUILD_JOBS` defaults to two compiler jobs; run pipeline
operations serially. `make clean` removes this checkout's build, dist and local
cache while preserving installed tools and the global dependency cache.

CTest covers vectors, malformed/truncated input, fragment boundaries, lifetime
and callback reentry, allocation failures, native backpressure, large generated
streams and real transports. The README examples run directly from their fenced
source; Lua editor declarations are checked against the loaded module. Pipeline
fixtures check cleanup scope, archive acquisition, documentation links, target
selection and independent source reconstruction.

Foreign Linux targets execute through qemu-aarch64 or qemu-arm with target
sysroots. Native glibc worker tests use 128 KiB stacks and disable the thread stack
cache; musl uses native defaults. Native tests verify stack-guard faults. QEMU
checks actual stack sizes; guard enforcement is tested on the native kernel.
See [hardening](hardening.md) for sanitizers, Memcheck, Helgrind, fuzzing and peers.

Product and facade C use `-std=c89` with strict warnings. Formatting uses the
checked-in clang-format settings; shell checks use `bash -n`. Upstream benchmark
code keeps its selected C standard.

## Editors

Run `make build` once. `.clangd` discovers the normal native Debug compilation
databases under `build/x86_64-linux-gnu-debug` and
`build/lua-x86_64-linux-gnu-debug`. The Lua implementation and its interop header
use the Lua database, including the installed SDK and prepared Lua headers.
Public C headers use their ordinary implementation includers.

[LuaLS declarations](../lua/cbor.lua) describe the native module's constructors,
methods, options, diagnostics and constants. Add the containing `lua/` directory
to your LuaLS `workspace.library`, or use the installed
`share/lua/5.5/cbor-doc` directory (`doc/lua` within a LuaRocks installation).
These are editor definitions; runtime loading
uses `cbor.so`. For example, configure LuaLS in your editor with:

```json
{"workspace.library": ["/path/to/libcbor/lua"]}
```

## Native macOS diagnostics

`make check-darwin` runs C and Lua Debug/Release tests on Apple Silicon using
Xcode's selected tools, arm64 architecture and a macOS 15 baseline. It also checks
the relocated Release SDK and consumers. Install Bash >=4.4, GNU coreutils/tar,
flock, ripgrep, CMake, Ninja and pkg-config. Expose GNU `realpath` and `sha256sum`
while preserving macOS `stat`; the workflow creates checkout-local command links.
Set `CPKT_LIFECYCLE_SCRIPTS_DIR` as on Linux.

The GitHub Actions workflow supplies macOS runtime diagnostics. Local osxcross
builds supply Darwin release artifacts and compile/link/inspection evidence;
see [delivery](delivery.md).
