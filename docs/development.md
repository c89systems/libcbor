# Development

Bash >=4.4, CMake >=3.21, Ninja, Make, Git, curl, GNU tar/gzip, SHA-256 tools,
pkg-config, flock, clang-format and clangd are workstation tools. The activated
pkt-systems-cmake-lifecycle skill supplies pinned Bootlin/osxcross resolvers.
Set CPKT_LIFECYCLE_SCRIPTS_DIR when it is outside the usual Codex skill directory.
Missing toolchains fail with their preparation requirement; the build never
falls back to host GCC or downloads an Apple SDK. Repository-local .cache owns
extracted dependencies. Shared verified archives can be read from the declared
cpkt global cache. No sibling checkout's sources or generated state are used.
Acquisition publishes verified archives under the shared cache's SHA-256 buckets
with a per-digest lock. `CPKT_DEPENDENCY_CACHE` selects this checkout's `build/`
or `.cache/` storage, or the standard global cpkt dependency cache. Corrupt inputs
fail rather than being silently replaced. Local archive hits can seed a missing
shared entry without network access.
COSE uses OpenSSL 3.6.5 from the pinned cpkt 0.7.0 SDK on every target. The core
links libcrypto directly through the provider targets; it needs neither libssl
nor a cpkt facade library. CMake consumers supply CpktCore_DIR alongside lonejson_DIR.
Lua builds prepare the pinned Lua.org 5.5.1 source into target/configuration-local
`build/lua-runtime-*` and `build/lua-sdk-*` directories. Upstream Lua compiles
with `-std=c89` and GNU inline spelling, retaining its normal 64-bit integer ABI
on armhf. The facade itself uses the public Lua C API with strict C89 warnings.

```
make build VERSION=0.1.0
make check-native VERSION=0.1.0
make matrix VERSION=0.1.0
make valgrind VERSION=0.1.0
make fuzz-smoke VERSION=0.1.0
```

The fuzz smoke runs separate codec, JSON, CBOR-to-JSON, mapped and COSE object/stream targets with
short reads and backpressure. `FUZZ_SECONDS` sets seconds per target (default
10); `FUZZ_CASES='cbor map'` selects a focused rerun. Corpus mutations, statistics
and any findings stay under `build/fuzz/results-<case>/`. Valgrind covers native
codec, receiver, bridge, mapped, COSE, API and Lua cases against the pinned runtime.
Concurrent operation tests share one prepared runtime across four workers and
check callback reentry and distinct outputs. Memcheck and Helgrind cover both
link modes. Runtime factories and lifecycle calls remain serialized by callers.

VERSION is an explicit preparation override, not a checked-in version source.
An untagged checkout without it builds as 0.0.0. Exact lightweight release tags
supply Git release versions; extracted source carries VERSION/RELEASE_MANIFEST.
BUILD_JOBS defaults to 2. Operations run serially; compiler jobs inside a single
build follow that bound. `make clean` removes build, dist, local .cache and the
editor database, preserving installed tools and the declared global cpkt cache.
`check-native` always selects x86_64 Linux glibc Debug, regardless of TARGET or
CONFIG inherited from the caller. `clean` resolves its owning Makefile and
checkout even when invoked with `make -f` from another directory.

Native pipeline fixtures cover cleanup ownership, archive cache miss/hit/corruption,
packaged documentation links, matrix lane selection and isolated source exports.
Lua's inventory check
verifies module selection, lifetime-suite inclusion and the worker-stack environment.

`make check-darwin` runs on Apple Silicon macOS with the selected Xcode tools and
SDK, arm64 architecture and macOS 15 deployment baseline. It runs C and Lua tests
in Debug and Release, then verifies the relocated Release SDK and its consumers.
Use Bash >=4.4 and GNU coreutils/tar plus flock, ripgrep, CMake, Ninja and pkg-config.
Set `CPKT_LIFECYCLE_SCRIPTS_DIR` to the prepared lifecycle helpers as on Linux.
The native toolchain never selects osxcross on macOS.

The normal native Debug build creates build/x86_64-linux-gnu-debug/compile_commands.json,
which .clangd discovers. Build once before opening the editor. Public headers
can be parsed through their ordinary implementation includers. There is no
editor-only SDK or bootstrap.

CTest covers vectors, malformed/truncated inputs, fragment boundaries, borrowed
ownership, terminal errors, native backpressure, large generated streaming and
real transports. Linux foreign architectures execute through qemu-aarch64 or
qemu-arm with their target sysroots. Darwin is compiled/linked/inspected locally
through osxcross; native runtime diagnostics run separately in the macOS workflow.
Glibc Debug worker tests constrain defaults to 128 KiB and
disable glibc's thread stack cache; musl workers use native defaults.

Formatting uses checked-in clang-format settings. Shell checks use bash -n;
optional shellcheck can add diagnostics when installed. Product C and facade C
use -std=c89 with strict warnings. Upstream benchmark dependency code retains its
own selected C standard. Tests never use Python as an execution driver.

Guard fault tests run natively. QEMU user mode on the preparation host returned
success for glibc's MADV_GUARD_INSTALL but permitted a guard read. Cross runtime
therefore proves actual default, nested and explicitly requested stack sizes;
it does not stand in for native kernel guard enforcement.
