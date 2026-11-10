# Development

Bash >=4.4, CMake >=3.21, Ninja, Make, Git, curl, GNU tar/gzip, SHA-256 tools,
pkg-config, clang-format and clangd are workstation tools. The activated
pkt-systems-cmake-lifecycle skill supplies pinned Bootlin/osxcross resolvers.
Set CPKT_LIFECYCLE_SCRIPTS_DIR when it is outside the usual Codex skill directory.
Missing toolchains fail with their preparation requirement; the build never
falls back to host GCC or downloads an Apple SDK. Repository-local .cache owns
extracted dependencies. Shared verified archives can be read from the declared
cpkt global cache. No sibling checkout's sources or generated state are used.

```
make build VERSION=0.1.0
make check-native VERSION=0.1.0
make matrix VERSION=0.1.0
make valgrind VERSION=0.1.0
make fuzz-smoke VERSION=0.1.0
```

VERSION is an explicit preparation override, not a checked-in version source.
An untagged checkout without it builds as 0.0.0. Exact lightweight release tags
supply Git release versions; extracted source carries VERSION/RELEASE_MANIFEST.
BUILD_JOBS defaults to 2. Operations run serially; compiler jobs inside a single
build follow that bound. `make clean` removes build, dist, local .cache and the
editor database, preserving installed tools and the declared global cpkt cache.

The normal native Debug build creates build/x86_64-linux-gnu-debug/compile_commands.json,
which .clangd discovers. Build once before opening the editor. Public headers
can be parsed through their ordinary implementation includers. There is no
editor-only SDK or bootstrap.

CTest covers vectors, malformed/truncated inputs, fragment boundaries, borrowed
ownership, terminal errors, native backpressure, large generated streaming and
real transports. Linux foreign architectures execute through qemu-aarch64 or
qemu-arm with their target sysroots. Darwin is compiled/linked/inspected locally
through osxcross; required native Darwin execution needs a Darwin host and is
reported separately. Glibc Debug worker tests constrain defaults to 128 KiB and
disable glibc's thread stack cache; musl workers use native defaults.

Formatting uses checked-in clang-format settings. Shell checks use bash -n;
optional shellcheck can add diagnostics when installed. Product C and facade C
use -std=c89 with strict warnings. Upstream benchmark dependency code retains its
own selected C standard. Tests never use Python as an execution driver.

Guard fault tests run natively. QEMU user mode on the preparation host returned
success for glibc's MADV_GUARD_INSTALL but permitted a guard read. Cross runtime
therefore proves actual default, nested and explicitly requested stack sizes;
it does not stand in for native kernel guard enforcement.
