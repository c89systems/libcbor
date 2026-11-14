# Delivery and release

The seven SDK targets are x86_64/aarch64/armhf Linux with glibc or musl, plus
arm64-apple-darwin. Each libcbor-VERSION-TARGET.tar.gz contains public C headers,
static and shared libcbor, relocatable CMake/pkg-config metadata, docs and MIT
license. Shared ABI is 0, independent of repository release version.

Additional products: libcbor-VERSION.tar.gz source;
libcbor-lua-VERSION.tar.gz facade source; libcbor-VERSION-1.rockspec; and
libcbor-VERSION-1.src.rock. libcbor-VERSION-CHECKSUMS is the complete upload
inventory. PJK/libcbor and upstream Lua binaries are not bundled in these products.
The required lonejson SDK and cpkt OpenSSL provider are installed separately.
Shared libcbor needs lonejson and libcrypto at runtime. Static consumers receive
the complete imported target closure; the SDK does not bundle provider archives.
LuaRocks requires CBOR_DIR, LONEJSON_DIR and CRYPTO_DIR plus Lua's normal headers.

`make package` stages one target/configuration via CMake install and writes a
scoped binary checksum under build/package. `make package-verify` extracts that
archive into a relocated path, checks architecture, ABI, exports, privacy,
metadata and real static/shared consumers. Target consumers execute on selected
Linux runners. GNU tar/gzip use stable order, timestamps, owners and gzip headers.

`make package-source` uses this owning repository's indexed sources, injecting
VERSION/RELEASE_MANIFEST. Stage new source files before preparation. Source smoke
extracts independently and rebuilds/tests with fresh local generated state;
it does not borrow the parent checkout's dependencies or binaries. `make matrix`
uses that reconstruction as its native Release lane: it builds/tests C and Lua,
packages and relocates the native SDK there, and exports only the verified archive
and its binary checksum. The remaining six target lanes run in the owning checkout;
the native library is not built a second time there.
The global verified archive cache can supply raw inputs. A checkout-local cache
override is remapped to the reconstructed source's own `.cache/shared`.

Preparation stays on one feature branch, with an explicit candidate VERSION if
needed. No release, signing, squash to trunk, tag or push is implicit in building.
For release, follow the lifecycle skill: squash verified work onto resolved local
default branch, let the engineer amend/sign, verify signature and exact lightweight
vX.Y.Z tag on that commit, then run `make release` without overrides. Its identity
gate runs before clean/build. A failure stops the release; fixes require a new
iteration. Remote refs remain unchanged. No script pushes or publishes artifacts.

`make prerelease` supplies local preparation checks. Runtime evidence is six Linux
targets on this Linux host; Darwin native execution remains a separately declared
runner requirement and must not be represented as completed here.

The Darwin deployment baseline is macOS 15.
`make prerelease-hardening` separately runs native sanitizers, memory checks,
the rootless reference peer and resumable longer fuzz campaigns. It is not part
of `make release`; see [hardening](hardening.md).
`make package-lua-verify` verifies the source rock's exact nested source and
rockspec, rebuilds both entrypoints against the extracted native SDK and runs
all registered Lua tests, including lifetime and GC cases, against each extracted
module. Its runner uses the extracted native SDK and a checkout-owned Lua runtime;
it does not rebuild the native library. Package verification checks the transitive
local documentation links from the shipped README. `make package-checksums`
verifies the complete inventory.
