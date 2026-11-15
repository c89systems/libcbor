# libcbor — c89.systems

An incremental [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) CBOR library
for C89 and Lua 5.5.1. It provides:

- A token encoder/decoder with caller-owned state and bounded buffers.
- Framed streams and POSIX adapters for files, pipes, TCP, Unix sockets and datagrams.
- Direct C record mapping through lonejson and bidirectional JSON conversion.
- COSE encryption, signatures, MACs, authenticated record streams and CWT claims.
- A native Lua module with typed handles and C-to-Lua pointer interop.

Applications control I/O readiness, limits and object lifetimes. Large payloads
flow through bounded chunks; `INPUT` and `OUTPUT` return control to your event loop.

## Build and link

```sh
make build        # native Debug C SDK and Lua module
make check-native # C/Lua tests, formatting and shell checks
```

The build prepares pinned lonejson 0.50.0, cpkt 0.8.0/OpenSSL 3.6.5 and Lua 5.5.1
inputs. See [development](docs/development.md) for workstation tools, toolchain
preparation, target selection and editor setup.

For an installed SDK, provide the libcbor, lonejson and cpkt prefixes through
`CMAKE_PREFIX_PATH`:

```cmake
find_package(C89Cbor CONFIG REQUIRED)
target_link_libraries(app PRIVATE C89Cbor::static) # or C89Cbor::shared
```

The pkg-config package is `c89cbor`. This is the c89.systems library; PJK/libcbor
uses a separate installation prefix. [Delivery](docs/delivery.md) describes the
seven SDK targets, LuaRocks packages and installation layout.

## C example

This complete program encodes integer 42 as the bytes `18 2a`. Link it against
one of the CMake targets above.

```c
#include <c89cbor/cbor.h>

int main(void) {
  c89cbor_encoder encoder;
  c89cbor_token value = {0};
  unsigned char bytes[9];
  size_t written = 0;
  int status = c89cbor_encoder_init(NULL, &encoder, NULL, 0, 0);
  if (status != C89CBOR_OK)
    return 1;
  value.type = C89CBOR_UINT;
  value.argument = 42;
  status = encoder.put(&encoder, &value);
  if (status == C89CBOR_OK)
    status = encoder.read(&encoder, bytes, sizeof(bytes), &written);
  if (status == C89CBOR_OK)
    status = encoder.finish(&encoder);
  (void)encoder.cleanup(&encoder);
  return status != C89CBOR_OK || written != 2 ||
         bytes[0] != 0x18 || bytes[1] != 0x2a;
}
```

Use `<c89cbor/cbor.h>` for tokens, `<c89cbor/io.h>` for framing and I/O, and
`<c89cbor/lonejson.h>` for the runtime and mapped/JSON conversions. The
[C API guide](docs/c-api.md) covers status handling, borrowed spans and native
records. [copy.c](examples/copy.c) is a complete descriptor-to-descriptor example;
[the authenticated client/server](docs/standalone.md) demonstrates all transports.

## Lua example

`require('cbor')` loads the native `cbor` module, which calls the public shared
C library. This example decodes the same integer:

```lua
local cbor = require('cbor')
local runtime = assert(cbor.create())
local decoder = assert(runtime:decoder_init())
local status, consumed, token = decoder:next('\x18\x2a')
assert(status == cbor.TOKEN and consumed == 2)
assert(token)
assert(token:argument() == 42)
assert(token:close() == cbor.OK)
assert(decoder:finish() == cbor.OK)
assert(decoder:close() == cbor.OK)
assert(runtime:close() == cbor.OK)
```

Native source/sink handles let Lua schedule whole transfers without per-token
Lua calls. Lua-only source packages build against installed SDKs; see the
[Lua guide](docs/lua.md) for installation, loading the module, streaming,
interop and editor declarations.

## Documentation

| Topic | Guide |
| --- | --- |
| Ownership, tokens, records and JSON | [C API](docs/c-api.md) |
| Lua handles and native embedding | [Lua API](docs/lua.md) |
| Encryption and authenticated streams | [COSE](docs/cose.md) |
| Signatures, MACs and claim policies | [Sign1, Mac0 and CWT](docs/sign1-cwt.md) |
| Builds, clangd, LuaLS and testing | [Development](docs/development.md) |
| SDKs, LuaRocks and releases | [Delivery](docs/delivery.md) |
| Test suites and independent peers | [Hardening](docs/hardening.md) |
| Workloads and measurements | [Benchmarks](docs/benchmarks.md) |
| Architecture and detailed contracts | [Design](docs/design.md), [specification](docs/spec.md) |
| Symbols and receiver methods | [API inventory](docs/api-inventory.md) |
| Attribution and upstream sources | [Provenance](docs/provenance.md) |

[MIT license](LICENSE).
