# libcbor — c89.systems

A bounded, incremental RFC 8949 CBOR codec for strict C89, with caller-owned
state, optional allocation, explicit backpressure and a native Lua facade.
Stream large values through files, pipes, Unix sockets or TCP. UDP uses
independently decodable bounded datagrams.

```sh
make build       # pinned native Debug C SDK and Lua facade
make check-native
```

```cmake
find_package(C89Cbor CONFIG REQUIRED)
target_link_libraries(app PRIVATE C89Cbor::static) # or C89Cbor::shared
```

Include `<c89cbor/cbor.h>` for tokens and codec state, `<c89cbor/io.h>` for framing
and I/O, or `<c89cbor/lonejson.h>` for the runtime receiver. Load
`require('cbor')` from Lua 5.5.1. The build acquires the required lonejson
0.50.0 SDK and cpkt's pinned OpenSSL provider for COSE encryption. Install
PJK/libcbor in its own prefix for comparisons.

- [Implementation specification](docs/spec.md)
- [Design and type ownership](docs/design.md)
- [C API and custom types](docs/c-api.md)
- [Lua API and native pointer interop](docs/lua.md)
- [COSE objects, keys and authenticated streams](docs/cose.md)
- [Development and toolchains](docs/development.md)
- [Benchmarks](docs/benchmarks.md)
- [SDK targets, packaging and release](docs/delivery.md)

[MIT license](LICENSE).
