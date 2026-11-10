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
and I/O, or load `require('cbor')` from Lua 5.5.1. The `libc89cbor` filename and
`c89cbor_*` symbols coexist with the unrelated PJK/libcbor implementation.

- [Implementation specification](docs/spec.md)
- [Design and type ownership](docs/design.md)
- [C API and custom types](docs/c-api.md)
- [Lua API and native pointer interop](docs/lua.md)
- [Development and toolchains](docs/development.md)
- [Benchmarks](docs/benchmarks.md)
- [SDK targets, packaging and release](docs/delivery.md)

[MIT license](LICENSE).
