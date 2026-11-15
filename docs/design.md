# Architecture

libcbor separates wire processing, I/O and application representations. The
native codec runs directly on CBOR tokens. Mapped and JSON conversion methods
use lonejson 0.50.0; COSE uses OpenSSL 3.6.5 from cpkt 0.8.0. Lua is a separate
module linked to the installed public shared library.

| Layer | Responsibility |
| --- | --- |
| Codec | Iterative CBOR grammar, incremental UTF-8 validation, borrowed DATA spans and resumable output. |
| Framing and I/O | SINGLE, RFC 8742 sequences, LENGTH32, partial writes and POSIX endpoints. |
| Mapped/JSON conversion | Native C records, bounded field storage, source/sink bindings and JSON visitor/writer integration. |
| COSE/CWT | Keys, authentication, bounded objects, ordered record streams and claim policy. |
| Lua | Typed userdata, owner pins, configuration and scheduling through the public C API. |

## Streaming and ownership

An initialized context has a stable address and one owner. Distinct operation
contexts can run concurrently. Applications serialize factories and lifecycle
calls on a shared runtime and provide thread-safe shared allocator callbacks.

The codec tracks nesting in bounded frames. DATA borrows an input fragment or
an encoder producer's bytes. An operation retains only its configured chunks
and metadata; source/sink callbacks handle partial acceptance and readiness.
The application owns event loops, descriptors and deadlines.

Successful item/record completion commits the value. Plain CBOR consumers may
receive a valid prefix before a later error. Authenticated operations publish
plaintext only after the corresponding record authenticates. Mapped fields
and callbacks remain provisional until the enclosing record completes.

Materialized record fields are an explicit destination choice. Stream fields
and field sinks deliver payload fragments directly; lonejson spools follow the
caller's storage policy. The [C API guide](c-api.md) describes ownership and
resource limits, and the [specification](spec.md) defines the complete contracts.

## Wire and transport model

The codec handles the RFC 8949 structural model, including integer magnitudes,
raw IEEE float widths, simple values, tags, maps, arrays and definite/indefinite
strings. Applications interpret tags and validate their message schemas.

SINGLE frames one item, SEQUENCE carries successive items, and LENGTH32 uses a
four-byte big-endian encoded-length prefix. TCP, Unix streams, files and pipes
use these framing choices. UDP and Unix datagrams use independently decodable
bounded items and atomic packet sends. Applications supply transport-specific
readiness, retry and delivery policy.

Mapped decoders check required fields, duplicates, native ranges and unknown
field policy. Generic token consumers perform their own semantic checks.
Deterministic producers choose field order and profile-appropriate encodings.

## Compatibility and provenance

Public structs, symbols and interop declarations form the C ABI. Shared ABI 0
is versioned independently of repository releases. CMake `C89Cbor` targets,
pkg-config `c89cbor`, headers and symbol prefixes identify this SDK.

The supported targets provide POSIX facilities, 64-bit integer types and the
compiler extensions used with strict C89 syntax. See [delivery](delivery.md)
for target and dependency versions, and [provenance](provenance.md) for the
original grammar/Unicode techniques and upstream attribution.
