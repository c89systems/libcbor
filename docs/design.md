# Architecture and commitments

libcbor is the reusable binary serialization foundation for c89.systems. The
codec is transport-independent and executes without creating a JSON runtime.
The complete library requires the released lonejson 0.50.0 SDK for its mapped
and JSON receiver methods. POSIX I/O is a separate translation unit. Lua is a separate facade linked
to the installed public shared library and using Lua 5.5.1's public C API.
COSE is a separate bounded record layer using libcrypto from cpkt's OpenSSL
provider. It uses the native CBOR codec for wire structures, never JSON or a
second CBOR parser. See [COSE](cose.md) for key, authentication and stream policy.

The implementation starts from cai's bounded grammar/UTF-8 approach, not its
application types or heap-only API. See [provenance](provenance.md). Integration
into cai is a later change in that repository; no cai source is modified here.

The wire data model is RFC 8949: unsigned and negative integer magnitudes through
UINT64_MAX, all simple values, all IEEE float widths and bit patterns, tags,
bytes/text, arrays/maps, and definite/indefinite forms where permitted. Tags are
uninterpreted wrappers. Native float conversion is a separately checked helper.
There is no implicit bignum arithmetic, date parser, Unicode normalization,
schema registry, DOM, reflection, or object allocator in the parser.

Encoding and decoding are iterative and have fixed default nesting capacity 32.
Applications can supply separate frame arrays. Each additional string chunk/tag
uses nesting capacity. Borrowed DATA spans are at most 2048 bytes by default;
callers may select another nonzero bound. Memory does not grow with item size.
Contexts are not movable by memcpy: their embedded-storage pointers refer to
that context. Distinct contexts are independent and thread-safe; each context
and external frame array has one owner. Callback transfer reentry is rejected.

Encoder DATA is not gathered or sized. A submitted borrowed span is drained in
bounded writes, with UTF-8 validated incrementally before each output fragment.
A consumer may receive a valid prefix before a later error. Successful item or
record completion is the commit boundary; the application decides admission,
durability and authorization. The transfer validates and forwards existing CBOR
bytes unchanged using one fixed chunk, including nonpreferred integer widths.

## Framing and transports

SINGLE decodes exactly one item and leaves following bytes unconsumed. Callers
requiring exactly one item must reject leftovers. SEQUENCE implements RFC 8742;
unknown-length producers use indefinite values. Malformed input terminates a
sequence; no reliable resynchronization is promised. LENGTH32 implements cai's
four-byte big-endian length framing, default limit 128 KiB. Its producer must
know the encoded size from field lengths; never serialize to discover the size.
Large/unknown-length application streams can use successive bounded records.

Unix streams, TCP, files and pipes carry bytes, not message boundaries. The
optional native transfer handles partial writes and would-block without an
unbounded backlog, worker threads or an event loop. The application schedules
INPUT/OUTPUT readiness and owns timeouts and descriptors. Darwin callers arrange
SO_NOSIGPIPE for socket descriptors; pipe SIGPIPE policy is caller-owned.

UDP and Unix datagrams carry independently decodable bounded SINGLE items.
A datagram must fit the explicitly chosen receive/MTU bound; recvmsg MSG_TRUNC
must be rejected. Socket datagram assembly is bounded and explicit, never used
as staging for a larger logical message. No reliability, ordering, fragmentation,
reassembly or congestion-control protocol is supplied. Do not concatenate packets
into a pretend stream. Applications needing reliable streaming use a suitable
transport and its own public adapter.

## Types and compatibility

A C application defines its own structs and encode/decode functions over tokens.
Generic source/sink, allocator, frame, status, token and borrowed-span concepts
are reusable. HTTP errors, agent types and cai.workspace schemas stay in cai.
A typed decoder checks expected field kinds, duplicates, required fields, limits,
unknown-field policy and extension semantics before committing an object. An
unknown value can be skipped incrementally by counting begin/end depth. Custom
semantic tags use defined application policy, not process-global registration.

The core reports map entries in order and does not detect arbitrary duplicate
keys. Schema decoders with bounded fields can use a seen-field bitmap. Automatic
sorting of arbitrary maps conflicts with bounded streaming. Deterministic
producers supply known lengths, ordered keys and profile-correct scalar forms;
this version does not claim a general deterministic-encoding validator.

C89 syntax is enforced with -std=c89 and strict warnings. POSIX stdint.h and
compiler-provided 64-bit integer types are an explicit platform requirement;
this is not a claim of support for freestanding C89 without 64-bit arithmetic.
Supported targets cover LP64 and 32-bit ARM EABI. Raw float tokens avoid native
floating assumptions; binary64 helpers check native representation parameters.

The project is pre-1.0. Clean API cutovers are expected; no implicit migrations,
negotiation or protocol marker increments. Shared library ABI starts at 0 and is
versioned independently. Public struct layouts and Lua interop functions are ABI.
Symbols, headers and CMake/pkg-config identifiers distinguish this SDK from
PJK/libcbor. Both products install a library named libcbor; use separate prefixes
and verify discovery and link paths. There is no public stability promise before release.
