# libcbor specification

This specification defines the implemented product's contracts and verification
requirements. Build and execution evidence is recorded by the local lifecycle;
cross-compilation alone does not establish target runtime behavior.

## Product and package identity

libcbor is the C89 Systems CBOR library. It supplies a general streaming
codec, explicit record framing, a receiver API, direct lonejson mapped-record
conversion, bidirectional JSON conversion and a native Lua facade. CBOR is the
shared binary representation. Each application continues to own its message
schema, protocol negotiation, authorization and business logic.

| Surface | Contract |
| --- | --- |
| Product, repository and library basename | `libcbor`. Install `libcbor.a` and the platform's versioned `libcbor.so` or `libcbor.dylib`. |
| Public C symbols and types | `c89cbor_*`, with `C89CBOR_*` constants and a `c89cbor` receiver type. |
| Public headers | `<c89cbor/cbor.h>`, `<c89cbor/io.h>`, `<c89cbor/lonejson.h>` and `<c89cbor/lua.h>`. |
| Package discovery | Retain `C89Cbor::static`, `C89Cbor::shared` and pkg-config `c89cbor` as discovery identifiers to distinguish the C89 Systems SDK. Both link modes expose the full receiver. |
| Lua | `require('cbor')` on Lua 5.5.1 through its public C API, without cpkt. Native interop uses typed C pointers and owner references. |
| Required dependency | [c89systems/lonejson 0.49.0](https://github.com/c89systems/lonejson/releases/tag/v0.49.0), shared ABI 29. |
| Reference implementation | PJK/libcbor stays in a private benchmark prefix. Compare separate executables linked against their respective libraries. |

The two CBOR products have overlapping library filenames. SDK instructions
must identify the intended prefix. Benchmark builds must resolve each
implementation from its own prefix and inspect the actual dependency
identities. The public C symbols and headers distinguish the APIs.

The normal static and shared products require lonejson. Every instance of
the main receiver has the four conversion methods. Keep JSON-specific code
outside the grammar and byte emission code so native CBOR operations can
run without creating a JSON runtime or executing JSON conversion. The
lonejson headers and libraries are separately installed SDK prerequisites
rather than copies embedded in libcbor.

Pin the released SDK by exact version, target and SHA-256. Verify its
package metadata, public ABI and linked library identity. Do not infer the
release version from header version macros alone. Installed CMake and
pkg-config metadata must resolve the complete static and shared dependency
closure from the consumer's SDK prefixes. JSON conversion needs lonejson's
base library, without its HTTP, authentication or curl components.

Use the release assets named `liblonejson-0.49.0-<target>.tar.gz` with
the following SHA-256 pins. The release's
[checksum manifest](https://github.com/c89systems/lonejson/releases/download/v0.49.0/lonejson-0.49.0-CHECKSUMS)
also identifies its source and Lua payloads.

| Target | SDK SHA-256 |
| --- | --- |
| `x86_64-linux-gnu` | `3fe1629888f264b9605fa5ba96ea57e4b5da11276c245cba11409608fb292480` |
| `x86_64-linux-musl` | `47049e9f26701f1a5b16c3fd9dfa4ad04357402539ec1f861745f7f8843c4be8` |
| `aarch64-linux-gnu` | `ce472cab6e7340dec9a4d713e04c31fbb207f2de72bfa9e7aaa8e9f9c2f02c3a` |
| `aarch64-linux-musl` | `76652c0a1656a38a5fb6b05c55a88607f80b2797c80d5859ce0bff81d49494db` |
| `armhf-linux-gnu` | `f466f7d639b09015b7b202d455d9d759d9a2249c0f43e4dc4c0b904f625ac716` |
| `armhf-linux-musl` | `03bb63d7f5f88217129bda677b35f85ee8109f785780723961aae8180de564c8` |
| `arm64-apple-darwin` | `51344ba031e2e09ea88266eb02b6e0ba3411a430c7081c9e204b237bc9bd4af8` |

## Native codec and receiver contracts

### API shape

Every public operation with a natural receiver is callable on that
receiver. This includes creation of child handles, lifecycle operations,
queries, conversion helpers and native Lua interop. Publish receiver-first
methods with direct call syntax such as `encoder->put(encoder, &token)`.
Constructors install the complete method surface before returning success.
Stateful methods take the handle whose state they advance. Runtime methods
supply configured factories and utilities shared across operation kinds.

Each method has an exported free-function twin with the same receiver as
its first argument, remaining parameters, result, diagnostics and ownership
contract. Both entry points use the same implementation. For example,
`c89cbor_encoder_put(encoder, &token)` and
`encoder->put(encoder, &token)` accept and drain the same token state.
Document each exported symbol's receiver and corresponding member in the
public API reference.

The root runtime constructor and initializer bootstrap the first receiver.
Default-value helpers can also be free functions so options and callback
records can be prepared before any runtime exists. Give a valid runtime
matching default and utility methods. The Lua module opener, binding
initializer and binding constructor bootstrap their own receiver.
These bootstrap functions are the explicit exceptions to instance-method
parity.

Tokens, spans, limits, allocator callbacks, endpoint callback descriptions
and lonejson map views remain plain data. Put operations on those values
on the runtime or an existing operation handle. The source's `read` and
sink's `write` remain provider callbacks with their declared context
argument. Receiver methods that drive them belong to a transfer or
conversion handle.

| Receiver | Required operations and ownership |
| --- | --- |
| `c89cbor` | Runtime cleanup and destruction, configured child factories and initializers, option defaults, `status_string`, `version`, `float64_set`, `float64_get`, `length32` and the mapped and JSON methods below. |
| `c89cbor_encoder` | `put`, copying `read`, borrowed-output `peek` and `advance`, `finish`, `reset`, `cleanup` and heap `destroy`. |
| `c89cbor_decoder` | `next`, `finish`, `reset`, `cleanup` and heap `destroy`. |
| `c89cbor_reader` | Framed `next`, `finish`, `reset`, `cleanup` and heap `destroy`. |
| `c89cbor_transfer` | Bounded `step`, progress query, `cleanup` and heap `destroy`. |
| `c89cbor_conversion` | Bounded `step`, progress query, `cleanup` and heap `destroy` for one mapped or JSON conversion. |
| `c89cbor_fd` | Borrowed source and sink views, `cleanup` and heap `destroy`. It borrows the operating-system descriptor. |
| `c89cbor_lua` | Typed `push_*` and `check_*` methods for native handles, record views, allocators and spans, with `cleanup` and heap `destroy`. It borrows one Lua state. |

Each stateful receiver also exposes a `diagnostic` query. Method pointers
belong to the library and remain read-only to callers. Public headers
declare complete shells for the caller-storage route, including the
required bounded native state. An active shell has a stable address and
can be passed by pointer. It cannot be copied or moved while initialized.

Integer and raw-float tokens can be constructed as plain data. The runtime
float helpers perform checked conversion to and from native binary64.
Tagged-value helpers belong to the encoder or decoder they advance.
Length32 formatting belongs to the runtime's framing utilities. Native
Lua interop belongs to the optional binding receiver declared in
`<c89cbor/lua.h>`.

The main receiver exposes `json_to_cbor`, `cbor_to_json`, `encode_map`
and `decode_map`, with borrowed-view variants for mapped records. Keep
the entry points symmetrical. Raw conversion takes
one source, one sink and optional conversion limits. Mapped conversion takes
one `lonejson_map`, a C record, and one source or sink as appropriate. Provide
a route that accepts `lonejson_record_view` for native interop. It borrows the
same record and schema with the view's size, ABI and lifetime checks. C
callers with ordinary structs can pass a map and record directly.

| Synchronous runtime method | Borrowed arguments in addition to the receiver, options and diagnostic |
| --- | --- |
| `json_to_cbor` | JSON source, CBOR sink. |
| `cbor_to_json` | CBOR source, JSON sink. |
| `encode_map` | `const lonejson_map *`, source record and its extent, CBOR sink. |
| `decode_map` | CBOR source, `const lonejson_map *`, initialized destination record and its extent. |
| `encode_map_view` | Borrowed `lonejson_record_view`, CBOR sink. |
| `decode_map_view` | CBOR source, borrowed writable `lonejson_record_view`. |

Each of these six methods has an `_open` factory on the same runtime.
It accepts the same value arguments and returns a `c89cbor_conversion`
handle through an output parameter. For example,
`codec->json_to_cbor_open(codec, ...)` and its exported twin
`c89cbor_json_to_cbor_open(codec, ...)` prepare a resumable operation.
Successful open validates configuration and borrows the endpoints. It
performs no endpoint I/O and delivers no record callbacks.

`conversion->step(conversion, ...)` advances that operation until a byte
or event budget is exhausted, input or output must wait, or it reaches
completion or failure. Progress reports cumulative input and output bytes
and completed records. It remains queryable after completion or failure.
The synchronous methods drive this same state to completion with blocking
endpoints. If an endpoint unexpectedly would block, they return a terminal
endpoint error with the progress already made. Callers that need to resume
use the `_open` factory and retain its operation handle.

Completion of a conversion includes final parser and writer checks and
draining pending output. Repeated steps after completion return completion
with unchanged counts and no callbacks. Failed steps preserve the terminal
diagnostic. Cleanup cancels a live operation and releases its owned state.
Already delivered bytes and record effects keep their provisional status
when cancellation prevents successful completion.

Reuse the native source and sink contracts. With a record view, use the
view's lonejson runtime for operations on the record. Check both view
versions, struct sizes and the record extent before using its pointers.
The plain map methods use the receiver's lonejson runtime. Require the
same runtime that owns the record's allocated fields.

A runtime can borrow a configured `lonejson *` or create and own a default
one. Borrowed runtimes and records must outlive operations that use them.
Runtime cleanup destroys only the resources it owns. Native token operations
also work with caller-initialized codec state and no runtime construction.
Optional allocating constructors use the configured allocator. Caller
storage remains usable without a hidden allocation fallback.

### Construction and lifecycle

Provide `c89cbor_default_config`, `c89cbor_init` for caller-owned runtime
storage and `c89cbor_create` for an allocated root runtime. Both initializer
and constructor accept configuration and an optional diagnostic. The
allocating constructor returns status and initializes its output pointer
to NULL before attempting allocation. Every public operational receiver
has an initializer for caller storage and an allocating constructor.

The optional binding bootstraps through `c89cbor_lua_init` or
`c89cbor_lua_create` using the already existing Lua state. Creating this
receiver requires the binding to have been loaded into that state.
Its methods then provide the full typed pointer interop surface.

Runtime factories use `<kind>_init` and `<kind>_create`, including
`encoder_init`, `encoder_create`, `decoder_init`, `decoder_create`,
`reader_init`, `reader_create`, `transfer_init`, `transfer_create`,
`fd_init` and `fd_create`. The six conversion `_open` methods are its
configured conversion constructors. Give the conversion receiver matching
caller-storage `<operation>_init` entry points on the runtime, such as
`json_to_cbor_init`. Their exported twins use the same receiver-first
signature. A NULL runtime on a native initializer or constructor selects
documented native defaults and the
supplied operation options. A conversion requires a configured runtime.

Snapshot scalar configuration and allocator callbacks during construction.
Options default helpers return fully initialized values. NULL options
select defaults, and zero selects the documented default for numerical
limits. Borrowed frame arrays, schemas, records, endpoint contexts,
allocator contexts and lonejson runtimes retain their explicit lifetime
requirements. A child created from a runtime borrows that runtime until
the child's cleanup. The runtime must outlive all such children. Its
cleanup and destruction return a busy status while dependents exist.

An initializer establishes a fresh caller-owned shell without inspecting
arbitrary prior bytes. Reinitializing caller storage requires cleanup
first. An allocated shell is destroyed and reconstructed when fresh
initialization is required. On initialization failure, the destination
is in a documented cleanup-safe
state. No endpoint or record becomes owned merely because initialization
succeeds. Native encoder, decoder, reader, fd and transfer initialization
and execution remain allocation-free with sufficient caller storage.
Record construction and lonejson workspace can allocate according to
their declared contracts. Document those allocations separately.

Every receiver supplies `cleanup` to release owned resources while
preserving its shell storage, and `destroy` to release an allocated
shell through its recorded allocator. Cleanup is idempotent for an
initialized shell. Destroying caller-owned storage returns invalid API
use without freeing it. An allocated shell remains destroyable after
cleanup. The caller releases every created child. Closing an fd adapter
leaves descriptor ownership with the caller. A closed borrowed Lua view
releases its pins while the native owner's lifecycle remains authoritative.

All lifecycle operations reject callback reentry and tracked dependent
borrows before changing state. Native callers finish using borrowed spans
before cleaning up their owner. Successful cleanup is also available for
paused and failed operations. Cleanup of mapped record storage follows
lonejson's separate record lifecycle. Context reset starts another item
using existing storage after successful finish. Changed configuration or
a terminal error requires reconstruction under the shell's ownership
contract.

### Results and diagnostics

Expose a common result convention for completion, input readiness, output
readiness, invalid API use, malformed data, unsupported conversion, limits,
I/O and allocation failure. A diagnostic identifies the failed layer and
operation. It carries an input offset when available, and a field path or
field identity for mapped failures. Preserve a lonejson status as the cause
when one exists. Diagnostic storage and lifetime must be documented. An
allocation failure must still return a meaningful status.

Completion, progress, a produced token and readiness conditions have
distinct results. Exhausting a drive budget reports progress. Input or
output readiness returns control to the caller. It never causes an
internal retry loop. Decoder consumption and encoder output counts remain
valid on every result, including errors. Every size output is initialized
before validation. Optional diagnostic output can be NULL.

Argument, ownership and busy errors leave an existing valid handle usable
without advancing it. Malformed wire data, schema violations and endpoint
failures are terminal for the current operation. A failed lifecycle
request leaves resource ownership and any stored terminal cause intact.

The handle retains its first terminal diagnostic until cleanup or reset
under its lifecycle contract. A diagnostic query copies it into caller
storage. Messages and bounded field paths require no allocation and
remain valid independently of an upstream callback's stack. Report when
a path has been shortened. An endpoint error after partial delivery
preserves the accepted byte counts and upstream cause.

### Wire behavior

Implement [RFC 8949 §3](https://www.rfc-editor.org/rfc/rfc8949.html#section-3)
for all major types. This includes the full 64-bit unsigned and negative
argument ranges, tags, simple values, binary16/32/64, and definite and
indefinite forms where the grammar permits them. Preserve the bits and
width of raw floating-point tokens. Native numerical conversion is a
separate operation. Accept valid nonpreferred input encodings. Emit
shortest integer, length and tag arguments when constructing output.

The decoder validates structure, container balance, integer and length
arguments, break placement and UTF-8, including the end of each
indefinite text chunk. Incomplete or malformed items never receive a
successful completion event. Tokens and emitted output may precede
completion. The receiver of a request decides when to commit its effects.

The raw codec preserves tags without interpreting them. It yields map
entries in input order. The schema or conversion profile that interprets
a map checks key equality, duplicates and tag semantics. A raw parse
success establishes wire structure and UTF-8 within the configured
limits. It does not certify all semantic constraints of a CBOR data item.
This boundary follows [RFC 8949 §5.3](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.3).

Custom types compose from tags and ordinary CBOR items. Provide helpers
for consuming and producing a tagged value through the same token state.
An application codec owns its tag assignment, accepted payload and any
semantic validation. A relay can forward an unknown tag and its item
unchanged. No global tag registry is required. CBOR core wire bytes are
independent of C struct layout, alignment, endianness and native integer
width. Document the supported C89 compiler and POSIX integer facilities.

A producer can supply a deterministic encoding by choosing definite lengths,
preferred numeric encodings and correctly ordered keys. The initial codec
does not sort arbitrary maps or certify deterministic input. Applications
that sign or hash a representation must explicitly select and test their
encoding profile. [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2)

### State, spans and backpressure

Keep a bounded stack of codec frames. The default is 32 frames and callers
can supply a larger frame array. Default payload fragments and transport
buffers are 2 KiB. Bounded transport buffers, header bytes and parser state
are separate from requested destination storage. A larger item must not
cause the native codec to allocate a larger buffer or retain all preceding
bytes. State survives arbitrary input fragmentation.

Borrow decoder DATA spans from input until that input is reused. Keep
encoder DATA borrowed until consumed. Provide a peek/advance output path
so an encoder can expose its header bytes and validated payload fragments
without copying payload into a second output buffer. A partial write
advances only by the bytes accepted. Repeated peeks return the unconsumed
suffix. The copying read helper uses the same drain state. Output memory
and its owning encoder must stay alive until the sink accepts the span.

Input and output readiness are separate conditions. A resumable operation
reports exact consumed and produced counts and returns promptly when the
next operation would block. Completion never consumes bytes belonging to
the following record. An empty input fragment can drain pending structural
events. EOF is a distinct action. A terminal failure is sticky for the
operation. After failure the caller releases the operation or reconstructs
it under its lifecycle contract.

An encoder `put` returning output readiness has left the submitted token
unaccepted. Drain prior output and retry the token. Successful submission
accepts the token exactly once and borrows any DATA until drained. This
acceptance rule is part of receiver and free-function parity. Lonejson's
visitor pause separately accepts its callback event, as specified below.

Handles have one owner. Independent operations can run concurrently with
independent state. Reusing or closing a busy handle from its callback fails.
No process-global mutable codec state. Preserve the caller's descriptor
flags, signal policy and scheduling. The application owns waits, deadlines,
cancellation and connection teardown.

Runtime configuration is fixed after initialization. Independent child
operations can execute concurrently while their runtime and borrowed
dependencies stay alive. Serialize factories, runtime utilities that
mutate state, and lifecycle calls on a shared runtime. Document any
additional concurrency requirements inherited from a user allocator,
lonejson runtime or endpoint. A Lua binding receiver follows its Lua
state's thread ownership.

For a nonempty read request, the native source reports positive bytes
with success, zero bytes with success for EOF, or zero bytes with input
readiness when it would block. The sink reports exact accepted bytes,
including a partial write followed by output readiness. A successful
zero-byte write for a nonempty request is an endpoint contract error.
Reject counts beyond the offered buffer or span. An operation drains
its pending output before accepting additional source data.

## Framing and transport

| Mode | Boundary and validity |
| --- | --- |
| Single item | Exactly one CBOR item. The standalone converter requires EOF and rejects trailing bytes. On a persistent transport supply a record-bounded source. |
| Sequence | Concatenated items per [RFC 8742](https://www.rfc-editor.org/rfc/rfc8742.html). Commit each completed item. A partial final item fails. A malformed item terminates the sequence. |
| Length32 | Four-byte big-endian payload size followed by exactly one item. Preserve cai's bytes, including the 128 KiB default record limit. The caller provides the known size before emitting the prefix. |
| Datagram | One complete bounded item per UDP or Unix datagram. Check the datagram size and reject truncation. Do not interpret a second packet as a continuation of the first. |

The codec is shared across Unix streams, TCP, pipes, files and datagrams.
Encrypted and other application transports can supply the same source and
sink callbacks. Framing stays above the codec. Use indefinite values or
an application sequence of bounded records when production length is
unknown. Length32 must never
serialize, replay or spool an item to discover its size. An existing CBOR
relay validates and forwards the original bytes. It does not reconstruct an
equivalent item from decoded tokens. Datagram retry, ordering, reassembly,
congestion control and admission belong to the application transport.

## Lonejson integration

### Direct mapped records

The direct path is C record → CBOR and CBOR → C record. Use the published
map descriptors, public record setters, array appenders, lifecycle calls
and borrowed views. The encode path reads typed fields and emits CBOR
tokens. The decode path feeds typed values into the mapped destination.
Neither path invokes a JSON parser or writer for a natively mapped field.
An explicitly JSON-backed field crosses a JSON representation boundary
of its own.

Use `lonejson_source_write_to_sink` and `lonejson_spooled_write_to_sink`
to drain outbound byte sources directly on synchronous calls. Adapt
embedded JSON from the handle's documented buffer, reader, file, fd or
path to the resumable visitor's push contract. A public push producer can
feed that visitor directly on a synchronous route. A resumable route must
also be able to pause its producer when output waits. Borrow existing
handles and close only resources the adapter opened.

Use the descriptor's field names as CBOR text keys. Preserve published
required, presence, nullable, omit-null and omit-empty semantics for the
supported field kinds. A required field must appear and null is valid only
when the mapped field accepts it. Optional fields apply the descriptor's
omission rules. An absent field leaves the initialized default. Reject
duplicate keys, wrong types and out-of-range numeric conversions. Reject
unknown fields by default. If a consumer explicitly allows unknown
fields, skip their values incrementally after checking the key and
validating the skipped structure. It is still an error to repeat an
unknown key in the same mapped object.

Emit fields in descriptor order. Use a definite map length when the
field count is available from the record and its metadata. Use an
indefinite map when an omission decision depends on reading a source.
Any source inspection needed to decide omission must retain at most a
bounded prefix and pass it directly to the encoder. Never consume a
source twice to decide the map length.

Validate map metadata and record bounds before traversal. Reject invalid
offsets, incompatible element strides, duplicate schema keys and inline
object cycles. Object-array recursion is governed by the same nesting and
record limits as other containers. Keep field matching and required-field
tracking per active object. Use the descriptor's existing key length and
boundary information where helpful. Add a reusable lookup plan only if
measured workloads justify it. A plan would borrow immutable schema
metadata and must never retain a particular record's storage.

| Field family | Encode | Decode |
| --- | --- | --- |
| Signed and unsigned integers, booleans, finite doubles | Emit native scalar tokens directly. | Check type and range before writing the native member. Set presence with the public helper. F64 accepts finite CBOR floats of any width and exactly representable CBOR integers. Preserve signed floating zero. |
| Fixed and allocated strings | Borrow existing UTF-8 storage and emit text. A fixed slot must contain a terminator within its extent. | Use the public string assignment contract. Reject embedded NUL in C-string fields. Honor the configured fixed-capacity overflow policy and surface any reported truncation. |
| Inline objects, scalar arrays and object arrays | Traverse nested descriptors and native array storage. Use known array counts directly. | Initialize children and append with the published record APIs. Honor fixed-array policy and enforce materialized record budgets. Never manufacture lonejson-owned storage with libcbor's allocator. |
| Streamed text and Base64 fields | Emit text or CBOR bytes respectively. Use the public raw source/spool operations. A lengthless source is drained once into bounded valid chunks. | A declared spool field is an explicit final storage choice. Append raw bytes to its initialized lonejson handle and honor its configured memory, size and spill policies. For applications that consume payload fragments directly, provide a field sink receiving borrowed text/byte spans. |
| Outbound source fields | Read `lonejson_source` as above. | Reject when used as an inbound field unless the caller binds a destination sink. A source handle alone cannot own incoming bytes. |
| Streamed array destinations | Encode ordinary typed arrays, or use the raw encoder for a producer-driven array. The inbound handler is not an outbound producer. | Deliver string fragments or one reusable mapped item at a time through the configured array handler. Do not accumulate the array. |
| Embedded `lonejson_json_value` | Use the JSON bridge on the explicitly supplied JSON source. | Use the JSON bridge for a configured JSON sink. Visitor or capture modes require a public delivery API that can preserve their declared contract. Report unsupported modes explicitly until that API is available. |

A mapped decode receives initialized empty or reset record storage. Use
`lonejson_init`, `lonejson_reset` and `lonejson_cleanup` for the record's
lifecycle. The caller configures stream destinations and fixed backing
storage before decoding. Record changes and
field callbacks are provisional until the item and schema checks finish.
On failure, the destination must remain safe to reset or clean up, with
any partially populated fields owned according to lonejson's API. The
caller can supply a separate initialized destination if it needs atomic
replacement of a live record.

Field sinks bind to a mapped field path and declared payload kind. They
receive begin, zero or more borrowed chunks, and end after that value
validates. A successful end covers the field only. The enclosing operation
still reports whether the record completed. A failure terminates delivery
and leaves cleanup of caller-owned effects to the sink owner. Mapped
array-item pointers are valid only for the item callback.

There is a deliberate distinction between streaming and constructing a
record. Decoding an allocated string or a materialized array fills the
caller-selected destination and uses the memory that representation
requires. For string setters that require a contiguous value, use a
borrowed contiguous span where available or one bounded field scratch
buffer. Report the limit before exceeding it. Do not assemble the
enclosing object or serialize it as JSON. Use stream fields for large
payloads. A declared lonejson spool can spill as final storage. libcbor
must never create one as an internal staging step.

### JSON conversion profile

JSON input grammar and JSON output framing belong to lonejson. Use its
arbitrary-value visitor and writer with bounded conversion state between
them. Apply the following mapping to exactly one value.

| Value | JSON to CBOR | CBOR to JSON |
| --- | --- | --- |
| Object and array | Map with text keys and array. Use indefinite containers when the item count is unavailable. | Preserve key and item order. Only text map keys are accepted. |
| String | UTF-8 text. Use bounded indefinite text chunks for a streamed value of unknown length. | Stream decoded text through the writer's string operations. |
| Integer | Preserve exactly from `-18446744073709551616` through `18446744073709551615`. Reject overflow without falling back to floating point. | Emit the exact decimal integer. The full negative range needs a bounded decimal formatting path beyond the signed 64-bit writer helper. |
| Decimal or exponent form | Convert to finite binary64, rounded to nearest with ties to even. Preserve floating negative zero. Accept representable subnormals. Report overflow or a nonzero magnitude rounded to zero. | Emit finite floats with a decimal point or exponent and enough precision to recover the binary64 value. Emit negative zero as `-0.0`. Float widths and JSON spelling may change. |
| Boolean and null | Matching CBOR simple values. | Matching JSON values. |
| Other CBOR values | The plain JSON profile has no source representation for these. | Reject byte strings, tags, undefined, other simple values, nonfinite floats and non-text keys. Typed fields may define an explicit representation. |

Compare object keys by decoded UTF-8 bytes, including escaped spelling
equivalences, without Unicode normalization. Reject duplicates in either
direction. The bridge needs bounded key storage because the current JSON
writer takes a complete key. Accumulate at most one bounded number lexeme
where decimal conversion requires it. Text chunks split at Unicode scalar
boundaries when emitting an indefinite CBOR text value. At most the bytes
of an incomplete UTF-8 scalar carry over into the next chunk.

Number handling is independent of the ambient locale. Format and parse
bounded number tokens using locale-independent operations and preserve
the caller's floating-point environment. Pass formatted numbers through
`lonejson_writer_number_text` for JSON grammar validation. Test locale and
rounding changes with the pinned SDK. Delegate JSON token
validation, escaping and document structure to lonejson. [RFC 8259 §6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6)

Initial defaults, configurable per operation with zero selecting the
documented default:

| Resource | Default and behavior |
| --- | --- |
| Nesting and payload chunk | 32 frames and 2 KiB, with distinct limits for wire state and adapter scratch as needed. |
| One transfer or conversion step | At most 2 KiB of new input, 2 KiB of delivered output and 256 converted events. Each budget is configurable. Exhaustion yields progress with retained state. |
| One decoded object key | 2 KiB. The cap applies to both directions. |
| Active keys in generic JSON conversion and unknown mapped fields | 256 keys and 16 KiB of decoded key bytes across open objects. Release their storage when the object closes. Compare exact bytes after any hash match. Known mapped fields use bounded schema presence tracking. |
| One JSON number token | 256 bytes. Longer numeric lexemes fail with a limit status. |
| Mapped materialization | 64 KiB per stored text field, 16,384 materialized array elements total and 1 MiB of logical new record storage per operation. Apply any stricter lonejson or field limits. Allocator accounting reports actual allocations separately. |
| Declared stream destinations | Bound codec and adapter memory independently of field length. Apply any caller-supplied size cap and final sink or spool policy. |

Use checked arithmetic for all sizes and counts. Keep multi-KiB scratch
storage in caller workspace or allocator-owned memory. The defaults must
fit in the default musl worker stack with the full call chain and
callbacks. Limit violations must be observable and distinct from syntax
failures.

### Streaming with the pinned dependency

Lonejson 0.49.0 provides `lonejson_value_visitor_stream` through
`runtime->value_visitor_stream_open` and equivalent free functions.
Use this public API for resumable JSON input in the initial bridge.
Both JSON conversion directions must retain their operation state across
input and output readiness. Return promptly when an endpoint would block
and let the caller schedule the next step. Provide synchronous convenience
entry points for blocking endpoints using the same conversion state.
Native CBOR operations retain their resumable contracts. [Lonejson v0.49.0 public header](https://github.com/c89systems/lonejson/blob/v0.49.0/include/lonejson.h)

Feed bounded input through `push` and advance by its exact `consumed`
count. `LONEJSON_STATUS_PAUSED` accepts the callback event once and stops
delivery until the next push. It can consume zero input while draining
pending number events. An empty push drains pending events. Input memory
can be reused after push returns. Callback chunk memory is borrowed only
until that callback returns. Retain one bounded output chunk before
pausing and drain it before resuming the visitor. Size that chunk for the
input fragment, CBOR token headers and at least one complete four-byte
UTF-8 scalar.

Call `finish` at EOF and repeat it after pauses until completion or failure.
No further input is accepted after signaling EOF. Trailing non-whitespace
and incomplete input fail. Keep output provisional until finish succeeds.
The visitor copies runtime limits and allocator configuration at open and
allocates bounded frame and number workspace. It streams keys and string
values without growing workspace with their length. Configure its string,
key, number and depth limits consistently with the bridge's limits.

The reverse direction must retain the
lonejson writer operation and its pending output across retries. Use the
public writer generator or a bounded sink for one writer event at a
time. Drain that output before accepting another event. Prove
equivalence to the synchronous route with one-byte input and short,
alternating would-block writes. One-shot and resumable entry points
should reuse the same event conversion rules.

Resumable mapped transfers keep field traversal and codec state in the
operation handle. Suspend only when every active endpoint has a compatible
pause contract. A one-shot lonejson source or sink callback can still be
used through the synchronous map methods. Reject an incompatible endpoint
when initializing a resumable operation.

Treat a missing upstream capability as a dependency boundary. Do not add
a second JSON parser, depend on private lonejson functions, or build
against unpublished sibling checkout state. This spec does not require
changing cai's transport framing to make a conversion path convenient.

## Lua and native interop

Expose the receiver and native handles as checked userdata. Lua calls the
public C API. Native libcbor and lonejson consumers exchange typed pointers
or the public borrowed record view through the facade headers. Keep the
owning runtime, schema, record, endpoint and input span alive throughout
each borrowed operation. Reject incompatible view versions, closed
handles and a close while an active borrow exists. Finalization must
release pins in either order.

A Lua call that connects native endpoints or passes a native mapped
record performs the traversal and transfer in C. JSON and CBOR chunks
should reach Lua only when the caller explicitly selects a Lua string,
token or callback API. No FFI dependency and no automatic conversion of
whole native records to Lua tables. Match C behavior for errors,
partial progress and unsupported representations.

Expose `cbor.create(config)` for a Lua runtime receiver. Its factories
produce checked encoder, decoder, reader, transfer and conversion userdata.
Lua colon methods map to the corresponding C receiver methods. Module
convenience constructors use these same factories with default
configuration. Resume conversion with its `step` method and close the
handle after completion, failure or cancellation. Binding push/check
methods use the per-state Lua binding receiver and preserve the existing
owner pin and type checks for every native pointer crossing.

## Verification and performance

### Correctness and conformance

- Test RFC 8949 Appendix A examples and initial-byte classes, malformed
  encodings, all numerical boundaries, truncated items, UTF-8, arbitrary
  fragmentation and maximum depth. Independently cross-check representative
  encode and decode fixtures with another CBOR implementation on the shared
  supported profile. Document what the interoperability suite covers.
- Exercise exact consumption, write progress, borrowed span lifetime,
  reentry, partial failure, EOF and resource limits. Verify a receiver
  method and its free function return equivalent events and errors.
- Maintain an API inventory mapping every exported function to its
  receiver member or documented bootstrap exception. Check declarations,
  exported symbols, C receiver members and Lua coverage together. Any
  missing natural receiver method fails the public API completeness gate.
  Exercise both entry points through installed static and shared SDKs.
- Test every receiver's caller-storage initializer and heap constructor,
  including allocation failure, output-pointer clearing, failed-init
  cleanup, repeated cleanup, destroy after cleanup, parent lifetime and
  invalid destruction of caller storage. Reject busy cleanup without
  changing state. Verify descriptors and borrowed runtimes remain owned
  by their callers. Prove native initialization and dispatch allocate no
  memory. Test conversion open without endpoint I/O, bounded step budgets,
  terminal queries and synchronous/resumable output equivalence.
- Demonstrate long native and JSON stream delivery before producer EOF
  with fixed working memory. Include indefinite byte and text strings,
  UTF-8 boundaries, large arrays, source failure after partial emission,
  and consumer stops. Test whether the actual public entry point attempts
  an allocation or seeks a source. Fixed scratch and explicit destination
  storage are accounted for separately.
- Test the conversion profile in both directions, including integer edges,
  underflow, locale, duplicate escaped keys, binary and tag rejection,
  and disallowed map keys. Check against independent expected bytes and
  JSON values, including negative cases. A self-round-trip alone cannot
  establish mapping correctness.
- Test direct map fixtures covering required, nullable and omitted fields,
  nested records, typed arrays, source consumption, binary bytes and
  receiver parity. Inject allocation and sink failures during mapped
  decode. Verify successful lonejson cleanup of partial destinations and
  observe owned allocations and user callbacks. Prove that a native map
  path does not invoke a JSON parser or writer for mapped fields.
- Run Unix stream, TCP, UDP, Unix datagram and pipe checks with verified
  payloads. Include slow readers, short writes, coalesced frames and
  truncated datagrams. Validate cai-compatible Length32 bytes with a
  captured fixture. The cai migration is a later change in that repository.
- Exercise Lua native interop through the installed shared SDK, including
  GC order, ownership, wrong view type, explicit copies and receiver API
  parity. Run native memory checks and fuzz codec and bridge entry points.
  Include default musl worker-stack tests and the constrained glibc checks
  from the lifecycle.

### Performance evidence

Publish benchmarks separately for native codec, framed transfer, mapped
encode and decode, JSON conversion, and the Lua native bridge. Use C for
native benchmarks. Compare mapped paths with a JSON serialization and
parse round trip as a control, and measure equivalent output and
validation work. Keep PJK/libcbor as an independent codec comparator.
Document any differences in validation and input boundaries.

Cover scalar-heavy and nested messages, short and large strings, binary
payloads, ASCII and multibyte UTF-8, unknown lengths, arbitrary split
points, and representative cai fixtures. Report both in-memory and
Unix/TCP/UDP workloads. Use the same verified bytes, budgets, compiler
and options for comparisons. Keep repeated UDP requests and streaming
throughput as separate workloads. Report median and distribution for
throughput and latency plus CPU time, payload copies, allocation count,
peak working memory and syscall counts where the harness measures them.
Include schema setup and reuse separately if preparation costs are
material. Record host, commit, toolchain, fixture and run settings.

The deterministic gates are the streaming and data-movement contracts.
The raw codec does not allocate for an initialized caller-owned context.
Native mapped scalar fields take no JSON conversion path. Native Lua
transfers perform no per-token VM calls. Payload copying, when required
by an endpoint or record setter, stays bounded and measurable. Use the
current [benchmark methodology](benchmarks.md) as the baseline. The goal
is to outperform established implementations on comparable work, while
preserving validation and bounded memory. A performance claim requires
the matching comparison results. A fixed throughput threshold on the
shared host is not a correctness gate.

## Delivery and implementation order

The seven SDK targets cover x86_64, aarch64 and armhf Linux with glibc
and musl, plus arm64 Darwin. Keep strict
`-std=c89`, documented POSIX integer facilities and the normal clangd
compilation database. All targets ship static and shared libcbor,
documented public headers, relocatable metadata and the required lonejson
dependency declaration. Produce source and Lua artifacts in addition to
the seven SDK archives. Verify extracted consumers and target library
identities. Darwin cross-link and native runtime proof are separate.

Document every public C type and entry point in clangd-readable header
comments, including ownership, lifetime, errors and allocation behavior
where applicable. Comment each public Lua surface in the module sources
and give Lua equivalent coverage for all public codec and receiver
operations.

The receiver layout and binary filename cutover must update the examples,
Lua bindings, CMake/pkg-config metadata, export checks, package
verification and benchmark isolation together. Do not add a parallel
legacy library or wire-format version. Apply the repository's shared ABI
rule against the latest released artifact or tag before choosing a
SONAME. A development candidate alone does not establish a released ABI
baseline.

1. Establish the required lonejson SDK pin and the receiver API. Complete
   the libcbor filename cutover and prove the existing native paths.
2. Ship both direct mapped operations and both resumable JSON conversions
   against 0.49.0. Prove type, ownership, bounded streaming, pause/resume
   and interoperable bytes, including mapped transfers with compatible
   endpoints. Keep the same value mapping and record ownership rules.
3. Integrate cai against the installed public SDK in its own repository.
   Verify its existing wire profile and use actual message shapes for
   performance work.

Follow the [delivery lifecycle](delivery.md) for the signed release
boundary and artifact inventory.
