# C API

Include `<c89cbor/cbor.h>` for the codec and `<c89cbor/io.h>` for framing/adapters.
Include `<c89cbor/lonejson.h>` for the root runtime receiver and required
lonejson 0.49.0 types. Initialize a caller-owned root with `c89cbor_init`, or
allocate it with `c89cbor_create`. Its factories construct native children.
Every child exposes receiver-first operation, cleanup, destruction and
diagnostic methods. Free-function twins share the same implementation.
Native initializers and constructors take the optional runtime first.
NULL selects native defaults. Keep a configured root alive until its
children have been cleaned up.
All declarations have editor documentation, ownership rules and status semantics.
The [API inventory](api-inventory.md) maps each export to its receiver and Lua
surface. Compiled parity assertions and export checks guard that inventory.
Initialize contexts; never memcpy an active context. NULL frames with capacity 0
uses embedded storage. A separate frame array and chunk bound are optional.
No init, next, put, read, framing or transfer operation allocates.

`decoder_next(input,length,&consumed,&token)` returns TOKEN, INPUT, DONE or a
negative error. Advance by consumed even if zero; implicit END tokens consume no
bytes. INPUT requires more input. DONE leaves trailing bytes untouched. Drain
pending events before finish, then require finish success at EOF. Reset reuses a
completed codec for the next item. Parsing errors are sticky until reinitialized.

`encoder_put(token)` accepts one event or returns OUTPUT without accepting it
when an earlier event remains pending. Drain with encoder_read into caller-owned
output until OK. Its maximum write is the configured chunk bound. DATA bytes stay
borrowed until fully drained. Encoding an unknown-length string/container starts
with indefinite=1; indefinite strings contain definite chunks. Every begun
string/container/tag, including definite empty values, requires an END event.
Tags own exactly one child. The encoder validates supplied grammar and UTF-8.

FLOAT16/32/64 arguments are raw bits. NEGATIVE's argument N represents -1-N;
UINT64_MAX therefore represents -18446744073709551616 without signed overflow.
All nonapplicable token fields must be zero. A text scalar can span DATA events,
but each separate encoded indefinite text chunk must end at a Unicode boundary.

Heap constructors accept an optional allocator override. The runtime's
allocator, or malloc/free for native defaults, otherwise owns the shell.
No realloc is needed. Destruction uses the allocator recorded at construction.
Cleanup preserves shell storage and is idempotent. Destruction rejects
caller-owned shells. A parent with live children reports BUSY. Fixed diagnostics
are copied into caller storage and remain queryable after failure.

`encoder->peek(encoder,&bytes,&length)` borrows a validated bounded output
span. A repeated peek returns its unconsumed suffix. Accept bytes through
`encoder->advance(encoder,count)` after a partial write. The copying read
method drains this same state. Output readiness from put means the new token
is still unaccepted. Drain output before retrying it.

## Custom C types

`encoder->tag(encoder,number)` and `encoder->end_tag(encoder)` submit the ordinary
TAG and END(TAG) events with put's acceptance rules. `decoder->next_tag` consumes
one tag header with normal fragmented-input progress, returning TOKEN and the
full tag number. Read its child and closing END through next. A different event
is a sticky SCHEMA error. No tag registry or payload interpretation is implied.

Keep application structs in the application. Encode a schema map/array through
ordinary tokens; stream variable-length fields directly from their producer.
Decode with a small schema state machine and bounded field tracking. Publish the
application object only after successful RECORD_END or single-item finish.
Never represent an unbounded string as an owned char* merely to fit a schema API:
provide a source/sink or fragment callback for that field. Native endpoints can
be handed to Lua using `<c89cbor/lua.h>` without serializing through Lua values.

## JSON conversion

The runtime exposes `json_to_cbor` and `cbor_to_json` for blocking endpoints.
Their `_open` factories allocate a resumable conversion receiver. The matching
`_init` methods initialize a caller-owned shell. Opening or initializing an
operation performs no endpoint I/O. Its bounded working buffers and lonejson
workspace use their configured allocators.

Call `operation->step(operation,&error)` until DONE. INPUT and OUTPUT return
control to the application's event loop. OK reports progress within the step
budgets. Pending output drains before another input fragment is accepted.
Query cumulative byte counts and completed records with the progress method.
Completion includes EOF validation and draining output. Cleanup cancels an
operation, and destroy frees an allocated shell after cleanup.

The [plain JSON profile](spec.md#json-conversion-profile) preserves the full
CBOR integer range and finite binary64 values, validates UTF-8, and rejects
duplicate keys and unsupported CBOR representations. Keys and number tokens
have explicit bounds. Payload strings flow through bounded fragments.
Numeric operations use the C locale and preserve the caller's floating-point
environment. Configure per-operation limits with `c89cbor_options` and the
owned lonejson runtime policy with `c89cbor_config.json_config`. A borrowed
lonejson runtime applies its own limits and allocator.

## Mapped records

`runtime->encode_map(runtime,map,record,sizeof(*record),sink,options,error)`
reads native fields directly. `decode_map` takes a source followed by the map,
initialized destination and its extent. Both have `_init` and `_open` variants
returning the same conversion receiver used for JSON. The `_view` variants
borrow a `lonejson_record_view`, including its owning lonejson runtime. Views
must have the published sizes and ABI version, zero flags, and sufficient
record extent. Keep the view's runtime, schema and record alive and unchanged
until the operation has been cleaned up.

Initialize or reset destination records through lonejson before decoding.
Configure fixed array backing and stream handlers before opening the operation.
The adapter uses public lonejson setters and appenders for owned fields. Partial
records remain caller-owned and cleanup-safe after errors or cancellation.
Required fields and duplicate keys are checked per object. Unknown fields fail
unless `allow_unknown_fields` is set; skipped values still undergo CBOR and
UTF-8 validation. Single-record completion requires EOF and rejects trailing
bytes. Record changes and callbacks are provisional until completion.

Native scalar, string, object and array fields never cross a JSON representation.
Text sources become CBOR text and Base64 sources become raw CBOR byte strings.
Unknown-length sources produce indefinite chunks with valid UTF-8 boundaries.
Encoding a spool uses a borrowed cursor copy and preserves its read position.
Files and descriptors supplied by callers remain borrowed. Paths are opened by
the operation and closed on completion or cancellation. Opening performs no I/O.

Allocated strings use a borrowed complete input span when available, otherwise
one bounded field scratch buffer. Defaults bound materialized strings to 64 KiB,
new logical record storage to 1 MiB, and materialized array items to 16384.
Use source fields, configured stream fields, or explicit field sinks for larger
payloads. A spool is an explicit destination storage choice and follows its
lonejson spool policy. Silent fixed-capacity truncation sets `error.truncated`
even on successful completion. The reporting truncation policy fails with LIMIT.

`c89cbor_options.field_sinks` binds JSON Pointer paths to TEXT, BYTES or JSON
payloads. Its begin/end callbacks return OK after acceptance, OUTPUT to retry an
unaccepted boundary, or a negative failure. Payload writes use exact partial
byte counts. Pointers are borrowed only for the callback duration. Mapped payload
fields deliver a null through begin(NULL-token)/end with no payload chunks,
preserving boundary retry semantics and the declared text/bytes representation.
Source fields require a sink when used as incoming destinations. A lonejson array-stream
callback returning PAUSED accepts that event once, then yields OUTPUT without
replay. Mapped array streams reuse and reset the caller-initialized item record
after each item callback, so callbacks must copy anything they retain.

JSON_VALUE fields alone use the JSON visitor/writer bridge. Outbound buffer,
reader, file, fd and path modes are supported. Incoming JSON sinks stream through
bounded buffers. Explicit capture materializes one field within `field_bytes`
and `record_bytes` through the public owned-buffer setter. Visitor and path
visitor delivery modes return UNSUPPORTED; they lack a public token-delivery API
that preserves their limits. A JSON_VALUE null with no delivery mode uses its
normal mapped null semantics.

## Linking

```cmake
find_package(C89Cbor CONFIG REQUIRED)
target_link_libraries(app PRIVATE C89Cbor::static) # or C89Cbor::shared
```

`pkg-config --cflags --libs c89cbor` is relocatable. Linux consumers select their
own pinned compiler/runtime; the SDK never exports workstation loader or cache
paths. Both link modes declare lonejson 0.49.0 as a required SDK prerequisite.
Supply its CMake prefix or pkg-config directory alongside libcbor's prefix.
The native transfer includes POSIX descriptor functions only when its
translation unit is linked.

The installed example `examples/copy.c` shows the complete blocking descriptor
workflow. Its input and output need no size pass. Use caller-controlled polling
with transfer_step when descriptors are nonblocking.
