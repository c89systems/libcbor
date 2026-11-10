# C API

Include `<c89cbor/cbor.h>` for the codec and `<c89cbor/io.h>` for framing/adapters.
All declarations have editor documentation, ownership rules and status semantics.
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

Heap constructors accept NULL for libc malloc/free or an explicit pair of native
allocator callbacks. No realloc is needed. Destroy only constructor-owned objects,
with the same allocator. Error text is static and never allocated.

## Custom C types

Keep application structs in the application. Encode a schema map/array through
ordinary tokens; stream variable-length fields directly from their producer.
Decode with a small schema state machine and bounded field tracking. Publish the
application object only after successful RECORD_END or single-item finish.
Never represent an unbounded string as an owned char* merely to fit a schema API:
provide a source/sink or fragment callback for that field. Native endpoints can
be handed to Lua using `<c89cbor/lua.h>` without serializing through Lua values.

## Linking

```cmake
find_package(C89Cbor CONFIG REQUIRED)
target_link_libraries(app PRIVATE C89Cbor::static) # or C89Cbor::shared
```

`pkg-config --cflags --libs c89cbor` is relocatable. Linux consumers select their
own pinned compiler/runtime; the SDK never exports workstation loader or cache
paths. The static core needs no extra libraries; the native transfer includes
POSIX descriptor functions only when its translation unit is linked.

The installed example `examples/copy.c` shows the complete blocking descriptor
workflow. Its input and output need no size pass. Use caller-controlled polling
with transfer_step when descriptors are nonblocking.
