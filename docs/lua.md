# Lua 5.5.1 facade

`require('cbor')` loads the native module linked to the installed libc89cbor
shared library and cpkt 0.7.0's public Lua facade. No FFI declarations, duplicate
codec or private libcbor symbols. [Commented Lua API](../lua/cbor.lua) documents
all public Lua constructors and methods. C interoperability is documented in
`<c89cbor/lua.h>`; that header additionally requires cpkt's installed Lua SDK.

The primary integration path is native source/sink handles:

```lua
local cbor = require('cbor')
-- source and sink are typed handles supplied by another native module.
local transfer = cbor.transfer(source, sink, cbor.SEQUENCE)
local status = transfer:run() -- entire shuffle stays in C
-- INPUT / OUTPUT returns control to the host event loop; call run again ready.
assert(status == cbor.DONE)
transfer:close()
```

Native code pushes a `c89cbor_source*` or `c89cbor_sink*` with the matching
`c89cbor_lua_push_*` function and an owner stack index. The userdata pins that
owner, not a copied message. `check_*` retrieves a typed pointer or NULL. Explicit
native-owner mode (index 0) requires the host to preserve the lifetime. Never
invalidate borrowed native pointers; Lua GC cannot govern an external C owner.
Foreign or closed userdata does not become an arbitrary trusted pointer.

Lua token processing is explicit: next returns a token userdata with borrowed
input pinned, and span:string()/encoder:read() copy only the selected span or
output chunk into a Lua string. This path lets callers choose Lua processing
rather than paying a VM transition for each token in native transfer.

Constructors correspond to C init or create; methods correspond to C next,
put, read, finish, reset, transfer_step and destroy. `frames` supplies custom
nesting storage; `fd` supplies source/sink views; `length32` emits a known-length
prefix. Allocator handles come from native C so allocator calls remain C-side.
Status constants and token/framing/event enums mirror the complete public C API.

Expected codec/I/O errors return integer statuses. Invalid Lua argument types
raise ordinary Lua argument errors before entering a codec operation. Integer
arguments preserve raw signed 64-bit Lua integer bits: -1 means UINT64_MAX for
unsigned/magnitude/float-bit arguments. Size/limit arguments reject negative and
out-of-range values. Native float64 helpers preserve their C behavior.

Owners are pinned across callbacks/operations. Explicit close is idempotent and
rejects active or borrowed owners; close borrowed child views first. GC cleans
owned heap contexts after dependents disappear. A failed stream cannot be retried
from its beginning against a destination which already received its prefix.

Lua release products are a separate source archive, rockspec and source rock.
SDK archives contain the C library, not an interpreter or prebuilt Lua module.
