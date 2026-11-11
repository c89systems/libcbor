# Lua 5.5.1 facade

`require('cbor')` loads the native module linked to the installed libcbor
shared library and calls Lua's public C API directly. No FFI declarations, duplicate
codec or private libcbor symbols. [Commented Lua API](../lua/cbor.lua) documents
all public Lua constructors and methods. C interoperability is documented in
`<c89cbor/lua.h>`; its opaque `struct lua_State` pointer needs no Lua headers.
Native embedders include `<lua.h>`, `<lauxlib.h>` and `<lualib.h>` when using
Lua directly. The host owns the Lua runtime; the module resolves its Lua symbols
there. There is no cpkt dependency. Lua uses 64-bit integers and binary64 numbers.

The build prepares unmodified upstream Lua 5.5.1 from its verified source archive
for local embedding tests on each target. It is a build prerequisite, not bundled
in the C SDK or Lua source products. External CMake builds accept `LUA_INCLUDE_DIR`
and `LUA_LIBRARY`; LuaRocks accepts its normal `LUA_INCDIR` and `LUA_LIBDIR`.

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

Native code initializes a per-state `c89cbor_lua` receiver with
`c89cbor_lua_init`, or allocates one with `c89cbor_lua_create`. Its typed
push/check methods have matching receiver-first exported twins. Push methods
take a native pointer and an owner stack index. The userdata pins that
owner, not a copied message. `check_*` retrieves a typed pointer or NULL. Explicit
native-owner mode (index 0) requires the host to preserve the lifetime. Never
invalidate borrowed native pointers; Lua GC cannot govern an external C owner.
Foreign or closed userdata does not become an arbitrary trusted pointer.
Binding cleanup leaves Lua and previously pushed handles alive. Destruction
uses the recorded allocator. Record views snapshot the public descriptor and
borrow the record, schema and owning lonejson runtime. Preserve these objects
unchanged until the view and its operations close. A producer using lonejson's
public Lua adapter can push that view with the original record userdata as owner.
The libcbor facade does not inspect foreign userdata layouts.

`cbor.create(config)` returns the runtime receiver. `cbor.init(config)` stores
the shell in userdata. Both accept a configuration table or typed native config.
Tables expose step budgets, allocator handles and JSON policy limits. Native
configs preserve every C field, including borrowed lonejson runtimes. Children
pin their runtime and other owners. Root cleanup rejects live children. GC
defers owner cleanup until dependent finalizers release their pins.

```lua
local runtime = cbor.create()
local operation = runtime:encode_map_open(record_view, sink, {chunk=2048})
local status, diagnostic = operation:run()
-- Resume run() after INPUT or OUTPUT readiness.
assert(status == cbor.DONE, diagnostic.message)
operation:close()
runtime:close()
```

The root supplies synchronous `json_to_cbor`, `cbor_to_json`, `encode_map` and
`decode_map`, with `_open` heap and `_init` userdata factories. Map calls accept
typed record views and have `_view` aliases. Conversion step/run, diagnostic and
progress methods delegate to the same C operation. Native field sink bindings
use typed options handles; tables configure ordinary limits. Blocking convenience
methods report IO if an endpoint would block.

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
The runtime exposes those helpers too. Encoder peek returns a borrowed span;
advance accepts exact byte counts. Close the span before put/reset can reuse
the encoder. Explicit string conversion remains available through span:string().

Owners are pinned across callbacks/operations. Explicit close is idempotent and
rejects active or borrowed owners; close borrowed child views first. GC cleans
owned heap contexts after dependents disappear. A failed stream cannot be retried
from its beginning against a destination which already received its prefix.

Lua release products are a separate source archive, rockspec and source rock.
SDK archives contain the C library, not an interpreter or prebuilt Lua module.
