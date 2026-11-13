# Lua 5.5.1 facade

`require('cbor')` loads the native module linked to the installed libcbor
shared library and calls Lua's public C API directly. No FFI declarations, duplicate
codec or private libcbor symbols. [Commented Lua API](../lua/cbor.lua) documents
all public Lua constructors and methods. C interoperability is documented in
`<c89cbor/lua.h>`; its opaque `struct lua_State` pointer needs no Lua headers.
Native embedders include `<lua.h>`, `<lauxlib.h>` and `<lualib.h>` when using
Lua directly. The host owns the Lua runtime; the module resolves its Lua symbols
there. The facade has no cpkt Lua dependency. libcbor's COSE implementation uses
libcrypto from cpkt's OpenSSL SDK. Lua uses 64-bit integers and binary64 numbers.

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
rejects active or borrowed owners; close borrowed child views first.
Synchronous JSON/map calls borrow their endpoints, record view and native
options until return, including native callbacks and error paths. GC cleans
owned heap contexts after dependents disappear. A failed stream cannot be retried
from its beginning against a destination which already received its prefix.

Lua release products are a separate source archive, rockspec and source rock.
SDK archives contain the C library, not an interpreter or prebuilt Lua module.

## COSE

`runtime:cose_key_init(kind, bytes, id=nil)` and `cose_key_create` import copied
keys (32 bytes, or 65 for P-256 public). Constants COSE_A256GCM, COSE_A256KW, COSE_X25519_PUBLIC and
COSE_X25519_PRIVATE select distinct key policies. `key:metadata()` returns
`status,{kind,key_id}`; `key:public_key()` returns `status,bytes` for public-key families,
or UNSUPPORTED for symmetric keys. Secret export is unavailable. Constructors
return a handle or `nil,status,error`. They also exist on the module for keys
with the default native allocator. Key cleanup/destroy/close and diagnostic
follow normal receiver ownership rules.

The root exposes `cose_encrypt0(source,sink,key,options=nil)`,
`cose_encrypt(source,sink,recipient_keys,options=nil)`,
`cose_decrypt(source,sink,key,options=nil)`,
`cose_encrypt_stream(source,sink,keys,options=nil)` and
`cose_decrypt_stream(source,sink,key,options=nil)`. Each has `_init` and `_open`
factories returning a COSE operation. Synchronous calls return `status,error`
and require blocking, message-scoped endpoints. `_init` stores a native shell
in userdata; `_open` allocates the shell through the runtime allocator.

`cbor.default_cose_options()` and the root method return a table. Options expose
record_bytes, header_bytes, recipients, step_input, step_output, step_events,
encrypt, aad, nonce and stream_id. AAD/nonce/ID accept strings or native spans;
nonce must be 12 bytes and ID 16. The native [nonce rules](cose.md) apply.
Table options and recipient arrays are snapshotted, pinning their actual byte
owners and every key wrapper. Later table mutation cannot invalidate an active
operation. Typed native options retain their native-owner lifetime contract.

COSE operations expose step/run, progress, diagnostic, cleanup/destroy/close
and `next(sink=nil,options=nil)`. Next preserves coalesced input after decrypt
DONE, keeps the old sink/AAD when omitted, and clears an expected stream ID.
Configured workspace limits and key policy cannot change. Failed/sealing
operations require reconstruction. Progress is cumulative across next calls.
Payload bytes stay on native endpoints; importing a Lua key string and exporting
public bytes are explicit copies. Native embedders use binding push/check pairs
for cose_key, cose_operation and cose_options, with the usual owner pins.

`operation:stream_info()` returns `status,{stream_id,encrypt,complete}` after a
stream's first record authenticates, or `INPUT,nil` before that point.
Standalone/sealing operations return `UNSUPPORTED,nil`. Empty streams expose
metadata after DONE. Applications own replay admission; authentication of an
individual stream never implies a persistent replay database.

## Sign1, Mac0 and CWT

Key kinds also include COSE_ED25519_PUBLIC/PRIVATE, COSE_P256_PUBLIC/PRIVATE
and COSE_HMAC256. Import 32 bytes except for the 65-byte uncompressed SEC1
P-256 public point. `public_key` returns 32 or 65 public bytes as appropriate.

`cose_sign1`, `cose_verify1`, `cose_mac0` and `cose_verify_mac0` use the same
`(source,sink,key,options)` signature, with `_init`, `_open` and `_stream`
variants. For example `cose_sign1_stream_open` opens a resumable record signer.
Every byte stays on native endpoints. Stream metadata additionally reports
`tag` (18/17 for Sign1/Mac0) and `algorithm` (-19/-9/5).

`root:cwt_init(options=nil)` and `root:cwt_create(options=nil)` return a
bounded token shell or `nil,status,error`. `default_cwt_options` exists on the
root and module. Options contain `cose` options, claim/audience count limits,
`require_cti` and `require_encryption`. Native options can also supply an admission
callback/context; Lua does not implement a hidden replay database.

- `token:set_claims(encoded_map)` copies local CBOR claims.
- `token:set_lonejson(native_claims,cti=nil)` encodes a typed native lonejson
  JWT claim pointer directly; no JSON serialization is involved.
- `token:set_seal_keys(signing_key,encryption_keys=nil)` and
  `token:set_verify_keys(verification_key,decryption_key=nil)` prepare key
  policies and retain snapshots of actual owners. Mutating a caller recipient
  table cannot change the binding. Successful replacement clears prior trust;
  failed replacement preserves it. Nil keys unbind.
- `token:seal(capacity=receiver_default)` returns
  `status,wire_span,error`. The owned native span passes directly to native
  consumers and `verify`; `wire_span:string()` explicitly requests a Lua copy.
  Borrowed native CWT handles default to a 6162-byte output capacity; supply
  capacity explicitly when their configured bounds are larger.
- `token:verify(wire,policy)` returns
  `status,error`. Policy can be a native lonejson policy handle or a table with
  native field names. Tables require an explicit integer `now`. Lists and their
  strings are snapshotted for the call. Algorithm names are Ed25519/ES256/HS256.
- `token:view_get()` returns `status,view` or `INPUT,nil`. The view is an explicit
  Lua copy with encoded claims, binary cti, claim_count, authenticated,
  algorithm and a claims table including audience/scp arrays.
- `token:claim(integer_or_text_or_token)` returns `status,encoded_value`, or
  `INPUT,nil` when absent. This is an explicit Lua copy of that one CBOR value.
- diagnostic and close/cleanup/destroy follow normal shell ownership rules.

A failed verification clears the published view. Local loading reports
`authenticated=false`; only crypto, native claim policy and application admission
can produce `authenticated=true`. `cwt` operations are bounded memory calls;
use native COSE operations for transport scheduling and unbounded values.

Native embedders have binding push/check pairs for cwt, cwt_options, jwt_claims
and jwt_policy. Native CWT consumers can read `view_get` directly without copying
records into Lua tables. These typed handles borrow storage and pin their owner,
without an FFI dependency. The [CWT specification](sign1-cwt.md) defines trust,
size, nesting, clock and replay contracts.

`datagram_init`/`datagram_create` on the module and root construct bounded
complete-packet receivers over borrowed sockets. Methods and native binding
push/check pairs cover the full [datagram API](hardening.md#datagram-integration).
Receive returns `status,{bytes=span,peer=span},error`; peer is absent for unnamed
senders. Borrowed spans expire at the next receive/reset/continuous-source read.
Endpoints return `status,source_or_sink` and keep the shell alive. Lua does not
copy datagram bytes into strings unless the application explicitly asks.
