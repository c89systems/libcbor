# Lua API

The Lua 5.5.1 native module links to the installed public libcbor shared library.
It uses the public C and Lua APIs. `lua/cbor.lua` contains
[typed LuaLS declarations](../lua/cbor.lua) for every constructor, receiver method,
option and constant. See [editor setup](development.md#editors).

## Install and load

`make build` prepares the SDK and builds `cbor.so` under
`build/lua-x86_64-linux-gnu-debug/`. The embedding process supplies Lua 5.5.1 with
64-bit integers and binary64 numbers. Install the module under `lib/lua/5.5`, or
set `LUA_CPATH` to its containing directory's `?.so` pattern. Make libcbor,
lonejson and libcrypto discoverable by your platform's shared-library loader.

The separate Lua source archive builds against installed SDKs:

```sh
cmake -S libcbor-lua-VERSION -B build-lua -G Ninja \
  -DCMAKE_PREFIX_PATH='/sdk/cbor;/sdk/lonejson;/sdk/cpkt' \
  -DLUA_INCLUDE_DIR=/sdk/lua/include -DLUA_LIBRARY=/sdk/lua/lib/liblua.so
cmake --build build-lua
cmake --install build-lua --prefix /your/prefix
```

For LuaRocks, install the source rock with `CBOR_DIR`, `LONEJSON_DIR`, `CRYPTO_DIR`
and the normal `LUA_INCDIR`/`LUA_LIBDIR` settings. The runtime is prepared for
repository tests; applications supply it independently. See [delivery](delivery.md)
for artifact names, dependencies and verification.

```lua
local cbor = require('cbor')
local runtime = assert(cbor.create())
-- Use runtime factories, then close children before closing runtime.
assert(runtime:close() == cbor.OK)
```

## Handles and statuses

`cbor.init(config)` stores the runtime shell in userdata; `cbor.create(config)`
allocates it through the selected allocator. Both accept ordinary configuration
tables or typed native config handles. Runtime methods use its configuration.
Module-level codec/I/O/key factories use native defaults. `_init` factories keep
the shell in userdata; `_create`/`_open` factories allocate the shell in C.

Factories generally return a handle on success or `nil,status,error` on failure;
CWT and datagram factories always return the status and diagnostic alongside the
handle. Expected operation failures return integer status codes. Invalid Lua
argument types raise Lua argument errors. The diagnostic table contains native
status, cause, system errno, byte offset, component, message and mapped field path.

Children pin the runtime and borrowed owners across callbacks and GC. `close`,
`cleanup` and `destroy` share idempotent Lua close behavior. Close borrowed children
first: an active receiver returns BUSY and a borrowed owner rejects close. GC
defers owner cleanup until dependent finalizers release their pins. Native
external owners must preserve their storage throughout the borrow.

Lua integers preserve raw signed 64-bit bit patterns: `-1` represents UINT64_MAX
for unsigned values, negative magnitudes and float bits. Size and limit arguments
reject negative or out-of-range values. Constants mirror public C statuses,
token kinds, key kinds, framing and record events.

## Tokens and native transfers

The [README example](../README.md#lua-example) shows incremental decoding.
`decoder:next(input)` returns `status,consumed,token`; END events can consume zero
bytes. Tokens retain their input owner. `token:span()` borrows DATA;
`span:string()` explicitly copies it to Lua. Encoder `peek` borrows bounded
output and `advance` accepts an exact byte count. Close that span before a
mutation can reuse its storage. `encoder:read()` copies at most one bounded
output chunk. Drain output before finish. See [C API](c-api.md) for token grammar.

For whole transfers, use typed native source/sink handles supplied by a descriptor,
datagram or another native module:

```lua
local transfer = assert(runtime:transfer_init(source, sink, cbor.SEQUENCE))
local status = transfer:run()
-- INPUT/OUTPUT: wait for the corresponding endpoint, then call run again.
assert(status == cbor.DONE)
assert(transfer:close() == cbor.OK)
```

Payloads remain in C during `run`; Lua schedules readiness. Token processing is
available when the application needs to inspect individual events in Lua.

## JSON and mapped records

Runtime methods `json_to_cbor`, `cbor_to_json`, `encode_map` and `decode_map` use
blocking endpoints. Their `_init` and `_open` variants return resumable conversion
handles with `step`, `run`, `progress` and `diagnostic`. `encode_map_view` and
`decode_map_view` are aliases for the typed record-view methods.

```lua
local operation = assert(runtime:encode_map_open(record_view, sink, {chunk=2048}))
local status, diagnostic = operation:run()
-- Resume after INPUT/OUTPUT readiness; DONE commits the record.
assert(status == cbor.DONE, diagnostic and diagnostic.message)
assert(operation:close() == cbor.OK)
```

Options tables configure ordinary limits; native options handles also carry
field-sink callbacks. Endpoints, views and options owners stay pinned through
completion or cancellation. Blocking convenience calls report IO if an endpoint
would block. A destination can already contain a prefix when an operation fails;
resume only after readiness, and reconstruct after a terminal error.

## COSE and CWT

Import copied keys with `runtime:cose_key_init(kind,bytes,id)` or
`cose_key_create`. Module-level equivalents use the default allocator.
`key:metadata()` returns `status,{kind,key_id}`; `key:public_key()` exports public
bytes for asymmetric keys. Key kinds and exact lengths are in the
[COSE guide](cose.md) and [Sign1/Mac0/CWT guide](sign1-cwt.md).

Runtime COSE methods cover Encrypt0, Encrypt, decrypt, Sign1, verify1, Mac0 and
verify_mac0, plus authenticated `_stream` variants. Each has `_init` and `_open`
factories with `step`, `run`, `next`, `progress` and `stream_info` methods.
`next(sink,options)` retains coalesced decrypt input and keys after DONE. Omitted
sink/AAD retain their prior values; an omitted expected stream ID clears it.
Progress accumulates across messages. `stream_info` returns authenticated ID,
family, tag, algorithm and completion after the first verified record.

`default_cose_options()` supplies bounds and step budgets. AAD, nonce and stream
ID accept strings or spans. Options tables and recipient arrays are snapshotted,
pinning the actual byte/key owners. Use a unique 12-byte nonce per key for
standalone encryption, or the automatic nonce policy described in [COSE](cose.md).

`runtime:cwt_init(options)` and `cwt_create(options)` construct bounded reusable
token receivers. The defaults contain COSE bounds, claim/audience limits,
`require_cti` and `require_encryption`. Their methods are:

- `set_claims(encoded_map)` copies local CBOR claims. `set_lonejson(claims,cti)`
  encodes a typed native JWT claim handle directly.
- `set_seal_keys(signing_key,encryption_keys)` and
  `set_verify_keys(verification_key,decryption_key)` retain key-owner snapshots.
  Successful replacement clears prior trust; nil keys unbind.
- `seal(capacity)` returns `status,wire_span,error`. The owned native span passes
  directly to verification or native consumers. Borrowed native CWT handles use
  a 6162-byte default output capacity; supply larger configured bounds explicitly.
- `verify(wire,policy)` accepts a typed native policy or a Lua policy table.
  Tables require integer `now`; lists and strings are snapshotted for the call.
  Accepted algorithm names are Ed25519, ES256 and HS256.
- `view_get()` returns `status,view`, an explicit Lua snapshot containing encoded
  claims, cti, count, authentication state, algorithm and standard claim fields.
  `claim(integer_or_text_or_token)` copies one encoded CBOR value, or returns
  `INPUT,nil` when absent.

Failed verification clears the published view. Local loading reports
`authenticated=false`; crypto, claim policy and application admission together
establish trust. CWT calls use bounded memory; use COSE record operations for
large producer-to-consumer flows. Native admission callbacks belong to the C
options handle. Applications own replay policy.

## Datagrams

`cbor.datagram_init(descriptor,capacity)` and `datagram_create` borrow an integer
socket descriptor; runtime methods use the same arguments. `receive` returns
`status,{bytes=span,peer=span},error`, with peer absent for unnamed senders.
Endpoints return `status,source_or_sink` and retain the receiver. Bytes remain
borrowed until the next receive/reset/continuous-source read. See the
[datagram contract](c-api.md#datagrams) for validation, atomic sends and readiness.

## Native embedding

Include `<c89cbor/lua.h>` and initialize a per-state `c89cbor_lua` receiver with
`c89cbor_lua_init` or `c89cbor_lua_create`. The opaque `struct lua_State` declaration
keeps Lua headers out of core interfaces. Include Lua's headers when calling its
API directly. Resolve bridge symbols from the loaded native module.

Typed `push_*`/`check_*` pairs cover every exposed native handle and have
receiver-first exported twins. Push takes a pointer and owner stack index;
index zero selects an externally maintained C lifetime. Check returns NULL for
foreign or closed userdata. Binding cleanup preserves Lua and pushed handles.
Record views copy the public descriptor and borrow the record, schema and
lonejson runtime. An upstream lonejson Lua adapter can supply its original record
userdata as owner; libcbor uses public descriptors and typed checks.
