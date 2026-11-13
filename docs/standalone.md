# Standalone authenticated client/server

[examples/cbor-peer.c](../examples/cbor-peer.c) is a complete POSIX application
using libcbor's public receiver API. `make build` builds `cbor-peer` under
`build/x86_64-linux-gnu-debug/`; SDKs also ship the source. Link it with
`C89Cbor::static` or `C89Cbor::shared`, defining `_POSIX_C_SOURCE=200809L` and
compiling with `-std=c89`. It has no cai dependency.

Generate two independent identities in existing private directories:

```sh
mkdir -m 700 -p build/peer/client build/peer/server
build/x86_64-linux-gnu-debug/cbor-peer keygen build/peer/client
build/x86_64-linux-gnu-debug/cbor-peer keygen build/peer/server
```

Keygen uses OS entropy and creates four raw 32-byte files per identity:
`sign.key` (Ed25519 seed), `sign.pub`, `encrypt.key` (X25519 private key) and
`encrypt.pub`. Creation is exclusive, with mode 0600. It never overwrites files;
a failed invocation can leave partial output. Keep private files at their owner;
distribute and authenticate public files through your application's trust setup.
The example does not discover or trust public keys received over the wire.

Run the server in one terminal:

```sh
build/x86_64-linux-gnu-debug/cbor-peer server tcp 9000 \
  build/peer/server/sign.key build/peer/client/sign.pub \
  build/peer/server/encrypt.key build/peer/client/encrypt.pub
```

Then run the client:

```sh
build/x86_64-linux-gnu-debug/cbor-peer client tcp 9000 \
  build/peer/client/sign.key build/peer/server/sign.pub \
  build/peer/client/encrypt.key build/peer/server/encrypt.pub 'hello'
```

Replace `tcp` with `udp` for complete datagrams, or use `unix`/`unixgram` and a
socket path instead of a port. IP sockets bind/connect loopback. Port 0 lets a
server choose a port and print `READY PORT` after binding. Unix paths must be
unused; the example removes only paths it successfully bound. A Unix datagram
client creates a temporary address alongside the server path. Stay within the
platform's sockaddr_un path bound, including that suffix.

The optional final server argument is a request count (1–1000, default 1).
The optional final client argument is a UTF-8 message of at most 64 bytes.
The server acknowledges each admitted request; the client authenticates and
correlates the response before printing success. Requests carry the custom CBOR
`msg` claim; the example server acknowledges admission rather than executing a
command from that field.

## Wire and ownership contract

Both directions use CWT tag 61 around Encrypt (A256GCM with X25519
ECDH-ES+A256KW recipients), enclosing Sign1/Ed25519. The trusted peer signing
key is separate from its encryption key. Issuer/audience, expiration and binary
16-byte request ID are authenticated. The caller supplies the clock through
lonejson's native policy; fields are encoded directly as CBOR without JSON.
`libcbor-peer` is the fixed external AAD for this example protocol.

Tokens are explicitly **bounded memory objects**, capped at 1200 wire bytes,
with 256-byte claims and header bounds. TCP/Unix streams add a four-byte network
order token length; datagram transports send exactly one token per packet via
`c89cbor_datagram`. This application does not present its tokens as unbounded
streaming. For large messages use the real incremental COSE record operations
and the datagram shell's continuous source/atomic sink where appropriate.

The client chooses a fresh ID using `/dev/urandom`; the response must repeat it.
The server rejects a repeat of its most recently admitted ID within this process.
This intentionally small, single-peer replay window is an example, not a durable
replay store. Applications admitting multiple outstanding requests need their
own bounded replay policy and persistence/lifetime rules. Expiration is 60
seconds. Both peers require `exp`; an otherwise valid authenticated token without
it is rejected. Socket inactivity and accept deadlines are three seconds; they produce an error rather
than retransmission. Complete UDP packets may arrive out of order; this example
has one request outstanding and does not implement reliable UDP.

Keys and CWT workspaces are prepared once. The process serializes calls on its
shells, borrows the socket, cleans receivers before keys/root, and closes the
socket itself. Errors terminate with nonzero exit status. No plaintext request
is acted on before decryption, signature, claim policy and replay admission.

## Executable proof

`standalone-peer` in CTest executes the actual keygen, server and client programs.
It covers all four transports, trusted/wrong peer keys, wrong AAD, missing
expiration in authenticated requests and responses, ciphertext
mutation, malformed/empty/oversized datagrams, duplicate token replay, truncated
and invalid stream frames, connection failure and missing-input deadlines.
Debug child processes inherit the test-only 128 KiB default worker-stack setup.
Only native x86_64 Linux glibc executes this E2E child-process suite. Other SDK
targets compile and link the application, with their library/socket tests run
on the declared runners. E2E execution on other targets is outside the selected
test scope.
