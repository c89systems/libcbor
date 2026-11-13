# COSE encryption design

The development implementation provides both `COSE_Encrypt0` and `COSE_Encrypt`.
Standalone bounded objects and
ordered record streams are in scope. OpenSSL comes from the cpkt SDK; Lua
continues to use its own public C API directly.

## Representation and transport

[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) defines COSE objects
independently of transport. A COSE object can cross TCP, Unix sockets, pipes,
files, UDP or relays without changing its cryptographic representation.
Confidentiality follows the object to a recipient holding the appropriate key.
Transport addresses, timing, lengths and unprotected headers are not hidden.

TCP and pipes provide byte streams; CBOR item boundaries or Length32 framing
still delimit records. UDP uses one complete bounded object or stream record per
datagram and rejects truncation. COSE adds neither reliable delivery nor ordering.
The record-stream profile below supplies authenticated ordering, not retransmission.

Plaintext is an opaque byte source. Applications normally supply encoded CBOR
and connect authenticated output to the existing CBOR reader, JSON conversion
or mapped decoder. Encryption does not serialize a record again or require a DOM.
Payload validation and application admission remain with the receiving consumer.

`COSE_Encrypt0` uses an application-provisioned symmetric content key and tag 16.
`COSE_Encrypt` uses tag 96 and carries one or more recipient descriptions.
Both structures use the exact protected-header bytes from the wire when computing
the COSE additional authenticated data. Never decode/re-encode protected headers
as a substitute for authenticating those original bytes.

## Initial algorithm profile

Use a deliberately declared interoperable subset of
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html). Implementing both object
structures does not mean accepting every algorithm in the COSE registries.

| Purpose | Initial algorithm |
| --- | --- |
| Content encryption | A256GCM, identifier 3; 32-byte key, 12-byte nonce, 16-byte authentication tag. |
| Encrypt0 content key | Caller-provisioned 32-byte symmetric key. |
| Encrypt symmetric recipients | A256KW, identifier -5; caller-provisioned 32-byte wrapping key. |
| Encrypt public-key recipients | ECDH-ES+A256KW, identifier -31, with X25519 and HKDF-SHA-256. |

Standalone Encrypt generates a fresh random content key for each object, then wraps that
key for every recipient. X25519 recipients use fresh ephemeral private keys;
only their public COSE_Key values travel in the recipient headers. Recipients
have no nested recipient layer in this milestone. Unsupported algorithms,
curves and recipient nesting make that recipient unusable; another supported
recipient can still succeed. Malformed duplicate headers are fatal.

Use the standard COSE_KDF_Context with AlgorithmID -5, 256 output bits and the
recipient's original protected-header bytes. PartyUInfo and PartyVInfo each
default to `[null, null, null]`; accept the standard -21 through -26 context
parameters within the header limit and incorporate them exactly as specified.
Absent salt means HKDF's standard absent-salt behavior. Reject invalid X25519
keys and all-zero shared-secret derivations. AES key unwrap must verify its
integrity check before the content key is used.

Require the body algorithm in protected headers. A256KW recipients have an
empty protected bucket and an unprotected algorithm, as required by RFC 9052
Section 8.5.2. ECDH recipients may protect their algorithm through the KDF
context. Emit definite containers and shortest arguments for generated
headers, COSE_KDF_Context and Enc_structure. Accept valid nonpreferred input
where COSE permits it. Reject duplicate labels, labels repeated across header
buckets, unknown critical parameters and critical parameters missing from the
protected bucket. Noncritical unknown values are skipped within bounded limits.
Encoded empty protected maps are accepted alongside empty byte strings.
Critical content-type metadata is unsupported: this opaque-byte API does not
interpret or expose an application's media-type policy.

Wire key IDs select candidates; they do not establish trusted identities.
Applications provision trusted keys and authorize their use. Public-recipient
encryption alone does not authenticate a sender: anyone holding the recipient's
public key can create an encrypted message. Use the implemented
[Sign1/Mac0 and CWT interfaces](sign1-cwt.md) for sender authentication and
explicit native claim policy.

## Authenticated delivery and bounds

Decryption must not deliver any plaintext from an object until its authentication
tag has verified. A failure delivers zero bytes from that object. Clear private
plaintext scratch on authentication failure and cleanup. This follows the
[OpenSSL AEAD contract](https://docs.openssl.org/3.6/man3/EVP_EncryptInit/).

The standalone object API is explicitly bounded. Its default maximum plaintext
is 2 KiB, configurable before opening an operation. Exceeding that bound fails
with LIMIT. Do not silently assemble an unbounded object, spill to a file or
label whole-message staging as streaming. Standalone sealing buffers this bounded
object and checks producer EOF before emitting it. Record streams emit before
logical producer EOF; a later producer failure leaves the stream incomplete.

Unknown-length logical values use independently authenticated bounded records.
Memory is bounded by configured record and metadata limits independently of
the logical value's length. Earlier authenticated records can reach the consumer
before producer EOF. Successfully authenticating a record does not certify that
the complete logical stream arrived.

Default limits are 2 KiB plaintext per record, 2 KiB encoded header material per
object, eight recipients, 64 bytes per key ID and 2 KiB external application AAD.
One operation allocates a state block, a byte workspace of
`4 * record_bytes + 8 * header_bytes + 592`, and a bounded recipient array.
An allocating constructor adds its shell allocation. Drive performs no further
libcbor allocator calls. OpenSSL's provider allocations are separate.
Byte/event drive budgets retain the native runtime defaults. Check all arithmetic,
OpenSSL integer-size conversions and recipient counts before allocation or copy.
Default configurations must run on supported musl worker stacks.

## Ordered record-stream profile

This is a libcbor application profile built from standard COSE objects. COSE
alone does not define this logical-stream envelope or its replay policy.
The outer wire item is a definite CBOR array:

```text
[stream_id : bstr .size 16, sequence : uint, final : bool, cose_object]
```

The complete item is carried as a CBOR Sequence item, a Length32 frame or one
bounded datagram. The COSE object is Encrypt0 or Encrypt as selected when opening
the stream. A stream cannot change object family, algorithm or configured key
policy midway through delivery.

An Encrypt stream generates one fresh content key for the whole logical stream.
Every record carries the same wrapped content-key distribution. Key agreement
and wrapping occur once; their public recipient descriptions can be repeated.
After authenticating the first record, the receiver retains its recovered
content key and requires constant-time equality with the content key recovered
from each later record. Keep that secret only in bounded private operation state.
An exact repeat of previously accepted recipient bytes is recognized by a
SHA-256 fingerprint, so it can reuse that established secret without another
key agreement. Changed recipient metadata takes the full unwrap and constant-time
content-key comparison path. Every record still verifies its own GCM tag.
Sequence/AAD checks alone are insufficient: an attacker knowing a recipient's
public key could otherwise substitute a newly encrypted object with another key.
This continuity check does not establish a sender identity for the first record.

Encrypt0 streams likewise use their fixed provisioned content key. Each record
uses a fresh nonce. Limit a stream to at most 2^24 records, including its final
record; key rotation/new logical streams must occur before exhausting that
cryptographic budget. Memory bounds remain independent of logical value length
within those limits.

Build the COSE external_aad as the definite, shortest-argument CBOR encoding of:

```text
["c89.systems/cbor-stream", application_aad : bstr,
 stream_id : bstr .size 16, sequence : uint, final : bool]
```

Use that byte string inside the standard COSE Enc_structure. This authenticates
the outer metadata without allocating private COSE header labels or new tags.
The context string distinguishes these records from standalone COSE objects.

Senders generate an unpredictable 16-byte stream ID and start at sequence zero.
Every subsequent record increments sequence by one; overflow fails. Exactly one
final record completes the stream. The final record may contain payload or be
empty. A full record can be emitted before EOF; an empty final record handles
EOF discovered immediately after a full record. No unauthenticated EOF implies
successful completion.

Receivers require sequence zero first, then exactly the expected sequence and
the same authenticated stream ID. Reject duplicates, gaps, reordering, mixed
IDs and records presented after the final marker. Metadata becomes authoritative
only after authentication. EOF before the final record is a truncation error.
Persistent receivers stop at the authenticated final marker and retain following
message bytes for next.
Already delivered authenticated records remain delivered on a later failure;
applications needing atomic whole-value effects stage those effects explicitly.

Opening accepts an optional expected stream ID from a trusted application
context. Without it, adopt the first authenticated record's ID. This prevents
splicing within an operation; rejecting a replay of an entire previously accepted
stream requires application-owned admission state. The library does not invent
a persistent replay database or promise global replay protection. Receivers expose
`stream_info` after the first verified record, including from a bounded sink
wrapper before it forwards payload. It copies the authenticated ID, Encrypt
family and completion flag. Before authentication it returns INPUT without an
ID. Empty streams expose their ID after DONE, so application replay admission
does not depend on receiving nonempty plaintext.

## Keys, nonce policy and lifetime

Provide immutable key receivers for symmetric keys and X25519 public/private
keys. Symmetric imports select A256GCM or A256KW explicitly; one imported key
cannot be used for both algorithms. Applications must not import the same raw
secret under different algorithm policies. Import copies key bytes and bounded ID. Private material
is never returned by ordinary metadata queries. Public-key export is explicit.
Cleanup clears owned symmetric/private material and releases OpenSSL objects;
destroy uses the recorded shell allocator. Active operations pin their keys.
Cleanup/destroy return BUSY while a key is borrowed.

Applications own provisioning, recipient trust, rotation and any persistent key
usage accounting. Encrypt0 must never repeat a nonce with the same key. The
normal route obtains a fresh 96-bit nonce from OpenSSL's secure RNG and fails
closed if randomness fails. An explicit nonce is allowed for application-managed
allocation and independent vectors; the caller then guarantees uniqueness across
all uses of the key, including other handles, processes and restarts.

Enforce a conservative per-key-handle sealing ceiling of 2^24 objects. Sharing
the same raw key through multiple handles does not reset its real cryptographic
usage budget; this remains an application provisioning obligation. Encrypt uses
a fresh content key and nonce for each standalone object; an Encrypt stream uses
its fixed stream content key and a fresh nonce for each record. Every stream record is a separate
object. Do not substitute sequence or stream IDs for the nonce without a
separately specified derivation. Cancellation consumes any reserved nonce/use.

## Receiver and integration surface

Add `<c89cbor/cose.h>` with complete caller-storage shells, constructors and
clangd-readable ownership/error comments. Keep OpenSSL types out of public
structs and method parameters. Runtime factories and exported receiver-first
twins cover key import, standalone encrypt0/encrypt/decrypt and record-stream
seal/open operations. Default-value helpers also belong to the runtime.

Keys expose public metadata/export, diagnostic, cleanup and destroy methods.
Use a COSE operation receiver with bounded step, progress, diagnostic, cleanup
and destroy, reusing the private generic conversion driver and backpressure
contract. Each operation has caller-storage init, allocating open and blocking
convenience routes.
Opening validates configuration and performs no source/sink callbacks.

Persistent decrypt receivers complete at the authenticated object/final-record
boundary, without requiring a TCP close. They retain any input read-ahead.
Their next method starts the next object/logical stream on the same source,
optionally selecting another sink and AAD/expected stream ID. Workspace limits
and key policy remain fixed. Cumulative progress spans these messages. Cleanup
releases the retained input; callers must use next to preserve coalesced messages.
Failed operations require reconstruction. Blocking one-shot convenience calls
instead require a message-scoped source and check its EOF/trailing bytes.

Borrow endpoints, configured key receivers and application AAD until cleanup.
Reject callback reentry and busy lifecycle operations before mutation. Retain
terminal diagnostics and exact accepted/delivered counts. Authentication failure
is distinct from syntax, unsupported algorithms, limits, I/O and allocation
failure. Never include secret bytes or plaintext in diagnostics.

Serialize factory/lifecycle operations as for the current runtime. Distinct
operations may execute concurrently with immutable keys; any usage-counter state
must be synchronized. No application-global OpenSSL allocator hooks or provider
configuration. Owned libcbor workspaces use its configured allocator; OpenSSL's
own contexts use OpenSSL allocation and must be accounted for separately.

Lua exposes the same factories, key receivers and conversion handles through the
public C API. Native mapped records and native source/sink pointers stay in C.
Explicit byte-string key import is an opt-in Lua copy. Add typed push/check key
interop on the binding receiver, preserving owner pins and GC order.

## cpkt/OpenSSL and packaging

Use cpkt as the OpenSSL SDK provider, following the lifecycle's provider and
dependency contracts. The available validated baseline is cpkt 0.7.0, whose
manifest selects OpenSSL 3.6.5 on all seven targets. Exact release/target/archive-SHA
pins are recorded in scripts/deps.sh. Do not acquire
OpenSSL independently, build from a sibling checkout or fall back to host libs.

Consume the provider's public OpenSSL EVP API. The static SDK target is
`OpenSSL::Crypto`; its shared target is `cpkt::openssl_crypto_shared`. COSE needs
libcrypto, without linking libssl or the cpkt Lua facade. Preserve the provider's
package layout and imported target dependency closure. Installed CMake/pkg-config
metadata must resolve the required provider component from its own prefix.

Ship COSE with the normal static/shared libcbor SDK and direct Lua facade on all
seven targets. Adding OpenSSL as a required crypto dependency must update build,
source smoke, installed consumers, LuaRocks prerequisites, exports and manifests
together. Choose any necessary ABI change against the latest released artifact,
independently of development version strings.

## Verification and performance

Prove Encrypt0 and Encrypt against independently constructed standard COSE
fixtures, including exact Enc_structure and COSE_KDF_Context bytes. Test AES-GCM,
AES key-wrap and X25519/HKDF with published vectors. A self-round-trip alone is
insufficient. Exercise both symmetric and public recipients, recipient order,
multi-recipient success and wrong-key rejection.

Tamper with every protected field, ciphertext, tag, ephemeral key, wrapped key
and application AAD. Verify zero plaintext delivery for failed objects and no
delivery of unauthenticated stream records. Cover duplicate headers, cross-bucket
duplicates, unknown critical fields, key/algorithm mismatches and bounded unknowns.

Fragment every boundary, pause input/output, cancel active operations, inject
allocation/RNG/source/sink failures and verify sticky diagnostics and cleanup.
Check nonce-use limits, ownership, receiver/free-function parity, constructor
failure and initialized caller storage. Fuzz both object parsers and stream state.

Generate a long logical stream without materializing it. Prove authenticated
delivery before source EOF, fixed memory, and detection of reordered, duplicated,
missing, spliced and truncated records. Test final markers, sequence overflow,
unknown lengths, wrong external AAD and whole-stream replay admission by a caller.

Run Unix/TCP/pipe streams and bounded UDP/Unix datagrams, native Lua pointers,
static/shared extracted consumers, Valgrind and all target/runtime gates from
the existing lifecycle. Benchmark content encryption separately from X25519/key
wrapping and recipient count. Report authenticated throughput/latency, CPU time,
copies and observed allocation/workspace costs with setup distinguished from
per-object work. Include the direct Lua route; never compare unauthenticated
plaintext delivery with authenticated delivery as equivalent performance.
