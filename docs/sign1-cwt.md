# Signatures, MACs and CBOR Web Tokens

This specification extends [the encryption profile](cose.md). All payload and
key processing stays in C, including calls made through Lua. JSON JWT/JWS/JWE
wire formats are outside this milestone.

## COSE authentication

Implement the tagged and untagged Sign1 and Mac0 structures from
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html). Emit tags 18 and 17,
respectively. Payloads are attached byte strings. Detached payloads and
countersignatures are unsupported. Authenticate the original protected bytes,
the external AAD and payload using the standard Sig_structure or MAC_structure.
Never authenticate a reconstructed protected map. Apply the existing duplicate,
critical-header and bounded-work rules before releasing authenticated payload.

Sign1 supports the fully specified algorithms from
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html): Ed25519 (-19) and
ESP256 (-9, P-256/SHA-256). Mac0 uses HMAC 256/256 (5) from
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html). Keys are typed and
immutable; encryption, wrapping, MAC and signature keys cannot substitute for
one another. Wire key IDs never confer trust. Applications supply trusted keys.
Ed25519 seeds, P-256 private scalars and HMAC keys are 32 bytes. Public Ed25519
keys are 32 bytes; P-256 public keys use the 65-byte uncompressed SEC1 form.
P-256 signatures on the wire are exactly 64-byte r || s, never DER.

Every operation has a root receiver method, caller-storage initializer,
allocating constructor and blocking convenience. Existing operation shells
provide step, progress, next, diagnostic and lifecycle methods. Signing and
verification use the same bounded standalone contract as encryption. Unknown
length values use the existing ordered-record envelope and external-AAD domain,
with each record independently signed or MACed. The trusted verification key,
algorithm, stream ID, sequence and final marker remain fixed throughout a
logical stream. Earlier authenticated records remain delivered if a later
record fails. Completion requires an authenticated final record.

## Bounded CWT receiver

A CWT is a bounded token, not an unbounded logical stream. Provide a root-owned
`c89cbor_cwt` shell with init/create, local claim loading, native lonejson claim
loading, sealing, verification, claim inspection and lifecycle methods. Bounds
are fixed at construction. Default claims and header bounds are 2 KiB each.
All arithmetic and backend integer conversions are checked before allocation.
Buffers use the root allocator; crypto-provider storage remains separate.

Encode and inspect CBOR claims directly. Preserve the original claims map and
custom integer/text labels, exposing borrowed encoded values without JSON
serialization or a DOM. Reject duplicate claim labels, malformed values and
trailing bytes. Registered labels 1 through 7 mean issuer, subject, audience,
expiration, not-before, issued-at and binary token ID, as specified by
[RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html). Audience accepts a text
string or an array of text strings. NumericDate accepts integers and finite
floating values within the supported signed 64-bit seconds range. Preserve
the original CBOR representation; adapt fractional dates conservatively to
integer-clock policy comparisons. Embedded NUL in strings mapped to lonejson's
C-string claims is rejected instead of comparing only a prefix.

Local claim loading does not establish remote authentication. Claim views
report whether they came from successful token verification. Failure clears
previous verified claims before any new token can be inspected. Views and
encoded spans remain borrowed until the next mutation or cleanup.

Sealing signs or MACs a claims map, optionally encrypting the resulting tagged
COSE object using Encrypt0 or Encrypt. Emit outer CWT tag 61. Verification
accepts the optional outer CWT tag, requires a tagged COSE object when that tag
is present, and allows at most one encryption layer around one Sign1/Mac0.
There is no unsigned or encryption-only token acceptance. The application
supplies a trusted verification key and, when required, a separate decryption
key. Do not choose trusted keys from unverified claims or key IDs.
Set `require_encryption` when accepting an unencrypted signed token would violate
the application profile; merely supplying a decryption key does not require an
encryption layer.

After cryptographic verification, adapt the native claims to lonejson 0.50.0's
`lonejson_jwt_validate_claims`. Enable its public `jwt` interface component;
do not use its compact-JWS signature input for COSE. Policy algorithm names
are `Ed25519`, `ES256` and `HS256`, mapping explicitly from the authenticated
COSE algorithm. Issuer, audience, explicit clock/skew and required-claim
policies remain application supplied. Text extension claims `nonce`, `azp`,
`scope` and `scp` populate the corresponding lonejson fields, so their policies
are not silently ignored. Binary `cti` has a separate CWT requirement/admission
hook. Applications own replay storage and authorize use only after admission.
Do not expose remotely verified claim views until crypto, policy and admission
have all succeeded. A replay callback receives only authenticated, policy-valid
claims; rejection publishes nothing.
Scope replay keys to the application's issuer/audience context and binary cti,
rather than hashing token wire bytes: valid signatures and CBOR representations
need not have a unique byte representation.
JWT compact-parser size fields do not define CWT bounds: the receiver's CBOR
claim/header/count limits are authoritative. JOSE critical-header allowlists do
not authorize otherwise unsupported COSE critical headers.

## Transport and verification

No cai process is needed for end-to-end tests. Exercise native claim/map inputs,
Sign1/Mac0, both encryption families, verification and native claim consumers
over Unix streams, TCP, pipes and bounded UDP datagrams. UDP carries exactly one
complete bounded object or record per datagram. Use recvmsg truncation detection;
never accept a valid prefix of a truncated datagram. Loss, duplication,
reordering, corruption, oversize, empty datagrams, split records, multiple items,
missing final records, replay and endpoint failures must be observable failures
or pending input as appropriate. UDP silence is not EOF; deadlines belong to
the application. There is no retransmission or reliable-UDP protocol.

Prove independent cryptographic vectors/interoperability, wrong-key and
algorithm confusion rejection, malformed and duplicate headers/claims, audience
arrays, exact time boundaries, fractional dates, binary IDs, custom claims,
nested tampering and zero publication on failed admission. Exercise allocation
failures, cleanup, parent/key pins, reentrancy, partial I/O and would-block.
Run static/shared and Lua coverage, constrained worker stacks, all seven SDK
targets, exported API/consumer/package checks and relevant memory/fuzz checks.
Benchmark signing, verification, MAC and CWT policy work separately from I/O;
include native Lua calls and existing transport benchmarks. Keep the README
short and reference this document for the contract and its explicit limits.

## Using the receiver

Include `<c89cbor/lonejson.h>` and link `C89Cbor::static` or `C89Cbor::shared`.
Both targets propagate `lonejson::jwt`; pkg-config uses `lonejson-jwt`. No OIDC,
curl, JWS provider or additional lonejson library is required. The original
claim map, native strings/arrays and binary ID are owned by the token receiver.

The typical native flow is:

```c
c89cbor_cwt token;
c89cbor_cwt_view view;
/* root, claims, policy, keys, output and error are application supplied. */
root.cwt_init(&root, &token, NULL, &error);
token.set_lonejson(&token, &claims, binary_id, binary_id_length, &error);
token.set_seal_keys(&token, signing_key, NULL, 0, &error);
token.set_verify_keys(&token, trusted_key, NULL, &error);
token.seal(&token, output, capacity, &written, &error);
token.verify(&token, output, written, &policy, &error);
token.view_get(&token, &view);
/* Use view.claims directly; check every preceding return status. */
token.cleanup(&token);
```

`set_claims` copies one already encoded local map; `set_lonejson` writes native
fields directly as CBOR. Neither asserts remote trust. `claim` looks up an
integer label using token.type/argument or a text label using token.data/length,
returning a borrowed encoded value. Local loading may reuse this receiver's
current claims/view; mutation invalidates the old view and removes its prior
remote-authentication status. Use a separate destination for `seal` output.
`verify` input must not alias receiver-owned views. Each mutation replaces the
previous diagnostic; verification failure removes all previously published
claims. `view_get` then returns INPUT with cleared output.

For encryption, bind an array of encryption keys with `set_seal_keys`. Its count must be
one for Encrypt0; set `options.cose.encrypt` before constructing the CWT receiver
for Encrypt recipients. `set_verify_keys` binds one explicit trusted signature/MAC
key and a separate decryption key. Both setters snapshot/pin keys; failed
replacement preserves prior bindings. NULL/empty bindings unbind. Successful
rebinding clears the view's authentication status and retains its local claims.
Bounds and callback context are fixed at
construction; initialize another receiver to change them. A token can be parsed
from one bounded datagram or framed from TCP before this memory-only API runs.
For large opaque values use the COSE record operation instead of a CWT token.

The tagged encryption envelope and nested signed/MACed object are bounded
separately. Claims default to 2 KiB, unique claims to 64, and audience/scp arrays
to 32 entries each. Construction allocates six libcbor blocks (state, claim byte
workspace, claim entries, string-pointer arrays, COSE workspace and recipients);
create adds its shell. Seal/verify reuse provider contexts and perform zero
libcbor allocator calls per token. OpenSSL's internal allocations are separate.
Bind keys and construct/clean receivers serially. Independent prepared CWT
receivers can then process tokens concurrently with shared immutable keys and
root. A receiver's own calls remain serialized. Workspace contains plaintext
and is cleared after failed verification and during cleanup.

Use the [datagram receiver](hardening.md#datagram-integration) for UDP and Unix
datagrams. It preserves complete packets and rejects truncation before feeding
COSE. `c89cbor_fd` remains for files/pipes/stream sockets. Neither silence nor
an empty packet becomes successful byte-stream EOF on the continuous source.
