# Production hardening and standalone interoperability

This milestone retains ABI 0: libcbor has no released ABI. It does not migrate
cai, publish artifacts or add reliable UDP. All public changes include receiver
methods, exported twins, constructors, native Lua coverage and editor comments.

## Datagram receiver

`c89cbor_datagram` borrows a POSIX UDP or Unix datagram socket. Init/create fix
the maximum wire datagram size (default 2 KiB), allocate bounded input/output
storage once and perform no message I/O. The caller configures nonblocking mode,
addresses, deadlines and socket ownership. No internal poll, retransmission,
fragmentation, reassembly or reorder queue is introduced.

Receive validates exactly one complete CBOR item before exposing borrowed bytes
and a borrowed sender address. Empty, truncated, malformed, oversized and
multiple-item datagrams expose nothing and do not poison the next datagram.
Use recvmsg's truncation flag even when a truncated prefix is independently
valid. Kernel would-block returns INPUT. Kernel/IP reassembly happens below
UDP; missing fragments mean datagram loss. UDP does not repair delivery order
or inform a sender that the application rejected a record. The authenticated
COSE record profile rejects gaps, duplicates and reordering. Standalone objects
have no intrinsic ordering. App deadlines detect a missing final record.

Send validates one bounded item and uses one atomic sendmsg. OUTPUT means retry
after socket readiness. It never splits a datagram. An optional default peer is
copied, with explicit per-send override. Addresses use ordinary sockaddr bytes
and lengths without requiring POSIX types in the public header.

The receiver supplies a message-scoped source for a received datagram, a source
that reads successive validated datagrams without synthesizing EOF, and a sink
that collects one bounded CBOR item before an atomic send. Partial writes and
would-block preserve byte acceptance: the final input byte remains unaccepted
until its complete datagram has been sent. Reset cancels pending input/output;
it does not reset cumulative counters. Endpoints borrow the shell until cleanup.
Errors retain project status and errno. Test real socket backpressure and every
boundary/error path, IPv4/IPv6 and Unix datagrams, C/Lua and both ownership modes.

The configured buffer ceiling is not a path-MTU guarantee. Applications choose
record payload and header limits to fit their wire budget; EMSGSIZE is reported
to the caller. The example uses a conservative bounded wire budget.

## Reusable CWT receiver

Each CWT receiver owns reusable COSE workspace and provider contexts. Explicit
`set_seal_keys` and `set_verify_keys` methods snapshot and pin key policies until
rebinding or cleanup. Setup/lifecycle remain serialized. Seal/verify then use
those bindings; keys are no longer passed to each call. Migrate existing native,
Lua, examples, tests and benchmark calls; retain no parallel legacy API.

Prepared independent CWT receivers can execute concurrently with immutable shared
keys and a shared root: steady-state calls do not mutate shared lifecycle counts.
No libcbor allocator calls occur per token. OpenSSL may allocate internally;
measure that distinction explicitly. Cache signature/MAC/cipher contexts, clear
private scratch on failure and cleanup, and preserve zero publication until
authentication, native lonejson policy and admission succeed. Rebinding invalidates
the prior view's authenticated status while preserving its local claims.

Prove allocation counts across repeated sealing/verifying, encrypted nesting,
binding replacement/failure, shared-key workers, cleanup/reentry, native Lua spans
and all existing malformed/time/replay cases. Benchmark construction separately
from steady-state processing with the same fixtures and validation work.

## Independent peer and examples

Run E2E only on native x86_64 Linux glibc (`x86_64-linux-gnu`). Keep unit tests
across all SDK targets on their declared runners; SDK compilation, ABI and
package verification remain target-specific. Other targets do not require E2E
execution, including native Darwin.

Use Python-CWT 4.0.0 as a bounded reference service in rootless Podman Kube. Pin
the base image by digest and every Python wheel by version and SHA-256. Python
only serves bounded fixture transformations using upstream APIs; CTest and C
executables own test assertions and expected failures. Do not emulate unsupported
wire algorithms by rewriting protected headers or adding production aliases.

One tracked manifest template describes the service. Render checkout-specific
names, loopback ports and owned state paths under build/. Use a protocol health
probe with a deadline, native Podman logs and teardown of only owned resources.
Verify container/host writes and unprivileged reset. No credentials or external
live service is needed. Keep this E2E environment outside the release pipeline.

Exchange Encrypt0, Encrypt/A256KW, Sign1/Ed25519, Sign1/ESP256,
Mac0 and signed/MACed encrypted CWTs in both directions. Exercise external AAD,
recipient fanout, wrong keys, tampering and native claim policy. Supplement with
applicable pinned COSE working-group examples. Record any upstream incompatibility
as a failing scoped test and diagnose it before claiming interoperability.
Python-CWT 4.0.0 cannot exchange the X25519 key-wrap form: its ECDH-ES code
hard-codes EC2. Test that form separately with independent cryptography
primitives, identifying it as fixture verification rather than COSE-library
interoperability. Retain exact applicable COSE WG vectors as offline proof.

Ship a documented standalone C client/server example using only public APIs,
explicit key files, TCP/Unix framing and bounded UDP/Unix datagrams. Authenticate
both request and response, correlate requests and show useful errors. Test the
actual executables without cai, including malformed/truncated input, wrong AAD,
wrong keys, replay, timeout and server/client failures. Test Debug children on
128 KiB default worker stacks. Keep private provider and build machinery out of
the application's normal wire flow.

## Hardening and review

Keep short fuzz smoke in its existing preparation path. Add a separate native
long-run target with a 120-second default per selected corpus, configurable for
overnight campaigns. Preserve prior long-run findings for resumption and fail
on any crash/hang. Prerelease hardening includes that campaign plus native
sanitizer/memory checks and container E2E; release does not invoke it implicitly.
Neither native AFL++ nor Valgrind runs through QEMU. Missing tools/runners fail
the requested check. Darwin native runtime evidence remains unclaimed on Linux.

Review the complete affected contracts, diagnose findings with focused tests,
repair them and rerun affected gates. Re-run all seven SDK/consumer/package
checks and source/Lua archive checks after implementation. Describe observed
evidence and remaining limitations rather than treating smoke tests as an audit.
