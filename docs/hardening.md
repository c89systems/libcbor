# Interoperability and prerelease hardening

Use the [production-hardening specification](production-hardening.md) for the
accepted behavior and [standalone application](standalone.md) for local peers.
These checks prepare an unreleased ABI 0; they do not release or migrate cai.

Unit tests cover the full SDK target matrix using the declared runners. E2E
tests (`standalone-peer` and `reference-peer`) run only in the native x86_64
Linux glibc host context (`x86_64-linux-gnu`), rather than once per SDK target.
Other targets retain compilation/linking and unit, ABI and package checks;
they have no deferred E2E runner requirement.

```sh
make check-native        # normal C/Lua, formatting and shell checks
make sanitize            # native ASan + UBSan, including child applications
make valgrind            # native Memcheck and shared-key Helgrind
make e2e                 # rootless Podman Kube reference peer
make fuzz-smoke          # 10 seconds per corpus, fresh smoke results
make fuzz-long           # 120 seconds per corpus, resumable results
make prerelease-hardening # normal, sanitizer, memory, peer and long fuzz checks
```

`prerelease-hardening` is separate from `prerelease` and `release`. Longer fuzzing
and the container service are never silently added to the release pipeline.
Missing declared tools fail the requested command. Native checks use the pinned
Bootlin compiler/AFL++ and prepared dependencies. They do not run via QEMU or on
native Darwin. The native sanitizer command targets x86_64 Linux; provider
libraries are the separately supplied pinned binaries. The intentional child
stack-guard fault retains the kernel signal rather than ASan's signal handler;
other ASan/UBSan detection and leak checks remain enabled.

Helgrind has one narrow suppression for OpenSSL 3.6.5's name-map counter read
during signature fetch. The pinned
[name-map source](https://github.com/openssl/openssl/blob/openssl-3.6.5/crypto/core_namemap.c)
uses the relaxed atomic operations in
[tsan_assist.h](https://github.com/openssl/openssl/blob/openssl-3.6.5/include/internal/tsan_assist.h).
On x86_64 those become plain load/store instructions which Helgrind cannot
identify as C atomics. The suppression matches that exact upstream function and
fetch call chain; it does not suppress libcbor accesses or general provider races.

## Reference peer

The selected independent implementation is
[Python-CWT 4.0.0](https://pypi.org/project/cwt/4.0.0/).
[tests/e2e/pod.yaml.in](../tests/e2e/pod.yaml.in) declares the single fixture
service. Its Python 3.12 Alpine base is pinned by digest; all six wheel artifacts
are pinned by version, URL and SHA-256 in
[tests/e2e/wheels.lock](../tests/e2e/wheels.lock). Dependencies are downloaded only
into this checkout's `.cache/e2e`. This fixture currently targets a native
x86_64 Linux Podman host. It requires rootless Podman, curl and sha256sum.
No live provider, credentials, privileged cleanup or broker is used.

Python only transforms bounded fixture bytes through library APIs. The compiled
C test owns assertions, expected failures and policy checks. It exchanges
Encrypt0, Encrypt/A256KW, Sign1/Ed25519 (-19), Sign1/ESP256 (-9), Mac0/HMAC256,
and signed/MACed encrypted CWTs in both directions. It tests external AAD,
recipient fanout, mutation rejection and native CWT expiration. These exchanges
exercise COSE/CWT encoding and cryptography; lonejson remains the native claim
policy validator in libcbor.

Python-CWT 4.0.0 supports X25519 key derivation, but cannot exchange our selected
X25519 ECDH-ES+A256KW (`-31`) form. Its
[OKP key validation](https://github.com/dajiaji/python-cwt/blob/v4.0.0/cwt/algs/okp.py)
rejects `-31`, and its
[wrapping encoder](https://github.com/dajiaji/python-cwt/blob/v4.0.0/cwt/recipient_algs/ecdh_aes_key_wrap.py)
always constructs an EC2 ephemeral key, which rejects the X25519 curve.
The fixture therefore identifies X25519 separately: an RFC 9053 bounded fixture
uses cryptography's X25519, HKDF-SHA256, AES-KW and AES-GCM primitives and cbor2.
Those bidirectional checks provide an independent primitive/encoding check,
**not** interoperability with another COSE library for X25519. Production headers
are never rewritten to emulate another algorithm. This upstream limitation is
not an unresolved libcbor test failure and is not hidden as a passed library test.

Offline tests additionally consume exact COSE WG Encrypt0/A256GCM and
Mac0/HMAC256 examples from commit
`53c9d634333bb4f529d78f5980fffa2667ee2c12` of
[cose-wg/Examples](https://github.com/cose-wg/Examples/tree/53c9d634333bb4f529d78f5980fffa2667ee2c12),
checking decode and byte-exact deterministic encode. Attribution and the upstream
public-domain license accompany the fixtures.

The script renders only known placeholders into `build/e2e/pod.yaml`, with a
checkout-specific pod name, loopback port and writable owned state. A bounded
HTTP readiness probe verifies protocol startup. Container/host writes and
unprivileged deletion are tested. EXIT teardown stops only that manifest's
resources. Logs, rendered manifest and image ID remain in `build/e2e/`; normal
success removes the mutable marker files. No container is retained after a run.
`make clean` removes generated state and local caches under normal job ownership.

## Fuzz campaigns

The 11 cases cover codec, JSON/CBOR visitation, maps, encrypted objects/streams,
Sign1 objects/streams, Mac0 objects/streams and CWT. Long campaigns retain AFL's
native state in `build/fuzz/long-CASE`, automatically resume its queue and fail on
any saved crash or hang. Smoke uses separate `results-CASE` directories and resets
only those results. Inspect AFL's `fuzzer_stats`, queues, crashes and hangs;
there is no secondary report/receipt format.

```sh
FUZZ_CASES='cose cose-stream cwt' FUZZ_SECONDS=3600 make fuzz-long
```

`FUZZ_SECONDS` is a positive per-case wall-clock duration. The default 120 seconds
is an initial prerelease campaign, not a claim of exhaustive security assurance.
The invoking terminal owns whole-job cancellation. Do not edit sources or share
mutable build/cache state with another operation during verification.

## Datagram integration

`<c89cbor/datagram.h>` provides init/create receiver constructors and twins for
receive/send/set_peer, source/stream_source/sink, reset, progress and diagnostics.
The [API inventory](api-inventory.md) covers C and Lua surfaces. Fixed allocation
at construction bounds packet memory; calls perform no libcbor allocation.
Receive rejects truncation even if the retained prefix is valid CBOR, and returns
no borrowed bytes for invalid packets. The next receive can recover. The scoped
source ends after one explicitly received packet; the continuous source waits
for subsequent validated datagrams and never invents EOF.

The kernel/IP layer reassembles IP fragments. UDP supplies no acknowledgement,
application admission feedback, ordering, retransmission or duplicate filter.
Applications own deadlines and replay policies; our authenticated ordered record
profile rejects gaps, duplicates and reordering without a reorder queue. Dropping
a final packet needs an application deadline. Buffer capacity is not a PMTU
promise; choose a payload/header budget that fits the application's packet budget.
The sink's final byte is accepted only after a successful atomic packet send, so
would-block cannot silently lose a completed item. Reset cancels pending work.
