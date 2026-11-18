# Benchmarks

## Run and compare

```sh
make benchmark VERSION=0.1.0
make benchmark-compare VERSION=0.1.0
```

Release workloads cover C encode/decode, mapped records, JSON conversion, native
Lua transfer, COSE/CWT and Unix/TCP/pipe/datagram transports. Setup and one warmup
are excluded; five measured rounds remain. JSONL rounds and source/toolchain/run
context live under `build/bench`. Run measurements serially and retain per-round
variation: this is a shared host, and throughput is an optimization signal rather
than a correctness gate.

The independent comparator is PJK/libcbor 0.14.0, built with the same pinned
Bootlin compiler and Release options. Executables link exclusively to their own
library prefixes; symbol checks reject accidental cross-linking. PJK source is a
pinned benchmark dependency. The product uses lonejson for mapped/JSON operations;
raw codec and transfer paths run directly on native CBOR tokens.

## Mapped records and JSON

Fixtures cover scalar-heavy records, nested records, 72-byte ASCII/multibyte text
and approximately 64 KiB text. Integer cases include signed/unsigned boundaries.
All fields are required. `interop-reference` compares exact native/PJK bytes for
minimal integer encodings and explicit binary64 floats.

PJK builds and destroys a DOM per record. Decode validates keys, duplicates,
required fields and native ranges. The native path opens, runs and cleans one
conversion per record, including workspace allocation and record/value checks.
Immutable singleton leaf schemas reuse validation metadata in a bounded
thread-local cache; other descriptors undergo full validation. Setup includes
runtime/schema preparation, and decode resets the initialized destination.
Direct mapped operations use native lonejson records. The separate JSON control
materializes a document to measure that additional representation boundary.

For focused runs:

```sh
build/x86_64-linux-gnu-release/profile_benchmark mapped-encode 1000000 0 scalars
build/x86_64-linux-gnu-release/reference_mapped_benchmark encode 1000000 scalars
```

Substitute decode modes as needed. The native chunk argument is zero for the 2 KiB default; PJK's
DOM accepts the complete fixture buffer. `BENCH_REPETITIONS` defaults to 10000
small records per round; large text uses one sixteenth as many.
`BENCH_CHUNK` selects the native input chunk bound.

Diagnostic controls default to zero:

| Control | Effect |
| --- | --- |
| `BENCH_SYSTEM_ALLOCATOR=1` | Use system allocators without allocation counters. |
| `BENCH_NO_VERIFY=1` | Verify output outside timing; retain input/type/range validation and endpoint counters. |
| `BENCH_TRANSIENT_SCHEMA=1` | Use an ordinary descriptor copy, including its different lonejson reset/analysis path. |
| `reset-control` executable mode | Measure destination reset separately. |

Keep control results separate and reverse execution order to check host bias.
JSONL includes the control flags. Latency samples use 16-record batch means for
small fixtures and individual operations for large text, with sample counts and
batch sizes reported.

### Mapped workspace measurements

The workspace/short-text optimization (`36c6d4d`) was measured against `70ab496`
with identical benchmark objects, Release options and CPU affinity 7. The full
allocator-tracked run used 100000 small records per round and 6251 large records.
These are five-round medians in microseconds per record:

| Fixture | Native encode | PJK DOM encode | Native decode | PJK DOM decode |
| --- | ---: | ---: | ---: | ---: |
| Scalars | 0.512 | 0.613 | 0.787 | 0.949 |
| Nested | 1.099 | 1.821 | 1.644 | 2.534 |
| Short ASCII | 0.397 | 0.364 | 0.607 | 0.432 |
| Short UTF-8 | 0.486 | 0.354 | 0.638 | 0.427 |
| Large ASCII | 9.465 | 149.699 | 11.827 | 149.919 |
| Large UTF-8 | 80.527 | 144.722 | 79.109 | 143.646 |

Two reversed-order system-allocator passes, with output comparisons outside
timing and 1000000 records per round, produced these ten-round medians:

| Profile | Before | Current | PJK DOM |
| --- | ---: | ---: | ---: |
| Short ASCII encode | 0.446 | 0.396 | 0.331 |
| Short ASCII decode | 0.628 | 0.567 | 0.407 |
| Scalars encode | 0.557 | 0.499 | 0.545 |
| Scalars decode | 0.858 | 0.781 | 0.824 |

Scalar performance meets the PJK comparison, and large ASCII leads by roughly
16× encode and 13× decode. Short ASCII improved about 11%/10% and remains behind
PJK. Raw rounds and context are `memory-*.jsonl` and `memory-comparison-context.txt`
under `build/bench`.

### Memory and accounting

Allocator-tracked peak user bytes include the 1600-byte prepared runtime baseline
and exclude caller storage and allocator bookkeeping:

| Workload | Before | Current |
| --- | ---: | ---: |
| Scalar/short-text encode, 2 KiB chunks | 18752 | 7176 |
| Scalar/short-text decode, 2 KiB chunks | 18752 | 9224 |
| Short ASCII decode, 16-byte chunks | 82256 | 7320 |
| Large ASCII decode, 2 KiB chunks | 84288 | 74760 |

Flat small records use one allocation per operation. Nested records reserve more
stack/source workspace: 17744 bytes encode and 16416 decode. PJK short-ASCII peaks
are 351/375 bytes. Fragmented materialized text grows scratch within the field
limit, including temporary old/new buffers during growth.

Peak allocation counters observe configured allocator hooks; RSS is the process
high-water mark. Endpoint copy counts measure harness reads, writes and final
record copies. Library-internal copies, provider allocations and Lua VM storage
have separate ownership and are outside those counters.

## Small-record codec costs

`codec_roundtrip_static` and `codec_roundtrip_shared` measure the existing public
C codec API in encode, decode or roundtrip mode. Each record includes finish and
reset; initialization is outside timing. Output passes through bounded borrowed
spans. Grammar and UTF-8 validation stay enabled; the final argument optionally
adds byte comparisons. For example:

```sh
scripts/build.sh core x86_64-linux-musl Release '' -DC89CBOR_BENCHMARKS=ON
build/x86_64-linux-musl-release/codec_roundtrip_static roundtrip 64 4194304 32768 text 0
```

On 2026-11-18, paired runs against v0.1.0 used the pinned musl Release compiler,
CPU affinity 7, one warmup and five measured rounds per invocation. Execution
order was reversed between passes. These ASCII roundtrip medians are nanoseconds
per record, with 20 measured rounds for 64 bytes and 10 for larger records:

| Payload bytes | Static before | Static after | Shared before | Shared after |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 110.0 | 93.8 | 121.9 | 114.2 |
| 4096 | 590.1 | 292.4 | 630.9 | 307.6 |
| 32768 | 4066.1 | 1640.4 | 4170.7 | 1656.5 |

The codec scans ASCII in bounded 32-byte groups and reuses established grammar
bounds when consuming DATA and emitting implicit END events. The 4 KiB multibyte
UTF-8 control retained essentially the same instruction count; its elapsed-time
medians stayed within 2.1% of baseline. Raw rounds, binary/source hashes and build
context are under `build/small-payload/`. The table uses 32 KiB chunks; separate
2 KiB chunk and byte-string controls are retained there too.

## Codec, Lua and transport workloads

The raw codec fixture repeats definite 1024-byte strings. Decode consumes borrowed
spans; encode copies to bounded output and verifies it. PJK's low-level decoder
is stateless, while the native decoder tracks enclosing grammar. This workload
measures those interfaces separately from the DOM record comparison.

Native Lua transfer generates 65536 independently encoded 1024-byte items through
C endpoints and a 2 KiB buffer. Timing includes Lua chunk loading and the wrapper
call; VM/module/endpoint setup is excluded. The sink verifies every byte. Reports
include CPU time, callback counts and endpoint copies.

Stream transports cover large definite items and producer-driven indefinite items
in 1024-byte chunks, including parser finish at EOF. Datagram cases pace independent
512-byte items with one request/ack outstanding. Small socket buffers exercise
backpressure. Setup is excluded; scheduling and completion are timed. Transport
CPU sums both processes; wire counts include both endpoints and acknowledgments.
Datagram latency samples cover the first 1024 exchanges. Generated streaming tests
separately verify bounded storage and delivery before producer EOF.

## COSE and CWT

`cose-<profile>-<mode>.jsonl` covers GCM, A256KW, X25519, eight-recipient fanout,
Ed25519, P-256 and HMAC. Objects use 1024-byte payloads, including operation
construction/cleanup; prepared keys belong to setup. The fanout fixture repeats
one public key with independent ephemeral keys.

Stream roundtrips use a 4096-byte ring, authenticate before verifying plaintext
and deliver before producer EOF. Default plaintext records are 2 KiB. JSONL counts
**1024-byte payload accounting units**: 1000 units mean 1024000 plaintext bytes
and 501 COSE records, including the empty final record. `mean_ns` and
`wire_bytes_per_record` use that accounting unit. Stream latency values are
amortized whole-stream samples; standalone samples cover individual operations.

C and Lua stream workloads share the public library, endpoints and native
scheduling. Lua timing includes borrowed-handle preparation and chunk execution.
Static C object runs and shared C/Lua comparisons are identified separately.
The common COSE workspace reserves `4 * record_bytes + 8 * header_bytes + 592`
bytes plus state/recipients. Use current JSONL allocator counters for its peak.

CWT workloads use prepared receivers, native claims and explicit lonejson
algorithm/issuer/audience/clock policy. Lua produces a native owned output span.
Wire throughput uses the actual small claim map. Construction/key binding belongs
to setup; seal/verify uses reusable bounded workspaces. The x86_64 OpenSSL 3.6.5
run with 1000 operations per round produced these five-round medians:

| Profile | Shared C seal µs | Shared C verify µs | Lua seal µs | Lua verify µs |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 | 24.18 | 62.58 | 27.14 | 63.73 |
| P-256 | 17.43 | 43.32 | 19.05 | 43.85 |
| HMAC-SHA-256 | 2.65 | 3.98 | 5.04 | 5.04 |

Those CWT intervals recorded zero libcbor allocator calls; provider and Lua
allocations are accounted for separately. Reproduce with the recorded compiler,
fixture and controls when evaluating another change.
