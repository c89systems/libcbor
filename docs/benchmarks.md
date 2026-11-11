# Benchmarks

Run `make benchmark VERSION=0.1.0` for Release C encode/decode, native Lua pointer
transfer, Unix-stream/TCP/pipe bulk transfer and paced UDP/Unix-datagram records.
One warmup is discarded; five measured rounds remain. JSONL and source/build
context live under build/bench. No other build/test command is launched during
measurement. The shared host's unrelated workloads remain uncontrolled.

Run `make benchmark-compare VERSION=0.1.0` for PJK/libcbor 0.14.0's allocation-free
stateless decoder and header-plus-payload encoder using the same Bootlin compiler,
Release configuration, fixture and payload accounting. Each implementation has
its own executable, linked exclusively against its own library prefix. Symbol
checks reject accidental cross-linking. The reference source archive has a pinned
SHA-256 in compare.sh, with tests/examples/sanitizers disabled. It is never shipped.

The initial codec fixture is repeated definite 1024-byte strings. Decode measures
borrowed byte access, not payload memory bandwidth; consumers count spans. Encode
copies into the same bounded output and verifies content. Setup is excluded.
Our decoder validates structure and tracks complete items; the upstream low-level
decoder has no enclosing grammar state. Neither byte-string case validates UTF-8.
Results must preserve this distinction, rather than comparing our streaming path
against an upstream DOM/materialization API and attributing that cost to CBOR.

C-side Lua transfer generates 65536 independently encoded 1024-byte string items.
A single native call moves them through C source/sink pointers and a 2 KiB buffer.
The timed interval includes Lua chunk loading and the short wrapper call, but no
VM creation, module load or endpoint setup. The explicit token-processing API is
covered separately by tests; token traffic through Lua is an opt-in cost.
The sink verifies every byte in both the C and Lua runs. Reports include process
CPU time, native endpoint callback counts and source-copy bytes. Verification is
timed equally; the sink compares bytes without making another payload copy.

## Records and JSON

`profile_benchmark` measures direct mapped encode/decode, JSON conversion, and
an explicit JSON serialization/parsing control. Fixtures cover scalar-heavy
records, nested records, 72-byte ASCII/multibyte text and approximately 64 KiB
text. Integer fixtures include both signed and unsigned boundaries. All fields
are required. Native and PJK executables independently emit and consume the same
preferred CBOR fixtures, with an exact byte comparison in `interop-reference`.
That interop check covers this declared profile; it is not a certification of
every representation accepted by either library.

The PJK record profile builds a DOM from the same C record for encoding, or loads
a DOM and checks keys, duplicates, required fields and native ranges for decoding.
DOM construction and destruction are timed. The native profile opens, runs and
cleans one conversion per record, including metadata validation and workspace
allocation. Runtime/schema/fixture preparation is reported separately. Native
decoding resets its initialized destination as required by the public API.

The JSON control deliberately materializes one fixture's JSON document in a
fixed benchmark buffer. It measures the cost of that additional representation
boundary. Direct mapped operations use no JSON parser or writer. These are
in-memory fixtures with caller-selected C record and output storage. Generated
multi-megabyte streaming and delivery-before-EOF proofs live in the conversion
and mapped tests, independently of benchmark destination buffers.

`BENCH_REPETITIONS` defaults to 10000 small records per round. Large text cases
use one sixteenth as many records. `BENCH_CHUNK` selects the native input chunk
bound (zero uses the 2 KiB default). Setup and one warmup are excluded; five timed
rounds remain. A separate latency pass reports distributions of 16-record batch
means for small fixtures and individual operations for large text. The JSONL
records include the batch size and sample count, so batch means are not mistaken
for single-request tail latency.

Record profiles report wall/CPU time, operations per second, allocator call
counts and peak live user bytes observed through both configured allocators.
Allocator bookkeeping headers and upstream process metadata outside those hooks
are excluded. RSS is the process high-water mark, including fixtures and code.
Endpoint copy counts cover the harness's reads, writes and final record copies;
they do not count library-internal copies. A zero value therefore does not imply
that the complete path copies nothing. Timing includes instrumentation on both
implementations. Keep the individual JSONL rounds when assessing shared-host
variance.

Transport results verify every payload byte and finish the parser after stream
EOF. Streams cover a large definite item and an unknown-length indefinite item
generated as bounded 1024-byte chunks. Datagram cases use independent 512-byte
items, one outstanding at a time with fixture acknowledgments, and therefore
measure paced request/ack throughput, not unreliable maximum packet flooding.
Socket setup is excluded; scheduling/startup and endpoint completion remain in
the elapsed interval. Socket buffers are deliberately small to exercise pressure.
Transport CPU time sums sender and receiver process times. I/O and poll syscall
counts include retries but exclude setup, teardown and the separate measurement
pipe. Wire counts include both endpoints and fixture acknowledgments; each
transmitted byte is counted twice. Datagram latency quantiles cover the first
1024 request/ack exchanges, with their sample count reported.

These are reproducible workloads, not a universal fastest claim. Improve against
measured profiles, retaining differences in validation and representation.
Do not turn noisy shared-host throughput into a correctness threshold. Performance
objective: exceed established implementations on the declared workload with equal
semantics, without relaxing validation, streaming or memory bounds.
