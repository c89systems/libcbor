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

Transport results verify every payload byte. Streams carry one large definite
item and small bounded producer chunks. Datagram cases use independent 512-byte
items, one outstanding at a time with fixture acknowledgments, and therefore
measure paced request/ack throughput, not unreliable maximum packet flooding.
Socket setup is excluded; scheduling/startup and endpoint completion remain in
the elapsed interval. Socket buffers are deliberately small to exercise pressure.

These are initial reproducible workloads, not a universal fastest claim. Improve
against measured profiles; expand workloads to scalar-heavy schemas, nesting,
ASCII/multibyte text, unknown-length production, more message/chunk sizes, latency
percentiles, syscall/CPU/allocation accounting and Lua token opt-in as needed.
Do not turn noisy shared-host throughput into a correctness threshold. Performance
objective: exceed established implementations on the declared workload with equal
semantics, without relaxing validation, streaming or memory bounds.
