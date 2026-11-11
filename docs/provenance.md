# Extraction provenance

The grammar stack, map-pair accounting, Unicode scalar validation and bounded
ASCII word-scan technique derive from `c89systems/cai`, `src/cai_cbor.c` and
`include/cai/cbor.h`, inspected at commit
`97b5f4f407967be6d53fbc9ebd5d558fdd596b69`. Original copyright is Michel Blomgren,
2026, MIT, retained in this project's LICENSE. The pull API, resumable output,
complete structural type coverage, native transfer and Lua interop are new here.

Cai's original profile is a strict subset: finite FLOAT64, no tags, no half/single
floats, undefined or general simple values. Its framing is length32 with a
128 KiB limit. Compatibility means identical bytes for the same representable
values and framing, not preserving cai API names or importing application types.

PJK/libcbor 0.14.0 is an optional benchmark-only upstream dependency, MIT:
https://github.com/PJK/libcbor/tree/v0.14.0 . It is not shipped in C SDKs or linked
into product code. Optional Lua builds use the public Lua 5.5.1 API and an
independently prepared upstream runtime for tests. Its source archive is pinned
in scripts/deps.sh to SHA-256
`1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`, from
[Lua.org](https://www.lua.org/download.html). Lua uses no cpkt facade library.

COSE uses OpenSSL 3.6.5 from the cpkt 0.7.0 SDK. Provider release archives and
all seven target SHA-256 pins are recorded in scripts/deps.sh. The product links
libcrypto's public EVP API, without copying OpenSSL code into this repository.
Consumers install the provider separately; its libraries are not bundled into
the libcbor shared SDK. Static consumers link the provider's static dependency
closure. See [COSE](cose.md) for protocol references and the declared algorithms.
