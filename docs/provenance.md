# Provenance

The grammar stack, map-pair accounting, Unicode scalar validation and bounded
ASCII word scan derive from `c89systems/cai`, `src/cai_cbor.c` and
`include/cai/cbor.h`, inspected at commit
`97b5f4f407967be6d53fbc9ebd5d558fdd596b69`. Michel Blomgren's 2026 MIT copyright
is retained in the project license. The pull API, resumable output, complete
structural type coverage, native transfer and Lua interop were developed here.
Cai's original profile uses finite FLOAT64 values and LENGTH32 framing with a
128 KiB limit; libcbor preserves its bytes for the same representable values.

Dependencies and archive SHA-256 pins are recorded in `scripts/deps.sh`:

- lonejson 0.50.0 supplies record mapping, JSON processing and native claim policy.
- cpkt 0.8.0 supplies OpenSSL 3.6.5; COSE calls the public libcrypto EVP API.
- Lua 5.5.1 supplies the public runtime API and the independently prepared test
  runtime. Its [Lua.org source](https://www.lua.org/ftp/lua-5.5.1.tar.gz) has SHA-256
  `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`.

Consumers install lonejson and the crypto provider separately. The SDK contains
libcbor's implementation, headers, metadata, documentation and license.

[PJK/libcbor 0.14.0](https://github.com/PJK/libcbor/tree/v0.14.0), MIT, is a
benchmark dependency pinned in `scripts/compare.sh`. Independent protocol peers
and their pinned sources are described in [hardening](hardening.md).
