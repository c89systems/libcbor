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
into product code. cpkt 0.7.0 supplies the Lua 5.5.1 facade/runtime for optional
Lua builds; per-target published SDK SHA-256 pins are in scripts/deps.sh.
