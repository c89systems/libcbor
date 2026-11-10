/** @file c89cbor/lua.h
 * Optional Lua 5.5.1 facade interop. Use cpkt::lua_facade_shared and resolve
 * bridge symbols from the loaded cbor module.
 * Functions accept typed native pointers, never FFI declarations. Push
 * functions borrow the pointer and pin owner_index (0 explicitly means
 * native-owned lifetime). Owners must not invalidate external native storage
 * while borrowed. Call luaopen_cbor once before pushing handles. Check
 * functions return NULL for wrong-type/closed handles and never raise Lua
 * errors. No ownership transfer.
 */
#ifndef C89CBOR_LUA_H
#define C89CBOR_LUA_H
#include <c89cbor/io.h>
#include <cpkt/lua.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Open module; pushes one Lua module table. Standard Lua module opener ABI. */
C89CBOR_API int luaopen_cbor(cpkt_lua_state *state);
/** Push a borrowed native decoder, pinning owner_index until close/GC. */
C89CBOR_API int c89cbor_lua_push_decoder(cpkt_lua_state *state,
                                         c89cbor_decoder *value,
                                         int owner_index);
/** Return borrowed decoder or NULL; do not destroy it from the borrower. */
C89CBOR_API c89cbor_decoder *c89cbor_lua_check_decoder(cpkt_lua_state *state,
                                                       int index);
/** Push a borrowed native encoder, pinning its owner. */
C89CBOR_API int c89cbor_lua_push_encoder(cpkt_lua_state *state,
                                         c89cbor_encoder *value,
                                         int owner_index);
/** Return borrowed encoder or NULL. */
C89CBOR_API c89cbor_encoder *c89cbor_lua_check_encoder(cpkt_lua_state *state,
                                                       int index);
/** Push a borrowed framed reader, pinning its owner. */
C89CBOR_API int c89cbor_lua_push_reader(cpkt_lua_state *state,
                                        c89cbor_reader *value, int owner_index);
/** Return borrowed reader or NULL. */
C89CBOR_API c89cbor_reader *c89cbor_lua_check_reader(cpkt_lua_state *state,
                                                     int index);
/** Push a native source; C transfer calls it without entering Lua. */
C89CBOR_API int c89cbor_lua_push_source(cpkt_lua_state *state,
                                        c89cbor_source *value, int owner_index);
/** Return borrowed source or NULL. */
C89CBOR_API c89cbor_source *c89cbor_lua_check_source(cpkt_lua_state *state,
                                                     int index);
/** Push a native sink; C transfer calls it without entering Lua. */
C89CBOR_API int c89cbor_lua_push_sink(cpkt_lua_state *state,
                                      c89cbor_sink *value, int owner_index);
/** Return borrowed sink or NULL. */
C89CBOR_API c89cbor_sink *c89cbor_lua_check_sink(cpkt_lua_state *state,
                                                 int index);
/** Push a borrowed transfer, pinning its owner. */
C89CBOR_API int c89cbor_lua_push_transfer(cpkt_lua_state *state,
                                          c89cbor_transfer *value,
                                          int owner_index);
/** Return borrowed transfer or NULL. */
C89CBOR_API c89cbor_transfer *c89cbor_lua_check_transfer(cpkt_lua_state *state,
                                                         int index);
/** Push a borrowed allocator; allocation callbacks always stay in C. */
C89CBOR_API int c89cbor_lua_push_allocator(cpkt_lua_state *state,
                                           c89cbor_allocator *value,
                                           int owner_index);
/** Return borrowed allocator or NULL. */
C89CBOR_API c89cbor_allocator *
c89cbor_lua_check_allocator(cpkt_lua_state *state, int index);
/** Push a borrowed byte span. NULL bytes is permitted only for length zero.
 * Pins owner_index. String conversion is explicit via span:string(). */
C89CBOR_API int c89cbor_lua_push_span(cpkt_lua_state *state, const void *bytes,
                                      size_t length, int owner_index);
/** Return borrowed bytes and length, or INVALID without modifying outputs. */
C89CBOR_API int c89cbor_lua_check_span(cpkt_lua_state *state, int index,
                                       const void **bytes, size_t *length);
#ifdef __cplusplus
}
#endif
#endif
