/** @file c89cbor/lua.h
 * Optional Lua 5.5.1 facade. Resolve bridge symbols from the cbor module.
 * Typed native pointers cross without FFI. Push methods borrow storage and pin
 * owner_index (0 selects native lifetime). The owner must preserve storage
 * while borrowed. Open the module before pushing handles. Checks return NULL
 * for foreign or closed userdata and never raise Lua argument errors.
 */
#ifndef C89CBOR_LUA_H
#define C89CBOR_LUA_H
#include <c89cbor/lonejson.h>
#include <cpkt/lua.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Per-state native binding receiver. State and allocator context are borrowed.
 * Cleanup leaves Lua and all pushed handles alive with their independent pins.
 */
typedef struct c89cbor_lua c89cbor_lua;
struct c89cbor_lua {
  int (*push_options)(c89cbor_lua *, c89cbor_options *,
                      int); /**< Push borrowed conversion configuration. */
  c89cbor_options *(*check_options)(
      c89cbor_lua *, int); /**< Check conversion configuration. */
  int (*push_config)(c89cbor_lua *, c89cbor_config *,
                     int); /**< Push borrowed runtime configuration. */
  c89cbor_config *(*check_config)(c89cbor_lua *,
                                  int); /**< Check runtime configuration. */
  int (*push_runtime)(c89cbor_lua *, c89cbor *,
                      int); /**< Push borrowed runtime. */
  c89cbor *(*check_runtime)(c89cbor_lua *,
                            int); /**< Check live runtime or NULL. */
  int (*push_conversion)(c89cbor_lua *, c89cbor_conversion *,
                         int); /**< Push borrowed conversion. */
  c89cbor_conversion *(*check_conversion)(
      c89cbor_lua *, int); /**< Check live conversion or NULL. */
  int (*push_record_view)(c89cbor_lua *, lonejson_record_view *,
                          int); /**< Push borrowed record_view. */
  lonejson_record_view *(*check_record_view)(
      c89cbor_lua *, int); /**< Check live record_view or NULL. */
  int (*push_decoder)(c89cbor_lua *, c89cbor_decoder *,
                      int); /**< Push borrowed decoder. */
  c89cbor_decoder *(*check_decoder)(c89cbor_lua *,
                                    int); /**< Check live decoder or NULL. */
  int (*push_encoder)(c89cbor_lua *, c89cbor_encoder *,
                      int); /**< Push borrowed encoder. */
  c89cbor_encoder *(*check_encoder)(c89cbor_lua *,
                                    int); /**< Check live encoder or NULL. */
  int (*push_reader)(c89cbor_lua *, c89cbor_reader *,
                     int); /**< Push borrowed reader. */
  c89cbor_reader *(*check_reader)(c89cbor_lua *,
                                  int); /**< Check live reader or NULL. */
  int (*push_source)(c89cbor_lua *, c89cbor_source *,
                     int); /**< Push borrowed source. */
  c89cbor_source *(*check_source)(c89cbor_lua *,
                                  int); /**< Check live source or NULL. */
  int (*push_sink)(c89cbor_lua *, c89cbor_sink *,
                   int); /**< Push borrowed sink. */
  c89cbor_sink *(*check_sink)(c89cbor_lua *,
                              int); /**< Check live sink or NULL. */
  int (*push_transfer)(c89cbor_lua *, c89cbor_transfer *,
                       int); /**< Push borrowed transfer. */
  c89cbor_transfer *(*check_transfer)(c89cbor_lua *,
                                      int); /**< Check live transfer or NULL. */
  int (*push_fd)(c89cbor_lua *, c89cbor_fd *, int); /**< Push borrowed fd. */
  c89cbor_fd *(*check_fd)(c89cbor_lua *, int); /**< Check live fd or NULL. */
  int (*push_allocator)(c89cbor_lua *, c89cbor_allocator *,
                        int); /**< Push borrowed allocator. */
  c89cbor_allocator *(*check_allocator)(
      c89cbor_lua *, int); /**< Check live allocator or NULL. */
  int (*push_span)(c89cbor_lua *, const void *, size_t,
                   int); /**< Push borrowed bytes. */
  int (*check_span)(c89cbor_lua *, int, const void **,
                    size_t *);   /**< Check span. */
  int (*cleanup)(c89cbor_lua *); /**< Invalidate binding. */
  int (*destroy)(c89cbor_lua *); /**< Free allocated binding. */
  int (*diagnostic)(const c89cbor_lua *,
                    c89cbor_error *); /**< Copy diagnostic. */
  cpkt_lua_state *state;              /**< Private borrowed state. */
  c89cbor_allocator allocator;        /**< Private recorded allocator. */
  c89cbor_error error;                /**< Private retained diagnostic. */
  int active;                         /**< Private initialization flag. */
  int owned;                          /**< Private ownership flag. */
};
/** Standard Lua module opener; bootstrap exception to receiver parity. */
C89CBOR_API int luaopen_cbor(cpkt_lua_state *state);
/** Initialize fresh storage; NULL allocator selects defaults. State is
 * borrowed. */
C89CBOR_API int c89cbor_lua_init(c89cbor_lua *binding, cpkt_lua_state *state,
                                 const c89cbor_allocator *allocator,
                                 c89cbor_error *error);
/** Allocate binding; clear *out before allocation. State remains borrowed. */
C89CBOR_API int c89cbor_lua_create(cpkt_lua_state *state,
                                   const c89cbor_allocator *allocator,
                                   c89cbor_lua **out, c89cbor_error *error);
/** Idempotent cleanup; never closes Lua or external pointers. */
C89CBOR_API int c89cbor_lua_cleanup(c89cbor_lua *binding);
/** Free constructor-owned binding through recorded allocator; NULL succeeds. */
C89CBOR_API int c89cbor_lua_destroy(c89cbor_lua *binding);
/** Copy fixed diagnostic, including after cleanup. */
C89CBOR_API int c89cbor_lua_diagnostic(const c89cbor_lua *binding,
                                       c89cbor_error *error);
/** Push borrowed runtime; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_runtime(c89cbor_lua *binding, c89cbor *value,
                                         int owner_index);
/** Check live borrowed runtime or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor *c89cbor_lua_check_runtime(c89cbor_lua *binding, int index);
/** Push borrowed conversion; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_conversion(c89cbor_lua *binding,
                                            c89cbor_conversion *value,
                                            int owner_index);
/** Check live borrowed conversion or NULL. No Lua errors or ownership transfer.
 */
C89CBOR_API c89cbor_conversion *
c89cbor_lua_check_conversion(c89cbor_lua *binding, int index);
/** Snapshot the view descriptor and borrow its runtime, schema and record.
 * Pin owner_index until close/GC. Native storage must stay initialized and
 * unchanged while borrowed; no record copy or ownership transfer.
 */
C89CBOR_API int c89cbor_lua_push_record_view(c89cbor_lua *binding,
                                             lonejson_record_view *value,
                                             int owner_index);
/** Check live borrowed record_view or NULL. No Lua errors or ownership
 * transfer. */
C89CBOR_API lonejson_record_view *
c89cbor_lua_check_record_view(c89cbor_lua *binding, int index);
/** Push borrowed decoder; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_decoder(c89cbor_lua *binding,
                                         c89cbor_decoder *value,
                                         int owner_index);
/** Check live borrowed decoder or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_decoder *c89cbor_lua_check_decoder(c89cbor_lua *binding,
                                                       int index);
/** Push borrowed encoder; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_encoder(c89cbor_lua *binding,
                                         c89cbor_encoder *value,
                                         int owner_index);
/** Check live borrowed encoder or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_encoder *c89cbor_lua_check_encoder(c89cbor_lua *binding,
                                                       int index);
/** Push borrowed reader; pin owner_index until close/GC. No ownership transfer.
 * Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_reader(c89cbor_lua *binding,
                                        c89cbor_reader *value, int owner_index);
/** Check live borrowed reader or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_reader *c89cbor_lua_check_reader(c89cbor_lua *binding,
                                                     int index);
/** Push borrowed source; pin owner_index until close/GC. No ownership transfer.
 * Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_source(c89cbor_lua *binding,
                                        c89cbor_source *value, int owner_index);
/** Check live borrowed source or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_source *c89cbor_lua_check_source(c89cbor_lua *binding,
                                                     int index);
/** Push borrowed sink; pin owner_index until close/GC. No ownership transfer.
 * Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_sink(c89cbor_lua *binding, c89cbor_sink *value,
                                      int owner_index);
/** Check live borrowed sink or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_sink *c89cbor_lua_check_sink(c89cbor_lua *binding,
                                                 int index);
/** Push borrowed transfer; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_transfer(c89cbor_lua *binding,
                                          c89cbor_transfer *value,
                                          int owner_index);
/** Check live borrowed transfer or NULL. No Lua errors or ownership transfer.
 */
C89CBOR_API c89cbor_transfer *c89cbor_lua_check_transfer(c89cbor_lua *binding,
                                                         int index);
/** Push borrowed fd; pin owner_index until close/GC. No ownership transfer.
 * Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_fd(c89cbor_lua *binding, c89cbor_fd *value,
                                    int owner_index);
/** Check live borrowed fd or NULL. No Lua errors or ownership transfer. */
C89CBOR_API c89cbor_fd *c89cbor_lua_check_fd(c89cbor_lua *binding, int index);
/** Push borrowed allocator; pin owner_index until close/GC. No ownership
 * transfer. Native storage must stay initialized and stable while borrowed.
 */
C89CBOR_API int c89cbor_lua_push_allocator(c89cbor_lua *binding,
                                           c89cbor_allocator *value,
                                           int owner_index);
/** Check live borrowed allocator or NULL. No Lua errors or ownership transfer.
 */
C89CBOR_API c89cbor_allocator *c89cbor_lua_check_allocator(c89cbor_lua *binding,
                                                           int index);
/** Push borrowed bytes; NULL valid only for zero length. No data copy. */
C89CBOR_API int c89cbor_lua_push_span(c89cbor_lua *binding, const void *bytes,
                                      size_t length, int owner_index);
/** Check borrowed bytes; clear outputs before validation. */
C89CBOR_API int c89cbor_lua_check_span(c89cbor_lua *binding, int index,
                                       const void **bytes, size_t *length);
/** Push borrowed options, including native field sinks; pin the owner. */
C89CBOR_API int c89cbor_lua_push_options(c89cbor_lua *binding,
                                         c89cbor_options *value,
                                         int owner_index);
/** Check borrowed conversion options or return NULL. */
C89CBOR_API c89cbor_options *c89cbor_lua_check_options(c89cbor_lua *binding,
                                                       int index);
/** Push borrowed root configuration, pinning dependent owners through
 * owner_index. */
C89CBOR_API int c89cbor_lua_push_config(c89cbor_lua *binding,
                                        c89cbor_config *value, int owner_index);
/** Check borrowed root configuration or return NULL. */
C89CBOR_API c89cbor_config *c89cbor_lua_check_config(c89cbor_lua *binding,
                                                     int index);
#ifdef __cplusplus
}
#endif
#endif
