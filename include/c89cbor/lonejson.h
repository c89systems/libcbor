/** @file c89cbor/lonejson.h
 * Runtime receiver and required lonejson 0.49.0 integration.
 * Caller storage and constructor storage have distinct ownership. Methods and
 * exported twins share implementation. Native defaults can use a NULL runtime.
 */
#ifndef C89CBOR_LONEJSON_H
#define C89CBOR_LONEJSON_H
#include <c89cbor/io.h>
#include <lonejson.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Runtime construction policy. Initialize with c89cbor_default_config(). */
typedef struct c89cbor_config {
  c89cbor_allocator
      allocator; /**< Owns runtime and child shells; context borrowed. */
  lonejson
      *json; /**< Optional borrowed JSON runtime, otherwise created lazily. */
  size_t step_input;  /**< Input bytes per drive step; zero selects 2 KiB. */
  size_t step_output; /**< Output bytes per drive step; zero selects 2 KiB. */
  size_t step_events; /**< Converted events per step; zero selects 256. */
} c89cbor_config;
/** Root receiver. Initialize before use; preserve its address until cleanup.
 * Children borrow it. Cleanup returns BUSY until they have been cleaned up.
 * Configuration is fixed. Serialize factories and lifecycle on a shared root.
 */
struct c89cbor {
  int (*cleanup)(c89cbor *); /**< Release owned runtime resources. */
  int (*destroy)(c89cbor *); /**< Free a constructor-owned runtime. */
  int (*diagnostic)(const c89cbor *,
                    c89cbor_error *); /**< Copy the first error. */
  c89cbor_config (*default_config)(
      c89cbor *); /**< Return native configuration defaults. */
  c89cbor_allocator (*default_allocator)(
      c89cbor *);                    /**< Return malloc/free callbacks. */
  const char *(*version)(c89cbor *); /**< Static library version. */
  const char *(*status_string)(c89cbor *,
                               int); /**< Static status description. */
  int (*float64_set)(c89cbor *, c89cbor_token *,
                     double); /**< Construct a native float token. */
  int (*float64_get)(c89cbor *, const c89cbor_token *,
                     double *); /**< Read a native float token. */
  int (*length32)(c89cbor *, uint32_t, uint32_t,
                  unsigned char *); /**< Format a known length. */
  int (*encoder_init)(c89cbor *, c89cbor_encoder *, c89cbor_frame *, size_t,
                      size_t); /**< Initialize caller storage. */
  int (*decoder_init)(c89cbor *, c89cbor_decoder *, c89cbor_frame *, size_t,
                      size_t); /**< Initialize caller storage. */
  int (*encoder_create)(c89cbor *, const c89cbor_allocator *,
                        c89cbor_encoder **); /**< Allocate an encoder. */
  int (*decoder_create)(c89cbor *, const c89cbor_allocator *,
                        c89cbor_decoder **); /**< Allocate a decoder. */
  int (*reader_init)(c89cbor *, c89cbor_reader *, c89cbor_framing,
                     uint32_t); /**< Initialize framed reader storage. */
  int (*reader_create)(c89cbor *, c89cbor_framing, uint32_t,
                       c89cbor_reader **); /**< Allocate a reader. */
  int (*transfer_init)(c89cbor *, c89cbor_transfer *, const c89cbor_source *,
                       const c89cbor_sink *, c89cbor_framing,
                       uint32_t); /**< Initialize transfer storage. */
  int (*transfer_create)(c89cbor *, const c89cbor_source *,
                         const c89cbor_sink *, c89cbor_framing, uint32_t,
                         c89cbor_transfer **); /**< Allocate a transfer. */
  int (*fd_init)(c89cbor *, c89cbor_fd *, int, c89cbor_source *,
                 c89cbor_sink *); /**< Initialize a borrowed fd. */
  int (*fd_create)(c89cbor *, int,
                   c89cbor_fd **); /**< Allocate a borrowed fd. */
  c89cbor_lifetime lifetime;       /**< Private lifecycle state. */
  lonejson *json;     /**< Private borrowed or lazily owned JSON runtime. */
  int json_owned;     /**< Private ownership flag. */
  size_t step_input;  /**< Private configured input budget. */
  size_t step_output; /**< Private configured output budget. */
  size_t step_events; /**< Private configured event budget. */
};
/** Return default malloc/free allocation and lazy JSON runtime creation. */
C89CBOR_API c89cbor_config c89cbor_default_config(void);
/** Receiver twin of c89cbor_default_config; runtime may be NULL. */
C89CBOR_API c89cbor_config c89cbor_runtime_default_config(c89cbor *runtime);
/** Receiver twin of c89cbor_default_allocator; runtime may be NULL. */
C89CBOR_API c89cbor_allocator
c89cbor_runtime_default_allocator(c89cbor *runtime);
/** Initialize fresh caller-owned runtime storage. No JSON runtime is allocated.
 * NULL config selects defaults. Failure leaves cleanup-safe storage.
 */
C89CBOR_API int c89cbor_init(c89cbor *runtime, const c89cbor_config *config,
                             c89cbor_error *error);
/** Allocate a runtime using config's allocator. Clears *out before allocation.
 */
C89CBOR_API int c89cbor_create(const c89cbor_config *config, c89cbor **out,
                               c89cbor_error *error);
/** Release owned JSON state. Reject busy roots before changing ownership. */
C89CBOR_API int c89cbor_cleanup(c89cbor *runtime);
/** Free an allocated root through its recorded allocator; NULL succeeds. */
C89CBOR_API int c89cbor_destroy(c89cbor *runtime);
/** Copy retained runtime diagnostics without allocation. */
C89CBOR_API int c89cbor_diagnostic(const c89cbor *runtime,
                                   c89cbor_error *error);
#ifdef __cplusplus
}
#endif
#endif
