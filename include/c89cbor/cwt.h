/** @file c89cbor/cwt.h
 * Explicitly bounded CBOR Web Tokens with native lonejson claim policies.
 * Enable lonejson's jwt interface component when including this header.
 */
#ifndef C89CBOR_CWT_H
#define C89CBOR_CWT_H
#include <c89cbor/cose.h>
#include <lonejson.h>
#ifndef LONEJSON_WITH_JWT
#error "libcbor requires the lonejson jwt interface component"
#endif
#ifdef __cplusplus
extern "C" {
#endif
/** Borrowed claim view. Invalidated by the next mutation or cleanup. Native
 * NumericDate fields are rounded upward for integer-clock policy comparison;
 * encoded preserves the exact original values, including fractional dates. */
typedef struct c89cbor_cwt_view {
  const lonejson_jwt_claims
      *claims;           /**< Native claims; never clean/free them. */
  const void *encoded;   /**< Original claims map, including custom claims. */
  size_t encoded_length; /**< Bounded map length. */
  const void *cti;       /**< Binary token ID; NULL when absent. */
  size_t cti_length;     /**< ID length; an empty present ID is allowed. */
  size_t claim_count;    /**< Number of unique map entries. */
  int authenticated;     /**< Verified, policy-valid claims. Published views
                          * additionally passed admission; the admission callback is
                          * provisional. */
  int algorithm; /**< Authenticated COSE identifier, zero for local claims. */
} c89cbor_cwt_view;
/** Fixed receiver bounds and borrowed context. Zero sizes select defaults. */
typedef struct c89cbor_cwt_options {
  c89cbor_cose_options
      cose;         /**< Claims bound is record_bytes; context borrowed. */
  size_t claims;    /**< Maximum unique claims; default 64. */
  size_t audiences; /**< Maximum audience/scp entries each; default 32. */
  int require_cti;  /**< Require a nonempty token ID on verification. */
  int require_encryption; /**< Reject tokens without an outer encryption layer.
                           */
  int (*admit)(void *, const c89cbor_cwt_view *); /**< Optional policy-valid,
    authenticated token admission. Return OK to admit; any other result rejects.
    No claims are published until success. Replay storage belongs to the app. */
  void *context; /**< Borrowed admission callback context. */
} c89cbor_cwt_options;
/** Bounded token receiver. Keep its address stable. Methods are synchronous
 * memory operations; transport/would-block flow uses the COSE operation API.
 * Calls construct temporary COSE operations: serialize calls sharing a root or
 * key handle, as for COSE factories/lifecycle. Callback reentry returns BUSY.
 */
typedef struct c89cbor_cwt {
  int (*set_claims)(struct c89cbor_cwt *, const void *, size_t,
                    c89cbor_error *);
  /**< Copy and validate one local claims map; not remote authentication. */
  int (*set_lonejson)(struct c89cbor_cwt *, const lonejson_jwt_claims *,
                      const void *, size_t, c89cbor_error *);
  /**< Encode native claims directly as CBOR, with an optional binary ID. */
  int (*seal)(struct c89cbor_cwt *, c89cbor_cose_key *,
              c89cbor_cose_key *const *, size_t, void *, size_t, size_t *,
              c89cbor_error *);
  /**< Sign/MAC, optionally encrypt, then emit CWT tag 61. NULL encryption keys
   * selects plain Sign1/Mac0; cose.encrypt selects Encrypt versus Encrypt0. */
  int (*verify)(struct c89cbor_cwt *, const void *, size_t, c89cbor_cose_key *,
                c89cbor_cose_key *, const lonejson_jwt_claim_policy *,
                c89cbor_error *);
  /**< Authenticate a token, optionally decrypting one outer layer, then apply
   * native claim policy and admission. Failure removes previous claim views. */
  int (*view_get)(const struct c89cbor_cwt *, c89cbor_cwt_view *);
  /**< Copy a borrowed view; INPUT when no local or admitted claims exist. */
  int (*claim)(const struct c89cbor_cwt *, const c89cbor_token *, const void **,
               size_t *);
  /**< Find an encoded value by UINT/NEGATIVE argument or TEXT data/length.
   * INPUT means absent; outputs are cleared before checking arguments. */
  int (*diagnostic)(const struct c89cbor_cwt *, c89cbor_error *);
  /**< Copy the most recent mutation's failure. */
  int (*cleanup)(
      struct c89cbor_cwt *); /**< Idempotent; clear private buffers. */
  int (*destroy)(struct c89cbor_cwt *); /**< Free constructor storage only. */
  c89cbor_lifetime lifetime; /**< Private ownership and parent pin. */
  void *state; /**< Private bounded workspace and native claim storage. */
} c89cbor_cwt;
/** Default token policy: 2 KiB claims and headers, 64 claims, 32 audiences. */
C89CBOR_API c89cbor_cwt_options c89cbor_default_cwt_options(void);
/** Root receiver twin; no allocation. */
C89CBOR_API c89cbor_cwt_options c89cbor_runtime_default_cwt_options(c89cbor *);
/** Initialize fresh caller storage and fixed bounded workspace; no I/O. */
C89CBOR_API int c89cbor_cwt_init(c89cbor *, c89cbor_cwt *,
                                 const c89cbor_cwt_options *, c89cbor_error *);
/** Allocate a token receiver; clear *out before validation/allocation. */
C89CBOR_API int c89cbor_cwt_create(c89cbor *, const c89cbor_cwt_options *,
                                   c89cbor_cwt **, c89cbor_error *);
/** Receiver twin; copy local CBOR claims without JSON serialization. */
C89CBOR_API int c89cbor_cwt_set_claims(c89cbor_cwt *, const void *, size_t,
                                       c89cbor_error *);
/** Receiver twin; directly encode native JWT claims and optional binary ID. */
C89CBOR_API int c89cbor_cwt_set_lonejson(c89cbor_cwt *,
                                         const lonejson_jwt_claims *,
                                         const void *, size_t, c89cbor_error *);
/** Receiver twin; write a bounded token. *written is zero on failure. Output
 * must not alias receiver-owned spans. No partial token is published. */
C89CBOR_API int c89cbor_cwt_seal(c89cbor_cwt *, c89cbor_cose_key *,
                                 c89cbor_cose_key *const *, size_t, void *,
                                 size_t, size_t *, c89cbor_error *);
/** Receiver twin; accept Sign1/Mac0 or one encrypted layer enclosing them.
 * Policy algorithms are Ed25519, ES256 and HS256. Clocks are caller supplied.
 * Token input must not alias receiver-owned views, which mutation invalidates.
 */
C89CBOR_API int c89cbor_cwt_verify(c89cbor_cwt *, const void *, size_t,
                                   c89cbor_cose_key *, c89cbor_cose_key *,
                                   const lonejson_jwt_claim_policy *,
                                   c89cbor_error *);
/** Receiver twin; clear output before reading the current borrowed view. */
C89CBOR_API int c89cbor_cwt_view_get(const c89cbor_cwt *, c89cbor_cwt_view *);
/** Receiver twin; inspect one encoded custom/registered claim without copying.
 */
C89CBOR_API int c89cbor_cwt_claim(const c89cbor_cwt *, const c89cbor_token *,
                                  const void **, size_t *);
/** Receiver twin; copy the most recent mutation's diagnostic. */
C89CBOR_API int c89cbor_cwt_diagnostic(const c89cbor_cwt *, c89cbor_error *);
/** Receiver twin; cancellation/cleanup is safe on NULL. */
C89CBOR_API int c89cbor_cwt_cleanup(c89cbor_cwt *);
/** Receiver twin; reject freeing caller storage; NULL is safe. */
C89CBOR_API int c89cbor_cwt_destroy(c89cbor_cwt *);
#ifdef __cplusplus
}
#endif
#endif
