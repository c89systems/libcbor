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
  void *context; /**< Borrowed admission context; synchronize it if shared
                  * across workers. */
} c89cbor_cwt_options;
/** Bounded token receiver. Keep its address stable. Methods are synchronous
 * memory operations; transport/would-block flow uses the COSE operation API.
 * Bind keys once before use. Independent prepared receivers can execute with
 * shared immutable keys; setup/rebinding/lifecycle are serialized. No libcbor
 * allocations occur per token. Provider allocations remain separate.
 */
typedef struct c89cbor_cwt {
  int (*set_claims)(struct c89cbor_cwt *, const void *, size_t,
                    c89cbor_error *);
  /**< Copy and validate one local claims map; not remote authentication. */
  int (*set_lonejson)(struct c89cbor_cwt *, const lonejson_jwt_claims *,
                      const void *, size_t, c89cbor_error *);
  /**< Encode native claims directly as CBOR, with an optional binary ID. */
  int (*set_seal_keys)(struct c89cbor_cwt *, c89cbor_cose_key *,
                       c89cbor_cose_key *const *, size_t, c89cbor_error *);
  /**< Snapshot/pin a signing/MAC key and optional encryption recipients. NULL
   * signing key and empty recipient list unbind. Success clears prior trust. */
  int (*set_verify_keys)(struct c89cbor_cwt *, c89cbor_cose_key *,
                         c89cbor_cose_key *, c89cbor_error *);
  /**< Pin a trusted verification key and optional decryption key. NULL/NULL
   * unbinds. Failed replacement preserves the previous binding. */
  int (*seal)(struct c89cbor_cwt *, void *, size_t, size_t *, c89cbor_error *);
  /**< Sign/MAC and optionally encrypt with the prepared key policy. */
  int (*verify)(struct c89cbor_cwt *, const void *, size_t,
                const lonejson_jwt_claim_policy *, c89cbor_error *);
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
C89CBOR_API int c89cbor_cwt_seal(c89cbor_cwt *, void *, size_t, size_t *,
                                 c89cbor_error *);
/** Receiver twin; prepare signing and optional Encrypt0/Encrypt recipients.
 * Bound handles are pinned until successful replacement or cleanup. */
C89CBOR_API int c89cbor_cwt_set_seal_keys(c89cbor_cwt *, c89cbor_cose_key *,
                                          c89cbor_cose_key *const *, size_t,
                                          c89cbor_error *);
/** Receiver twin; prepare trusted verification and optional decryption keys.
 * Serialize setup; binding does not perform cryptographic I/O. */
C89CBOR_API int c89cbor_cwt_set_verify_keys(c89cbor_cwt *, c89cbor_cose_key *,
                                            c89cbor_cose_key *,
                                            c89cbor_error *);
/** Receiver twin; accept Sign1/Mac0 or one encrypted layer enclosing them.
 * Policy algorithms are Ed25519, ES256 and HS256. Clocks are caller supplied.
 * Token input must not alias receiver-owned views, which mutation invalidates.
 */
C89CBOR_API int c89cbor_cwt_verify(c89cbor_cwt *, const void *, size_t,
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
