/** @file c89cbor/cose.h
 * Bounded authenticated COSE objects and ordered record streams. OpenSSL is a
 * private implementation dependency supplied by the cpkt SDK. All endpoints,
 * keys and option pointer fields are borrowed until conversion cleanup.
 */
#ifndef C89CBOR_COSE_H
#define C89CBOR_COSE_H
#include <c89cbor/io.h>
#ifdef __cplusplus
extern "C" {
#endif
struct c89cbor_cose_options;
/** Nonsecret authenticated stream metadata. No ID is returned before the first
 * successful record authentication. Applications own replay admission. */
typedef struct c89cbor_cose_stream_info {
  unsigned char stream_id[16]; /**< First authenticated stream identifier. */
  int encrypt;                 /**< True for Encrypt, false for Encrypt0. */
  int complete; /**< True only after successful final-record delivery/DONE. */
} c89cbor_cose_stream_info;
/** COSE operation receiver. Decryption retains read-ahead after DONE and next
 * starts another object/logical stream on the same source. Keep its address
 * stable; keys and endpoints stay pinned until cleanup. Its private conversion
 * shares only the generic drive/lifecycle machinery, not JSON behavior.
 */
typedef struct c89cbor_cose_operation {
  int (*step)(struct c89cbor_cose_operation *, c89cbor_error *);
  /**< Advance bounded work; DONE leaves following messages buffered. */
  int (*next)(struct c89cbor_cose_operation *, const c89cbor_sink *,
              const struct c89cbor_cose_options *, c89cbor_error *);
  /**< After successful decrypt DONE, keep the source and select the next
   * sink/AAD. */
  int (*progress)(const struct c89cbor_cose_operation *, c89cbor_progress *);
  /**< Copy cumulative I/O/record totals, including retained input read-ahead.
   */
  int (*stream_info)(const struct c89cbor_cose_operation *,
                     c89cbor_cose_stream_info *);
  /**< Read authenticated ID/family, including from a plaintext sink callback.
   * INPUT before authentication; UNSUPPORTED for standalone/sealing operations.
   */
  int (*diagnostic)(const struct c89cbor_cose_operation *, c89cbor_error *);
  /**< Copy the first terminal error. */
  int (*cleanup)(
      struct c89cbor_cose_operation *); /**< Cancel and release pins. */
  int (*destroy)(
      struct c89cbor_cose_operation *); /**< Free constructor storage. */
  int owned; /**< Private ownership flag for the complete COSE shell. */
  c89cbor_conversion conversion; /**< Private shared lifecycle and driver. */
} c89cbor_cose_operation;
/** Symmetric content/wrapping keys and X25519 recipient keys are 32 bytes. */
typedef enum c89cbor_cose_key_kind {
  C89CBOR_COSE_A256GCM = 0,       /**< AES-256-GCM content key only. */
  C89CBOR_COSE_A256KW = 1,        /**< AES-256 key-wrapping key only. */
  C89CBOR_COSE_X25519_PUBLIC = 2, /**< Trusted recipient public key. */
  C89CBOR_COSE_X25519_PRIVATE =
      3 /**< Recipient private key; public export allowed. */
} c89cbor_cose_key_kind;
/** Copied nonsecret metadata. The unused key_id suffix is zero. */
typedef struct c89cbor_cose_key_info {
  c89cbor_cose_key_kind kind; /**< Imported key family. */
  size_t key_id_length;       /**< Number of meaningful key_id bytes. */
  unsigned char key_id[64]; /**< Binary identifier; never a trust assertion. */
} c89cbor_cose_key_info;
/** Immutable imported key receiver. Active conversions pin it. Private bytes
 * are copied on import and cleared on cleanup; OpenSSL owns its native objects.
 * Keep shell addresses stable. Shared execution is allowed; factories/lifecycle
 * are serialized by the caller. Crypto backend allocations are separate from
 * the configured libcbor allocator.
 */
typedef struct c89cbor_cose_key {
  int (*metadata)(const struct c89cbor_cose_key *, c89cbor_cose_key_info *);
  /**< Copy nonsecret metadata; initialize output before validation. */
  int (*public_key)(const struct c89cbor_cose_key *, void *, size_t, size_t *);
  /**< Copy 32 X25519 public bytes; symmetric keys return UNSUPPORTED. */
  int (*diagnostic)(const struct c89cbor_cose_key *, c89cbor_error *);
  /**< Copy the first retained failure without allocating. */
  int (*cleanup)(
      struct c89cbor_cose_key *); /**< Idempotent; BUSY while borrowed. */
  int (*destroy)(
      struct c89cbor_cose_key *); /**< Free constructor storage only. */
  c89cbor_lifetime lifetime; /**< Private lifecycle and recorded allocator. */
  void *state; /**< Private owned key and synchronized usage state. */
} c89cbor_cose_key;
/** COSE limits and borrowed authenticated context. Initialize through defaults.
 * Zero size limits select defaults. Nonces are 12 bytes and stream IDs 16.
 * Explicit Encrypt0 nonces require caller-guaranteed uniqueness across every
 * use of the key. Stream sealing rejects a fixed nonce. Imported key usage is
 * capped at 2^24 Encrypt0 objects per handle; applications account across
 * handles.
 */
typedef struct c89cbor_cose_options {
  const void *aad; /**< External application AAD; NULL only for zero length. */
  size_t aad_length; /**< Default maximum 2 KiB, fixed by header_bytes. */
  const unsigned char *nonce;     /**< Optional explicit standalone nonce. */
  const unsigned char *stream_id; /**< Optional sender/expected receiver ID. */
  size_t record_bytes; /**< Maximum plaintext per object; default 2 KiB. */
  size_t header_bytes; /**< Encoded metadata and separate application AAD caps;
                        * default 2 KiB each. */
  size_t recipients; /**< Maximum recipient count; default eight, at most 32. */
  size_t step_input; /**< New input per step; zero selects runtime defaults. */
  size_t step_output; /**< Delivered output per step; zero selects defaults. */
  size_t step_events; /**< Converted records/events per step; zero selects
                         defaults. */
  int encrypt; /**< Stream seal uses Encrypt when true, Encrypt0 when false. */
} c89cbor_cose_options;
/** Receiver twin; advance bounded work without polling blocked endpoints. */
C89CBOR_API int c89cbor_cose_operation_step(c89cbor_cose_operation *,
                                            c89cbor_error *);
/** Start the next object/stream after decrypt DONE, retaining read-ahead and
 * cumulative progress. NULL sink keeps the old sink. NULL options keep bounds
 * and AAD, but clear an expected stream ID. Supplied workspace limits must
 * match construction. Failed/sealing operations require cleanup and
 * reconstruction.
 */
C89CBOR_API int c89cbor_cose_operation_next(c89cbor_cose_operation *,
                                            const c89cbor_sink *,
                                            const c89cbor_cose_options *,
                                            c89cbor_error *);
/** Copy cumulative accepted/delivered bytes and authenticated records. */
C89CBOR_API int c89cbor_cose_operation_progress(const c89cbor_cose_operation *,
                                                c89cbor_progress *);
/** Clear output, then copy authenticated stream metadata. Read-only and safe
 * from the operation's sink callback for replay admission before delivery.
 * INPUT returns no metadata before the first verified record; standalone and
 * sealing operations return UNSUPPORTED. Valid after DONE, including an empty
 * stream, until cleanup or next. Failure preserves previously authenticated ID.
 */
C89CBOR_API int
c89cbor_cose_operation_stream_info(const c89cbor_cose_operation *,
                                   c89cbor_cose_stream_info *);
/** Copy the first retained error; independent of upstream stack storage. */
C89CBOR_API int
c89cbor_cose_operation_diagnostic(const c89cbor_cose_operation *,
                                  c89cbor_error *);
/** Idempotent cancellation; release workspace and key pins, preserving shell.
 */
C89CBOR_API int c89cbor_cose_operation_cleanup(c89cbor_cose_operation *);
/** Destroy allocating constructor storage; reject caller storage. NULL is safe.
 */
C89CBOR_API int c89cbor_cose_operation_destroy(c89cbor_cose_operation *);
/** Prepare zero/default bounds without constructing a runtime. */
C89CBOR_API c89cbor_cose_options c89cbor_default_cose_options(void);
/** Matching root receiver utility; no allocation. */
C89CBOR_API c89cbor_cose_options
c89cbor_runtime_default_cose_options(c89cbor *);
/** Import exactly 32 key bytes and copy at most 64 identifier bytes into fresh
 * caller-owned storage. NULL runtime selects native allocator defaults. No I/O.
 * Failure leaves a cleanup-safe shell. Key material is never logged.
 */
C89CBOR_API int c89cbor_cose_key_init(c89cbor *, c89cbor_cose_key *,
                                      c89cbor_cose_key_kind, const void *,
                                      size_t, const void *, size_t,
                                      c89cbor_error *);
/** Allocating import; initialize *out to NULL before validation or allocation.
 */
C89CBOR_API int c89cbor_cose_key_create(c89cbor *, c89cbor_cose_key_kind,
                                        const void *, size_t, const void *,
                                        size_t, c89cbor_cose_key **,
                                        c89cbor_error *);
/** Receiver twin; copy metadata without exposing secret bytes. */
C89CBOR_API int c89cbor_cose_key_metadata(const c89cbor_cose_key *,
                                          c89cbor_cose_key_info *);
/** Receiver twin; clear *written, then copy a public key into caller storage.
 */
C89CBOR_API int c89cbor_cose_key_public_key(const c89cbor_cose_key *, void *,
                                            size_t, size_t *);
/** Receiver twin; copy the retained failure. */
C89CBOR_API int c89cbor_cose_key_diagnostic(const c89cbor_cose_key *,
                                            c89cbor_error *);
/** Receiver twin; clear private material and release resources. NULL is safe.
 */
C89CBOR_API int c89cbor_cose_key_cleanup(c89cbor_cose_key *);
/** Receiver twin; reject caller storage without freeing it. NULL is safe. */
C89CBOR_API int c89cbor_cose_key_destroy(c89cbor_cose_key *);

/** Seal a bounded standalone Encrypt0 object through blocking endpoints. */
C89CBOR_API int c89cbor_cose_encrypt0(c89cbor *, const c89cbor_source *,
                                      const c89cbor_sink *, c89cbor_cose_key *,
                                      const c89cbor_cose_options *,
                                      c89cbor_error *);
/** Open a resumable Encrypt0 conversion without endpoint I/O; clear *out. */
C89CBOR_API int c89cbor_cose_encrypt0_open(
    c89cbor *, const c89cbor_source *, const c89cbor_sink *, c89cbor_cose_key *,
    const c89cbor_cose_options *, c89cbor_cose_operation **, c89cbor_error *);
/** Initialize fresh caller conversion storage; borrow key and endpoints. */
C89CBOR_API int c89cbor_cose_encrypt0_init(c89cbor *, c89cbor_cose_operation *,
                                           const c89cbor_source *,
                                           const c89cbor_sink *,
                                           c89cbor_cose_key *,
                                           const c89cbor_cose_options *,
                                           c89cbor_error *);
/** Seal an Encrypt object for symmetric wrapping or public X25519 recipients.
 */
C89CBOR_API int c89cbor_cose_encrypt(c89cbor *, const c89cbor_source *,
                                     const c89cbor_sink *,
                                     c89cbor_cose_key *const *, size_t,
                                     const c89cbor_cose_options *,
                                     c89cbor_error *);
/** Allocate Encrypt state, snapshot recipient pointers and pin their keys. */
C89CBOR_API int c89cbor_cose_encrypt_open(c89cbor *, const c89cbor_source *,
                                          const c89cbor_sink *,
                                          c89cbor_cose_key *const *, size_t,
                                          const c89cbor_cose_options *,
                                          c89cbor_cose_operation **,
                                          c89cbor_error *);
/** Initialize fresh Encrypt conversion storage without endpoint callbacks. */
C89CBOR_API int c89cbor_cose_encrypt_init(c89cbor *, c89cbor_cose_operation *,
                                          const c89cbor_source *,
                                          const c89cbor_sink *,
                                          c89cbor_cose_key *const *, size_t,
                                          const c89cbor_cose_options *,
                                          c89cbor_error *);
/** Open either standalone family with an explicit symmetric/private key.
 * No plaintext is delivered until authentication succeeds. This blocking
 * convenience requires a message-scoped source and checks trailing bytes/EOF.
 * Init/open receivers complete at the object boundary and retain read-ahead.
 */
C89CBOR_API int c89cbor_cose_decrypt(c89cbor *, const c89cbor_source *,
                                     const c89cbor_sink *, c89cbor_cose_key *,
                                     const c89cbor_cose_options *,
                                     c89cbor_error *);
/** Allocate a resumable bounded decrypt operation; clear *out before opening.
 */
C89CBOR_API int c89cbor_cose_decrypt_open(
    c89cbor *, const c89cbor_source *, const c89cbor_sink *, c89cbor_cose_key *,
    const c89cbor_cose_options *, c89cbor_cose_operation **, c89cbor_error *);
/** Initialize caller decrypt shell; snapshot bounds and borrow context. */
C89CBOR_API int c89cbor_cose_decrypt_init(c89cbor *, c89cbor_cose_operation *,
                                          const c89cbor_source *,
                                          const c89cbor_sink *,
                                          c89cbor_cose_key *,
                                          const c89cbor_cose_options *,
                                          c89cbor_error *);
/** Seal an unbounded source as ordered bounded authenticated COSE records.
 * options.encrypt selects Encrypt; otherwise exactly one symmetric key is used.
 */
C89CBOR_API int c89cbor_cose_encrypt_stream(c89cbor *, const c89cbor_source *,
                                            const c89cbor_sink *,
                                            c89cbor_cose_key *const *, size_t,
                                            const c89cbor_cose_options *,
                                            c89cbor_error *);
/** Allocate ordered stream-sealing state without invoking endpoints. */
C89CBOR_API int c89cbor_cose_encrypt_stream_open(
    c89cbor *, const c89cbor_source *, const c89cbor_sink *,
    c89cbor_cose_key *const *, size_t, const c89cbor_cose_options *,
    c89cbor_cose_operation **, c89cbor_error *);
/** Initialize caller stream-sealing shell with bounded record workspace. */
C89CBOR_API int
c89cbor_cose_encrypt_stream_init(c89cbor *, c89cbor_cose_operation *,
                                 const c89cbor_source *, const c89cbor_sink *,
                                 c89cbor_cose_key *const *, size_t,
                                 const c89cbor_cose_options *, c89cbor_error *);
/** Open an ordered stream; release only authenticated records. Completion
 * requires an authenticated final marker. The blocking convenience additionally
 * checks scoped-source EOF. A later truncation does not
 * revoke earlier authenticated records already delivered to the caller.
 */
C89CBOR_API int c89cbor_cose_decrypt_stream(c89cbor *, const c89cbor_source *,
                                            const c89cbor_sink *,
                                            c89cbor_cose_key *,
                                            const c89cbor_cose_options *,
                                            c89cbor_error *);
/** Allocate bounded ordered-stream receiver state; clear *out on every error.
 */
C89CBOR_API int c89cbor_cose_decrypt_stream_open(
    c89cbor *, const c89cbor_source *, const c89cbor_sink *, c89cbor_cose_key *,
    const c89cbor_cose_options *, c89cbor_cose_operation **, c89cbor_error *);
/** Initialize a caller-owned ordered-stream receiver shell; no endpoint I/O. */
C89CBOR_API int
c89cbor_cose_decrypt_stream_init(c89cbor *, c89cbor_cose_operation *,
                                 const c89cbor_source *, const c89cbor_sink *,
                                 c89cbor_cose_key *,
                                 const c89cbor_cose_options *, c89cbor_error *);
#ifdef __cplusplus
}
#endif
#endif
