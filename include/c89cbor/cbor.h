/** @file c89cbor/cbor.h
 * Allocation-free incremental RFC 8949 codec. C89 syntax with POSIX stdint.h.
 * Contexts have one owner; separate contexts may run concurrently. No
 * callbacks, sockets, locale, global state, implicit allocation, or recursive
 * parsing.
 */
#ifndef C89CBOR_H
#define C89CBOR_H
#include <stddef.h>
#include <stdint.h>
#if defined(__GNUC__)
#define C89CBOR_API __attribute__((visibility("default")))
#else
#define C89CBOR_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
/** Default nesting capacity, including tags and string chunks. */
#define C89CBOR_DEPTH 32U
/** Default maximum borrowed DATA span and adapter I/O buffer size. */
#define C89CBOR_CHUNK 2048U
/** Operation result; positive values are resumable, negative values terminal.
 */
typedef enum c89cbor_status {
  C89CBOR_OK = 0,       /**< Operation succeeded. */
  C89CBOR_TOKEN = 1,    /**< One borrowed token is available. */
  C89CBOR_INPUT = 2,    /**< Supply more input; consumed bytes stay consumed. */
  C89CBOR_OUTPUT = 3,   /**< Drain output before submitting another token. */
  C89CBOR_DONE = 4,     /**< Exactly one complete item; reset for the next. */
  C89CBOR_INVALID = -1, /**< Invalid argument or operation order. */
  C89CBOR_MALFORMED = -2, /**< Invalid CBOR grammar, UTF-8, or truncation. */
  C89CBOR_LIMIT = -3,     /**< Configured nesting or framing limit exceeded. */
  C89CBOR_NOMEM = -4,     /**< Optional constructor allocation failed. */
  C89CBOR_BUSY = -6, /**< Handle has active callbacks or dependent borrows. */
  C89CBOR_UNSUPPORTED =
      -7,              /**< Value or endpoint has no supported conversion. */
  C89CBOR_SCHEMA = -8, /**< Mapped record violates its schema. */
  C89CBOR_IO = -5      /**< Adapter I/O failed; stream cannot be resumed. */
} c89cbor_status;
/** Token kinds. A TAG begins one child and has an END like other containers. */
typedef enum c89cbor_type {
  C89CBOR_UINT = 0,     /**< Unsigned integer; argument is the value. */
  C89CBOR_NEGATIVE = 1, /**< Mathematical value -1-argument, including 2^64. */
  C89CBOR_BYTES = 2, /**< Begin bytes; argument is length unless indefinite. */
  C89CBOR_TEXT = 3,  /**< Begin UTF-8 text; embedded NUL is valid. */
  C89CBOR_ARRAY = 4, /**< Begin array; argument is item count. */
  C89CBOR_MAP = 5,   /**< Begin map; argument is pair count, never doubled. */
  C89CBOR_TAG = 6,   /**< Begin uninterpreted tag; argument is tag number. */
  C89CBOR_BOOL = 7,  /**< Boolean; argument must be 0 or 1. */
  C89CBOR_NULL = 8,  /**< Null; argument must be zero. */
  C89CBOR_UNDEFINED = 9, /**< Undefined; argument must be zero. */
  C89CBOR_SIMPLE = 10,   /**< Simple value 0..19 or 32..255. */
  C89CBOR_FLOAT16 =
      11, /**< Raw IEEE binary16 bits in argument's low 16 bits. */
  C89CBOR_FLOAT32 =
      12, /**< Raw IEEE binary32 bits in argument's low 32 bits. */
  C89CBOR_FLOAT64 =
      13,            /**< Raw IEEE binary64 bits; all bit patterns accepted. */
  C89CBOR_DATA = 14, /**< Borrowed fragment of a definite bytes/text value. */
  C89CBOR_END = 15   /**< Close value; argument is the matching begin kind. */
} c89cbor_type;
/** Zero-initialize before constructing a token. Decoder tokens borrow input
 * until that input is reused; encoder DATA is borrowed until fully drained.
 * Every string/container/tag, including empty values, has an END token.
 * Indefinite strings contain definite chunks of their own type, with ENDs.
 * DATA fragmentation is independent of encoded indefinite-string boundaries.
 */
typedef struct c89cbor_token {
  c89cbor_type type; /**< Kind of this event. */
  uint64_t argument; /**< Value, raw float bits, length, tag, or END kind. */
  const void *data;  /**< Borrowed DATA bytes; NULL only for zero length. */
  size_t length;     /**< DATA byte count; zero for other kinds. */
  int indefinite;    /**< Nonzero only for indefinite strings/arrays/maps. */
} c89cbor_token;
/** Root receiver, defined by <c89cbor/lonejson.h>. */
typedef struct c89cbor c89cbor;
/** Optional per-object allocator. Both functions required; context outlives
 * object. */
typedef struct c89cbor_allocator {
  void *context; /**< Passed unchanged to both callbacks. */
  void *(*alloc)(void *context,
                 size_t size); /**< Return aligned storage or NULL. */
  void (*free)(void *context,
               void *ptr); /**< Release a successful allocation. */
} c89cbor_allocator;

/** Fixed diagnostic copied into caller storage; no allocation is required. */
typedef struct c89cbor_error {
  int status;       /**< libcbor status, zero on success. */
  int cause;        /**< Preserved dependency status when applicable. */
  int system_errno; /**< Endpoint errno when available. */
  uint64_t offset;  /**< Accepted input offset. */
  int shortened;    /**< Field path was shortened to fit path. */
  int truncated;  /**< A mapped overflow policy retained only a value prefix. */
  char layer[24]; /**< Failed codec or adapter layer. */
  char message[160]; /**< Human-readable error text. */
  char path[160];    /**< Mapped field path when available. */
} c89cbor_error;
/** Cumulative operation progress, available after completion or failure. */
typedef struct c89cbor_progress {
  uint64_t input;   /**< Accepted source bytes. */
  uint64_t output;  /**< Delivered sink bytes. */
  uint64_t records; /**< Successfully completed records. */
} c89cbor_progress;
/** Private lifecycle storage shared by receiver shells. Never edit fields. */
typedef struct c89cbor_lifetime {
  c89cbor *parent;             /**< Borrowed parent until cleanup. */
  c89cbor_allocator allocator; /**< Recorded allocator and borrowed context. */
  c89cbor_error error;         /**< First terminal diagnostic. */
  c89cbor_progress progress;   /**< Cumulative accepted bytes and records. */
  size_t dependents;           /**< Tracked child borrows. */
  unsigned int magic;          /**< Initialization marker. */
  int live;                    /**< Initialized resource state. */
  int owned;                   /**< Shell was allocated by its constructor. */
  int busy;                    /**< Callback reentry guard. */
} c89cbor_lifetime;

/** One caller-owned grammar frame. Fields are private implementation state. */
typedef struct c89cbor_frame {
  uint64_t remaining; /**< Private remaining byte/item/pair count. */
  uint32_t scalar;    /**< Private incremental Unicode scalar. */
  uint32_t minimum;   /**< Private shortest UTF-8 scalar threshold. */
  unsigned int utf8;  /**< Private UTF-8 continuation count. */
  unsigned int odd;   /**< Private map key/value parity. */
  int indefinite;     /**< Private indefinite marker. */
  c89cbor_type type;  /**< Private frame kind. */
} c89cbor_frame;
/** Shared grammar state. Fields are private; use init/reset functions. */
typedef struct c89cbor_state {
  c89cbor_frame *frames; /**< Borrowed caller storage, or local_frames. */
  size_t capacity;       /**< Frame capacity fixed at initialization. */
  size_t depth;          /**< Current private nesting depth. */
  size_t chunk;          /**< Maximum DATA span per next/read, never zero. */
  int complete;          /**< Private root completion marker. */
  int failed;            /**< Sticky negative status. */
  c89cbor_frame local_frames[C89CBOR_DEPTH]; /**< Default bounded storage. */
} c89cbor_state;
/** Caller-owned decoder; initialize before use. Never copy an active context.
 */
typedef struct c89cbor_decoder {
  int (*next_tag)(struct c89cbor_decoder *, const void *, size_t, size_t *,
                  uint64_t *); /**< Consume the next tag header. */
  int (*next)(struct c89cbor_decoder *, const void *, size_t, size_t *,
              c89cbor_token *); /**< Decode one borrowed event. */
  int (*finish)(
      struct c89cbor_decoder *); /**< Validate the final item at EOF. */
  int (*reset)(struct c89cbor_decoder
                   *); /**< Start another item after successful finish. */
  int (*cleanup)(struct c89cbor_decoder
                     *); /**< Release resources, preserving shell storage. */
  int (*destroy)(
      struct c89cbor_decoder *); /**< Free a constructor-owned shell. */
  int (*diagnostic)(const struct c89cbor_decoder *,
                    c89cbor_error *); /**< Copy the retained error. */
  c89cbor_lifetime lifetime;          /**< Private lifecycle storage. */
  c89cbor_state state;                /**< Private grammar state. */
  unsigned char header[9];            /**< Private partial scalar header. */
  size_t have; /**< Private number of header bytes retained. */
  size_t need; /**< Private required header length. */
} c89cbor_decoder;
/** Caller-owned encoder; initialize before use. Never copy an active context.
 */
typedef struct c89cbor_encoder {
  int (*tag)(struct c89cbor_encoder *,
             uint64_t);                     /**< Begin an application tag. */
  int (*end_tag)(struct c89cbor_encoder *); /**< End its completed payload. */
  int (*put)(struct c89cbor_encoder *,
             const c89cbor_token *); /**< Submit one token. */
  int (*read)(struct c89cbor_encoder *, void *, size_t,
              size_t *); /**< Copy bounded pending bytes. */
  int (*peek)(struct c89cbor_encoder *, const void **,
              size_t *); /**< Borrow validated pending output. */
  int (*advance)(struct c89cbor_encoder *,
                 size_t); /**< Accept bytes from the last peek. */
  int (*finish)(
      struct c89cbor_encoder *); /**< Require a complete, drained item. */
  int (*reset)(struct c89cbor_encoder
                   *); /**< Start another item after successful finish. */
  int (*cleanup)(struct c89cbor_encoder
                     *); /**< Release resources, preserving shell storage. */
  int (*destroy)(
      struct c89cbor_encoder *); /**< Free a constructor-owned shell. */
  int (*diagnostic)(const struct c89cbor_encoder *,
                    c89cbor_error *); /**< Copy the retained error. */
  c89cbor_lifetime lifetime;          /**< Private lifecycle storage. */
  c89cbor_state state;                /**< Private grammar state. */
  unsigned char header[9];            /**< Private pending encoded header. */
  size_t offset;                      /**< Private pending header offset. */
  size_t size;                        /**< Private pending header size. */
  const unsigned char *data;          /**< Private borrowed pending DATA. */
  size_t remaining;                   /**< Private pending DATA length. */
  size_t validated; /**< Private validated DATA prefix for peek/advance. */
} c89cbor_encoder;
/** Static human-readable status text. Never allocated; never free. */
C89CBOR_API const char *c89cbor_status_string(c89cbor *runtime, int status);
/** Static library release version. Independent of wire formats and shared ABI.
 */
C89CBOR_API const char *c89cbor_version(c89cbor *runtime);
/** Submit a tag begin using ordinary put acceptance and drain rules.
 * Emit exactly one child through put, then close it with end_tag. No registry
 * or tag interpretation is applied; the application validates its payload.
 */
C89CBOR_API int c89cbor_encoder_tag(c89cbor_encoder *encoder, uint64_t number);
/** Submit END(TAG); OUTPUT leaves the request unaccepted until output drains.
 */
C89CBOR_API int c89cbor_encoder_end_tag(c89cbor_encoder *encoder);
/** Decode the next event as a tag header. TOKEN writes its full 64-bit number.
 * INPUT preserves partial header state. Consume the child and END(TAG) with
 * ordinary next. A different event is a terminal SCHEMA error. All counts
 * remain valid on errors; outputs are cleared before argument validation.
 */
C89CBOR_API int c89cbor_decoder_next_tag(c89cbor_decoder *decoder,
                                         const void *input, size_t length,
                                         size_t *consumed, uint64_t *number);
/** Initialize without allocation. frames == NULL selects embedded storage and
 * requires capacity == 0. Otherwise capacity must be positive. chunk == 0
 * selects 2 KiB. Caller frames outlive context and must not overlap it.
 */
C89CBOR_API int c89cbor_decoder_init(c89cbor *runtime, c89cbor_decoder *decoder,
                                     c89cbor_frame *frames, size_t capacity,
                                     size_t chunk);
/** Same storage contract as decoder_init. */
C89CBOR_API int c89cbor_encoder_init(c89cbor *runtime, c89cbor_encoder *encoder,
                                     c89cbor_frame *frames, size_t capacity,
                                     size_t chunk);
/** Decode one event. Always sets consumed to bytes actually consumed, including
 * on failure. TOKEN may consume zero bytes (implicit END). INPUT means all
 * available input was consumed. DONE leaves following-item bytes untouched.
 * NULL input is valid only with length zero. Malformed/limit failures stick.
 * Tokens are provisional until finish succeeds; consumers must not commit an
 * incomplete request. Map duplicate keys and tag semantics belong to schemas.
 */
C89CBOR_API int c89cbor_decoder_next(c89cbor_decoder *decoder,
                                     const void *input, size_t length,
                                     size_t *consumed, c89cbor_token *token);
/** Assert complete input at EOF/record boundary. Rejects truncated items;
 * pending implicit END events must first be obtained with next(NULL,0,...).
 */
C89CBOR_API int c89cbor_decoder_finish(c89cbor_decoder *decoder);
/** Reuse storage after successful finish; unfinished/failed state is rejected.
 */
C89CBOR_API int c89cbor_decoder_reset(c89cbor_decoder *decoder);
/** Submit one token. OUTPUT means an earlier token still needs draining, and
 * this token was not accepted. Successful DATA submission borrows its bytes
 * until read has drained them. No sizing pass, spooling or message buffer.
 * Validation may fail after previous fragments have reached the consumer.
 */
C89CBOR_API int c89cbor_encoder_put(c89cbor_encoder *encoder,
                                    const c89cbor_token *token);
/** Drain pending bytes into caller output. Writes at most capacity and chunk;
 * OUTPUT means bytes remain, OK means drained. With capacity zero, output may
 * be NULL. Validation failures are sticky and written is still initialized.
 */
C89CBOR_API int c89cbor_encoder_read(c89cbor_encoder *encoder, void *output,
                                     size_t capacity, size_t *written);
/** Require one completed item and drained output; OUTPUT is resumable. */
C89CBOR_API int c89cbor_encoder_finish(c89cbor_encoder *encoder);
/** Reuse after successful finish, with the same storage and chunk bound. */
C89CBOR_API int c89cbor_encoder_reset(c89cbor_encoder *encoder);
/** Optional heap constructor. NULL allocator selects malloc/free. On failure
 * *out is NULL. Destroy with the same allocator; no allocation during parsing.
 */
C89CBOR_API int c89cbor_decoder_create(c89cbor *runtime,
                                       const c89cbor_allocator *allocator,
                                       c89cbor_decoder **out);
/** Release a constructor-owned decoder only; NULL object is accepted. */
C89CBOR_API int c89cbor_decoder_destroy(c89cbor_decoder *decoder);
/** Optional encoder constructor, with decoder_create's allocator contract. */
C89CBOR_API int c89cbor_encoder_create(c89cbor *runtime,
                                       const c89cbor_allocator *allocator,
                                       c89cbor_encoder **out);
/** Release a constructor-owned encoder only; NULL object is accepted. */
C89CBOR_API int c89cbor_encoder_destroy(c89cbor_encoder *encoder);
/** Convert native binary64 to a FLOAT64 token. Nonfinite values are valid;
 * output is unchanged on incompatible native floating representation. */
C89CBOR_API int c89cbor_float64_set(c89cbor *runtime, c89cbor_token *token,
                                    double value);
/** Convert FLOAT64 raw bits to native binary64, with the same platform check.
 */
C89CBOR_API int c89cbor_float64_get(c89cbor *runtime,
                                    const c89cbor_token *token, double *value);

/** Initialize a default allocator using malloc/free. Context is NULL. */
C89CBOR_API c89cbor_allocator c89cbor_default_allocator(void);
/** Borrow validated output until advance/read/cleanup. Repeated peeks return
 * the same suffix. OUTPUT means a nonempty span; OK means drained.
 * Both outputs are initialized even on failure. */
C89CBOR_API int c89cbor_encoder_peek(c89cbor_encoder *encoder,
                                     const void **bytes, size_t *length);
/** Consume up to the length returned by the current peek, without copying. */
C89CBOR_API int c89cbor_encoder_advance(c89cbor_encoder *encoder, size_t count);
/** Release decoder state. Idempotent after initialization; preserves storage.
 */
C89CBOR_API int c89cbor_decoder_cleanup(c89cbor_decoder *decoder);
/** Release encoder state. Idempotent after initialization; preserves storage.
 */
C89CBOR_API int c89cbor_encoder_cleanup(c89cbor_encoder *encoder);
/** Copy a decoder's first terminal error. Output is required. */
C89CBOR_API int c89cbor_decoder_diagnostic(const c89cbor_decoder *decoder,
                                           c89cbor_error *error);
/** Copy an encoder's first terminal error. Output is required. */
C89CBOR_API int c89cbor_encoder_diagnostic(const c89cbor_encoder *encoder,
                                           c89cbor_error *error);

#ifdef __cplusplus
}
#endif
#endif
