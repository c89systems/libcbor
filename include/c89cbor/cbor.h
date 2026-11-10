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
  C89CBOR_IO = -5         /**< Adapter I/O failed; stream cannot be resumed. */
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
  c89cbor_state state;     /**< Private grammar state. */
  unsigned char header[9]; /**< Private partial scalar header. */
  size_t have;             /**< Private number of header bytes retained. */
  size_t need;             /**< Private required header length. */
} c89cbor_decoder;
/** Caller-owned encoder; initialize before use. Never copy an active context.
 */
typedef struct c89cbor_encoder {
  c89cbor_state state;       /**< Private grammar state. */
  unsigned char header[9];   /**< Private pending encoded header. */
  size_t offset;             /**< Private pending header offset. */
  size_t size;               /**< Private pending header size. */
  const unsigned char *data; /**< Private borrowed pending DATA. */
  size_t remaining;          /**< Private pending DATA length. */
} c89cbor_encoder;
/** Optional per-object allocator. Both functions required; context outlives
 * object. */
typedef struct c89cbor_allocator {
  void *context; /**< Passed unchanged to both callbacks. */
  void *(*alloc)(void *context,
                 size_t size); /**< Return aligned storage or NULL. */
  void (*free)(void *context,
               void *ptr); /**< Release a successful allocation. */
} c89cbor_allocator;
/** Static human-readable status text. Never allocated; never free. */
C89CBOR_API const char *c89cbor_status_string(int status);
/** Static library release version. Independent of wire formats and shared ABI.
 */
C89CBOR_API const char *c89cbor_version(void);
/** Initialize without allocation. frames == NULL selects embedded storage and
 * requires capacity == 0. Otherwise capacity must be positive. chunk == 0
 * selects 2 KiB. Caller frames outlive context and must not overlap it.
 */
C89CBOR_API int c89cbor_decoder_init(c89cbor_decoder *decoder,
                                     c89cbor_frame *frames, size_t capacity,
                                     size_t chunk);
/** Same storage contract as decoder_init. */
C89CBOR_API int c89cbor_encoder_init(c89cbor_encoder *encoder,
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
C89CBOR_API int c89cbor_decoder_create(const c89cbor_allocator *allocator,
                                       c89cbor_decoder **out);
/** Release a constructor-owned decoder only; NULL object is accepted. */
C89CBOR_API void c89cbor_decoder_destroy(c89cbor_decoder *decoder,
                                         const c89cbor_allocator *allocator);
/** Optional encoder constructor, with decoder_create's allocator contract. */
C89CBOR_API int c89cbor_encoder_create(const c89cbor_allocator *allocator,
                                       c89cbor_encoder **out);
/** Release a constructor-owned encoder only; NULL object is accepted. */
C89CBOR_API void c89cbor_encoder_destroy(c89cbor_encoder *encoder,
                                         const c89cbor_allocator *allocator);
/** Convert native binary64 to a FLOAT64 token. Nonfinite values are valid;
 * output is unchanged on incompatible native floating representation. */
C89CBOR_API int c89cbor_float64_set(c89cbor_token *token, double value);
/** Convert FLOAT64 raw bits to native binary64, with the same platform check.
 */
C89CBOR_API int c89cbor_float64_get(const c89cbor_token *token, double *value);
#ifdef __cplusplus
}
#endif
#endif
