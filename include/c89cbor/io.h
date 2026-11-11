/** @file c89cbor/io.h
 * Optional framing, native source/sink transfer, and POSIX descriptor adapters.
 * Transfer preserves encoded bytes, incrementally validates them, and uses one
 * fixed 2 KiB buffer. It never assembles an item, record, or logical stream.
 */
#ifndef C89CBOR_IO_H
#define C89CBOR_IO_H
#include <c89cbor/cbor.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Framing policy; no wire version marker or automatic negotiation. */
typedef enum c89cbor_framing {
  C89CBOR_SINGLE = 0, /**< Exactly one item, including for one UDP datagram. */
  C89CBOR_SEQUENCE =
      1, /**< RFC 8742 concatenation; unknown-length items allowed. */
  C89CBOR_LENGTH32 =
      2 /**< Big-endian 4-byte length then one item, cai-compatible. */
} c89cbor_framing;
/** Framing events; content is provisional until RECORD_END. */
typedef enum c89cbor_event_type {
  C89CBOR_RECORD_BEGIN =
      0, /**< Record begins; length known only in LENGTH32. */
  C89CBOR_RECORD_TOKEN = 1, /**< One borrowed token. */
  C89CBOR_RECORD_END = 2 /**< One validated record; not an admission receipt. */
} c89cbor_event_type;
/** Borrowed event returned by reader_next; never retain its DATA unpinned. */
typedef struct c89cbor_event {
  c89cbor_event_type type; /**< Event kind. */
  uint32_t length;     /**< Encoded payload size in LENGTH32; zero otherwise. */
  c89cbor_token token; /**< Initialized only for RECORD_TOKEN. */
} c89cbor_event;
/** Caller-owned framed reader; fields are private. */
typedef struct c89cbor_reader {
  int (*next)(struct c89cbor_reader *, const void *, size_t, size_t *,
              c89cbor_event *);           /**< Decode one framing event. */
  int (*finish)(struct c89cbor_reader *); /**< Validate record EOF. */
  int (*reset)(
      struct c89cbor_reader *); /**< Reuse a successfully finished reader. */
  int (*cleanup)(struct c89cbor_reader
                     *); /**< Release state, preserving caller storage. */
  int (*destroy)(
      struct c89cbor_reader *); /**< Free a constructor-owned shell. */
  int (*diagnostic)(const struct c89cbor_reader *,
                    c89cbor_error *); /**< Copy the first error. */
  c89cbor_lifetime lifetime;          /**< Private lifecycle storage. */
  c89cbor_decoder decoder;            /**< Private item decoder. */
  c89cbor_framing framing;            /**< Selected framing mode. */
  uint32_t limit;                     /**< Maximum LENGTH32 payload. */
  uint32_t length;                    /**< Current declared length. */
  uint32_t remaining;                 /**< Current remaining payload. */
  unsigned int have;                  /**< Partial prefix byte count. */
  int active;                         /**< Private record marker. */
  int complete; /**< Private single-item completion marker. */
  int failed;   /**< Sticky error. */
} c89cbor_reader;
/** Initialize framing. limit == 0 selects cai's 128 KiB record bound in
 * LENGTH32; it does not bound individual items in other modes. Core chunk and
 * nesting defaults apply; customize reader.decoder before the first next.
 */
C89CBOR_API int c89cbor_reader_init(c89cbor *runtime, c89cbor_reader *reader,
                                    c89cbor_framing framing, uint32_t limit);
/** Decode one framing event. TOKEN can consume zero bytes. INPUT requires more
 * input. Single-item DONE leaves extra bytes untouched; callers must reject
 * those bytes when exactly one item is required (not silently discard them).
 */
C89CBOR_API int c89cbor_reader_next(c89cbor_reader *reader, const void *input,
                                    size_t length, size_t *consumed,
                                    c89cbor_event *event);
/** Validate EOF. Empty sequences/framed streams are valid; empty SINGLE is not.
 * Drain zero-consumption events with next before calling finish. */
C89CBOR_API int c89cbor_reader_finish(c89cbor_reader *reader);
/** Write a known payload length as four big-endian bytes. Zero or over-limit
 * lengths fail without changing output; limit == 0 selects 128 KiB. The caller
 * produces exactly this many bytes, without a preliminary serialization pass.
 */
C89CBOR_API int c89cbor_length32(c89cbor *runtime, uint32_t length,
                                 uint32_t limit, unsigned char output[4]);
/** Read callback: OK with *count > 0 for progress, OK with zero for EOF,
 * INPUT with zero for would-block, or a negative terminal error. */
typedef int (*c89cbor_read_fn)(void *context, void *buffer, size_t capacity,
                               size_t *count);
/** Write callback: OK with positive *count, OUTPUT for would-block (partial
 * progress allowed), or a negative error. Never retain the borrowed bytes. */
typedef int (*c89cbor_write_fn)(void *context, const void *bytes, size_t length,
                                size_t *count);
/** Native input endpoint; caller owns context and all referenced storage. */
typedef struct c89cbor_source {
  void *context;        /**< Borrowed callback context. */
  c89cbor_read_fn read; /**< Required native callback. */
} c89cbor_source;
/** Native output endpoint, independently usable by typed application codecs. */
typedef struct c89cbor_sink {
  void *context;          /**< Borrowed callback context. */
  c89cbor_write_fn write; /**< Required native callback. */
} c89cbor_sink;
/** Caller-owned validated byte transfer. Fields are private except totals. */
typedef struct c89cbor_transfer {
  int (*step)(struct c89cbor_transfer *); /**< Advance one bounded I/O step. */
  int (*progress)(const struct c89cbor_transfer *,
                  c89cbor_progress *); /**< Copy totals. */
  int (*cleanup)(struct c89cbor_transfer
                     *); /**< Release state, preserving caller storage. */
  int (*destroy)(
      struct c89cbor_transfer *); /**< Free a constructor-owned shell. */
  int (*diagnostic)(const struct c89cbor_transfer *,
                    c89cbor_error *);  /**< Copy the first error. */
  c89cbor_lifetime lifetime;           /**< Private lifecycle storage. */
  c89cbor_reader reader;               /**< Private validator. */
  c89cbor_source source;               /**< Borrowed source copy. */
  c89cbor_sink sink;                   /**< Borrowed sink copy. */
  unsigned char buffer[C89CBOR_CHUNK]; /**< Bounded pending transport chunk. */
  size_t offset;                       /**< Private pending output offset. */
  size_t length;                       /**< Private pending output length. */
  size_t validation_offset; /**< Private validation position in buffer. */
  size_t input_budget;      /**< Private configured input budget. */
  size_t output_budget;     /**< Private configured output budget. */
  size_t event_budget;      /**< Private configured event budget. */
  int validated;            /**< Private output validation marker. */
  uint64_t read_bytes;      /**< Input bytes accepted so far. */
  uint64_t written_bytes;   /**< Output bytes delivered so far. */
  int finished;             /**< Private successful EOF marker. */
  int failed;               /**< Sticky terminal status. */
  int busy;                 /**< Private reentry guard. */
} c89cbor_transfer;
/** Initialize a native-to-native transfer without allocation. Endpoints and
 * their owners must outlive it. No Lua callback or token conversion is needed.
 * Output is provisional until DONE; errors may follow partial delivery.
 */
C89CBOR_API int c89cbor_transfer_init(c89cbor *runtime,
                                      c89cbor_transfer *transfer,
                                      const c89cbor_source *source,
                                      const c89cbor_sink *sink,
                                      c89cbor_framing framing, uint32_t limit);
/** Perform at most one 2 KiB read and one write. OK means progress, INPUT or
 * OUTPUT means wait for endpoint readiness, DONE means validated EOF. Counts
 * survive retries. Callback reentry is rejected. No busy-wait or worker thread.
 */
C89CBOR_API int c89cbor_transfer_step(c89cbor_transfer *transfer);
/** Borrowed POSIX descriptor. Never closed, reconfigured, or polled internally.
 * Stream sockets, files and pipes only; UDP requires datagram boundaries and
 * must be handled using reader SINGLE per datagram. Socket writes suppress
 * SIGPIPE where MSG_NOSIGNAL exists; pipe SIGPIPE policy belongs to the caller.
 */
typedef struct c89cbor_fd {
  int (*source)(struct c89cbor_fd *,
                c89cbor_source *); /**< Obtain a borrowed source view. */
  int (*sink)(struct c89cbor_fd *,
              c89cbor_sink *); /**< Obtain a borrowed sink view. */
  int (*cleanup)(
      struct c89cbor_fd *); /**< Release state, preserving caller storage. */
  int (*destroy)(struct c89cbor_fd *); /**< Free a constructor-owned shell. */
  int (*diagnostic)(const struct c89cbor_fd *,
                    c89cbor_error *); /**< Copy the first error. */
  c89cbor_lifetime lifetime;          /**< Private lifecycle storage. */
  int descriptor; /**< Open descriptor owned by the caller. */
} c89cbor_fd;
/** Initialize an fd and optional source/sink views; at least one view required.
 * Both views borrow fd, which must remain alive. No descriptor I/O on init. */
C89CBOR_API int c89cbor_fd_init(c89cbor *runtime, c89cbor_fd *fd,
                                int descriptor, c89cbor_source *source,
                                c89cbor_sink *sink);

/** Release initialized reader resources without freeing shell storage. */
C89CBOR_API int c89cbor_reader_cleanup(c89cbor_reader *value);
/** Free a constructor-owned reader; reject caller-owned storage. */
C89CBOR_API int c89cbor_reader_destroy(c89cbor_reader *value);
/** Copy the reader's first terminal diagnostic. */
C89CBOR_API int c89cbor_reader_diagnostic(const c89cbor_reader *value,
                                          c89cbor_error *error);

/** Release initialized transfer resources without freeing shell storage. */
C89CBOR_API int c89cbor_transfer_cleanup(c89cbor_transfer *value);
/** Free a constructor-owned transfer; reject caller-owned storage. */
C89CBOR_API int c89cbor_transfer_destroy(c89cbor_transfer *value);
/** Copy the transfer's first terminal diagnostic. */
C89CBOR_API int c89cbor_transfer_diagnostic(const c89cbor_transfer *value,
                                            c89cbor_error *error);

/** Release initialized fd resources without freeing shell storage. */
C89CBOR_API int c89cbor_fd_cleanup(c89cbor_fd *value);
/** Free a constructor-owned fd; reject caller-owned storage. */
C89CBOR_API int c89cbor_fd_destroy(c89cbor_fd *value);
/** Copy the fd's first terminal diagnostic. */
C89CBOR_API int c89cbor_fd_diagnostic(const c89cbor_fd *value,
                                      c89cbor_error *error);

/** Allocate a framed reader with the runtime's allocator, or native defaults.
 */
C89CBOR_API int c89cbor_reader_create(c89cbor *runtime, c89cbor_framing framing,
                                      uint32_t limit, c89cbor_reader **out);
/** Allocate a validated transfer borrowing both endpoints until cleanup. */
C89CBOR_API int c89cbor_transfer_create(c89cbor *runtime,
                                        const c89cbor_source *source,
                                        const c89cbor_sink *sink,
                                        c89cbor_framing framing, uint32_t limit,
                                        c89cbor_transfer **out);
/** Allocate an adapter that borrows descriptor and never closes it. */
C89CBOR_API int c89cbor_fd_create(c89cbor *runtime, int descriptor,
                                  c89cbor_fd **out);
/** Reset a successfully finished reader using its original framing and limit.
 */
C89CBOR_API int c89cbor_reader_reset(c89cbor_reader *reader);
/** Copy cumulative transfer input/output and completed record counts. */
C89CBOR_API int c89cbor_transfer_progress(const c89cbor_transfer *transfer,
                                          c89cbor_progress *progress);
/** Bind a source view to an initialized, live fd receiver. */
C89CBOR_API int c89cbor_fd_source(c89cbor_fd *fd, c89cbor_source *source);
/** Bind a sink view to an initialized, live fd receiver. */
C89CBOR_API int c89cbor_fd_sink(c89cbor_fd *fd, c89cbor_sink *sink);

/** One source-to-sink operation. Initialize or open through its runtime.
 * Endpoints and runtime are borrowed until cleanup. Step never polls or retries
 * a blocked endpoint internally. Cleanup cancels provisional work.
 */
typedef struct c89cbor_conversion {
  int (*step)(struct c89cbor_conversion *,
              c89cbor_error *); /**< Advance one bounded step. */
  int (*progress)(const struct c89cbor_conversion *,
                  c89cbor_progress *); /**< Copy cumulative totals. */
  int (*diagnostic)(const struct c89cbor_conversion *,
                    c89cbor_error *);          /**< Copy the retained error. */
  int (*cleanup)(struct c89cbor_conversion *); /**< Release operation state. */
  int (*destroy)(struct c89cbor_conversion *); /**< Free an allocated shell. */
  c89cbor_lifetime lifetime;                   /**< Private lifecycle state. */
  void *state; /**< Private bounded adapter state. */
} c89cbor_conversion;

#ifdef __cplusplus
}
#endif
#endif
