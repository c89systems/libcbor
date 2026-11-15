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
  /** Exactly one item, including for one UDP datagram. */
  C89CBOR_SINGLE = 0,
  /** RFC 8742 concatenation; unknown-length items allowed. */
  C89CBOR_SEQUENCE = 1,
  /** Big-endian 4-byte length then one item, cai-compatible. */
  C89CBOR_LENGTH32 = 2
} c89cbor_framing;
/** Framing events; content is provisional until RECORD_END. */
typedef enum c89cbor_event_type {
  /** Record begins; length known only in LENGTH32. */
  C89CBOR_RECORD_BEGIN = 0,
  /** One borrowed token. */
  C89CBOR_RECORD_TOKEN = 1,
  /** One validated record; not an admission receipt. */
  C89CBOR_RECORD_END = 2
} c89cbor_event_type;
/** Borrowed event returned by reader_next; never retain its DATA unpinned. */
typedef struct c89cbor_event {
  /** Event kind. */
  c89cbor_event_type type;
  /** Encoded payload size in LENGTH32; zero otherwise. */
  uint32_t length;
  /** Initialized only for RECORD_TOKEN. */
  c89cbor_token token;
} c89cbor_event;
/** Caller-owned framed reader; fields are private. */
typedef struct c89cbor_reader {
  /** Decode one framing event. */
  int (*next)(struct c89cbor_reader *, const void *, size_t, size_t *,
              c89cbor_event *);
  /** Validate record EOF. */
  int (*finish)(struct c89cbor_reader *);
  /** Reuse a successfully finished reader. */
  int (*reset)(struct c89cbor_reader *);
  /** Release state, preserving caller storage. */
  int (*cleanup)(struct c89cbor_reader *);
  /** Free a constructor-owned shell. */
  int (*destroy)(struct c89cbor_reader *);
  /** Copy the first error. */
  int (*diagnostic)(const struct c89cbor_reader *, c89cbor_error *);
  /** Private lifecycle storage. */
  c89cbor_lifetime lifetime;
  /** Private item decoder. */
  c89cbor_decoder decoder;
  /** Selected framing mode. */
  c89cbor_framing framing;
  /** Maximum LENGTH32 payload. */
  uint32_t limit;
  /** Current declared length. */
  uint32_t length;
  /** Current remaining payload. */
  uint32_t remaining;
  /** Partial prefix byte count. */
  unsigned int have;
  /** Private record marker. */
  int active;
  /** Private single-item completion marker. */
  int complete;
  /** Sticky error. */
  int failed;
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
  /** Borrowed callback context. */
  void *context;
  /** Required native callback. */
  c89cbor_read_fn read;
} c89cbor_source;
/** Native output endpoint, independently usable by typed application codecs. */
typedef struct c89cbor_sink {
  /** Borrowed callback context. */
  void *context;
  /** Required native callback. */
  c89cbor_write_fn write;
} c89cbor_sink;
/** Caller-owned validated byte transfer. Fields are private except totals. */
typedef struct c89cbor_transfer {
  /** Advance one bounded I/O step. */
  int (*step)(struct c89cbor_transfer *);
  /** Copy totals. */
  int (*progress)(const struct c89cbor_transfer *, c89cbor_progress *);
  /** Release state, preserving caller storage. */
  int (*cleanup)(struct c89cbor_transfer *);
  /** Free a constructor-owned shell. */
  int (*destroy)(struct c89cbor_transfer *);
  /** Copy the first error. */
  int (*diagnostic)(const struct c89cbor_transfer *, c89cbor_error *);
  /** Private lifecycle storage. */
  c89cbor_lifetime lifetime;
  /** Private validator. */
  c89cbor_reader reader;
  /** Borrowed source copy. */
  c89cbor_source source;
  /** Borrowed sink copy. */
  c89cbor_sink sink;
  /** Bounded pending transport chunk. */
  unsigned char buffer[C89CBOR_CHUNK];
  /** Private pending output offset. */
  size_t offset;
  /** Private pending output length. */
  size_t length;
  /** Private validation position in buffer. */
  size_t validation_offset;
  /** Private configured input budget. */
  size_t input_budget;
  /** Private configured output budget. */
  size_t output_budget;
  /** Private configured event budget. */
  size_t event_budget;
  /** Private output validation marker. */
  int validated;
  /** Input bytes accepted so far. */
  uint64_t read_bytes;
  /** Output bytes delivered so far. */
  uint64_t written_bytes;
  /** Private successful EOF marker. */
  int finished;
  /** Sticky terminal status. */
  int failed;
  /** Private reentry guard. */
  int busy;
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
  /** Obtain a borrowed source view. */
  int (*source)(struct c89cbor_fd *, c89cbor_source *);
  /** Obtain a borrowed sink view. */
  int (*sink)(struct c89cbor_fd *, c89cbor_sink *);
  /** Release state, preserving caller storage. */
  int (*cleanup)(struct c89cbor_fd *);
  /** Free a constructor-owned shell. */
  int (*destroy)(struct c89cbor_fd *);
  /** Copy the first error. */
  int (*diagnostic)(const struct c89cbor_fd *, c89cbor_error *);
  /** Private lifecycle storage. */
  c89cbor_lifetime lifetime;
  /** Open descriptor owned by the caller. */
  int descriptor;
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
 * Step/cleanup reentry from allocator callbacks during construction returns
 * BUSY, just as it does during an active step.
 */
typedef struct c89cbor_conversion {
  /** Advance one bounded step. */
  int (*step)(struct c89cbor_conversion *, c89cbor_error *);
  /** Copy cumulative totals. */
  int (*progress)(const struct c89cbor_conversion *, c89cbor_progress *);
  /** Copy the retained error. */
  int (*diagnostic)(const struct c89cbor_conversion *, c89cbor_error *);
  /** Release operation state. */
  int (*cleanup)(struct c89cbor_conversion *);
  /** Free an allocated shell. */
  int (*destroy)(struct c89cbor_conversion *);
  /** Private lifecycle state. */
  c89cbor_lifetime lifetime;
  /** Private bounded adapter state. */
  void *state;
} c89cbor_conversion;

#ifdef __cplusplus
}
#endif
#endif
