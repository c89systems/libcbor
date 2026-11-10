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
  c89cbor_decoder decoder; /**< Private item decoder. */
  c89cbor_framing framing; /**< Selected framing mode. */
  uint32_t limit;          /**< Maximum LENGTH32 payload. */
  uint32_t length;         /**< Current declared length. */
  uint32_t remaining;      /**< Current remaining payload. */
  unsigned int have;       /**< Partial prefix byte count. */
  int active;              /**< Private record marker. */
  int complete;            /**< Private single-item completion marker. */
  int failed;              /**< Sticky error. */
} c89cbor_reader;
/** Initialize framing. limit == 0 selects cai's 128 KiB record bound in
 * LENGTH32; it does not bound individual items in other modes. Core chunk and
 * nesting defaults apply; customize reader.decoder before the first next.
 */
C89CBOR_API int c89cbor_reader_init(c89cbor_reader *reader,
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
C89CBOR_API int c89cbor_length32(uint32_t length, uint32_t limit,
                                 unsigned char output[4]);
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
  c89cbor_reader reader;               /**< Private validator. */
  c89cbor_source source;               /**< Borrowed source copy. */
  c89cbor_sink sink;                   /**< Borrowed sink copy. */
  unsigned char buffer[C89CBOR_CHUNK]; /**< Bounded pending transport chunk. */
  size_t offset;                       /**< Private pending output offset. */
  size_t length;                       /**< Private pending output length. */
  uint64_t read_bytes;                 /**< Input bytes accepted so far. */
  uint64_t written_bytes;              /**< Output bytes delivered so far. */
  int finished;                        /**< Private successful EOF marker. */
  int failed;                          /**< Sticky terminal status. */
  int busy;                            /**< Private reentry guard. */
} c89cbor_transfer;
/** Initialize a native-to-native transfer without allocation. Endpoints and
 * their owners must outlive it. No Lua callback or token conversion is needed.
 * Output is provisional until DONE; errors may follow partial delivery.
 */
C89CBOR_API int c89cbor_transfer_init(c89cbor_transfer *transfer,
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
  int descriptor; /**< Open descriptor owned by the caller. */
} c89cbor_fd;
/** Initialize an fd and optional source/sink views; at least one view required.
 * Both views borrow fd, which must remain alive. No descriptor I/O on init. */
C89CBOR_API int c89cbor_fd_init(c89cbor_fd *fd, int descriptor,
                                c89cbor_source *source, c89cbor_sink *sink);
#ifdef __cplusplus
}
#endif
#endif
