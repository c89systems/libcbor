/** @file c89cbor/datagram.h
 * Bounded complete CBOR datagrams over borrowed POSIX datagram sockets.
 * The caller owns socket configuration, readiness, deadlines and lifetime.
 */
#ifndef C89CBOR_DATAGRAM_H
#define C89CBOR_DATAGRAM_H
#include <c89cbor/io.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Borrowed input and sender address; invalidated by the next receive/reset or
 * stream-source read. No bytes are exposed before full datagram validation. */
typedef struct c89cbor_datagram_message {
  /** One complete CBOR item. */
  const void *bytes;
  /** Wire bytes, bounded at construction. */
  size_t length;
  /** sockaddr bytes, or NULL for an unnamed socket peer. */
  const void *peer;
  /** Address length for send/set_peer. */
  size_t peer_length;
} c89cbor_datagram_message;
/** Cumulative successful traffic and discarded invalid datagrams. */
typedef struct c89cbor_datagram_counts {
  /** Received wire bytes admitted after CBOR validation. */
  uint64_t input;
  /** Atomically sent wire bytes. */
  uint64_t output;
  /** Successfully validated datagrams. */
  uint64_t received;
  /** Successfully sent datagrams. */
  uint64_t sent;
  /** Invalid/oversized received datagrams. */
  uint64_t rejected;
} c89cbor_datagram_counts;
/** Datagram receiver/sender shell. Init fixes the wire bound; zero selects
 * 2 KiB. This bound is not a path-MTU promise. Three bounded allocations occur
 * at init; drive performs none. Validation uses the codec's default 32-frame
 * nesting bound. Preserve the shell's address until cleanup.
 * Serialize calls on one shell. Endpoints borrow it until their cleanup. */
typedef struct c89cbor_datagram {
  /** Receive one datagram: OK, INPUT on would-block, or a negative status.
   * Failure clears the output; another receive can recover from a bad packet.
   */
  int (*receive)(struct c89cbor_datagram *, c89cbor_datagram_message *,
                 c89cbor_error *);
  /** Validate/send one item atomically; OUTPUT means retry the same bytes.
   * NULL peer uses set_peer, or the socket's connected destination. */
  int (*send)(struct c89cbor_datagram *, const void *, size_t, const void *,
              size_t, c89cbor_error *);
  /** Copy an optional default sockaddr. NULL/zero restores connected send. */
  int (*set_peer)(struct c89cbor_datagram *, const void *, size_t);
  /** Message-scoped source of the last received item; INPUT before receive,
   * EOF only after its bytes are consumed. Getter performs no socket I/O. */
  int (*source)(struct c89cbor_datagram *, c89cbor_source *);
  /** Read successive validated datagrams; INPUT on would-block, never EOF.
   * COSE authenticates sequence/final markers; UDP does not restore order. */
  int (*stream_source)(struct c89cbor_datagram *, c89cbor_source *);
  /** Collect at most one bounded item and send atomically. Standard partial
   * acceptance applies; retain/retry every unaccepted input byte. */
  int (*sink)(struct c89cbor_datagram *, c89cbor_sink *);
  /** Cancel pending item/source state and clear errors, preserving counters.
   */
  int (*reset)(struct c89cbor_datagram *);
  /** Copy cumulative counters, clearing output first. */
  int (*progress)(const struct c89cbor_datagram *, c89cbor_datagram_counts *);
  /** Copy the latest endpoint failure. */
  int (*diagnostic)(const struct c89cbor_datagram *, c89cbor_error *);
  /** Idempotent; never close socket. */
  int (*cleanup)(struct c89cbor_datagram *);
  /** Free constructor storage only. */
  int (*destroy)(struct c89cbor_datagram *);
  /** Private allocator, parent and reentry guard. */
  c89cbor_lifetime lifetime;
  /** Private bounded buffers and framing state. */
  void *state;
} c89cbor_datagram;
/** Initialize fresh caller storage, borrowing a SOCK_DGRAM descriptor. The
 * descriptor must be nonnegative; no packet I/O or polling occurs. */
C89CBOR_API int c89cbor_datagram_init(c89cbor *, c89cbor_datagram *, int,
                                      size_t, c89cbor_error *);
/** Allocate a shell and bounded buffers; clear *out before validation. */
C89CBOR_API int c89cbor_datagram_create(c89cbor *, int, size_t,
                                        c89cbor_datagram **, c89cbor_error *);
/** Receiver twin; invalid/truncated packets publish no prefix. */
C89CBOR_API int c89cbor_datagram_receive(c89cbor_datagram *,
                                         c89cbor_datagram_message *,
                                         c89cbor_error *);
/** Receiver twin; one atomic complete-item send, no fragmentation/retry loop.
 */
C89CBOR_API int c89cbor_datagram_send(c89cbor_datagram *, const void *, size_t,
                                      const void *, size_t, c89cbor_error *);
/** Receiver twin; copy sockaddr bytes without exposing private POSIX layouts.
 */
C89CBOR_API int c89cbor_datagram_set_peer(c89cbor_datagram *, const void *,
                                          size_t);
/** Receiver twin; bind a source to an explicitly received datagram. */
C89CBOR_API int c89cbor_datagram_source(c89cbor_datagram *, c89cbor_source *);
/** Receiver twin; bind an input source that preserves complete packet bounds.
 */
C89CBOR_API int c89cbor_datagram_stream_source(c89cbor_datagram *,
                                               c89cbor_source *);
/** Receiver twin; bind a bounded atomic datagram sink. */
C89CBOR_API int c89cbor_datagram_sink(c89cbor_datagram *, c89cbor_sink *);
/** Receiver twin; discard pending work without resetting traffic counters. */
C89CBOR_API int c89cbor_datagram_reset(c89cbor_datagram *);
/** Receiver twin; copy successful traffic and invalid-packet counters. */
C89CBOR_API int c89cbor_datagram_progress(const c89cbor_datagram *,
                                          c89cbor_datagram_counts *);
/** Receiver twin; copy the most recent endpoint diagnostic. */
C89CBOR_API int c89cbor_datagram_diagnostic(const c89cbor_datagram *,
                                            c89cbor_error *);
/** Receiver twin; release private buffers and parent pin. NULL is safe. */
C89CBOR_API int c89cbor_datagram_cleanup(c89cbor_datagram *);
/** Receiver twin; free only allocating constructor storage. NULL is safe. */
C89CBOR_API int c89cbor_datagram_destroy(c89cbor_datagram *);
#ifdef __cplusplus
}
#endif
#endif
