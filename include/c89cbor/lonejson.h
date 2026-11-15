/** @file c89cbor/lonejson.h
 * Runtime receiver and required lonejson 0.50.0 integration.
 * Caller storage and constructor storage have distinct ownership. Methods and
 * exported twins share implementation. Native defaults can use a NULL runtime.
 */
#ifndef C89CBOR_LONEJSON_H
#define C89CBOR_LONEJSON_H
#include <c89cbor/io.h>
#include <c89cbor/cose.h>
#include <c89cbor/cwt.h>
#include <c89cbor/datagram.h>
#include <lonejson.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Representation delivered to an explicitly configured field sink. */
typedef enum c89cbor_payload {
  /** Decoded UTF-8 bytes. */
  C89CBOR_PAYLOAD_TEXT = 0,
  /** Raw CBOR byte-string payload. */
  C89CBOR_PAYLOAD_BYTES = 1,
  /** Plain JSON bytes for a JSON_VALUE field. */
  C89CBOR_PAYLOAD_JSON = 2
} c89cbor_payload;
/** Bind a mapped field by JSON Pointer path. The binding and path are borrowed.
 * begin/end return OK when accepted, OUTPUT to retry the unaccepted event, or
 * a negative error. The sink's write callback uses normal partial-write rules.
 * Callbacks are provisional until the enclosing record completes.
 * A mapped null calls begin with C89CBOR_NULL and then end, with no chunks.
 */
typedef struct c89cbor_field_sink {
  /** UTF-8 JSON Pointer, such as /payload. */
  const char *path;
  /** Required field representation. */
  c89cbor_payload payload;
  /** Consumer of borrowed payload spans. */
  c89cbor_sink sink;
  /** Optional borrowed wire-value boundary. */
  int (*begin)(void *context, const c89cbor_token *value);
  /** Optional validated value boundary. */
  int (*end)(void *context);
} c89cbor_field_sink;

/** Conversion bounds. Zero selects the documented default for each size.
 * JSON runtime policy can impose stricter limits. Flags default to false.
 */
typedef struct c89cbor_options {
  /** Borrowed field sink bindings. */
  const c89cbor_field_sink *field_sinks;
  /** Number of field_sinks; zero disables bindings. */
  size_t field_sink_count;
  /** Codec and conversion frames; default 32. */
  size_t depth;
  /** New input fragment bytes; default 2 KiB. */
  size_t chunk;
  /** One decoded map key; default 2 KiB. */
  size_t key_bytes;
  /** Active duplicate-key entries; default 256. */
  size_t active_keys;
  /** Key storage across open maps; default 16 KiB. */
  size_t active_key_bytes;
  /** One JSON number lexeme; default 256. */
  size_t number_bytes;
  /** One materialized string; default 64 KiB. */
  size_t field_bytes;
  /** Materialized array elements; default 16384. */
  size_t array_elements;
  /** Logical new mapped storage; default 1 MiB. */
  size_t record_bytes;
  /** Input per step; defaults to the runtime budget. */
  size_t step_input;
  /** Output per step; defaults to the runtime budget. */
  size_t step_output;
  /** Events per step; defaults to the runtime budget. */
  size_t step_events;
  /** Skip unknown mapped fields after validation. */
  int allow_unknown_fields;
} c89cbor_options;

/** Runtime construction policy. Initialize with c89cbor_default_config(). */
typedef struct c89cbor_config {
  /** Lazy runtime policy; pointer fields remain borrowed. */
  lonejson_config json_config;
  /** Owns runtime and child shells; context borrowed. */
  c89cbor_allocator allocator;
  /** Optional borrowed JSON runtime, otherwise created lazily. */
  lonejson *json;
  /** Input bytes per drive step; zero selects 2 KiB. */
  size_t step_input;
  /** Output bytes per drive step; zero selects 2 KiB. */
  size_t step_output;
  /** Converted events per step; zero selects 256. */
  size_t step_events;
} c89cbor_config;
/** Root receiver. Initialize before use; preserve its address until cleanup.
 * Children borrow it. Cleanup returns BUSY until they have been cleaned up.
 * Configuration is fixed. Serialize factories and lifecycle on a shared root.
 */
struct c89cbor {
  /** Initialize a bounded
                                            borrowed-socket datagram shell. */
  int (*datagram_init)(c89cbor *, c89cbor_datagram *, int, size_t,
                       c89cbor_error *);
  /** Allocate a bounded datagram
                                              shell; no packet I/O. */
  int (*datagram_create)(c89cbor *, int, size_t, c89cbor_datagram **,
                         c89cbor_error *);
  /** Default token bounds. */
  c89cbor_cwt_options (*default_cwt_options)(c89cbor *);
  /** Initialize caller token storage. */
  int (*cwt_init)(c89cbor *, c89cbor_cwt *, const c89cbor_cwt_options *,
                  c89cbor_error *);
  /** Allocate bounded token receiver. */
  int (*cwt_create)(c89cbor *, const c89cbor_cwt_options *, c89cbor_cwt **,
                    c89cbor_error *);
  /** Create one bounded object; borrow the
                                         explicitly typed key. */
  int (*cose_sign1)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                    c89cbor_cose_key *, const c89cbor_cose_options *,
                    c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_sign1_open)(c89cbor *, const c89cbor_source *,
                         const c89cbor_sink *, c89cbor_cose_key *,
                         const c89cbor_cose_options *,
                         c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_sign1_init)(c89cbor *, c89cbor_cose_operation *,
                         const c89cbor_source *, const c89cbor_sink *,
                         c89cbor_cose_key *, const c89cbor_cose_options *,
                         c89cbor_error *);
  /** Authenticate one bounded object; release payload
                           only after authentication. */
  int (*cose_verify1)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                      c89cbor_cose_key *, const c89cbor_cose_options *,
                      c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_verify1_open)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, c89cbor_cose_key *,
                           const c89cbor_cose_options *,
                           c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_verify1_init)(c89cbor *, c89cbor_cose_operation *,
                           const c89cbor_source *, const c89cbor_sink *,
                           c89cbor_cose_key *, const c89cbor_cose_options *,
                           c89cbor_error *);
  /** Create one bounded object; borrow the
                                        explicitly typed key. */
  int (*cose_mac0)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                   c89cbor_cose_key *, const c89cbor_cose_options *,
                   c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_mac0_open)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                        c89cbor_cose_key *, const c89cbor_cose_options *,
                        c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_mac0_init)(c89cbor *, c89cbor_cose_operation *,
                        const c89cbor_source *, const c89cbor_sink *,
                        c89cbor_cose_key *, const c89cbor_cose_options *,
                        c89cbor_error *);
  /** Authenticate one bounded object; release payload
                           only after authentication. */
  int (*cose_verify_mac0)(c89cbor *, const c89cbor_source *,
                          const c89cbor_sink *, c89cbor_cose_key *,
                          const c89cbor_cose_options *, c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_verify_mac0_open)(c89cbor *, const c89cbor_source *,
                               const c89cbor_sink *, c89cbor_cose_key *,
                               const c89cbor_cose_options *,
                               c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_verify_mac0_init)(c89cbor *, c89cbor_cose_operation *,
                               const c89cbor_source *, const c89cbor_sink *,
                               c89cbor_cose_key *, const c89cbor_cose_options *,
                               c89cbor_error *);
  /** Create ordered bounded records; borrow the
                           explicitly typed key. */
  int (*cose_sign1_stream)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, c89cbor_cose_key *,
                           const c89cbor_cose_options *, c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_sign1_stream_open)(c89cbor *, const c89cbor_source *,
                                const c89cbor_sink *, c89cbor_cose_key *,
                                const c89cbor_cose_options *,
                                c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_sign1_stream_init)(c89cbor *, c89cbor_cose_operation *,
                                const c89cbor_source *, const c89cbor_sink *,
                                c89cbor_cose_key *,
                                const c89cbor_cose_options *, c89cbor_error *);
  /** Authenticate ordered bounded records; release
                           payload only after authentication. */
  int (*cose_verify1_stream)(c89cbor *, const c89cbor_source *,
                             const c89cbor_sink *, c89cbor_cose_key *,
                             const c89cbor_cose_options *, c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_verify1_stream_open)(c89cbor *, const c89cbor_source *,
                                  const c89cbor_sink *, c89cbor_cose_key *,
                                  const c89cbor_cose_options *,
                                  c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_verify1_stream_init)(c89cbor *, c89cbor_cose_operation *,
                                  const c89cbor_source *, const c89cbor_sink *,
                                  c89cbor_cose_key *,
                                  const c89cbor_cose_options *,
                                  c89cbor_error *);
  /** Create ordered bounded records; borrow the
                           explicitly typed key. */
  int (*cose_mac0_stream)(c89cbor *, const c89cbor_source *,
                          const c89cbor_sink *, c89cbor_cose_key *,
                          const c89cbor_cose_options *, c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_mac0_stream_open)(c89cbor *, const c89cbor_source *,
                               const c89cbor_sink *, c89cbor_cose_key *,
                               const c89cbor_cose_options *,
                               c89cbor_cose_operation **, c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_mac0_stream_init)(c89cbor *, c89cbor_cose_operation *,
                               const c89cbor_source *, const c89cbor_sink *,
                               c89cbor_cose_key *, const c89cbor_cose_options *,
                               c89cbor_error *);
  /** Authenticate ordered bounded records; release
                           payload only after authentication. */
  int (*cose_verify_mac0_stream)(c89cbor *, const c89cbor_source *,
                                 const c89cbor_sink *, c89cbor_cose_key *,
                                 const c89cbor_cose_options *, c89cbor_error *);
  /** Allocate operation; no I/O. */
  int (*cose_verify_mac0_stream_open)(c89cbor *, const c89cbor_source *,
                                      const c89cbor_sink *, c89cbor_cose_key *,
                                      const c89cbor_cose_options *,
                                      c89cbor_cose_operation **,
                                      c89cbor_error *);
  /** Initialize caller operation. */
  int (*cose_verify_mac0_stream_init)(c89cbor *, c89cbor_cose_operation *,
                                      const c89cbor_source *,
                                      const c89cbor_sink *, c89cbor_cose_key *,
                                      const c89cbor_cose_options *,
                                      c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  c89cbor_cose_options (*default_cose_options)(c89cbor *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_key_init)(c89cbor *, c89cbor_cose_key *, c89cbor_cose_key_kind,
                       const void *, size_t, const void *, size_t,
                       c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_key_create)(c89cbor *, c89cbor_cose_key_kind, const void *, size_t,
                         const void *, size_t, c89cbor_cose_key **,
                         c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt0)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                       c89cbor_cose_key *, const c89cbor_cose_options *,
                       c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt0_open)(c89cbor *, const c89cbor_source *,
                            const c89cbor_sink *, c89cbor_cose_key *,
                            const c89cbor_cose_options *,
                            c89cbor_cose_operation **, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt0_init)(c89cbor *, c89cbor_cose_operation *,
                            const c89cbor_source *, const c89cbor_sink *,
                            c89cbor_cose_key *, const c89cbor_cose_options *,
                            c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                      c89cbor_cose_key *const *, size_t,
                      const c89cbor_cose_options *, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt_open)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, c89cbor_cose_key *const *,
                           size_t, const c89cbor_cose_options *,
                           c89cbor_cose_operation **, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt_init)(c89cbor *, c89cbor_cose_operation *,
                           const c89cbor_source *, const c89cbor_sink *,
                           c89cbor_cose_key *const *, size_t,
                           const c89cbor_cose_options *, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                      c89cbor_cose_key *, const c89cbor_cose_options *,
                      c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt_open)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, c89cbor_cose_key *,
                           const c89cbor_cose_options *,
                           c89cbor_cose_operation **, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt_init)(c89cbor *, c89cbor_cose_operation *,
                           const c89cbor_source *, const c89cbor_sink *,
                           c89cbor_cose_key *, const c89cbor_cose_options *,
                           c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt_stream)(c89cbor *, const c89cbor_source *,
                             const c89cbor_sink *, c89cbor_cose_key *const *,
                             size_t, const c89cbor_cose_options *,
                             c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt_stream_open)(c89cbor *, const c89cbor_source *,
                                  const c89cbor_sink *,
                                  c89cbor_cose_key *const *, size_t,
                                  const c89cbor_cose_options *,
                                  c89cbor_cose_operation **, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_encrypt_stream_init)(c89cbor *, c89cbor_cose_operation *,
                                  const c89cbor_source *, const c89cbor_sink *,
                                  c89cbor_cose_key *const *, size_t,
                                  const c89cbor_cose_options *,
                                  c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt_stream)(c89cbor *, const c89cbor_source *,
                             const c89cbor_sink *, c89cbor_cose_key *,
                             const c89cbor_cose_options *, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt_stream_open)(c89cbor *, const c89cbor_source *,
                                  const c89cbor_sink *, c89cbor_cose_key *,
                                  const c89cbor_cose_options *,
                                  c89cbor_cose_operation **, c89cbor_error *);
  /** COSE receiver twin; see <c89cbor/cose.h>. */
  int (*cose_decrypt_stream_init)(c89cbor *, c89cbor_cose_operation *,
                                  const c89cbor_source *, const c89cbor_sink *,
                                  c89cbor_cose_key *,
                                  const c89cbor_cose_options *,
                                  c89cbor_error *);
  /** Convert one mapped record synchronously. */
  int (*encode_map)(c89cbor *, const lonejson_map *, const void *, size_t,
                    const c89cbor_sink *, const c89cbor_options *,
                    c89cbor_error *);
  /** Allocate mapped operation without I/O. */
  int (*encode_map_open)(c89cbor *, const lonejson_map *, const void *, size_t,
                         const c89cbor_sink *, const c89cbor_options *,
                         c89cbor_conversion **, c89cbor_error *);
  /** Initialize caller-owned mapped operation. */
  int (*encode_map_init)(c89cbor *, c89cbor_conversion *, const lonejson_map *,
                         const void *, size_t, const c89cbor_sink *,
                         const c89cbor_options *, c89cbor_error *);
  /** Convert one mapped record synchronously. */
  int (*encode_map_view)(c89cbor *, const lonejson_record_view *,
                         const c89cbor_sink *, const c89cbor_options *,
                         c89cbor_error *);
  /** Allocate mapped operation without I/O. */
  int (*encode_map_view_open)(c89cbor *, const lonejson_record_view *,
                              const c89cbor_sink *, const c89cbor_options *,
                              c89cbor_conversion **, c89cbor_error *);
  /** Initialize caller-owned mapped operation. */
  int (*encode_map_view_init)(c89cbor *, c89cbor_conversion *,
                              const lonejson_record_view *,
                              const c89cbor_sink *, const c89cbor_options *,
                              c89cbor_error *);
  /** Convert one mapped record synchronously. */
  int (*decode_map)(c89cbor *, const c89cbor_source *, const lonejson_map *,
                    void *, size_t, const c89cbor_options *, c89cbor_error *);
  /** Allocate mapped operation without I/O. */
  int (*decode_map_open)(c89cbor *, const c89cbor_source *,
                         const lonejson_map *, void *, size_t,
                         const c89cbor_options *, c89cbor_conversion **,
                         c89cbor_error *);
  /** Initialize caller-owned mapped operation. */
  int (*decode_map_init)(c89cbor *, c89cbor_conversion *,
                         const c89cbor_source *, const lonejson_map *, void *,
                         size_t, const c89cbor_options *, c89cbor_error *);
  /** Convert one mapped record synchronously. */
  int (*decode_map_view)(c89cbor *, const c89cbor_source *,
                         const lonejson_record_view *, const c89cbor_options *,
                         c89cbor_error *);
  /** Allocate mapped operation without I/O. */
  int (*decode_map_view_open)(c89cbor *, const c89cbor_source *,
                              const lonejson_record_view *,
                              const c89cbor_options *, c89cbor_conversion **,
                              c89cbor_error *);
  /** Initialize caller-owned mapped operation. */
  int (*decode_map_view_init)(c89cbor *, c89cbor_conversion *,
                              const c89cbor_source *,
                              const lonejson_record_view *,
                              const c89cbor_options *, c89cbor_error *);

  /** Return conversion defaults. */
  c89cbor_options (*default_options)(c89cbor *);
  /** Synchronous conversion on blocking endpoints. */
  int (*json_to_cbor)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                      const c89cbor_options *, c89cbor_error *);
  /** Allocate resumable conversion. */
  int (*json_to_cbor_open)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, const c89cbor_options *,
                           c89cbor_conversion **, c89cbor_error *);
  /** Initialize caller-owned conversion shell. */
  int (*json_to_cbor_init)(c89cbor *, c89cbor_conversion *,
                           const c89cbor_source *, const c89cbor_sink *,
                           const c89cbor_options *, c89cbor_error *);
  /** Synchronous conversion on blocking endpoints. */
  int (*cbor_to_json)(c89cbor *, const c89cbor_source *, const c89cbor_sink *,
                      const c89cbor_options *, c89cbor_error *);
  /** Allocate resumable conversion. */
  int (*cbor_to_json_open)(c89cbor *, const c89cbor_source *,
                           const c89cbor_sink *, const c89cbor_options *,
                           c89cbor_conversion **, c89cbor_error *);
  /** Initialize caller-owned conversion shell. */
  int (*cbor_to_json_init)(c89cbor *, c89cbor_conversion *,
                           const c89cbor_source *, const c89cbor_sink *,
                           const c89cbor_options *, c89cbor_error *);
  /** Private snapshot for lazy runtime creation. */
  lonejson_config json_config;
  /** Release owned runtime resources. */
  int (*cleanup)(c89cbor *);
  /** Free a constructor-owned runtime. */
  int (*destroy)(c89cbor *);
  /** Copy the first error. */
  int (*diagnostic)(const c89cbor *, c89cbor_error *);
  /** Return native configuration defaults. */
  c89cbor_config (*default_config)(c89cbor *);
  /** Return malloc/free callbacks. */
  c89cbor_allocator (*default_allocator)(c89cbor *);
  /** Static library version. */
  const char *(*version)(c89cbor *);
  /** Static status description. */
  const char *(*status_string)(c89cbor *, int);
  /** Construct a native float token. */
  int (*float64_set)(c89cbor *, c89cbor_token *, double);
  /** Read a native float token. */
  int (*float64_get)(c89cbor *, const c89cbor_token *, double *);
  /** Format a known length. */
  int (*length32)(c89cbor *, uint32_t, uint32_t, unsigned char *);
  /** Initialize caller storage. */
  int (*encoder_init)(c89cbor *, c89cbor_encoder *, c89cbor_frame *, size_t,
                      size_t);
  /** Initialize caller storage. */
  int (*decoder_init)(c89cbor *, c89cbor_decoder *, c89cbor_frame *, size_t,
                      size_t);
  /** Allocate an encoder. */
  int (*encoder_create)(c89cbor *, const c89cbor_allocator *,
                        c89cbor_encoder **);
  /** Allocate a decoder. */
  int (*decoder_create)(c89cbor *, const c89cbor_allocator *,
                        c89cbor_decoder **);
  /** Initialize framed reader storage. */
  int (*reader_init)(c89cbor *, c89cbor_reader *, c89cbor_framing, uint32_t);
  /** Allocate a reader. */
  int (*reader_create)(c89cbor *, c89cbor_framing, uint32_t, c89cbor_reader **);
  /** Initialize transfer storage. */
  int (*transfer_init)(c89cbor *, c89cbor_transfer *, const c89cbor_source *,
                       const c89cbor_sink *, c89cbor_framing, uint32_t);
  /** Allocate a transfer. */
  int (*transfer_create)(c89cbor *, const c89cbor_source *,
                         const c89cbor_sink *, c89cbor_framing, uint32_t,
                         c89cbor_transfer **);
  /** Initialize a borrowed fd. */
  int (*fd_init)(c89cbor *, c89cbor_fd *, int, c89cbor_source *,
                 c89cbor_sink *);
  /** Allocate a borrowed fd. */
  int (*fd_create)(c89cbor *, int, c89cbor_fd **);
  /** Private lifecycle state. */
  c89cbor_lifetime lifetime;
  /** Private borrowed or lazily owned JSON runtime. */
  lonejson *json;
  /** Private ownership flag. */
  int json_owned;
  /** Private configured input budget. */
  size_t step_input;
  /** Private configured output budget. */
  size_t step_output;
  /** Private configured event budget. */
  size_t step_events;
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

/** Return conversion bounds with zero selecting documented defaults. */
C89CBOR_API c89cbor_options c89cbor_default_options(void);
/** Runtime twin of c89cbor_default_options; runtime may be NULL. */
C89CBOR_API c89cbor_options c89cbor_runtime_default_options(c89cbor *runtime);

/** Convert one value synchronously. Unexpected would-block is a terminal
 * endpoint error after possible partial delivery. Use open/init to resume. */
C89CBOR_API int c89cbor_json_to_cbor(c89cbor *runtime,
                                     const c89cbor_source *source,
                                     const c89cbor_sink *sink,
                                     const c89cbor_options *options,
                                     c89cbor_error *error);
/** Allocate an operation without endpoint I/O. Clears *out before allocation.
 * Both endpoints and runtime must remain valid until cleanup. */
C89CBOR_API int c89cbor_json_to_cbor_open(c89cbor *runtime,
                                          const c89cbor_source *source,
                                          const c89cbor_sink *sink,
                                          const c89cbor_options *options,
                                          c89cbor_conversion **out,
                                          c89cbor_error *error);
/** Initialize caller shell; bounded adapter and lonejson state can allocate.
 * Failure leaves cleanup-safe storage. No endpoint I/O occurs on init. */
C89CBOR_API int c89cbor_json_to_cbor_init(c89cbor *runtime,
                                          c89cbor_conversion *conversion,
                                          const c89cbor_source *source,
                                          const c89cbor_sink *sink,
                                          const c89cbor_options *options,
                                          c89cbor_error *error);

/** Convert one value synchronously. Unexpected would-block is a terminal
 * endpoint error after possible partial delivery. Use open/init to resume. */
C89CBOR_API int c89cbor_cbor_to_json(c89cbor *runtime,
                                     const c89cbor_source *source,
                                     const c89cbor_sink *sink,
                                     const c89cbor_options *options,
                                     c89cbor_error *error);
/** Allocate an operation without endpoint I/O. Clears *out before allocation.
 * Both endpoints and runtime must remain valid until cleanup. */
C89CBOR_API int c89cbor_cbor_to_json_open(c89cbor *runtime,
                                          const c89cbor_source *source,
                                          const c89cbor_sink *sink,
                                          const c89cbor_options *options,
                                          c89cbor_conversion **out,
                                          c89cbor_error *error);
/** Initialize caller shell; bounded adapter and lonejson state can allocate.
 * Failure leaves cleanup-safe storage. No endpoint I/O occurs on init. */
C89CBOR_API int c89cbor_cbor_to_json_init(c89cbor *runtime,
                                          c89cbor_conversion *conversion,
                                          const c89cbor_source *source,
                                          const c89cbor_sink *sink,
                                          const c89cbor_options *options,
                                          c89cbor_error *error);

/** Drive one step. INPUT/OUTPUT mean wait, OK means progress, DONE is terminal
 * success. Accepted byte counts survive errors. Reentry returns BUSY. */
C89CBOR_API int c89cbor_conversion_step(c89cbor_conversion *conversion,
                                        c89cbor_error *error);
/** Copy progress after success, failure or cancellation. */
C89CBOR_API int
c89cbor_conversion_progress(const c89cbor_conversion *conversion,
                            c89cbor_progress *progress);
/** Copy the first terminal diagnostic. */
C89CBOR_API int
c89cbor_conversion_diagnostic(const c89cbor_conversion *conversion,
                              c89cbor_error *error);
/** Cancel and release operation-owned buffers, preserving shell storage. */
C89CBOR_API int c89cbor_conversion_cleanup(c89cbor_conversion *conversion);
/** Release a heap shell with its recorded allocator; NULL succeeds. */
C89CBOR_API int c89cbor_conversion_destroy(c89cbor_conversion *conversion);

/** Encode native fields directly. Keep record and schema stable until
 * completion. */
C89CBOR_API int c89cbor_encode_map(c89cbor *runtime, const lonejson_map *map,
                                   const void *record, size_t extent,
                                   const c89cbor_sink *sink,
                                   const c89cbor_options *options,
                                   c89cbor_error *error);
/** Allocate an operation borrowing schema, record and endpoints. Clears *out.
 */
C89CBOR_API int c89cbor_encode_map_open(
    c89cbor *runtime, const lonejson_map *map, const void *record,
    size_t extent, const c89cbor_sink *sink, const c89cbor_options *options,
    c89cbor_conversion **out, c89cbor_error *error);
/** Initialize caller shell, validating metadata and bounds before endpoint I/O.
 */
C89CBOR_API int
c89cbor_encode_map_init(c89cbor *runtime, c89cbor_conversion *conversion,
                        const lonejson_map *map, const void *record,
                        size_t extent, const c89cbor_sink *sink,
                        const c89cbor_options *options, c89cbor_error *error);

/** Encode native fields directly. Keep record and schema stable until
 * completion. */
C89CBOR_API int c89cbor_encode_map_view(c89cbor *runtime,
                                        const lonejson_record_view *view,
                                        const c89cbor_sink *sink,
                                        const c89cbor_options *options,
                                        c89cbor_error *error);
/** Allocate an operation borrowing schema, record and endpoints. Clears *out.
 */
C89CBOR_API int c89cbor_encode_map_view_open(c89cbor *runtime,
                                             const lonejson_record_view *view,
                                             const c89cbor_sink *sink,
                                             const c89cbor_options *options,
                                             c89cbor_conversion **out,
                                             c89cbor_error *error);
/** Initialize caller shell, validating metadata and bounds before endpoint I/O.
 */
C89CBOR_API int c89cbor_encode_map_view_init(c89cbor *runtime,
                                             c89cbor_conversion *conversion,
                                             const lonejson_record_view *view,
                                             const c89cbor_sink *sink,
                                             const c89cbor_options *options,
                                             c89cbor_error *error);

/** Decode into initialized empty/reset record storage. Partial fields remain
 * safe for lonejson cleanup. */
C89CBOR_API int
c89cbor_decode_map(c89cbor *runtime, const c89cbor_source *source,
                   const lonejson_map *map, void *record, size_t extent,
                   const c89cbor_options *options, c89cbor_error *error);
/** Allocate an operation borrowing schema, record and endpoints. Clears *out.
 */
C89CBOR_API int
c89cbor_decode_map_open(c89cbor *runtime, const c89cbor_source *source,
                        const lonejson_map *map, void *record, size_t extent,
                        const c89cbor_options *options,
                        c89cbor_conversion **out, c89cbor_error *error);
/** Initialize caller shell, validating metadata and bounds before endpoint I/O.
 */
C89CBOR_API int
c89cbor_decode_map_init(c89cbor *runtime, c89cbor_conversion *conversion,
                        const c89cbor_source *source, const lonejson_map *map,
                        void *record, size_t extent,
                        const c89cbor_options *options, c89cbor_error *error);

/** Decode into initialized empty/reset record storage. Partial fields remain
 * safe for lonejson cleanup. */
C89CBOR_API int c89cbor_decode_map_view(c89cbor *runtime,
                                        const c89cbor_source *source,
                                        const lonejson_record_view *view,
                                        const c89cbor_options *options,
                                        c89cbor_error *error);
/** Allocate an operation borrowing schema, record and endpoints. Clears *out.
 */
C89CBOR_API int c89cbor_decode_map_view_open(c89cbor *runtime,
                                             const c89cbor_source *source,
                                             const lonejson_record_view *view,
                                             const c89cbor_options *options,
                                             c89cbor_conversion **out,
                                             c89cbor_error *error);
/** Initialize caller shell, validating metadata and bounds before endpoint I/O.
 */
C89CBOR_API int c89cbor_decode_map_view_init(c89cbor *runtime,
                                             c89cbor_conversion *conversion,
                                             const c89cbor_source *source,
                                             const lonejson_record_view *view,
                                             const c89cbor_options *options,
                                             c89cbor_error *error);

#ifdef __cplusplus
}
#endif
#endif
