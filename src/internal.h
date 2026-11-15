#ifndef C89CBOR_INTERNAL_H
#define C89CBOR_INTERNAL_H
#include <c89cbor/lonejson.h>
#define C89_LIFETIME_MAGIC 0x43424f52U
/* Each conversion owns one bounded operation state. JSON and mapped traversal
 * have separate state machines and share only receiver lifecycle and driving.
 */
typedef struct c89_operation {
  int (*step)(void *state);
  void (*release)(void *state);
} c89_operation;
int c89_utf8(c89cbor_frame *frame, const unsigned char *data, size_t count);
int c89_encoder_buffer(c89cbor_encoder *encoder, const c89cbor_token *token,
                       unsigned char *output, size_t capacity, size_t *written);
int c89_encoder_buffer_text(c89cbor_encoder *encoder, const void *text,
                            size_t length, unsigned char *output,
                            size_t capacity, size_t *written);
int c89_encoder_buffer_key(c89cbor_encoder *encoder,
                           const lonejson_field *field, unsigned char *output,
                           size_t capacity, size_t *written);
int c89_encoder_buffer_pair(c89cbor_encoder *encoder,
                            const lonejson_field *field,
                            const c89cbor_token *value, unsigned char *output,
                            size_t capacity, size_t *written);
int c89_decoder_text(c89cbor_decoder *decoder, const unsigned char *input,
                     size_t length, size_t *consumed, int matched);
int c89_decoder_span(c89cbor_decoder *decoder, const void *input,
                     size_t length);
void c89_options_resolve(const c89cbor *runtime, const c89cbor_options *options,
                         c89cbor_options *resolved);
int c89_conversion_prepare(c89cbor *runtime, c89cbor_conversion *conversion,
                           c89cbor_error *error);
int c89_conversion_run(c89cbor_conversion *conversion, c89cbor_error *error);
void c89_cose_runtime_methods(c89cbor *runtime);
void c89_cwt_runtime_methods(c89cbor *runtime);
int c89_json_encode_init(c89cbor *runtime, c89cbor_conversion *conversion,
                         const c89cbor_source *source, const c89cbor_sink *sink,
                         const c89cbor_options *options,
                         c89cbor_encoder *encoder, c89cbor_error *error);
int c89_json_decode_init(c89cbor *runtime, c89cbor_conversion *conversion,
                         const c89cbor_sink *sink,
                         const c89cbor_options *options, c89cbor_error *error);
int c89_json_decode_put(c89cbor_conversion *conversion,
                        const c89cbor_token *token, c89cbor_error *error);
int c89_lifetime_init(c89cbor_lifetime *life, c89cbor *parent,
                      const c89cbor_allocator *allocator);
int c89_lifetime_cleanup(c89cbor_lifetime *life);
int c89_lifetime_destroy(c89cbor_lifetime *life, void *shell);
int c89_lifetime_diagnostic(const c89cbor_lifetime *life, c89cbor_error *error);
int c89_error(c89cbor_lifetime *life, int status, const char *layer);
int c89_allocator_valid(const c89cbor_allocator *allocator);
int c89_allocate(c89cbor *parent, const c89cbor_allocator *override,
                 size_t size, void **out, c89cbor_allocator *selected);
#endif
