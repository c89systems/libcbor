#include <c89cbor/cbor.h>
#include <c89cbor/io.h>
#include <c89cbor/lonejson.h>
#include <assert.h>
#include <string.h>
typedef struct record {
  lonejson_int64 n;
} record;
static const lonejson_field fields[] = {LONEJSON_FIELD_I64_REQ(record, n, "n")};
LONEJSON_MAP_DEFINE(map, record, fields);
typedef struct memory {
  const unsigned char *input;
  size_t length, offset, used;
  unsigned char output[32];
} memory;
static int read_bytes(void *context, void *bytes, size_t capacity,
                      size_t *count) {
  memory *buffer = context;
  size_t take = buffer->offset < buffer->length && capacity != 0 ? 1u : 0u;
  if (take != 0)
    memcpy(bytes, buffer->input + buffer->offset, take);
  buffer->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int write_bytes(void *context, const void *bytes, size_t length,
                       size_t *count) {
  memory *buffer = context;
  size_t take = length < 2u ? length : 2u;
  assert(take <= sizeof(buffer->output) - buffer->used);
  memcpy(buffer->output + buffer->used, bytes, take);
  buffer->used += take;
  *count = take;
  return C89CBOR_OK;
}
static void conversions(void) {
  static const unsigned char expected[] = {0xa1, 0x61, 'n', 0x18, 0x2a};
  static const unsigned char indefinite[] = {0xbf, 0x61, 'n', 0x18, 0x2a, 0xff};
  static const char document[] = "{\"n\":42}";
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  lonejson_error json_error;
  lonejson *json = lonejson_new(NULL, &json_error);
  c89cbor_source source;
  c89cbor_sink sink;
  memory buffer;
  record value;
  assert(json != NULL);
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  source.context = &buffer;
  source.read = read_bytes;
  sink.context = &buffer;
  sink.write = write_bytes;
  memset(&buffer, 0, sizeof(buffer));
  buffer.input = (const unsigned char *)document;
  buffer.length = strlen(document);
  assert(runtime.json_to_cbor(&runtime, &source, &sink, NULL, &error) == 0);
  assert(buffer.used == sizeof(indefinite) &&
         memcmp(buffer.output, indefinite, sizeof(indefinite)) == 0);
  memset(&buffer, 0, sizeof(buffer));
  buffer.input = expected;
  buffer.length = sizeof(expected);
  assert(runtime.cbor_to_json(&runtime, &source, &sink, NULL, &error) == 0);
  assert(buffer.used == strlen(document) &&
         memcmp(buffer.output, document, strlen(document)) == 0);
  assert(lonejson_init(json, &map, &value, &json_error) == LONEJSON_STATUS_OK);
  buffer.offset = 0;
  assert(c89cbor_decode_map(&runtime, &source, &map, &value, sizeof(value),
                            NULL, &error) == 0 &&
         value.n == 42);
  buffer.used = 0;
  assert(runtime.encode_map(&runtime, &map, &value, sizeof(value), &sink, NULL,
                            &error) == 0);
  assert(buffer.used == sizeof(expected) &&
         memcmp(buffer.output, expected, sizeof(expected)) == 0);
  assert(json->cleanup(json, &map, &value, &json_error) == LONEJSON_STATUS_OK);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
int main(void) {
  c89cbor_decoder d;
  c89cbor_token t;
  const unsigned char input[] = {0x18, 0x2a};
  size_t used;
  conversions();
  if (c89cbor_decoder_init(NULL, &d, 0, 0, 0) != 0)
    return 1;
  if (c89cbor_decoder_next(&d, input, sizeof(input), &used, &t) !=
          C89CBOR_TOKEN ||
      used != 2 || t.type != C89CBOR_UINT || t.argument != 42)
    return 2;
  if (c89cbor_decoder_finish(&d) != 0)
    return 3;
  return strcmp(c89cbor_version(NULL), EXPECTED_VERSION) != 0;
}
