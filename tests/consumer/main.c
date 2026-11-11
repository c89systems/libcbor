#include <c89cbor/cbor.h>
#include <c89cbor/io.h>
#include <c89cbor/lonejson.h>
#include <c89cbor/lua.h>
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
  unsigned char output[512];
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
static void cose(void) {
  c89cbor runtime;
  c89cbor_cose_key content, wrapping, private_key, public_key, *keys[2];
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  unsigned char raw[32] = {0}, public_bytes[32], wire[512];
  size_t length, wire_length;
  memory buffer;
  int encrypt;
  assert(c89cbor_init(&runtime, NULL, &error) == 0);
  assert(runtime.cose_key_init(&runtime, &content, C89CBOR_COSE_A256GCM, raw,
                               32u, NULL, 0, &error) == 0);
  raw[0] = 1;
  assert(runtime.cose_key_init(&runtime, &wrapping, C89CBOR_COSE_A256KW, raw,
                               32u, NULL, 0, &error) == 0);
  assert(runtime.cose_key_init(&runtime, &private_key,
                               C89CBOR_COSE_X25519_PRIVATE, raw, 32u, NULL, 0,
                               &error) == 0);
  assert(private_key.public_key(&private_key, public_bytes, 32u, &length) == 0);
  assert(runtime.cose_key_init(&runtime, &public_key,
                               C89CBOR_COSE_X25519_PUBLIC, public_bytes, length,
                               NULL, 0, &error) == 0);
  keys[0] = &wrapping;
  keys[1] = &public_key;
  source.context = sink.context = &buffer;
  source.read = read_bytes;
  sink.write = write_bytes;
  for (encrypt = 0; encrypt < 2; ++encrypt) {
    memset(&buffer, 0, sizeof(buffer));
    buffer.input = (const unsigned char *)"\203\001\002\003";
    buffer.length = 4u;
    assert((encrypt ? runtime.cose_encrypt(&runtime, &source, &sink, keys, 2u,
                                           NULL, &error)
                    : runtime.cose_encrypt0(&runtime, &source, &sink, &content,
                                            NULL, &error)) == 0);
    wire_length = buffer.used;
    memcpy(wire, buffer.output, wire_length);
    buffer.offset = buffer.used = 0;
    buffer.input = wire;
    buffer.length = wire_length;
    assert(runtime.cose_decrypt(&runtime, &source, &sink,
                                encrypt ? &private_key : &content, NULL,
                                &error) == 0);
    assert(buffer.used == 4u &&
           memcmp(buffer.output, "\203\001\002\003", 4u) == 0);
  }
  assert(public_key.cleanup(&public_key) == 0 &&
         private_key.cleanup(&private_key) == 0);
  assert(wrapping.cleanup(&wrapping) == 0 && content.cleanup(&content) == 0 &&
         runtime.cleanup(&runtime) == 0);
}
int main(void) {
  c89cbor_decoder d;
  c89cbor_token t;
  const unsigned char input[] = {0x18, 0x2a};
  size_t used;
  conversions();
  cose();
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
