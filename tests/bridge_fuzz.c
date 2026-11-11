#include <c89cbor/lonejson.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fuzz_record {
  lonejson_int64 id;
  char *name;
  lonejson_string_array labels;
} fuzz_record;
static const lonejson_field fields[] = {
    LONEJSON_FIELD_I64_REQ(fuzz_record, id, "id"),
    LONEJSON_FIELD_STRING_ALLOC_REQ(fuzz_record, name, "name"),
    LONEJSON_FIELD_STRING_ARRAY(fuzz_record, labels, "labels",
                                LONEJSON_OVERFLOW_FAIL)};
LONEJSON_MAP_DEFINE(map, fuzz_record, fields);
typedef struct memory {
  const unsigned char *input;
  size_t length, offset, fragment, used, reads, writes;
  unsigned char output[16384];
} memory;
static int read_bytes(void *context, void *bytes, size_t capacity,
                      size_t *count) {
  memory *m = context;
  size_t take = m->length - m->offset;
  *count = 0;
  if ((++m->reads % 3u) == 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > m->fragment)
    take = m->fragment;
  if (take != 0)
    memcpy(bytes, m->input + m->offset, take);
  m->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int write_bytes(void *context, const void *bytes, size_t length,
                       size_t *count) {
  memory *m = context;
  size_t take = length;
  *count = 0;
  if ((++m->writes % 3u) == 0)
    return C89CBOR_OUTPUT;
  if (take > m->fragment)
    take = m->fragment;
  assert(take <= sizeof(m->output) - m->used);
  memcpy(m->output + m->used, bytes, take);
  m->used += take;
  *count = take;
  return C89CBOR_OUTPUT;
}
static int drive(c89cbor_conversion *operation, memory *m) {
  c89cbor_error error, repeated;
  c89cbor_progress progress;
  size_t steps = 0, reads, writes;
  int status;
  do {
    reads = m->reads;
    status = operation->step(operation, &error);
    assert(m->reads - reads <= 1u && ++steps < 200000u);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(operation->progress(operation, &progress) == 0);
  assert(progress.input == m->offset && progress.output == m->used);
  reads = m->reads;
  writes = m->writes;
  assert(operation->step(operation, &repeated) == status);
  assert(m->reads == reads && m->writes == writes);
  assert(operation->cleanup(operation) == 0 &&
         operation->cleanup(operation) == 0);
  return status;
}
int main(int argc, char **argv) {
  unsigned char bytes[4096];
  size_t length = fread(bytes, 1, sizeof(bytes), stdin);
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_conversion operation;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_error error;
  lonejson_error json_error;
  lonejson *json;
  fuzz_record record;
  memory *m = malloc(sizeof(*m));
  int status;
  if (m == NULL)
    return 1;
  memset(m, 0, sizeof(*m));
  m->input = bytes;
  m->length = length;
  m->fragment = length == 0 ? 1u : (size_t)(bytes[0] % 17u) + 1u;
  source.context = m;
  source.read = read_bytes;
  sink.context = m;
  sink.write = write_bytes;
  json = lonejson_new(NULL, &json_error);
  assert(json != NULL);
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  options.depth = 8;
  options.chunk = m->fragment;
  options.key_bytes = 32;
  options.number_bytes = 64;
  options.field_bytes = 512;
  options.record_bytes = 4096;
  options.array_elements = 128;
  options.step_events = 7;
  options.allow_unknown_fields = 1;
  assert(argc == 2);
  if (strcmp(argv[1], "json") == 0) {
    assert(runtime.json_to_cbor_init(&runtime, &operation, &source, &sink,
                                     &options, &error) == 0);
    status = drive(&operation, m);
    if (status == C89CBOR_DONE) {
      memcpy(bytes, m->output,
             m->used < sizeof(bytes) ? m->used : sizeof(bytes));
      if (m->used <= sizeof(bytes)) {
        m->length = m->used;
        m->offset = m->used = m->reads = m->writes = 0;
        assert(runtime.cbor_to_json_init(&runtime, &operation, &source, &sink,
                                         &options, &error) == 0);
        assert(drive(&operation, m) == C89CBOR_DONE);
      }
    }
  } else if (strcmp(argv[1], "cbor") == 0) {
    assert(runtime.cbor_to_json_init(&runtime, &operation, &source, &sink,
                                     &options, &error) == 0);
    (void)drive(&operation, m);
  } else {
    assert(strcmp(argv[1], "map") == 0);
    assert(lonejson_init(json, &map, &record, &json_error) ==
           LONEJSON_STATUS_OK);
    assert(runtime.decode_map_init(&runtime, &operation, &source, &map, &record,
                                   sizeof(record), &options, &error) == 0);
    status = drive(&operation, m);
    if (status == C89CBOR_DONE) {
      m->offset = m->used = m->reads = m->writes = 0;
      assert(runtime.encode_map_init(&runtime, &operation, &map, &record,
                                     sizeof(record), &sink, &options,
                                     &error) == 0);
      assert(drive(&operation, m) == C89CBOR_DONE);
    }
    assert(json->cleanup(json, &map, &record, &json_error) ==
           LONEJSON_STATUS_OK);
  }
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
  free(m);
  return 0;
}
