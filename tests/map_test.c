#define _GNU_SOURCE
#include <c89cbor/lonejson.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct child {
  lonejson_int64 id;
  char *name;
} child;
static const lonejson_field child_fields[] = {
    LONEJSON_FIELD_I64_REQ(child, id, "id"),
    LONEJSON_FIELD_STRING_ALLOC_REQ(child, name, "name")};
LONEJSON_MAP_DEFINE(child_map, child, child_fields);
typedef struct record {
  lonejson_int64 signed_number;
  lonejson_uint64 unsigned_number;
  double number;
  bool enabled;
  char name[16];
  char *description;
  child nested;
  lonejson_i64_array integers;
  lonejson_u64_array unsigneds;
  lonejson_f64_array numbers;
  lonejson_bool_array booleans;
  lonejson_string_array strings;
  lonejson_object_array objects;
} record;
static const lonejson_field fields[] = {
    LONEJSON_FIELD_I64_REQ(record, signed_number, "signed"),
    LONEJSON_FIELD_U64_REQ(record, unsigned_number, "unsigned"),
    LONEJSON_FIELD_F64_REQ(record, number, "number"),
    LONEJSON_FIELD_BOOL_REQ(record, enabled, "enabled"),
    LONEJSON_FIELD_STRING_FIXED(record, name, "name", LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_STRING_ALLOC_OMIT_NULL(record, description, "description"),
    LONEJSON_FIELD_OBJECT_REQ(record, nested, "nested", &child_map),
    LONEJSON_FIELD_I64_ARRAY(record, integers, "integers",
                             LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_U64_ARRAY(record, unsigneds, "unsigneds",
                             LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_F64_ARRAY(record, numbers, "numbers",
                             LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_BOOL_ARRAY(record, booleans, "booleans",
                              LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_STRING_ARRAY(record, strings, "strings",
                                LONEJSON_OVERFLOW_FAIL),
    LONEJSON_FIELD_OBJECT_ARRAY(record, objects, "objects", child, &child_map,
                                LONEJSON_OVERFLOW_FAIL)};
LONEJSON_MAP_DEFINE(record_map, record, fields);
typedef struct endpoint {
  const unsigned char *bytes;
  size_t length, offset, fragment, reads, writes;
  unsigned char output[8192];
  size_t used;
  int pause;
} endpoint;
static int read_bytes(void *context, void *buffer, size_t capacity,
                      size_t *count) {
  endpoint *e = context;
  size_t take = e->length - e->offset;
  *count = 0;
  if (e->pause && (++e->reads % 2u) != 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > e->fragment)
    take = e->fragment;
  memcpy(buffer, e->bytes + e->offset, take);
  e->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int write_bytes(void *context, const void *bytes, size_t length,
                       size_t *count) {
  endpoint *e = context;
  size_t take = length;
  ++e->writes;
  if (take > e->fragment)
    take = e->fragment;
  assert(take <= sizeof(e->output) - e->used);
  memcpy(e->output + e->used, bytes, take);
  e->used += take;
  *count = take;
  return e->pause ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static int drive(c89cbor_conversion *operation, c89cbor_error *error) {
  size_t calls = 0;
  int status;
  do {
    status = operation->step(operation, error);
    if (++calls == 100000u) {
      fprintf(stderr, "conversion stalled: input=%lu output=%lu\n",
              (unsigned long)operation->lifetime.progress.input,
              (unsigned long)operation->lifetime.progress.output);
      abort();
    }
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  return status;
}
static void roundtrip(void) {
  static const char json[] =
      "{\"signed\":-9223372036854775808,\"unsigned\":18446744073709551615,"
      "\"number\":1.5,\"enabled\":true,\"name\":\"hello\",\"description\":"
      "\"world\","
      "\"nested\":{\"id\":42,\"name\":\"child\"},\"integers\":[-1,0,42],"
      "\"unsigneds\":[0,18446744073709551615],\"numbers\":[-0.0,1.5],"
      "\"booleans\":[true,false],\"strings\":[\"hello\",\"\",\"caf\303\251\"],"
      "\"objects\":[{\"id\":7,\"name\":\"first\"},{\"id\":8,\"name\":"
      "\"second\"}]}";
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  lonejson_error jerror;
  lonejson *json_runtime = lonejson_new(NULL, &jerror);
  record input, output;
  endpoint encoded, decoded;
  c89cbor_sink sink;
  c89cbor_source source;
  c89cbor_conversion operation;
  c89cbor_options options = c89cbor_default_options();
  size_t split;
  assert(json_runtime != NULL);
  config.json = json_runtime;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(lonejson_init(json_runtime, &record_map, &input, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_parse_cstr(json_runtime, &record_map, &input, json,
                             &jerror) == LONEJSON_STATUS_OK);
  for (split = 1; split <= 33; ++split) {
    memset(&encoded, 0, sizeof(encoded));
    encoded.fragment = split;
    encoded.pause = 1;
    sink.context = &encoded;
    sink.write = write_bytes;
    options.chunk = split;
    assert(runtime.encode_map_init(&runtime, &operation, &record_map, &input,
                                   sizeof(input), &sink, &options,
                                   &error) == 0);
    assert(encoded.writes == 0);
    assert(runtime.cleanup(&runtime) == C89CBOR_BUSY);
    assert(drive(&operation, &error) == C89CBOR_DONE);
    assert(operation.cleanup(&operation) == 0);
    memset(&decoded, 0, sizeof(decoded));
    decoded.bytes = encoded.output;
    decoded.length = encoded.used;
    decoded.fragment = split;
    decoded.pause = 1;
    source.context = &decoded;
    source.read = read_bytes;
    assert(lonejson_init(json_runtime, &record_map, &output, &jerror) ==
           LONEJSON_STATUS_OK);
    assert(runtime.decode_map_init(&runtime, &operation, &source, &record_map,
                                   &output, sizeof(output), &options,
                                   &error) == 0);
    assert(decoded.reads == 0);
    assert(drive(&operation, &error) == C89CBOR_DONE);
    assert(operation.cleanup(&operation) == 0);
    assert(output.signed_number == input.signed_number);
    assert(output.unsigned_number == input.unsigned_number &&
           output.number == 1.5 && output.enabled);
    assert(strcmp(output.name, "hello") == 0 &&
           strcmp(output.description, "world") == 0);
    assert(output.nested.id == 42 && strcmp(output.nested.name, "child") == 0);
    assert(output.integers.count == 3 && output.integers.items[0] == -1 &&
           output.integers.items[2] == 42);
    assert(output.unsigneds.count == 2 &&
           output.unsigneds.items[1] == UINT64_MAX);
    assert(output.numbers.count == 2 && output.numbers.items[1] == 1.5);
    assert(output.booleans.count == 2 && output.booleans.items[0] &&
           !output.booleans.items[1]);
    assert(output.strings.count == 3 &&
           strcmp(output.strings.items[2], "caf\303\251") == 0);
    assert(output.objects.count == 2 &&
           ((child *)output.objects.items)[1].id == 8);
    assert(strcmp(((child *)output.objects.items)[0].name, "first") == 0);
    assert(json_runtime->cleanup(json_runtime, &record_map, &output, &jerror) ==
           LONEJSON_STATUS_OK);
  }
  assert(json_runtime->cleanup(json_runtime, &record_map, &input, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json_runtime);
}
typedef struct value_record {
  lonejson_json_value value;
  lonejson_int64 after;
} value_record;
static const lonejson_field value_fields[] = {
    LONEJSON_FIELD_JSON_VALUE_REQ(value_record, value, "value"),
    LONEJSON_FIELD_I64_REQ(value_record, after, "after")};
LONEJSON_MAP_DEFINE(value_map, value_record, value_fields);
typedef struct stream_record {
  lonejson_string_array_stream strings;
  lonejson_mapped_array_stream objects;
} stream_record;
static const lonejson_field stream_fields[] = {
    LONEJSON_FIELD_STRING_ARRAY_STREAM_REQ(stream_record, strings, "strings"),
    LONEJSON_FIELD_MAPPED_ARRAY_STREAM_REQ(stream_record, objects, "objects")};
LONEJSON_MAP_DEFINE(stream_map, stream_record, stream_fields);
typedef struct text_record {
  char *text;
} text_record;
static const lonejson_field text_fields[] = {
    LONEJSON_FIELD_STRING_ALLOC_REQ(text_record, text, "text")};
LONEJSON_MAP_DEFINE(text_map, text_record, text_fields);
static int json_wire(c89cbor *runtime, const char *json, endpoint *wire) {
  endpoint input;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_error error;
  memset(&input, 0, sizeof(input));
  input.bytes = (const unsigned char *)json;
  input.length = strlen(json);
  input.fragment = 8192;
  memset(wire, 0, sizeof(*wire));
  wire->fragment = 8192;
  source.context = &input;
  source.read = read_bytes;
  sink.context = wire;
  sink.write = write_bytes;
  return runtime->json_to_cbor(runtime, &source, &sink, NULL, &error);
}
static int decode_record(c89cbor *runtime, endpoint *wire,
                         const lonejson_map *map, void *record_storage,
                         const c89cbor_options *options, c89cbor_error *error) {
  c89cbor_conversion operation;
  c89cbor_source source;
  int status;
  wire->bytes = wire->output;
  wire->length = wire->used;
  wire->offset = 0;
  wire->pause = 1;
  source.context = wire;
  source.read = read_bytes;
  status = runtime->decode_map_init(runtime, &operation, &source, map,
                                    record_storage, map->struct_size, options,
                                    error);
  if (status == 0)
    status = drive(&operation, error);
  assert(operation.cleanup(&operation) == 0);
  return status;
}
static void malformed(void) {
  static const unsigned char nul_text[] = {0xa1, 0x64, 't', 'e', 'x',
                                           't',  0x63, 'a', 0,   'b'};
  static const unsigned char duplicate[] = {
      0xa2, 0x64, 't', 'e', 'x', 't', 0x60, 0x64, 't', 'e', 'x', 't', 0x60};
  static const unsigned char unknown_duplicate[] = {
      0xa3, 0x64, 't', 'e', 'x', 't', 0x60, 0x61, 'x', 0, 0x61, 'x', 1};
  static const unsigned char skipped_utf8[] = {0xa2, 0x64, 't', 'e',  'x', 't',
                                               0x60, 0x61, 'x', 0x61, 0xff};
  static const unsigned char indefinite[] = {0xbf, 0x7f, 0x62, 't',  'e',  0x62,
                                             'x',  't',  0xff, 0x7f, 0x61, 'a',
                                             0x62, 0xc3, 0xa9, 0xff, 0xff};
  static const unsigned char trailing[] = {0xa1, 0x64, 't',  'e',
                                           'x',  't',  0x60, 0};
  static const unsigned char missing[] = {0xa0};
  static const unsigned char nontext[] = {0xa1, 0, 0};
  const unsigned char *fixtures[] = {
      nul_text,   duplicate, unknown_duplicate, skipped_utf8,
      indefinite, trailing,  missing,           nontext};
  const size_t lengths[] = {sizeof(nul_text),          sizeof(duplicate),
                            sizeof(unknown_duplicate), sizeof(skipped_utf8),
                            sizeof(indefinite),        sizeof(trailing),
                            sizeof(missing),           sizeof(nontext)};
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  c89cbor_options options = c89cbor_default_options();
  lonejson_error jerror;
  lonejson *json = lonejson_new(NULL, &jerror);
  text_record value;
  endpoint wire;
  size_t i, split;
  int status;
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  options.allow_unknown_fields = 1;
  for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
    for (split = 1; split <= 16; ++split) {
      assert(lonejson_init(json, &text_map, &value, &jerror) ==
             LONEJSON_STATUS_OK);
      memset(&wire, 0, sizeof(wire));
      memcpy(wire.output, fixtures[i], lengths[i]);
      wire.used = lengths[i];
      wire.fragment = split;
      status =
          decode_record(&runtime, &wire, &text_map, &value, &options, &error);
      if (i == 4) {
        assert(status == C89CBOR_DONE);
        assert(strcmp(value.text, "a\303\251") == 0);
      } else
        assert(status < 0);
      assert(json->cleanup(json, &text_map, &value, &jerror) ==
             LONEJSON_STATUS_OK);
    }
  }
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
static lonejson_status json_consumer(void *context, const void *bytes,
                                     size_t length, lonejson_error *error) {
  endpoint *e = context;
  (void)error;
  assert(length <= sizeof(e->output) - e->used);
  memcpy(e->output + e->used, bytes, length);
  e->used += length;
  ++e->writes;
  return LONEJSON_STATUS_PAUSED;
}
static void json_fields(void) {
  static const char body[] =
      "{\"array\":[1,true,null,\"caf\303\251\"],\"object\":{\"k\":\"v\"}}";
  static const char document[] =
      "{\"value\":{\"array\":[1,true,null,\"caf\303\251\"],\"object\":{\"k\":"
      "\"v\"}},\"after\":42}";
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  lonejson_error jerror;
  c89cbor_error error;
  lonejson *json = lonejson_new(NULL, &jerror);
  value_record value;
  c89cbor_conversion operation;
  c89cbor_sink sink;
  endpoint wire, output, validation;
  c89cbor_source source;
  size_t split;
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  for (split = 1; split < 16; ++split) {
    assert(json_wire(&runtime, document, &wire) == 0);
    assert(lonejson_init(json, &value_map, &value, &jerror) ==
           LONEJSON_STATUS_OK);
    assert(lonejson_json_value_enable_parse_capture(&value.value, &jerror) ==
           LONEJSON_STATUS_OK);
    wire.fragment = split;
    assert(decode_record(&runtime, &wire, &value_map, &value, NULL, &error) ==
           C89CBOR_DONE);
    assert(value.after == 42 && value.value.len == strlen(body));
    assert(memcmp(value.value.json, body, strlen(body)) == 0);
    memset(&output, 0, sizeof(output));
    output.fragment = split;
    output.pause = 1;
    sink.context = &output;
    sink.write = write_bytes;
    assert(runtime.encode_map_init(&runtime, &operation, &value_map, &value,
                                   sizeof(value), &sink, NULL, &error) == 0);
    assert(drive(&operation, &error) == C89CBOR_DONE);
    assert(operation.cleanup(&operation) == 0);
    output.bytes = output.output;
    output.length = output.used;
    output.offset = 0;
    output.pause = 0;
    source.context = &output;
    source.read = read_bytes;
    memset(&validation, 0, sizeof(validation));
    validation.fragment = sizeof(validation.output);
    sink.context = &validation;
    assert(runtime.cbor_to_json(&runtime, &source, &sink, NULL, &error) == 0);
    assert(validation.used == strlen(document) &&
           memcmp(validation.output, document, validation.used) == 0);
    assert(json->reset(json, &value_map, &value, &jerror) ==
           LONEJSON_STATUS_OK);
    memset(&output, 0, sizeof(output));
    assert(lonejson_json_value_set_parse_sink(&value.value, json_consumer,
                                              &output,
                                              &jerror) == LONEJSON_STATUS_OK);
    assert(decode_record(&runtime, &wire, &value_map, &value, NULL, &error) ==
           C89CBOR_DONE);
    assert(value.after == 42 && output.used == strlen(body));
    assert(memcmp(output.output, body, output.used) == 0);
    assert(json->cleanup(json, &value_map, &value, &jerror) ==
           LONEJSON_STATUS_OK);
  }
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
typedef struct stream_counts {
  size_t begins, ends, bytes, items;
} stream_counts;
static lonejson_status string_begin(void *context, lonejson_error *error) {
  stream_counts *counts = context;
  (void)error;
  ++counts->begins;
  return LONEJSON_STATUS_PAUSED;
}
static lonejson_status string_chunk(void *context, const char *bytes,
                                    size_t length, lonejson_error *error) {
  stream_counts *counts = context;
  (void)error;
  (void)bytes;
  counts->bytes += length;
  return LONEJSON_STATUS_PAUSED;
}
static lonejson_status string_end(void *context, lonejson_error *error) {
  stream_counts *counts = context;
  (void)error;
  ++counts->ends;
  return LONEJSON_STATUS_PAUSED;
}
static lonejson_status object_item(void *context, void *storage,
                                   lonejson_error *error) {
  stream_counts *counts = context;
  child *item = storage;
  (void)error;
  ++counts->items;
  assert(item->id == (lonejson_int64)counts->items);
  assert(strcmp(item->name, "item") == 0);
  return LONEJSON_STATUS_PAUSED;
}
static void streamed_arrays(void) {
  static const char document[] =
      "{\"strings\":[\"abc\",\"\",\"def\"],\"objects\":[{\"id\":1,\"name\":"
      "\"item\"},{\"id\":2,\"name\":\"item\"}]}";
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  lonejson_error jerror;
  lonejson *json = lonejson_new(NULL, &jerror);
  stream_record value;
  child item;
  stream_counts counts;
  lonejson_array_stream_string_handler strings;
  lonejson_mapped_array_stream_handler objects;
  endpoint wire;
  memset(&counts, 0, sizeof(counts));
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(lonejson_init(json, &stream_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_init(json, &child_map, &item, &jerror) == LONEJSON_STATUS_OK);
  strings.begin = string_begin;
  strings.chunk = string_chunk;
  strings.end = string_end;
  assert(lonejson_string_array_stream_set_handler(
             &value.strings, &strings, &counts, &jerror) == LONEJSON_STATUS_OK);
  objects.item_map = &child_map;
  objects.item_dst = &item;
  objects.item = object_item;
  objects.user = &counts;
  assert(lonejson_mapped_array_stream_set_handler(
             &value.objects, &objects, &jerror) == LONEJSON_STATUS_OK);
  assert(json_wire(&runtime, document, &wire) == 0);
  wire.fragment = 1;
  assert(decode_record(&runtime, &wire, &stream_map, &value, NULL, &error) ==
         C89CBOR_DONE);
  assert(counts.begins == 3 && counts.ends == 3 && counts.bytes == 6 &&
         counts.items == 2);
  assert(item.name == NULL);
  assert(json->cleanup(json, &stream_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(json->cleanup(json, &child_map, &item, &jerror) == LONEJSON_STATUS_OK);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
typedef struct source_record {
  lonejson_source text;
} source_record;
static const lonejson_field source_fields[] = {
    LONEJSON_FIELD_STRING_SOURCE_REQ(source_record, text, "text")};
LONEJSON_MAP_DEFINE(source_map, source_record, source_fields);
static const lonejson_field bytes_source_fields[] = {
    LONEJSON_FIELD_BASE64_SOURCE_REQ(source_record, text, "text")};
LONEJSON_MAP_DEFINE(bytes_source_map, source_record, bytes_source_fields);
typedef struct null_probe {
  endpoint *wire;
  size_t begins, ends, accepted_begin, accepted_end, offset;
} null_probe;
static int null_begin(void *context, const c89cbor_token *token) {
  null_probe *probe = context;
  assert(token->type == C89CBOR_NULL && token->argument == 0 &&
         token->length == 0 && token->data == NULL);
  if (++probe->begins == 1) {
    probe->offset = probe->wire->offset;
    return C89CBOR_OUTPUT;
  }
  assert(probe->wire->offset == probe->offset && probe->accepted_begin == 0);
  ++probe->accepted_begin;
  return C89CBOR_OK;
}
static int null_end(void *context) {
  null_probe *probe = context;
  assert(probe->accepted_begin == 1 && probe->accepted_end == 0 &&
         probe->wire->offset == probe->offset);
  if (++probe->ends == 1)
    return C89CBOR_OUTPUT;
  ++probe->accepted_end;
  return C89CBOR_OK;
}
static int no_payload(void *context, const void *bytes, size_t length,
                      size_t *count) {
  (void)context;
  (void)bytes;
  (void)length;
  *count = 0;
  assert(0);
  return C89CBOR_IO;
}
static void bound_null(void) {
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_error error;
  lonejson_error json_error;
  lonejson *json = lonejson_new(NULL, &json_error);
  source_record value;
  c89cbor_field_sink binding;
  endpoint wire;
  null_probe probe;
  const lonejson_map *schema;
  size_t variant;
  assert(json != NULL);
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  memset(&binding, 0, sizeof(binding));
  binding.path = "/text";
  binding.begin = null_begin;
  binding.end = null_end;
  binding.sink.context = &probe;
  binding.sink.write = no_payload;
  options.field_sinks = &binding;
  options.field_sink_count = 1;
  options.step_events = 1;
  for (variant = 0; variant < 3; ++variant) {
    schema = variant == 1 ? &bytes_source_map : &source_map;
    binding.payload =
        variant == 0 ? C89CBOR_PAYLOAD_TEXT : C89CBOR_PAYLOAD_BYTES;
    assert(lonejson_init(json, schema, &value, &json_error) ==
           LONEJSON_STATUS_OK);
    assert(json_wire(&runtime, "{\"text\":null}", &wire) == 0);
    wire.fragment = 1;
    memset(&probe, 0, sizeof(probe));
    probe.wire = &wire;
    if (variant == 2) {
      assert(decode_record(&runtime, &wire, schema, &value, &options, &error) ==
             C89CBOR_SCHEMA);
      assert(probe.begins == 0 && probe.ends == 0);
    } else {
      assert(decode_record(&runtime, &wire, schema, &value, &options, &error) ==
             C89CBOR_DONE);
      assert(probe.begins == 2 && probe.ends == 2 &&
             probe.accepted_begin == 1 && probe.accepted_end == 1);
    }
    assert(value.text.kind == LONEJSON_SOURCE_NONE);
    assert(json->cleanup(json, schema, &value, &json_error) ==
           LONEJSON_STATUS_OK);
  }
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
typedef struct allocation_count {
  size_t calls, live, fail;
} allocation_count;
static void *tracked_allocate(void *context, size_t size) {
  allocation_count *count = context;
  void *memory;
  if (++count->calls == count->fail)
    return NULL;
  memory = malloc(size);
  if (memory != NULL)
    ++count->live;
  return memory;
}
static void tracked_free(void *context, void *memory) {
  allocation_count *count = context;
  if (memory != NULL) {
    assert(count->live != 0);
    --count->live;
    free(memory);
  }
}
typedef struct large_stream {
  size_t length, offset, received, begins, ends, writes;
  int begin_blocked, end_blocked, early;
  unsigned char prefix[11];
  size_t prefix_length;
} large_stream;
static int large_read(void *context, void *buffer, size_t capacity,
                      size_t *count) {
  large_stream *stream = context;
  unsigned char *bytes = buffer;
  size_t take = stream->prefix_length + stream->length - stream->offset, i;
  if (take > capacity)
    take = capacity;
  for (i = 0; i < take; ++i) {
    bytes[i] = stream->offset < stream->prefix_length
                   ? stream->prefix[stream->offset]
                   : 'x';
    ++stream->offset;
  }
  *count = take;
  return C89CBOR_OK;
}
static int large_write(void *context, const void *buffer, size_t length,
                       size_t *count) {
  large_stream *stream = context;
  const unsigned char *bytes = buffer;
  size_t i, take = length < 127u ? length : 127u;
  for (i = 0; i < take; ++i)
    assert(bytes[i] == 'x');
  stream->received += take;
  ++stream->writes;
  if (stream->offset < stream->prefix_length + stream->length)
    stream->early = 1;
  *count = take;
  return C89CBOR_OUTPUT;
}
static int large_begin(void *context, const c89cbor_token *token) {
  large_stream *stream = context;
  assert(token->type == C89CBOR_TEXT && token->argument == stream->length);
  if (!stream->begin_blocked) {
    stream->begin_blocked = 1;
    return C89CBOR_OUTPUT;
  }
  ++stream->begins;
  return C89CBOR_OK;
}
static int large_end(void *context) {
  large_stream *stream = context;
  if (!stream->end_blocked) {
    stream->end_blocked = 1;
    return C89CBOR_OUTPUT;
  }
  ++stream->ends;
  return C89CBOR_OK;
}
static void bound_payload(void) {
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_error error;
  lonejson_error jerror;
  lonejson *json = lonejson_new(NULL, &jerror);
  source_record value;
  large_stream stream;
  allocation_count allocations;
  c89cbor_source source;
  c89cbor_conversion *operation;
  c89cbor_field_sink binding;
  size_t calls;
  memset(&allocations, 0, sizeof(allocations));
  memset(&stream, 0, sizeof(stream));
  config.json = json;
  config.allocator.alloc = tracked_allocate;
  config.allocator.free = tracked_free;
  config.allocator.context = &allocations;
  stream.length = 3u * 1024u * 1024u;
  stream.prefix[0] = 0xa1;
  stream.prefix[1] = 0x64;
  memcpy(stream.prefix + 2, "text", 4);
  stream.prefix[6] = 0x7a;
  stream.prefix[7] = 0;
  stream.prefix[8] = 0x30;
  stream.prefix[9] = 0;
  stream.prefix[10] = 0;
  stream.prefix_length = sizeof(stream.prefix);
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(lonejson_init(json, &source_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  memset(&binding, 0, sizeof(binding));
  binding.path = "/text";
  binding.sink.context = &stream;
  binding.sink.write = large_write;
  binding.begin = large_begin;
  binding.end = large_end;
  options.field_sinks = &binding;
  options.field_sink_count = 1;
  options.step_output = 113;
  source.context = &stream;
  source.read = large_read;
  assert(runtime.decode_map_open(&runtime, &source, &source_map, &value,
                                 sizeof(value), &options, &operation,
                                 &error) == 0);
  calls = allocations.calls;
  assert(drive(operation, &error) == C89CBOR_DONE);
  assert(stream.received == stream.length && stream.begins == 1 &&
         stream.ends == 1 && stream.early);
  assert(allocations.calls == calls);
  assert(operation->destroy(operation) == 0 && allocations.live == 0);
  assert(json->cleanup(json, &source_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
static void allocation_failures(void) {
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  lonejson_error jerror;
  lonejson *json = lonejson_new(NULL, &jerror);
  text_record value;
  endpoint output;
  c89cbor_sink sink;
  c89cbor_conversion *operation;
  allocation_count count;
  size_t point;
  int status;
  config.json = json;
  config.allocator.alloc = tracked_allocate;
  config.allocator.free = tracked_free;
  config.allocator.context = &count;
  assert(lonejson_init(json, &text_map, &value, &jerror) == LONEJSON_STATUS_OK);
  assert(lonejson_record_assign_string(json, &text_map, &value, text_fields,
                                       "hello", 5,
                                       &jerror) == LONEJSON_STATUS_OK);
  memset(&output, 0, sizeof(output));
  output.fragment = 2;
  sink.context = &output;
  sink.write = write_bytes;
  for (point = 1; point < 32; ++point) {
    memset(&count, 0, sizeof(count));
    count.fail = point;
    assert(c89cbor_init(&runtime, &config, &error) == 0);
    status = runtime.encode_map_open(&runtime, &text_map, &value, sizeof(value),
                                     &sink, NULL, &operation, &error);
    if (status == 0) {
      assert(drive(operation, &error) == C89CBOR_DONE);
      assert(operation->destroy(operation) == 0);
    } else {
      assert(status == C89CBOR_NOMEM && operation == NULL);
    }
    assert(runtime.cleanup(&runtime) == 0 && count.live == 0);
    if (status == 0)
      break;
  }
  assert(point > 10 && point < 32);
  assert(json->cleanup(json, &text_map, &value, &jerror) == LONEJSON_STATUS_OK);
  lonejson_free(json);
}
typedef struct wire_validator {
  c89cbor_decoder decoder;
  size_t payload, data_calls;
} wire_validator;
static int validate_output(void *context, const void *bytes, size_t length,
                           size_t *count) {
  wire_validator *validator = context;
  c89cbor_token token;
  size_t take = length < 127u ? length : 127u, offset = 0, consumed, i;
  int status;
  do {
    status = validator->decoder.next(&validator->decoder,
                                     (const unsigned char *)bytes + offset,
                                     take - offset, &consumed, &token);
    offset += consumed;
    assert(status >= 0);
    if (status == C89CBOR_TOKEN && token.type == C89CBOR_DATA) {
      ++validator->data_calls;
      if (validator->data_calls > 1) {
        for (i = 0; i < token.length; ++i)
          assert(((const unsigned char *)token.data)[i] == 'x');
        validator->payload += token.length;
      }
    }
  } while (status == C89CBOR_TOKEN);
  assert(offset == take);
  *count = take;
  return C89CBOR_OUTPUT;
}
static void source_payload(void) {
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  lonejson_error jerror;
  c89cbor_error error;
  lonejson *json = lonejson_new(NULL, &jerror);
  c89cbor_conversion *operation;
  source_record value;
  wire_validator validator;
  c89cbor_sink sink;
  allocation_count allocations;
  unsigned char chunk[2048];
  size_t i, calls, total = 3u * 1024u * 1024u;
  FILE *file = tmpfile();
  assert(file != NULL);
  memset(chunk, 'x', sizeof(chunk));
  for (i = 0; i < total / sizeof(chunk); ++i)
    assert(fwrite(chunk, 1, sizeof(chunk), file) == sizeof(chunk));
  rewind(file);
  memset(&allocations, 0, sizeof(allocations));
  memset(&validator, 0, sizeof(validator));
  config.json = json;
  config.allocator.context = &allocations;
  config.allocator.alloc = tracked_allocate;
  config.allocator.free = tracked_free;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(c89cbor_decoder_init(NULL, &validator.decoder, NULL, 0, 0) == 0);
  assert(lonejson_init(json, &source_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_source_set_file(&value.text, file, &jerror) ==
         LONEJSON_STATUS_OK);
  sink.context = &validator;
  sink.write = validate_output;
  assert(runtime.encode_map_open(&runtime, &source_map, &value, sizeof(value),
                                 &sink, NULL, &operation, &error) == 0);
  assert(ftell(file) == 0);
  calls = allocations.calls;
  assert(drive(operation, &error) == C89CBOR_DONE &&
         allocations.calls == calls);
  assert(validator.payload == total &&
         validator.decoder.finish(&validator.decoder) == 0);
  assert(ftell(file) == (long)total);
  assert(operation->destroy(operation) == 0 && allocations.live == 0);
  assert(validator.decoder.cleanup(&validator.decoder) == 0);
  assert(json->cleanup(json, &source_map, &value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(fseek(file, 0, SEEK_SET) == 0 && fclose(file) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
typedef struct fixed_record {
  char text[4];
  lonejson_i64_array integers;
  lonejson_int64 number;
  int present;
} fixed_record;
static const lonejson_field fixed_fields[] = {
    LONEJSON_FIELD_STRING_FIXED(fixed_record, text, "text",
                                LONEJSON_OVERFLOW_TRUNCATE_SILENT),
    LONEJSON_FIELD_I64_ARRAY(fixed_record, integers, "integers",
                             LONEJSON_OVERFLOW_TRUNCATE_SILENT),
    LONEJSON_FIELD_I64_PRESENT_NULLABLE(fixed_record, number, present,
                                        "number")};
LONEJSON_MAP_DEFINE(fixed_map, fixed_record, fixed_fields);
static void fixed_text_truncation(void) {
  static const char *const inputs[] = {"",
                                       "abc",
                                       "abcd",
                                       "ab\303\251x",
                                       "a\342\202\254x",
                                       "\360\237\230\200x",
                                       "\342\202\254x",
                                       "a\303\251x"};
  static const char *const expected[] = {
      "", "abc", "abc", "ab", "a", "", "\342\202\254", "a\303\251"};
  static const lonejson_overflow_policy policies[] = {
      LONEJSON_OVERFLOW_FAIL, LONEJSON_OVERFLOW_TRUNCATE,
      LONEJSON_OVERFLOW_TRUNCATE_SILENT};
  c89cbor runtime;
  c89cbor_error error;
  c89cbor_options options = c89cbor_default_options();
  lonejson_error jerror;
  lonejson *json = lonejson_new(NULL, &jerror);
  c89cbor_config config = c89cbor_default_config();
  lonejson_field field = fixed_fields[0];
  lonejson_map map = fixed_map;
  fixed_record value;
  endpoint wire;
  size_t i, policy, split, length, at;
  int indefinite, status, truncated;
  assert(json != NULL);
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  map.fields = &field;
  map.field_count = 1;
  for (policy = 0; policy < sizeof(policies) / sizeof(policies[0]); ++policy) {
    field.overflow_policy = policies[policy];
    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
      length = strlen(inputs[i]);
      truncated = length >= sizeof(value.text);
      for (indefinite = 0; indefinite < 2; ++indefinite)
        for (split = 1; split <= 16; ++split) {
          memset(&wire, 0, sizeof(wire));
          memcpy(wire.output, "\241\144text", 6);
          at = 6;
          if (indefinite)
            wire.output[at++] = 0x7f;
          wire.output[at++] = (unsigned char)(0x60u + length);
          memcpy(wire.output + at, inputs[i], length);
          at += length;
          if (indefinite)
            wire.output[at++] = 0xff;
          wire.used = at;
          wire.fragment = split;
          assert(lonejson_init(json, &map, &value, &jerror) ==
                 LONEJSON_STATUS_OK);
          status =
              decode_record(&runtime, &wire, &map, &value, &options, &error);
          assert(status == (truncated && policies[policy] !=
                                             LONEJSON_OVERFLOW_TRUNCATE_SILENT
                                ? C89CBOR_LIMIT
                                : C89CBOR_DONE));
          if (!truncated || policies[policy] != LONEJSON_OVERFLOW_FAIL) {
            assert(strcmp(value.text, expected[i]) == 0);
            assert(error.truncated == truncated);
            if (truncated && policies[policy] == LONEJSON_OVERFLOW_TRUNCATE)
              assert(error.cause == LONEJSON_STATUS_TRUNCATED);
          }
          assert(json->cleanup(json, &map, &value, &jerror) ==
                 LONEJSON_STATUS_OK);
        }
    }
  }
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
static void policies_and_views(void) {
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  lonejson_error jerror;
  c89cbor_error error;
  lonejson *json = lonejson_new(NULL, &jerror);
  fixed_record value;
  lonejson_int64 backing[1];
  c89cbor_options options = c89cbor_default_options();
  lonejson_record_view view;
  c89cbor_conversion operation;
  c89cbor_sink sink;
  endpoint wire, output;
  lonejson_field bad_fields[sizeof(fixed_fields) / sizeof(fixed_fields[0])];
  lonejson_map bad_map = fixed_map;
  size_t split;
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  for (split = 1; split <= 32; ++split) {
    assert(json_wire(&runtime,
                     "{\"text\":\"ab\303\251cdefgh\",\"integers\":[1,2,3],"
                     "\"number\":null}",
                     &wire) == 0);
    assert(lonejson_init(json, &fixed_map, &value, &jerror) ==
           LONEJSON_STATUS_OK);
    value.integers.items = backing;
    value.integers.capacity = 1;
    value.integers.flags = LONEJSON_ARRAY_FIXED_CAPACITY;
    options.record_bytes = 12;
    options.array_elements = 1;
    wire.fragment = split;
    assert(decode_record(&runtime, &wire, &fixed_map, &value, &options,
                         &error) == C89CBOR_DONE);
    assert(strcmp(value.text, "ab") == 0 && error.truncated && !value.present);
    assert(value.integers.count == 1 && backing[0] == 1);
    memset(&view, 0, sizeof(view));
    view.size = sizeof(view);
    view.abi_version = LONEJSON_VIEW_ABI_VERSION;
    view.schema.size = sizeof(view.schema);
    view.schema.abi_version = LONEJSON_VIEW_ABI_VERSION;
    view.schema.runtime = json;
    view.schema.map = &fixed_map;
    view.schema.record_size = sizeof(value);
    view.record = &value;
    memset(&output, 0, sizeof(output));
    output.fragment = 32;
    sink.context = &output;
    sink.write = write_bytes;
    assert(runtime.encode_map_view_init(&runtime, &operation, &view, &sink,
                                        NULL, &error) == 0);
    assert(drive(&operation, &error) == C89CBOR_DONE &&
           operation.cleanup(&operation) == 0);
    view.flags = 1;
    assert(runtime.encode_map_view_init(&runtime, &operation, &view, &sink,
                                        NULL, &error) == C89CBOR_INVALID);
    assert(operation.cleanup(&operation) == 0);
    assert(json->cleanup(json, &fixed_map, &value, &jerror) ==
           LONEJSON_STATUS_OK);
  }
  memcpy(bad_fields, fixed_fields, sizeof(fixed_fields));
  bad_map.fields = bad_fields;
  bad_fields[0].struct_offset = sizeof(value);
  assert(runtime.encode_map_init(&runtime, &operation, &bad_map, &value,
                                 sizeof(value), &sink, NULL,
                                 &error) == C89CBOR_INVALID);
  assert(operation.cleanup(&operation) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
typedef struct spool_record {
  lonejson_spooled text, bytes;
} spool_record;
static const lonejson_field spool_fields[] = {
    LONEJSON_FIELD_STRING_STREAM_REQ(spool_record, text, "text"),
    LONEJSON_FIELD_BASE64_STREAM_REQ(spool_record, bytes, "bytes")};
LONEJSON_MAP_DEFINE(spool_map, spool_record, spool_fields);
static void spool_fields_test(void) {
  static const char text[] = "a\303\251\342\202\254\360\237\230\200z";
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_error error;
  lonejson_error jerror;
  lonejson_read_result result;
  lonejson *json = lonejson_new(NULL, &jerror);
  spool_record input, output;
  source_record source_value;
  c89cbor_conversion operation;
  c89cbor_sink sink;
  endpoint wire, validated;
  c89cbor_source source;
  unsigned char bytes[256], readback[256];
  size_t i, split;
  FILE *file;
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  for (i = 0; i < sizeof(bytes); ++i)
    bytes[i] = (unsigned char)i;
  assert(lonejson_init(json, &spool_map, &input, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_spooled_append(&input.text, text, strlen(text), &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_spooled_append(&input.bytes, bytes, sizeof(bytes), &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_spooled_rewind(&input.bytes, &jerror) == LONEJSON_STATUS_OK);
  result = lonejson_spooled_read(&input.bytes, readback, 3);
  assert(result.bytes_read == 3);
  for (split = 1; split <= 5; ++split) {
    memset(&wire, 0, sizeof(wire));
    wire.fragment = split;
    wire.pause = 1;
    options.chunk = split;
    sink.context = &wire;
    sink.write = write_bytes;
    assert(runtime.encode_map_init(&runtime, &operation, &spool_map, &input,
                                   sizeof(input), &sink, &options,
                                   &error) == 0);
    assert(drive(&operation, &error) == C89CBOR_DONE &&
           operation.cleanup(&operation) == 0);
    assert(lonejson_init(json, &spool_map, &output, &jerror) ==
           LONEJSON_STATUS_OK);
    assert(decode_record(&runtime, &wire, &spool_map, &output, &options,
                         &error) == C89CBOR_DONE);
    assert(lonejson_spooled_size(&output.text) == strlen(text));
    assert(lonejson_spooled_rewind(&output.bytes, &jerror) ==
           LONEJSON_STATUS_OK);
    result = lonejson_spooled_read(&output.bytes, readback, sizeof(readback));
    assert(result.bytes_read == sizeof(bytes) &&
           memcmp(readback, bytes, sizeof(bytes)) == 0);
    assert(json->cleanup(json, &spool_map, &output, &jerror) ==
           LONEJSON_STATUS_OK);
  }
  result = lonejson_spooled_read(&input.bytes, readback, 3);
  assert(result.bytes_read == 3 && readback[0] == 3);
  assert(json->cleanup(json, &spool_map, &input, &jerror) ==
         LONEJSON_STATUS_OK);
  file = tmpfile();
  assert(file != NULL);
  assert(fwrite(text, 1, strlen(text), file) == strlen(text));
  rewind(file);
  assert(lonejson_init(json, &source_map, &source_value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_source_set_file(&source_value.text, file, &jerror) ==
         LONEJSON_STATUS_OK);
  memset(&wire, 0, sizeof(wire));
  wire.fragment = 1;
  options.chunk = 1;
  sink.context = &wire;
  assert(runtime.encode_map(&runtime, &source_map, &source_value,
                            sizeof(source_value), &sink, &options,
                            &error) == 0);
  wire.bytes = wire.output;
  wire.length = wire.used;
  wire.offset = 0;
  source.context = &wire;
  source.read = read_bytes;
  memset(&validated, 0, sizeof(validated));
  validated.fragment = 1024;
  sink.context = &validated;
  assert(runtime.cbor_to_json(&runtime, &source, &sink, NULL, &error) == 0);
  assert(validated.used == strlen(text) + 11u);
  assert(memcmp(validated.output + 9, text, strlen(text)) == 0);
  assert(json->cleanup(json, &source_map, &source_value, &jerror) ==
         LONEJSON_STATUS_OK);
  assert(fclose(file) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
}
static void *run_tests(void *unused) {
  (void)unused;
  roundtrip();
  malformed();
  json_fields();
  streamed_arrays();
  bound_payload();
  bound_null();
  allocation_failures();
  source_payload();
  fixed_text_truncation();
  policies_and_views();
  spool_fields_test();
  return NULL;
}
int main(void) {
  pthread_t thread;
  assert(pthread_create(&thread, NULL, run_tests, NULL) == 0);
  assert(pthread_join(thread, NULL) == 0);
  return 0;
}
