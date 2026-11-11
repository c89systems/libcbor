#include "measure.h"
#include "records.h"
#include <c89cbor/lonejson.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const lonejson_field scalar_fields[] = {
    LONEJSON_FIELD_I64_REQ(bench_scalar, a, "a"),
    LONEJSON_FIELD_I64_REQ(bench_scalar, b, "b"),
    LONEJSON_FIELD_I64_REQ(bench_scalar, c, "c"),
    LONEJSON_FIELD_U64_REQ(bench_scalar, mask, "mask"),
    LONEJSON_FIELD_F64_REQ(bench_scalar, ratio, "ratio"),
    LONEJSON_FIELD_BOOL_REQ(bench_scalar, enabled, "enabled"),
    LONEJSON_FIELD_STRING_FIXED_REQ(bench_scalar, label, "label",
                                    LONEJSON_OVERFLOW_FAIL)};
LONEJSON_MAP_DEFINE(scalar_map, bench_scalar, scalar_fields);
static const lonejson_field nested_fields[] = {
    LONEJSON_FIELD_OBJECT_REQ(bench_nested, first, "first", &scalar_map),
    LONEJSON_FIELD_OBJECT_REQ(bench_nested, second, "second", &scalar_map)};
LONEJSON_MAP_DEFINE(nested_map, bench_nested, nested_fields);
static const lonejson_field text_fields[] = {
    LONEJSON_FIELD_I64_REQ(bench_text, id, "id"),
    LONEJSON_FIELD_STRING_FIXED_REQ(bench_text, body, "body",
                                    LONEJSON_OVERFLOW_FAIL)};
LONEJSON_MAP_DEFINE(text_map, bench_text, text_fields);
typedef struct memory {
  bench_counts *counts;
  const unsigned char *input;
  size_t length, offset, used;
  unsigned char output[BENCH_CAPACITY];
} memory;
typedef struct benchmark {
  c89cbor runtime;
  lonejson *json;
  lonejson_allocator allocator;
  bench_counts counts;
  bench_record input, output;
  const lonejson_map *map;
  c89cbor_options options;
  memory wire, text;
  unsigned char native_wire[BENCH_CAPACITY], expected[BENCH_CAPACITY],
      json_fixture[BENCH_CAPACITY];
  size_t native_length, expected_length, json_length;
  int verify_output;
  bench_samples samples;
} benchmark;
enum mode {
  MAPPED_ENCODE,
  MAPPED_DECODE,
  JSON_CONTROL_ENCODE,
  JSON_CONTROL_DECODE,
  JSON_ENCODE,
  JSON_DECODE
};
static const char *const mode_names[] = {
    "mapped-encode",       "mapped-decode", "json-control-encode",
    "json-control-decode", "json-to-cbor",  "cbor-to-json"};
static int read_bytes(void *context, void *bytes, size_t capacity,
                      size_t *count) {
  memory *m = context;
  size_t take = m->length - m->offset;
  if (take > capacity)
    take = capacity;
  if (take != 0)
    memcpy(bytes, m->input + m->offset, take);
  m->offset += take;
  *count = take;
  ++m->counts->reads;
  m->counts->copies += (uint64_t)take;
  return C89CBOR_OK;
}
static int write_bytes(void *context, const void *bytes, size_t length,
                       size_t *count) {
  memory *m = context;
  assert(length <= sizeof(m->output) - m->used);
  memcpy(m->output + m->used, bytes, length);
  m->used += length;
  *count = length;
  ++m->counts->writes;
  m->counts->copies += (uint64_t)length;
  return C89CBOR_OK;
}
static lonejson_status write_json(void *context, const void *bytes,
                                  size_t length, lonejson_error *error) {
  size_t count;
  (void)error;
  return write_bytes(context, bytes, length, &count) == 0
             ? LONEJSON_STATUS_OK
             : LONEJSON_STATUS_CALLBACK_FAILED;
}
static void reset_record(benchmark *b) {
  lonejson_error error;
  assert(lonejson_reset(b->json, b->map, bench_record_data(&b->output),
                        &error) == LONEJSON_STATUS_OK);
}
static void run_once(benchmark *b, enum mode mode) {
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_error error;
  lonejson_error json_error;
  b->wire.offset = b->wire.used = b->text.offset = b->text.used = 0;
  b->wire.input = b->native_wire;
  b->wire.length = b->native_length;
  source.read = read_bytes;
  sink.write = write_bytes;
  source.context = &b->wire;
  sink.context = &b->wire;
  if (mode == MAPPED_ENCODE) {
    assert(b->runtime.encode_map(
               &b->runtime, b->map, bench_record_const_data(&b->input),
               b->map->struct_size, &sink, &b->options, &error) == 0);
  } else if (mode == MAPPED_DECODE) {
    reset_record(b);
    assert(b->runtime.decode_map(
               &b->runtime, &source, b->map, bench_record_data(&b->output),
               b->map->struct_size, &b->options, &error) == 0);
    assert(bench_record_equal(&b->input, &b->output));
  } else if (mode == JSON_CONTROL_ENCODE || mode == JSON_ENCODE) {
    if (mode == JSON_CONTROL_ENCODE) {
      assert(lonejson_serialize_sink(
                 b->json, b->map, bench_record_const_data(&b->input),
                 write_json, &b->text, &json_error) == LONEJSON_STATUS_OK);
      b->text.input = b->text.output;
      b->text.length = b->text.used;
    } else {
      b->text.input = b->json_fixture;
      b->text.length = b->json_length;
    }
    source.context = &b->text;
    assert(b->runtime.json_to_cbor(&b->runtime, &source, &sink, &b->options,
                                   &error) == 0);
  } else {
    sink.context = &b->text;
    assert(b->runtime.cbor_to_json(&b->runtime, &source, &sink, &b->options,
                                   &error) == 0);
    if (mode == JSON_CONTROL_DECODE) {
      reset_record(b);
      assert(lonejson_parse_buffer(
                 b->json, b->map, bench_record_data(&b->output), b->text.output,
                 b->text.used, &json_error) == LONEJSON_STATUS_OK);
      assert(bench_record_equal(&b->input, &b->output));
    }
  }
  if (b->verify_output && mode != MAPPED_DECODE &&
      mode != JSON_CONTROL_DECODE) {
    memory *result = mode == JSON_DECODE ? &b->text : &b->wire;
    assert(result->used == b->expected_length &&
           memcmp(result->output, b->expected, result->used) == 0);
  }
}
static void prepare(benchmark *b, bench_kind kind, enum mode mode,
                    size_t chunk) {
  c89cbor_config config = c89cbor_default_config();
  lonejson_config json_config = lonejson_default_config();
  c89cbor_error error;
  lonejson_error json_error;
  c89cbor_sink sink;
  c89cbor_source source;
  memset(b, 0, sizeof(*b));
  b->allocator.malloc_fn = bench_allocate;
  b->allocator.realloc_fn = bench_reallocate;
  b->allocator.free_fn = bench_free;
  b->allocator.ctx = &b->counts;
  json_config.allocator = &b->allocator;
  b->json = lonejson_new(&json_config, &json_error);
  assert(b->json != NULL);
  config.json = b->json;
  config.allocator.context = &b->counts;
  config.allocator.alloc = bench_allocate;
  config.allocator.free = bench_free;
  assert(c89cbor_init(&b->runtime, &config, &error) == 0);
  b->options = c89cbor_default_options();
  b->options.chunk = chunk;
  b->map = kind == BENCH_SCALAR   ? &scalar_map
           : kind == BENCH_NESTED ? &nested_map
                                  : &text_map;
  bench_record_fill(&b->input, kind);
  b->output.kind = kind;
  assert(lonejson_init(b->json, b->map, bench_record_data(&b->output),
                       &json_error) == LONEJSON_STATUS_OK);
  b->wire.counts = b->text.counts = &b->counts;
  sink.context = &b->wire;
  sink.write = write_bytes;
  assert(b->runtime.encode_map(
             &b->runtime, b->map, bench_record_const_data(&b->input),
             b->map->struct_size, &sink, &b->options, &error) == 0);
  b->native_length = b->wire.used;
  memcpy(b->native_wire, b->wire.output, b->native_length);
  if (mode == JSON_ENCODE) {
    assert(lonejson_serialize_sink(
               b->json, b->map, bench_record_const_data(&b->input), write_json,
               &b->text, &json_error) == LONEJSON_STATUS_OK);
    b->json_length = b->text.used;
    memcpy(b->json_fixture, b->text.output, b->json_length);
  }
  run_once(b, mode);
  if (mode != MAPPED_DECODE && mode != JSON_CONTROL_DECODE) {
    memory *result = mode == JSON_DECODE ? &b->text : &b->wire;
    b->expected_length = result->used;
    memcpy(b->expected, result->output, result->used);
    b->verify_output = 1;
    if (mode == JSON_DECODE) {
      assert(lonejson_parse_buffer(
                 b->json, b->map, bench_record_data(&b->output), result->output,
                 result->used, &json_error) == LONEJSON_STATUS_OK);
    } else {
      b->text.input = result->output;
      b->text.length = result->used;
      b->text.offset = 0;
      source.context = &b->text;
      source.read = read_bytes;
      assert(b->runtime.decode_map(
                 &b->runtime, &source, b->map, bench_record_data(&b->output),
                 b->map->struct_size, &b->options, &error) == 0);
    }
    assert(bench_record_equal(&b->input, &b->output));
  }
}
int main(int argc, char **argv) {
  benchmark *b = malloc(sizeof(*b));
  enum mode mode;
  bench_kind kind;
  size_t repetitions = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 10000u;
  size_t chunk = argc > 3 ? (size_t)strtoul(argv[3], NULL, 10) : 0;
  size_t i, sample, batch, records;
  int round;
  double setup, begin, cpu, seconds, cpu_seconds, at;
  bench_counts snapshot;
  lonejson_error error;
  if (b != NULL && argc == 2 && strcmp(argv[1], "check") == 0) {
    for (kind = BENCH_SCALAR; kind <= BENCH_LAST;
         kind = (bench_kind)((int)kind + 1)) {
      for (mode = MAPPED_ENCODE; mode <= JSON_DECODE;
           mode = (enum mode)((int)mode + 1)) {
        prepare(b, kind, mode, 0);
        run_once(b, mode);
        assert(b->json->cleanup(b->json, b->map, bench_record_data(&b->output),
                                &error) == LONEJSON_STATUS_OK);
        assert(b->runtime.cleanup(&b->runtime) == 0);
        lonejson_free(b->json);
        assert(b->counts.bytes == 0);
      }
    }
    free(b);
    return 0;
  }
  if (b != NULL && argc == 3 &&
      (strcmp(argv[1], "emit") == 0 || strcmp(argv[1], "verify") == 0)) {
    for (kind = BENCH_SCALAR;
         kind <= BENCH_LAST && strcmp(argv[2], bench_fixture_name(kind)) != 0;
         kind = (bench_kind)((int)kind + 1)) {
    }
    assert(kind <= BENCH_LAST);
    prepare(b, kind, MAPPED_ENCODE, 0);
    if (strcmp(argv[1], "emit") == 0)
      assert(fwrite(b->native_wire, 1, b->native_length, stdout) ==
             b->native_length);
    else {
      b->native_length =
          fread(b->native_wire, 1, sizeof(b->native_wire), stdin);
      assert(fgetc(stdin) == EOF);
      run_once(b, MAPPED_DECODE);
    }
    assert(b->json->cleanup(b->json, b->map, bench_record_data(&b->output),
                            &error) == LONEJSON_STATUS_OK);
    assert(b->runtime.cleanup(&b->runtime) == 0);
    lonejson_free(b->json);
    assert(b->counts.bytes == 0);
    free(b);
    return 0;
  }
  if (b == NULL)
    return 1;
  if (argc < 2 || repetitions == 0) {
    free(b);
    return 1;
  }
  for (mode = MAPPED_ENCODE;
       mode <= JSON_DECODE && strcmp(argv[1], mode_names[(int)mode]) != 0;
       mode = (enum mode)((int)mode + 1)) {
  }
  if (mode > JSON_DECODE) {
    free(b);
    return 1;
  }
  for (kind = BENCH_SCALAR; kind <= BENCH_LAST;
       kind = (bench_kind)((int)kind + 1)) {
    setup = bench_wall();
    prepare(b, kind, mode, chunk);
    setup = bench_wall() - setup;
    records = kind >= BENCH_LARGE_ASCII ? repetitions / 16u + 1u : repetitions;
    for (round = -1; round < 5; ++round) {
      bench_counts_reset(&b->counts);
      begin = bench_wall();
      cpu = bench_cpu();
      for (i = 0; i < records; ++i)
        run_once(b, mode);
      cpu_seconds = bench_cpu() - cpu;
      seconds = bench_wall() - begin;
      snapshot = b->counts;
      if (round < 0)
        continue;
      b->samples.count = kind >= BENCH_LARGE_ASCII ? 128u : 256u;
      b->samples.batch = kind >= BENCH_LARGE_ASCII ? 1u : 16u;
      for (sample = 0; sample < b->samples.count; ++sample) {
        at = bench_wall();
        for (batch = 0; batch < b->samples.batch; ++batch)
          run_once(b, mode);
        b->samples.values[sample] =
            (bench_wall() - at) * 1e9 / (double)b->samples.batch;
      }
      bench_report("c89.systems", mode_names[(int)mode],
                   bench_fixture_name(kind), round, records,
                   mode == MAPPED_ENCODE || mode == JSON_CONTROL_ENCODE ||
                           mode == JSON_ENCODE
                       ? b->wire.used
                       : b->native_length,
                   seconds, cpu_seconds, setup, &snapshot, &b->samples);
    }
    assert(b->json->cleanup(b->json, b->map, bench_record_data(&b->output),
                            &error) == LONEJSON_STATUS_OK);
    assert(b->runtime.cleanup(&b->runtime) == 0);
    lonejson_free(b->json);
    assert(b->counts.bytes == 0);
  }
  free(b);
  return 0;
}
