/* C record -> PJK DOM -> CBOR and CBOR -> PJK DOM -> C record. This executable
 * links PJK/libcbor alone and performs the same field/range/presence checks. */
#include "measure.h"
#include "records.h"
/* PJK's C99 public headers spell restrict directly. Preserve its qualifier
 * using the compiler's accepted C89 spelling, without changing the ABI. */
#define restrict __restrict__
#include <cbor.h>
#undef restrict
#include <assert.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bench_counts allocations;
static void *allocate(size_t length) {
  return bench_allocate(&allocations, length);
}
static void *reallocate(void *memory, size_t length) {
  return bench_reallocate(&allocations, memory, length);
}
static void release(void *memory) { bench_free(&allocations, memory); }
static cbor_item_t *build_uint(uint64_t value, int negative) {
  if (value <= UINT8_MAX)
    return negative ? cbor_build_negint8((uint8_t)value)
                    : cbor_build_uint8((uint8_t)value);
  if (value <= UINT16_MAX)
    return negative ? cbor_build_negint16((uint16_t)value)
                    : cbor_build_uint16((uint16_t)value);
  if (value <= UINT32_MAX)
    return negative ? cbor_build_negint32((uint32_t)value)
                    : cbor_build_uint32((uint32_t)value);
  return negative ? cbor_build_negint64(value) : cbor_build_uint64(value);
}
static cbor_item_t *build_int(bench_i64 value) {
  return build_uint(value < 0 ? (uint64_t)(-(value + 1)) : (uint64_t)value,
                    value < 0);
}
static void add(cbor_item_t *map, const char *key, cbor_item_t *value) {
  struct cbor_pair pair;
  pair.key = cbor_build_string(key);
  pair.value = value;
  assert(pair.key != NULL && value != NULL && cbor_map_add(map, pair));
  cbor_decref(&pair.key);
  cbor_decref(&value);
}
static cbor_item_t *build_scalar(const bench_scalar *value) {
  cbor_item_t *map = cbor_new_definite_map(7);
  assert(map != NULL);
  add(map, "a", build_int(value->a));
  add(map, "b", build_int(value->b));
  add(map, "c", build_int(value->c));
  add(map, "mask", build_uint((uint64_t)value->mask, 0));
  add(map, "ratio", cbor_build_float8(value->ratio));
  add(map, "enabled", cbor_build_bool(value->enabled != 0));
  add(map, "label", cbor_build_string(value->label));
  return map;
}
static cbor_item_t *build_record(const bench_record *value) {
  cbor_item_t *map;
  if (value->kind == BENCH_SCALAR)
    return build_scalar(&value->data.scalar);
  map = cbor_new_definite_map(2);
  assert(map != NULL);
  if (value->kind == BENCH_NESTED) {
    add(map, "first", build_scalar(&value->data.nested.first));
    add(map, "second", build_scalar(&value->data.nested.second));
  } else {
    add(map, "id", build_int(value->data.text.id));
    add(map, "body", cbor_build_string(value->data.text.body));
  }
  return map;
}
static int key_index(const cbor_item_t *key, const char *const *names,
                     size_t count) {
  size_t i;
  assert(cbor_isa_string(key) && cbor_string_is_definite(key));
  for (i = 0; i < count; ++i)
    if (cbor_string_length(key) == strlen(names[i]) &&
        memcmp(cbor_string_handle(key), names[i], strlen(names[i])) == 0)
      return (int)i;
  abort();
  return -1;
}
static bench_i64 read_int(const cbor_item_t *item) {
  uint64_t value;
  assert(cbor_isa_uint(item) || cbor_isa_negint(item));
  value = cbor_get_int(item);
  assert(value <= (uint64_t)INT64_MAX);
  return cbor_isa_negint(item) ? (bench_i64)(-1 - (bench_i64)value)
                               : (bench_i64)value;
}
static void read_text(const cbor_item_t *item, char *output, size_t capacity) {
  size_t length;
  assert(cbor_isa_string(item) && cbor_string_is_definite(item));
  length = cbor_string_length(item);
  assert(length < capacity &&
         memchr(cbor_string_handle(item), 0, length) == NULL);
  memcpy(output, cbor_string_handle(item), length);
  allocations.copies += (uint64_t)length;
  output[length] = '\0';
}
static void read_scalar(const cbor_item_t *item, bench_scalar *output) {
  static const char *const names[] = {"a",     "b",       "c",    "mask",
                                      "ratio", "enabled", "label"};
  struct cbor_pair *pairs;
  cbor_item_t *value;
  size_t i;
  unsigned int seen = 0;
  int index;
  assert(cbor_isa_map(item) && cbor_map_size(item) == 7);
  pairs = cbor_map_handle(item);
  for (i = 0; i < 7; ++i) {
    index = key_index(pairs[i].key, names, 7);
    assert((seen & (1u << index)) == 0);
    seen |= 1u << index;
    value = pairs[i].value;
    switch (index) {
    case 0:
      output->a = read_int(value);
      break;
    case 1:
      output->b = read_int(value);
      break;
    case 2:
      output->c = read_int(value);
      break;
    case 3:
      assert(cbor_isa_uint(value));
      output->mask = (bench_u64)cbor_get_int(value);
      break;
    case 4:
      assert(cbor_is_float(value));
      output->ratio = cbor_float_get_float(value);
      assert(output->ratio == output->ratio && output->ratio <= DBL_MAX &&
             output->ratio >= -DBL_MAX);
      break;
    case 5:
      assert(cbor_is_bool(value));
      output->enabled = cbor_get_bool(value);
      break;
    default:
      read_text(value, output->label, sizeof(output->label));
      break;
    }
  }
  assert(seen == 127u);
}
static void read_record(const cbor_item_t *item, bench_record *output) {
  static const char *const nested_names[] = {"first", "second"};
  static const char *const text_names[] = {"id", "body"};
  struct cbor_pair *pairs;
  size_t i;
  int index;
  unsigned int seen = 0;
  if (output->kind == BENCH_SCALAR) {
    read_scalar(item, &output->data.scalar);
    return;
  }
  assert(cbor_isa_map(item) && cbor_map_size(item) == 2);
  pairs = cbor_map_handle(item);
  for (i = 0; i < 2; ++i) {
    index =
        key_index(pairs[i].key,
                  output->kind == BENCH_NESTED ? nested_names : text_names, 2);
    assert((seen & (1u << index)) == 0);
    seen |= 1u << index;
    if (output->kind == BENCH_NESTED)
      read_scalar(pairs[i].value, index == 0 ? &output->data.nested.first
                                             : &output->data.nested.second);
    else if (index == 0)
      output->data.text.id = read_int(pairs[i].value);
    else
      read_text(pairs[i].value, output->data.text.body,
                sizeof(output->data.text.body));
  }
  assert(seen == 3u);
}
typedef struct benchmark {
  bench_record input, output;
  unsigned char wire[BENCH_CAPACITY], encoded[BENCH_CAPACITY];
  size_t length;
  bench_samples samples;
} benchmark;
static void run_once(benchmark *b, int encode) {
  cbor_item_t *root;
  struct cbor_load_result result;
  size_t length;
  if (encode) {
    root = build_record(&b->input);
    assert(root != NULL);
    length = cbor_serialize(root, b->encoded, sizeof(b->encoded));
    assert(length == b->length && memcmp(b->encoded, b->wire, length) == 0);
  } else {
    root = cbor_load(b->wire, b->length, &result);
    assert(root != NULL && result.read == b->length);
    read_record(root, &b->output);
    assert(bench_record_equal(&b->input, &b->output));
  }
  cbor_decref(&root);
  assert(allocations.bytes == 0);
}
int main(int argc, char **argv) {
  benchmark *b = malloc(sizeof(*b));
  cbor_item_t *root;
  bench_counts snapshot;
  bench_kind kind;
  size_t repetitions = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 10000u;
  size_t i, sample, batch, records;
  int round, encode;
  double setup, begin, cpu, seconds, cpu_seconds, at;
  if (b == NULL)
    return 1;
  if (argc < 2) {
    free(b);
    return 1;
  }
  cbor_set_allocs(allocate, reallocate, release);
  if (argc == 2 && strcmp(argv[1], "check") == 0) {
    for (kind = BENCH_SCALAR; kind <= BENCH_LAST;
         kind = (bench_kind)((int)kind + 1)) {
      memset(b, 0, sizeof(*b));
      bench_record_fill(&b->input, kind);
      b->output.kind = kind;
      root = build_record(&b->input);
      b->length = cbor_serialize(root, b->wire, sizeof(b->wire));
      assert(b->length != 0);
      cbor_decref(&root);
      run_once(b, 0);
      run_once(b, 1);
    }
    assert(allocations.bytes == 0);
    free(b);
    return 0;
  }
  if (argc == 3 &&
      (strcmp(argv[1], "emit") == 0 || strcmp(argv[1], "verify") == 0)) {
    for (kind = BENCH_SCALAR;
         kind <= BENCH_LAST && strcmp(argv[2], bench_fixture_name(kind)) != 0;
         kind = (bench_kind)((int)kind + 1)) {
    }
    assert(kind <= BENCH_LAST);
    memset(b, 0, sizeof(*b));
    bench_record_fill(&b->input, kind);
    b->output.kind = kind;
    if (strcmp(argv[1], "emit") == 0) {
      root = build_record(&b->input);
      b->length = cbor_serialize(root, b->wire, sizeof(b->wire));
      assert(b->length != 0);
      cbor_decref(&root);
      assert(fwrite(b->wire, 1, b->length, stdout) == b->length);
    } else {
      b->length = fread(b->wire, 1, sizeof(b->wire), stdin);
      assert(fgetc(stdin) == EOF);
      run_once(b, 0);
    }
    assert(allocations.bytes == 0);
    free(b);
    return 0;
  }
  encode = strcmp(argv[1], "encode") == 0;
  if ((!encode && strcmp(argv[1], "decode") != 0) || repetitions == 0) {
    free(b);
    return 1;
  }
  for (kind = BENCH_SCALAR; kind <= BENCH_LAST;
       kind = (bench_kind)((int)kind + 1)) {
    setup = bench_wall();
    memset(b, 0, sizeof(*b));
    bench_record_fill(&b->input, kind);
    b->output.kind = kind;
    root = build_record(&b->input);
    b->length = cbor_serialize(root, b->wire, sizeof(b->wire));
    assert(b->length != 0);
    cbor_decref(&root);
    run_once(b, encode);
    setup = bench_wall() - setup;
    records = kind >= BENCH_LARGE_ASCII ? repetitions / 16u + 1u : repetitions;
    for (round = -1; round < 5; ++round) {
      bench_counts_reset(&allocations);
      begin = bench_wall();
      cpu = bench_cpu();
      for (i = 0; i < records; ++i)
        run_once(b, encode);
      cpu_seconds = bench_cpu() - cpu;
      seconds = bench_wall() - begin;
      snapshot = allocations;
      if (round < 0)
        continue;
      b->samples.count = kind >= BENCH_LARGE_ASCII ? 128u : 256u;
      b->samples.batch = kind >= BENCH_LARGE_ASCII ? 1u : 16u;
      for (sample = 0; sample < b->samples.count; ++sample) {
        at = bench_wall();
        for (batch = 0; batch < b->samples.batch; ++batch)
          run_once(b, encode);
        b->samples.values[sample] =
            (bench_wall() - at) * 1e9 / (double)b->samples.batch;
      }
      bench_report("PJK/libcbor-0.14.0", encode ? "dom-encode" : "dom-decode",
                   bench_fixture_name(kind), round, records, b->length, seconds,
                   cpu_seconds, setup, &snapshot, &b->samples);
    }
  }
  free(b);
  return 0;
}
