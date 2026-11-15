#include "records.h"
#include <stdint.h>
#include <string.h>
static void scalar_fill(bench_scalar *value, int second) {
  value->a = second ? 314 : 42;
  value->b = second ? -27 : -7;
  value->c = (bench_i64)INT64_MIN;
  value->mask = (bench_u64)UINT64_MAX;
  value->ratio = second ? -0.125 : 1.5;
  value->enabled = !second;
  strcpy(value->label, second ? "second" : "first");
}
const char *bench_fixture_name(bench_kind kind) {
  static const char *const names[] = {"scalars", "nested",      "ascii",
                                      "utf8",    "large-ascii", "large-utf8"};
  return names[(int)kind];
}
void bench_record_fill(bench_record *record, bench_kind kind) {
  static const char utf8[] = "\303\251\342\202\254\360\237\230\200";
  size_t i, length;
  memset(record, 0, sizeof(*record));
  record->kind = kind;
  if (kind == BENCH_SCALAR)
    scalar_fill(&record->data.scalar, 0);
  else if (kind == BENCH_NESTED) {
    scalar_fill(&record->data.nested.first, 0);
    scalar_fill(&record->data.nested.second, 1);
  } else {
    record->data.text.id = 42;
    length = kind >= BENCH_LARGE_ASCII ? 65536u : 72u;
    if (kind == BENCH_ASCII || kind == BENCH_LARGE_ASCII)
      memset(record->data.text.body, 'a', length);
    else
      for (i = 0; i < length / (sizeof(utf8) - 1u); ++i)
        memcpy(record->data.text.body + i * (sizeof(utf8) - 1u), utf8,
               sizeof(utf8) - 1u);
  }
}
void *bench_record_data(bench_record *record) {
  if (record->kind == BENCH_SCALAR)
    return &record->data.scalar;
  if (record->kind == BENCH_NESTED)
    return &record->data.nested;
  return &record->data.text;
}
const void *bench_record_const_data(const bench_record *record) {
  if (record->kind == BENCH_SCALAR)
    return &record->data.scalar;
  if (record->kind == BENCH_NESTED)
    return &record->data.nested;
  return &record->data.text;
}
static int scalar_equal(const bench_scalar *a, const bench_scalar *b) {
  return a->a == b->a && a->b == b->b && a->c == b->c && a->mask == b->mask &&
         a->ratio == b->ratio && a->enabled == b->enabled &&
         strcmp(a->label, b->label) == 0;
}
int bench_record_equal(const bench_record *a, const bench_record *b) {
  if (a->kind != b->kind)
    return 0;
  if (a->kind == BENCH_SCALAR)
    return scalar_equal(&a->data.scalar, &b->data.scalar);
  if (a->kind == BENCH_NESTED)
    return scalar_equal(&a->data.nested.first, &b->data.nested.first) &&
           scalar_equal(&a->data.nested.second, &b->data.nested.second);
  return a->data.text.id == b->data.text.id &&
         strcmp(a->data.text.body, b->data.text.body) == 0;
}
