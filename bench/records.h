#ifndef CBOR_BENCH_RECORDS_H
#define CBOR_BENCH_RECORDS_H
#include <stddef.h>
typedef signed long long bench_i64;
typedef unsigned long long bench_u64;
typedef struct bench_scalar {
  bench_i64 a, b, c;
  bench_u64 mask;
  double ratio;
  int enabled;
  char label[80];
} bench_scalar;
typedef struct bench_nested {
  bench_scalar first, second;
} bench_nested;
typedef struct bench_text {
  bench_i64 id;
  char body[65537];
} bench_text;
typedef enum bench_kind {
  BENCH_SCALAR,
  BENCH_NESTED,
  BENCH_ASCII,
  BENCH_UTF8,
  BENCH_LARGE_ASCII,
  BENCH_LARGE_UTF8
} bench_kind;
#define BENCH_LAST BENCH_LARGE_UTF8
#define BENCH_CAPACITY 131072u
typedef struct bench_record {
  bench_kind kind;
  union {
    bench_scalar scalar;
    bench_nested nested;
    bench_text text;
  } data;
} bench_record;
const char *bench_fixture_name(bench_kind kind);
void bench_record_fill(bench_record *record, bench_kind kind);
void *bench_record_data(bench_record *record);
const void *bench_record_const_data(const bench_record *record);
int bench_record_equal(const bench_record *left, const bench_record *right);
#endif
