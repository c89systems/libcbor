#ifndef CBOR_BENCH_MEASURE_H
#define CBOR_BENCH_MEASURE_H
#include <stddef.h>
#include <stdint.h>
typedef struct bench_counts {
  size_t allocations, reallocations, frees, bytes, peak;
  uint64_t copies, reads, writes;
} bench_counts;
typedef struct bench_samples {
  double values[256];
  size_t count;
  size_t batch;
} bench_samples;
void *bench_allocate(void *context, size_t length);
void *bench_reallocate(void *context, void *memory, size_t length);
void bench_free(void *context, void *memory);
void bench_counts_reset(bench_counts *counts);
double bench_wall(void);
double bench_cpu(void);
void bench_report(const char *implementation, const char *name,
                  const char *fixture, int round, size_t records,
                  size_t wire_size, double seconds, double cpu_seconds,
                  double setup_seconds, const bench_counts *counts,
                  bench_samples *samples);
#endif
