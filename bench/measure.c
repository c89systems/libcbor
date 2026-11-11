#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
/* ru_maxrss is a BSD extension hidden by Darwin's strict POSIX namespace. */
#define _DARWIN_C_SOURCE 1
#endif
#include "measure.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
typedef union allocation_header {
  struct {
    size_t length;
    bench_counts *owner;
  } value;
  long double alignment;
  uint64_t integer;
  void *pointer;
} allocation_header;
void *bench_allocate(void *context, size_t length) {
  bench_counts *counts = context;
  allocation_header *header;
  ++counts->allocations;
  if (length > (size_t)-1 - sizeof(*header))
    return NULL;
  header = malloc(sizeof(*header) + length);
  if (header == NULL)
    return NULL;
  header->value.length = length;
  header->value.owner = counts;
  counts->bytes += length;
  if (counts->bytes > counts->peak)
    counts->peak = counts->bytes;
  return header + 1;
}
void *bench_reallocate(void *context, void *memory, size_t length) {
  bench_counts *counts = context;
  allocation_header *header =
      memory == NULL ? NULL : (allocation_header *)memory - 1;
  size_t previous = header == NULL ? 0 : header->value.length;
  ++counts->allocations;
  ++counts->reallocations;
  if (length > (size_t)-1 - sizeof(*header))
    return NULL;
  assert(header == NULL || header->value.owner == counts);
  header = realloc(header, sizeof(*header) + length);
  if (header == NULL)
    return NULL;
  header->value.length = length;
  header->value.owner = counts;
  counts->bytes = counts->bytes - previous + length;
  if (counts->bytes > counts->peak)
    counts->peak = counts->bytes;
  return header + 1;
}
void bench_free(void *context, void *memory) {
  bench_counts *counts = context;
  allocation_header *header;
  if (memory == NULL)
    return;
  header = (allocation_header *)memory - 1;
  assert(header->value.owner == counts &&
         header->value.length <= counts->bytes);
  ++counts->frees;
  counts->bytes -= header->value.length;
  free(header);
}
void bench_counts_reset(bench_counts *counts) {
  size_t live = counts->bytes;
  memset(counts, 0, sizeof(*counts));
  counts->bytes = counts->peak = live;
}
double bench_wall(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    abort();
  return (double)value.tv_sec + (double)value.tv_nsec / 1e9;
}
double bench_cpu(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) != 0)
    abort();
  return (double)value.tv_sec + (double)value.tv_nsec / 1e9;
}
static int compare_double(const void *left, const void *right) {
  double a = *(const double *)left, b = *(const double *)right;
  return a < b ? -1 : a > b ? 1 : 0;
}
void bench_report(const char *implementation, const char *name,
                  const char *fixture, int round, size_t records,
                  size_t wire_size, double seconds, double cpu_seconds,
                  double setup_seconds, const bench_counts *counts,
                  bench_samples *samples) {
  struct rusage usage;
  uint64_t rss;
  size_t n = samples->count;
  assert(n != 0 && records != 0 && seconds > 0);
  qsort(samples->values, n, sizeof(samples->values[0]), compare_double);
  if (getrusage(RUSAGE_SELF, &usage) != 0)
    abort();
  rss = (uint64_t)usage.ru_maxrss;
#if !defined(__APPLE__)
  rss *= 1024u;
#endif
  printf("{\"implementation\":\"%s\",\"case\":\"%s\",\"fixture\":\"%s\","
         "\"round\":%d,"
         "\"records\":%lu,\"wire_bytes_per_record\":%lu,\"seconds\":%.9f,\"cpu_"
         "seconds\":%.9f,"
         "\"records_s\":%.3f,\"mean_ns\":%.3f,\"batch_mean_p50_ns\":%.3f,"
         "\"batch_mean_p95_ns\":%.3f,\"batch_mean_p99_ns\":%.3f,"
         "\"latency_batch_records\":%lu,\"latency_samples\":%lu,\"allocation_"
         "calls\":%lu,\"reallocation_"
         "calls\":%lu,\"peak_owned_bytes\":%lu,"
         "\"endpoint_copy_bytes\":%.0f,\"read_calls\":%.0f,\"write_calls\":%."
         "0f,\"rss_bytes\":%.0f,\"setup_seconds\":%.9f}\n",
         implementation, name, fixture, round, (unsigned long)records,
         (unsigned long)wire_size, seconds, cpu_seconds,
         (double)records / seconds, seconds * 1e9 / (double)records,
         samples->values[n / 2u], samples->values[(n - 1u) * 95u / 100u],
         samples->values[(n - 1u) * 99u / 100u], (unsigned long)samples->batch,
         (unsigned long)n, (unsigned long)counts->allocations,
         (unsigned long)counts->reallocations, (unsigned long)counts->peak,
         (double)counts->copies, (double)counts->reads, (double)counts->writes,
         (double)rss, setup_seconds);
}
