#include <c89cbor/cbor.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef C89CBOR_REFERENCE
#include <cbor/streaming.h>
#endif
static volatile uint64_t observed;
static double now(void) {
  struct timespec t;
  int rc = clock_gettime(CLOCK_MONOTONIC, &t);
  if (rc != 0)
    abort();
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
#ifdef C89CBOR_REFERENCE
static void reference_bytes(void *ctx, cbor_data bytes, size_t n) {
  uint64_t *count = ctx;
  (void)bytes;
  *count += n;
}
#endif
int main(int argc, char **argv) {
  c89cbor_decoder d;
  c89cbor_encoder e;
  c89cbor_token t;
  unsigned char input[1027], output[2048];
  size_t i, rounds = 5, repetitions = 65536, used, at, written;
  uint64_t count;
  double start, seconds;
  int round, rc;
  const char *mode = argc > 1 ? argv[1] : "decode";
  int reference = strcmp(mode, "reference-decode") == 0;
  int encode = strcmp(mode, "encode") == 0;
#ifdef C89CBOR_REFERENCE
  struct cbor_callbacks callbacks = cbor_empty_callbacks;
  struct cbor_decoder_result decoded;
  callbacks.byte_string = reference_bytes;
#else
  if (reference) {
    fputs("Configure C89CBOR_REFERENCE_PREFIX first\n", stderr);
    return 1;
  }
#endif
  input[0] = 0x59;
  input[1] = 4;
  input[2] = 0;
  memset(input + 3, 'x', 1024);
  if (argc > 2)
    repetitions = (size_t)strtoul(argv[2], NULL, 10);
  if (!repetitions)
    return 1;
  if (c89cbor_decoder_init(&d, NULL, 0, 0) != 0 ||
      c89cbor_encoder_init(&e, NULL, 0, 0) != 0)
    abort();
  for (round = -1; round < (int)rounds; ++round) {
    count = 0;
    start = now();
    for (i = 0; i < repetitions; ++i) {
#ifdef C89CBOR_REFERENCE
      if (reference) {
        decoded = cbor_stream_decode(input, sizeof(input), &callbacks, &count);
        if (decoded.status != CBOR_DECODER_FINISHED ||
            decoded.read != sizeof(input))
          abort();
      } else
#endif
          if (encode) {
        memset(&t, 0, sizeof(t));
        t.type = C89CBOR_BYTES;
        t.argument = 1024;
        if (c89cbor_encoder_put(&e, &t) != 0)
          abort();
        if (c89cbor_encoder_read(&e, output, sizeof(output), &written) != 0 ||
            written != 3)
          abort();
        memset(&t, 0, sizeof(t));
        t.type = C89CBOR_DATA;
        t.data = input + 3;
        t.length = 1024;
        if (c89cbor_encoder_put(&e, &t) != 0)
          abort();
        if (c89cbor_encoder_read(&e, output, sizeof(output), &written) != 0 ||
            written != 1024)
          abort();
        if (memcmp(output, input + 3, 1024))
          abort();
        memset(&t, 0, sizeof(t));
        t.type = C89CBOR_END;
        t.argument = C89CBOR_BYTES;
        if (c89cbor_encoder_put(&e, &t) != 0 ||
            c89cbor_encoder_finish(&e) != 0 || c89cbor_encoder_reset(&e) != 0)
          abort();
        count += written;
      } else {
        at = 0;
        do {
          rc = c89cbor_decoder_next(&d, input + at, sizeof(input) - at, &used,
                                    &t);
          at += used;
          if (rc == C89CBOR_TOKEN && t.type == C89CBOR_DATA)
            count += t.length;
        } while (rc == C89CBOR_TOKEN);
        if (rc != C89CBOR_DONE || at != sizeof(input) ||
            c89cbor_decoder_finish(&d) != 0 || c89cbor_decoder_reset(&d) != 0)
          abort();
      }
    }
    seconds = now() - start;
    observed = count;
    if (count != (uint64_t)repetitions * 1024U)
      abort();
    if (round >= 0)
      printf("{\"case\":\"%s\",\"round\":%d,\"payload_bytes\":%lu,\"seconds\":%"
             ".9f,\"mib_s\":%.3f}\n",
             mode, round, (unsigned long)count, seconds,
             (double)count / 1048576.0 / seconds);
  }
  return observed == 0;
}
