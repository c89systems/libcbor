#include <c89cbor/cbor.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static volatile uint64_t observed;
static double now(void) {
  struct timespec t;
  int rc = clock_gettime(CLOCK_MONOTONIC, &t);
  if (rc != 0)
    abort();
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
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
  int encode = strcmp(mode, "encode") == 0;
  if (!encode && strcmp(mode, "decode") != 0) {
    fputs("Use decode or encode\n", stderr);
    return 1;
  }
  input[0] = 0x59;
  input[1] = 4;
  input[2] = 0;
  memset(input + 3, 'x', 1024);
  if (argc > 2)
    repetitions = (size_t)strtoul(argv[2], NULL, 10);
  if (!repetitions)
    return 1;
  if (c89cbor_decoder_init(NULL, &d, NULL, 0, 0) != 0 ||
      c89cbor_encoder_init(NULL, &e, NULL, 0, 0) != 0)
    abort();
  for (round = -1; round < (int)rounds; ++round) {
    count = 0;
    start = now();
    for (i = 0; i < repetitions; ++i) {
      if (encode) {
        memset(&t, 0, sizeof(t));
        t.type = C89CBOR_BYTES;
        t.argument = 1024;
        if (c89cbor_encoder_put(&e, &t) != 0)
          abort();
        if (c89cbor_encoder_read(&e, output, sizeof(output), &written) != 0 ||
            written != 3)
          abort();
        if (memcmp(output, input, written) != 0)
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
