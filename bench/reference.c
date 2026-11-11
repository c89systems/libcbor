/* Independent PJK/libcbor executable. Never include or link the C89 Systems
 * codec here: both projects intentionally share the libcbor filename. */
#include <cbor/streaming.h>
#include <cbor/encoding.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static volatile uint64_t observed;
static double now(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    abort();
  return (double)value.tv_sec + (double)value.tv_nsec / 1e9;
}
static void bytes_callback(void *context, cbor_data bytes, size_t length) {
  uint64_t *count = context;
  (void)bytes;
  *count += (uint64_t)length;
}
int main(int argc, char **argv) {
  struct cbor_callbacks callbacks = cbor_empty_callbacks;
  struct cbor_decoder_result decoded;
  unsigned char input[1027], output[1027];
  const char *mode = argc > 1 ? argv[1] : "decode";
  size_t i,
      repetitions = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 65536u;
  size_t header;
  int round, encode = strcmp(mode, "encode") == 0;
  uint64_t count;
  double begin, seconds;
  if ((!encode && strcmp(mode, "decode") != 0) || repetitions == 0)
    return 1;
  input[0] = 0x59;
  input[1] = 4;
  input[2] = 0;
  memset(input + 3, 'x', sizeof(input) - 3u);
  callbacks.byte_string = bytes_callback;
  for (round = -1; round < 5; ++round) {
    count = 0;
    begin = now();
    for (i = 0; i < repetitions; ++i) {
      if (encode) {
        header = cbor_encode_bytestring_start(1024u, output, sizeof(output));
        if (header != 3)
          abort();
        memcpy(output + header, input + header, 1024u);
        if (memcmp(output, input, sizeof(input)) != 0)
          abort();
        count += 1024u;
      } else {
        decoded = cbor_stream_decode(input, sizeof(input), &callbacks, &count);
        if (decoded.status != CBOR_DECODER_FINISHED ||
            decoded.read != sizeof(input))
          abort();
      }
    }
    seconds = now() - begin;
    observed = count;
    if (count != (uint64_t)repetitions * 1024u)
      abort();
    if (round >= 0)
      printf("{\"implementation\":\"PJK/"
             "libcbor-0.14.0\",\"case\":\"%s\",\"round\":%d,\"payload_bytes\":%"
             "lu,\"seconds\":%.9f,\"mib_s\":%.3f}\n",
             mode, round, (unsigned long)count, seconds,
             (double)count / 1048576.0 / seconds);
  }
  return observed == 0;
}
