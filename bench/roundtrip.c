/* Public C89 codec costs for bounded byte and UTF-8 records. */
#include <c89cbor/cbor.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct fixture {
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  const unsigned char *payload;
  unsigned char header[3];
  size_t length, header_length;
  uint64_t bytes, records, spans, output;
  int verify, roundtrip;
} fixture;
static volatile uint64_t observed;
static size_t number(const char *text) {
  char *end;
  unsigned long value;
  errno = 0;
  value = strtoul(text, &end, 10);
  if (*text < '0' || *text > '9' || *end || errno != 0) {
    fputs("Expected a nonnegative decimal integer\n", stderr);
    exit(2);
  }
  return (size_t)value;
}
static double clock_seconds(clockid_t clock) {
  struct timespec time;
  assert(clock_gettime(clock, &time) == 0);
  return (double)time.tv_sec + (double)time.tv_nsec / 1e9;
}
static void feed(fixture *f, const void *bytes, size_t length) {
  const unsigned char *input = bytes;
  c89cbor_token token;
  size_t consumed;
  int status;
  do {
    status =
        c89cbor_decoder_next(&f->decoder, input, length, &consumed, &token);
    input += consumed;
    length -= consumed;
    if (status == C89CBOR_TOKEN && token.type == C89CBOR_DATA) {
      if (f->verify) {
        size_t offset = (size_t)(f->bytes % f->length);
        assert(token.length <= f->length - offset);
        assert(memcmp(token.data, f->payload + offset, token.length) == 0);
      }
      f->bytes += token.length;
      ++f->spans;
    } else if (status == C89CBOR_TOKEN && token.type == C89CBOR_END) {
      ++f->records;
    }
  } while (status == C89CBOR_TOKEN);
  assert(length == 0 && (status == C89CBOR_DONE || status == C89CBOR_INPUT));
}
static void put(fixture *f, const c89cbor_token *token) {
  const void *bytes;
  size_t length;
  int status;
  assert(c89cbor_encoder_put(&f->encoder, token) == C89CBOR_OK);
  for (;;) {
    status = c89cbor_encoder_peek(&f->encoder, &bytes, &length);
    if (status == C89CBOR_OK)
      return;
    assert(status == C89CBOR_OUTPUT);
    if (f->verify) {
      size_t offset = (size_t)(f->output % (f->length + f->header_length));
      if (offset < f->header_length) {
        assert(length <= f->header_length - offset);
        assert(memcmp(bytes, f->header + offset, length) == 0);
      } else {
        offset -= f->header_length;
        assert(length <= f->length - offset);
        assert(memcmp(bytes, f->payload + offset, length) == 0);
      }
    }
    f->output += length;
    if (f->roundtrip)
      feed(f, bytes, length);
    status = c89cbor_encoder_advance(&f->encoder, length);
    if (status == C89CBOR_OK)
      return;
    assert(status == C89CBOR_OUTPUT);
  }
}
int main(int argc, char **argv) {
  static const char corpus[] =
      "The **benchmark** measures `streaming` text with bounded chunks.\n\n";
  fixture *f;
  unsigned char *payload;
  c89cbor_token begin, data, end;
  const char *mode;
  size_t length, records, chunk, i, verify;
  double start, cpu, elapsed, cpu_elapsed;
  int round, text, decode, encode;
  if (argc != 7) {
    fputs("Use MODE LENGTH RECORDS CHUNK text|bytes|utf8 VERIFY\n", stderr);
    return 2;
  }
  mode = argv[1];
  decode = strcmp(mode, "decode") == 0;
  encode = strcmp(mode, "encode") == 0;
  length = number(argv[2]);
  records = number(argv[3]);
  chunk = number(argv[4]);
  verify = number(argv[6]);
  text = strcmp(argv[5], "bytes") != 0;
  if ((!text && strcmp(argv[5], "bytes") != 0) ||
      (text && strcmp(argv[5], "text") != 0 && strcmp(argv[5], "utf8") != 0) ||
      (strcmp(mode, "encode") != 0 && strcmp(mode, "decode") != 0 &&
       strcmp(mode, "roundtrip") != 0) ||
      !length || length > 32768 || !records || verify > 1 ||
      (uint64_t)records > UINT64_MAX / (length + 3))
    return 2;
  f = calloc(1, sizeof(*f));
  payload = malloc(length);
  assert(f != NULL && payload != NULL);
  for (i = 0; i < length; ++i)
    payload[i] = (unsigned char)corpus[i % (sizeof(corpus) - 1)];
  payload[length - 1] = '\n';
  if (strcmp(argv[5], "utf8") == 0) {
    for (i = 0; i + 1 < length; i += 2) {
      payload[i] = 0xc3;
      payload[i + 1] = 0xa9;
    }
    if (i < length)
      payload[i] = '\n';
  }
  f->payload = payload;
  f->length = length;
  f->verify = verify != 0;
  f->header[0] = text ? 0x60 : 0x40;
  f->header_length = length < 24 ? 1 : length <= 255 ? 2 : 3;
  if (f->header_length == 1)
    f->header[0] |= (unsigned char)length;
  else {
    f->header[0] |= f->header_length == 2 ? 24 : 25;
    f->header[f->header_length - 1] = (unsigned char)length;
    if (f->header_length == 3)
      f->header[1] = (unsigned char)(length >> 8);
  }
  assert(c89cbor_encoder_init(NULL, &f->encoder, NULL, 0, chunk) == 0);
  assert(c89cbor_decoder_init(NULL, &f->decoder, NULL, 0, chunk) == 0);
  memset(&begin, 0, sizeof(begin));
  begin.type = text ? C89CBOR_TEXT : C89CBOR_BYTES;
  begin.argument = length;
  memset(&data, 0, sizeof(data));
  data.type = C89CBOR_DATA;
  data.data = payload;
  data.length = length;
  memset(&end, 0, sizeof(end));
  end.type = C89CBOR_END;
  end.argument = begin.type;
  f->roundtrip = !encode && !decode;
  for (round = -1; round < 5; ++round) {
    f->bytes = f->records = f->spans = f->output = 0;
    cpu = clock_seconds(CLOCK_PROCESS_CPUTIME_ID);
    start = clock_seconds(CLOCK_MONOTONIC);
    for (i = 0; i < records; ++i) {
      if (decode) {
        feed(f, f->header, f->header_length);
        feed(f, payload, length);
      } else {
        put(f, &begin);
        put(f, &data);
        put(f, &end);
        assert(c89cbor_encoder_finish(&f->encoder) == 0);
        assert(c89cbor_encoder_reset(&f->encoder) == 0);
      }
      if (!encode) {
        assert(c89cbor_decoder_finish(&f->decoder) == 0);
        assert(c89cbor_decoder_reset(&f->decoder) == 0);
      }
    }
    elapsed = clock_seconds(CLOCK_MONOTONIC) - start;
    cpu_elapsed = clock_seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    if (!encode)
      assert(f->bytes == (uint64_t)records * length && f->records == records);
    if (!decode)
      assert(f->output == (uint64_t)records * (length + f->header_length));
    observed = f->bytes + records;
    if (round >= 0)
      printf("{\"case\":\"%s\",\"fixture\":\"%s\",\"length\":%lu,\"chunk\":%lu,"
             "\"records\":%lu,\"round\":%d,\"verify\":%d,\"seconds\":%.9f,"
             "\"cpu_seconds\":%.9f,\"mean_ns\":%.3f,\"mib_s\":%.3f,\"spans\":%"
             "lu}\n",
             mode, argv[5], (unsigned long)length, (unsigned long)chunk,
             (unsigned long)records, round, f->verify, elapsed, cpu_elapsed,
             elapsed * 1e9 / (double)records,
             (double)length * (double)records / elapsed / 1048576.0,
             (unsigned long)f->spans);
  }
  assert(c89cbor_encoder_cleanup(&f->encoder) == 0);
  assert(c89cbor_decoder_cleanup(&f->decoder) == 0);
  free(payload);
  free(f);
  return observed == 0;
}
