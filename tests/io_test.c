#include <c89cbor/io.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct memory {
  const unsigned char *input;
  size_t length, at, written;
  unsigned char output[32];
  int pause_read, pause_write;
} memory;
static int read_memory(void *ctx, void *out, size_t cap, size_t *count) {
  memory *m = ctx;
  *count = 0;
  if (!m->pause_read++)
    return C89CBOR_INPUT;
  if (m->at == m->length)
    return 0;
  assert(cap > 0);
  *(unsigned char *)out = m->input[m->at++];
  *count = 1;
  return 0;
}
static int write_memory(void *ctx, const void *data, size_t length,
                        size_t *count) {
  memory *m = ctx;
  *count = 0;
  if (!(m->pause_write++ & 1))
    return C89CBOR_OUTPUT;
  assert(length && m->written < sizeof(m->output));
  m->output[m->written++] = *(const unsigned char *)data;
  *count = 1;
  return 0;
}
static void transfer_case(const unsigned char *bytes, size_t length,
                          c89cbor_framing mode, int expected) {
  memory m;
  c89cbor_transfer t;
  c89cbor_source source;
  c89cbor_sink sink;
  int rc, calls = 0;
  memset(&m, 0, sizeof(m));
  m.input = bytes;
  m.length = length;
  source.context = &m;
  source.read = read_memory;
  sink.context = &m;
  sink.write = write_memory;
  assert(c89cbor_transfer_init(&t, &source, &sink, mode, 32) == 0);
  do {
    rc = c89cbor_transfer_step(&t);
    assert(++calls < 256);
  } while (rc == 0 || rc == C89CBOR_INPUT || rc == C89CBOR_OUTPUT);
  assert(rc == expected);
  if (expected == C89CBOR_DONE) {
    assert(m.written == length && memcmp(bytes, m.output, length) == 0);
    assert(t.written_bytes == length && t.read_bytes == length);
  } else
    assert(c89cbor_transfer_step(&t) == expected);
}
static int reenter(void *ctx, void *out, size_t cap, size_t *count) {
  (void)out;
  (void)cap;
  *count = 0;
  return c89cbor_transfer_step(ctx);
}
static void descriptors(void) {
  int in[2], out[2];
  c89cbor_fd input, output;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_transfer t;
  unsigned char actual[4];
  assert(pipe(in) == 0 && pipe(out) == 0);
  assert(fcntl(in[0], F_SETFL, O_NONBLOCK) == 0);
  assert(c89cbor_fd_init(&input, in[0], &source, NULL) == 0);
  assert(c89cbor_fd_init(&output, out[1], NULL, &sink) == 0);
  assert(c89cbor_transfer_init(&t, &source, &sink, C89CBOR_SINGLE, 0) == 0);
  assert(c89cbor_transfer_step(&t) == C89CBOR_INPUT);
  assert(write(in[1], "cabc", 4) == 4);
  assert(close(in[1]) == 0);
  assert(c89cbor_transfer_step(&t) == C89CBOR_OK);
  assert(c89cbor_transfer_step(&t) == C89CBOR_DONE);
  assert(t.read_bytes == 4 && t.written_bytes == 4);
  assert(read(out[0], actual, sizeof(actual)) == 4);
  assert(memcmp(actual, "cabc", 4) == 0);
  assert(close(in[0]) == 0 && close(out[0]) == 0 && close(out[1]) == 0);
}
int main(void) {
  static const unsigned char single[] = {0x63, 'a', 'b', 'c'};
  static const unsigned char seq[] = {0, 0x81, 1, 0x7f, 0x61, 'a', 0xff};
  static const unsigned char framed[] = {0, 0, 0, 1, 0, 0, 0, 0, 2, 0x81, 1};
  static const unsigned char bad[] = {0, 0, 0, 2, 0, 0};
  static const unsigned char large[] = {0, 0, 0, 33};
  /* cai.workspace request: ascending integer keys and a typed payload map. */
  static const unsigned char cai[] = {
      0, 0, 0, 23, 0xa8, 0, 5, 1,    0x18, 42,   2,   0,   3,  1,
      4, 0, 5, 0,  6,    1, 7, 0xa1, 0,    0x63, 'a', 'b', 'c'};
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_transfer t;
  memory m;
  unsigned char prefix[4] = {1, 2, 3, 4};
  size_t i;
  transfer_case(single, sizeof(single), C89CBOR_SINGLE, C89CBOR_DONE);
  transfer_case(seq, sizeof(seq), C89CBOR_SEQUENCE, C89CBOR_DONE);
  transfer_case(framed, sizeof(framed), C89CBOR_LENGTH32, C89CBOR_DONE);
  transfer_case(cai, sizeof(cai), C89CBOR_LENGTH32, C89CBOR_DONE);
  transfer_case(bad, sizeof(bad), C89CBOR_LENGTH32, C89CBOR_MALFORMED);
  transfer_case(large, sizeof(large), C89CBOR_LENGTH32, C89CBOR_LIMIT);
  transfer_case(seq, sizeof(seq), C89CBOR_SINGLE, C89CBOR_MALFORMED);
  for (i = 0; i < sizeof(single); ++i)
    transfer_case(single, i, C89CBOR_SINGLE, C89CBOR_MALFORMED);
  assert(c89cbor_length32(0, 0, prefix) == C89CBOR_LIMIT && prefix[0] == 1);
  assert(c89cbor_length32(128U * 1024U, 0, prefix) == 0);
  assert(prefix[0] == 0 && prefix[1] == 2 && prefix[2] == 0 && prefix[3] == 0);
  memset(&m, 0, sizeof(m));
  source.context = &t;
  source.read = reenter;
  sink.context = &m;
  sink.write = write_memory;
  assert(c89cbor_transfer_init(&t, &source, &sink, C89CBOR_SEQUENCE, 0) == 0);
  assert(c89cbor_transfer_step(&t) == C89CBOR_INVALID);
  descriptors();
  puts("io: framing, backpressure, truncation, byte preservation, reentry "
       "passed");
  return 0;
}
