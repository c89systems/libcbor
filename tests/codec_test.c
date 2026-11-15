#include <c89cbor/cbor.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static size_t unhex(const char *text, unsigned char *out) {
  size_t n = 0;
  unsigned int byte;
  while (*text) {
    assert(sscanf(text, "%2x", &byte) == 1);
    out[n++] = (unsigned char)byte;
    text += 2;
  }
  return n;
}
static int check(const unsigned char *bytes, size_t length, size_t fragment,
                 int roundtrip) {
  c89cbor_decoder d;
  c89cbor_encoder e;
  c89cbor_token t;
  size_t at = 0, used, take, written, output = 0;
  unsigned char encoded[512];
  int rc, wr;
  assert(c89cbor_decoder_init(NULL, &d, NULL, 0, 3) == 0);
  assert(c89cbor_encoder_init(NULL, &e, NULL, 0, 2) == 0);
  for (;;) {
    take = length - at;
    if (take > fragment)
      take = fragment;
    rc = c89cbor_decoder_next(&d, bytes + at, take, &used, &t);
    assert(used <= take);
    at += used;
    if (rc == C89CBOR_TOKEN) {
      if (!roundtrip)
        continue;
      assert(c89cbor_encoder_put(&e, &t) == 0);
      do {
        wr = c89cbor_encoder_read(&e, encoded + output,
                                  sizeof(encoded) - output, &written);
        assert(wr == 0 || wr == C89CBOR_OUTPUT);
        output += written;
      } while (wr == C89CBOR_OUTPUT);
    } else if (rc == C89CBOR_DONE) {
      assert(at == length);
      assert(c89cbor_decoder_finish(&d) == 0);
      if (roundtrip) {
        assert(c89cbor_encoder_finish(&e) == 0);
        assert(output == length && memcmp(bytes, encoded, length) == 0);
      }
      return 0;
    } else if (rc < 0)
      return rc;
    else if (at == length)
      return c89cbor_decoder_finish(&d);
  }
}
static void vectors(void) {
  static const char *const valid[] = {"00",
                                      "17",
                                      "1818",
                                      "18ff",
                                      "190100",
                                      "19ffff",
                                      "1a00010000",
                                      "1affffffff",
                                      "1b0000000100000000",
                                      "1bffffffffffffffff",
                                      "20",
                                      "3818",
                                      "3bffffffffffffffff",
                                      "40",
                                      "43010203",
                                      "60",
                                      "63616263",
                                      "64f09f9880",
                                      "620061",
                                      "80",
                                      "83010203",
                                      "a0",
                                      "a201616102820304",
                                      "9f018202039f0405ffff",
                                      "bf616101ff",
                                      "5f4201024043030405ff",
                                      "7f616162c3bcff",
                                      "c001",
                                      "d8206161",
                                      "d9d9f7a0",
                                      "c0c140",
                                      "f4",
                                      "f5",
                                      "f6",
                                      "f7",
                                      "e0",
                                      "f3",
                                      "f820",
                                      "f8ff",
                                      "f90000",
                                      "f98000",
                                      "f93c00",
                                      "f97c00",
                                      "f97e01",
                                      "fa7f800000",
                                      "fa7fc00001",
                                      "fb3ff0000000000000",
                                      "fbfff0000000000000"};
  static const char *const invalid[] = {
      "1c",   "1d",           "1e",       "1f",         "3f",
      "df",   "ff",           "f8",       "f818",       "f81f",
      "9f01", "bf01ff",       "5f6161ff", "5f5fff",     "7f7fff",
      "61ff", "62c080",       "63eda080", "64f4908080", "64f0808080",
      "61c2", "7f61c261a2ff", "81",       "c0",         "1bffffffff",
      "42ff"};
  unsigned char bytes[512];
  size_t i, n, split, cut;
  for (i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
    n = unhex(valid[i], bytes);
    for (split = 1; split <= n; ++split) {
      int result = check(bytes, n, split, 1);
      if (result)
        fprintf(stderr, "vector %s fragment %lu: %d\n", valid[i],
                (unsigned long)split, result);
      assert(result == 0);
    }
    for (cut = 0; cut < n; ++cut)
      assert(check(bytes, cut, 1, 0) < 0);
  }
  for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    n = unhex(invalid[i], bytes);
    for (split = 1; split <= n; ++split)
      assert(check(bytes, n, split, 0) < 0);
  }
}
static void bounds(void) {
  c89cbor_decoder d;
  c89cbor_encoder e;
  c89cbor_frame f[1];
  c89cbor_token t;
  size_t n;
  unsigned char bytes[2] = {0x81, 0x80}, out;
  assert(c89cbor_decoder_init(NULL, &d, f, 1, 1) == 0);
  assert(c89cbor_decoder_next(&d, bytes, 2, &n, &t) == C89CBOR_TOKEN);
  assert(n == 1);
  assert(c89cbor_decoder_next(&d, bytes + 1, 1, &n, &t) == C89CBOR_LIMIT);
  assert(c89cbor_decoder_next(&d, NULL, 0, &n, &t) == C89CBOR_LIMIT);
  assert(c89cbor_decoder_reset(&d) == C89CBOR_INVALID);
  assert(c89cbor_encoder_init(NULL, &e, NULL, 0, 0) == 0);
  memset(&t, 0, sizeof(t));
  t.type = C89CBOR_UINT;
  t.argument = UINT64_MAX;
  assert(c89cbor_encoder_put(&e, &t) == 0);
  assert(c89cbor_encoder_put(&e, &t) == C89CBOR_OUTPUT);
  assert(c89cbor_encoder_finish(&e) == C89CBOR_OUTPUT);
  assert(c89cbor_encoder_read(&e, NULL, 0, &n) == C89CBOR_OUTPUT && n == 0);
  for (n = 0; n < 9;) {
    size_t wrote;
    int rc = c89cbor_encoder_read(&e, &out, 1, &wrote);
    assert(wrote == 1);
    ++n;
    assert(out == (n == 1 ? 0x1b : 0xff));
    assert(rc == (n == 9 ? 0 : C89CBOR_OUTPUT));
  }
  assert(c89cbor_encoder_finish(&e) == 0);
  assert(c89cbor_encoder_reset(&e) == 0);
  t.type = C89CBOR_BOOL;
  t.argument = 2;
  assert(c89cbor_encoder_put(&e, &t) == C89CBOR_MALFORMED);
  assert(c89cbor_encoder_finish(&e) == C89CBOR_MALFORMED);
  assert(c89cbor_decoder_init(NULL, &d, NULL, 1, 0) == C89CBOR_INVALID);
  assert(c89cbor_decoder_next(&d, NULL, 1, &n, &t) == C89CBOR_INVALID);
}
static void *no_alloc(void *unused) {
  c89cbor_decoder d;
  c89cbor_encoder e;
  c89cbor_token t, decoded;
  unsigned char input[2048], output[31];
  uint64_t total = UINT64_C(64) * 1024U * 1024U, received = 0;
  size_t at, got, wrote, i;
  int rc, wr;
  (void)unused;
  assert(c89cbor_decoder_init(NULL, &d, NULL, 0, 0) == 0);
  assert(c89cbor_encoder_init(NULL, &e, NULL, 0, 0) == 0);
  memset(input, 'a', sizeof(input));
  memset(&t, 0, sizeof(t));
  t.type = C89CBOR_TEXT;
  t.argument = total;
  for (i = 0; i < (size_t)(total / sizeof(input)) + 2; ++i) {
    if (i == 1) {
      memset(&t, 0, sizeof(t));
      t.type = C89CBOR_DATA;
      t.data = input;
      t.length = sizeof(input);
    }
    if (i == (size_t)(total / sizeof(input)) + 1) {
      memset(&t, 0, sizeof(t));
      t.type = C89CBOR_END;
      t.argument = C89CBOR_TEXT;
    }
    assert(c89cbor_encoder_put(&e, &t) == 0);
    do {
      wr = c89cbor_encoder_read(&e, output, sizeof(output), &wrote);
      assert(wr >= 0);
      at = 0;
      do {
        rc = c89cbor_decoder_next(&d, output + at, wrote - at, &got, &decoded);
        at += got;
        if (rc == C89CBOR_TOKEN && decoded.type == C89CBOR_DATA)
          received += decoded.length;
        assert(rc >= 0);
      } while (rc == C89CBOR_TOKEN);
      assert(at == wrote);
    } while (wr == C89CBOR_OUTPUT);
    if (i > 0 && t.type == C89CBOR_DATA)
      assert(received == i * sizeof(input));
  }
  assert(received == total);
  assert(c89cbor_decoder_finish(&d) == 0);
  assert(c89cbor_encoder_finish(&e) == 0);
  return NULL;
}
static void *refuse_alloc(void *context, size_t n) {
  (void)context;
  (void)n;
  return NULL;
}
static void free_alloc(void *context, void *p) {
  (void)context;
  free(p);
}
static void ownership(void) {
  c89cbor_allocator a;
  c89cbor_decoder *d;
  c89cbor_encoder *e;
  c89cbor_token t;
  double value = 0;
  memset(&a, 0, sizeof(a));
  a.alloc = refuse_alloc;
  a.free = free_alloc;
  assert(c89cbor_decoder_create(NULL, &a, &d) == C89CBOR_NOMEM && d == NULL);
  assert(c89cbor_encoder_create(NULL, &a, &e) == C89CBOR_NOMEM && e == NULL);
  assert(c89cbor_decoder_create(NULL, NULL, &d) == 0);
  assert(c89cbor_encoder_create(NULL, NULL, &e) == 0);
  c89cbor_decoder_destroy(d);
  c89cbor_encoder_destroy(e);
  assert(c89cbor_float64_set(NULL, &t, -0.0) == 0);
  assert(t.argument == (UINT64_C(1) << 63));
  assert(c89cbor_float64_get(NULL, &t, &value) == 0 && value == 0.0);
  assert(strchr(c89cbor_version(NULL), '.') != NULL);
  assert(c89cbor_status_string(NULL, -100) != NULL);
}
static void incomplete_text(void) {
  static const unsigned char bytes[] = {0x61, 0xf1};
  c89cbor_decoder decoder;
  c89cbor_encoder encoder;
  c89cbor_token token;
  unsigned char out;
  size_t n;
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  assert(c89cbor_encoder_init(NULL, &encoder, NULL, 0, 0) == 0);
  assert(c89cbor_decoder_next(&decoder, bytes, sizeof(bytes), &n, &token) ==
         C89CBOR_TOKEN);
  assert(n == 1 && token.type == C89CBOR_TEXT);
  assert(c89cbor_encoder_put(&encoder, &token) == 0);
  assert(c89cbor_encoder_read(&encoder, &out, 1, &n) == 0);
  assert(n == 1 && out == bytes[0]);
  assert(c89cbor_decoder_next(&decoder, bytes + 1, 1, &n, &token) ==
         C89CBOR_MALFORMED);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_DATA;
  token.data = bytes + 1;
  token.length = 1;
  assert(c89cbor_encoder_put(&encoder, &token) == 0);
  assert(c89cbor_encoder_read(&encoder, &out, 1, &n) == C89CBOR_MALFORMED);
  assert(n == 0);
}
int main(void) {
  pthread_t worker;
  vectors();
  bounds();
  ownership();
  incomplete_text();
  assert(pthread_create(&worker, NULL, no_alloc, NULL) == 0);
  assert(pthread_join(worker, NULL) == 0);
  puts("codec: vectors, fragmentation, truncation, limits, ownership, 64 MiB "
       "stream passed");
  return 0;
}
