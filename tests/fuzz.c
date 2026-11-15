#include <c89cbor/cbor.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t hash(uint64_t h, const c89cbor_token *t) {
  const unsigned char *p = t->data;
  size_t i;
  if (t->type == C89CBOR_DATA) {
    for (i = 0; i < t->length; ++i)
      h = h * 33U + p[i];
  } else {
    h = h * 33U + (unsigned int)t->type;
    h = h * 33U + t->argument;
    h = h * 33U + (unsigned int)t->indefinite;
  }
  return h;
}
int main(void) {
  c89cbor_decoder d, verify;
  c89cbor_encoder e;
  c89cbor_token t, v;
  unsigned char input[2048], output[17];
  size_t length, at, used, wrote, position, consumed;
  uint64_t expected = 0, actual = 0;
  int rc = C89CBOR_INPUT, wr, vr;
  assert(c89cbor_decoder_init(NULL, &d, NULL, 0, 7) == 0);
  assert(c89cbor_decoder_init(NULL, &verify, NULL, 0, 3) == 0);
  assert(c89cbor_encoder_init(NULL, &e, NULL, 0, 5) == 0);
  while ((length = fread(input, 1, sizeof(input), stdin)) != 0) {
    at = 0;
    do {
      rc = c89cbor_decoder_next(&d, input + at, length - at, &used, &t);
      at += used;
      if (rc < 0)
        return 0;
      if (rc == C89CBOR_TOKEN) {
        expected = hash(expected, &t);
        assert(c89cbor_encoder_put(&e, &t) == 0);
        do {
          wr = c89cbor_encoder_read(&e, output, sizeof(output), &wrote);
          assert(wr >= 0);
          position = 0;
          do {
            vr = c89cbor_decoder_next(&verify, output + position,
                                      wrote - position, &consumed, &v);
            position += consumed;
            assert(vr >= 0);
            if (vr == C89CBOR_TOKEN)
              actual = hash(actual, &v);
          } while (vr == C89CBOR_TOKEN);
          assert(position == wrote);
        } while (wr == C89CBOR_OUTPUT);
      }
    } while (rc == C89CBOR_TOKEN);
    if (rc == C89CBOR_DONE)
      break;
  }
  if (rc == C89CBOR_DONE) {
    assert(c89cbor_decoder_finish(&d) == 0 &&
           c89cbor_decoder_finish(&verify) == 0);
    assert(c89cbor_encoder_finish(&e) == 0 && expected == actual);
  }
  return 0;
}
