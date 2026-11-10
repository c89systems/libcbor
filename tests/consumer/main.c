#include <c89cbor/cbor.h>
#include <c89cbor/io.h>
#include <string.h>
int main(void) {
  c89cbor_decoder d;
  c89cbor_token t;
  const unsigned char input[] = {0x18, 0x2a};
  size_t used;
  if (c89cbor_decoder_init(&d, 0, 0, 0) != 0)
    return 1;
  if (c89cbor_decoder_next(&d, input, sizeof(input), &used, &t) !=
          C89CBOR_TOKEN ||
      used != 2 || t.type != C89CBOR_UINT || t.argument != 42)
    return 2;
  if (c89cbor_decoder_finish(&d) != 0)
    return 3;
  return strcmp(c89cbor_version(), EXPECTED_VERSION) != 0;
}
