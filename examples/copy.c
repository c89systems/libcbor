/* Validate and forward a CBOR sequence from blocking stdin to stdout. */
#include <c89cbor/io.h>
#include <stdio.h>
int main(void) {
  c89cbor_transfer transfer;
  c89cbor_fd input, output;
  c89cbor_source source;
  c89cbor_sink sink;
  int status = c89cbor_fd_init(&input, 0, &source, NULL);
  if (status == C89CBOR_OK)
    status = c89cbor_fd_init(&output, 1, NULL, &sink);
  if (status == C89CBOR_OK)
    status =
        c89cbor_transfer_init(&transfer, &source, &sink, C89CBOR_SEQUENCE, 0);
  while (status == C89CBOR_OK)
    status = c89cbor_transfer_step(&transfer);
  if (status == C89CBOR_DONE)
    return 0;
  fprintf(stderr, "copy: %s\n", c89cbor_status_string(status));
  return 1;
}
