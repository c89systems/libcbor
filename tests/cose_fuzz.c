#include <c89cbor/lonejson.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct fuzz_io {
  unsigned char bytes[8192];
  size_t length, offset, output, calls;
} fuzz_io;
static int read_input(void *context, void *bytes, size_t capacity,
                      size_t *count) {
  fuzz_io *io = context;
  size_t take = io->length - io->offset;
  *count = 0;
  if (++io->calls % 3u == 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > 13u)
    take = 13u;
  memcpy(bytes, io->bytes + io->offset, take);
  io->offset += take;
  *count = take;
  return 0;
}
static int count_output(void *context, const void *bytes, size_t length,
                        size_t *count) {
  fuzz_io *io = context;
  (void)bytes;
  *count = length > 7u ? 7u : length;
  io->output += *count;
  assert(io->output <= 8192u);
  return C89CBOR_OUTPUT;
}
static int seed_output(void *context, const void *bytes, size_t length,
                       size_t *count) {
  (void)context;
  *count = fwrite(bytes, 1u, length, stdout);
  return *count == length ? 0 : C89CBOR_IO;
}
int main(int argc, char **argv) {
  fuzz_io *io = calloc(1, sizeof(*io));
  c89cbor root;
  c89cbor_cose_key key[4], *keys[1];
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_operation op;
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  unsigned char raw[32] = {0}, public_bytes[32];
  size_t i, steps;
  int status, stream;
  assert(argc == 2 && io != NULL);
  stream = strstr(argv[1], "stream") != NULL;
  io->length = fread(io->bytes, 1u, 4096u, stdin);
  source.context = sink.context = io;
  source.read = read_input;
  sink.write = count_output;
  assert(c89cbor_init(&root, NULL, &error) == 0);
  for (i = 0; i < 3u; ++i) {
    assert(root.cose_key_init(&root, &key[i],
                              i == 0   ? C89CBOR_COSE_A256GCM
                              : i == 1 ? C89CBOR_COSE_A256KW
                                       : C89CBOR_COSE_X25519_PRIVATE,
                              raw, 32u, NULL, 0, &error) == 0);
  }
  assert(key[2].public_key(&key[2], public_bytes, 32u, &i) == 0);
  assert(root.cose_key_init(&root, &key[3], C89CBOR_COSE_X25519_PUBLIC,
                            public_bytes, 32u, NULL, 0, &error) == 0);
  if (strncmp(argv[1], "seed", 4u) == 0) {
    io->bytes[0] = 0;
    io->length = 1u;
    sink.write = seed_output;
    keys[0] = strstr(argv[1], "-kw") != NULL  ? &key[1]
              : strstr(argv[1], "-x") != NULL ? &key[3]
                                              : &key[0];
    options.encrypt = keys[0] != &key[0];
    status = stream ? root.cose_encrypt_stream_init(&root, &op, &source, &sink,
                                                    keys, 1u, &options, &error)
             : options.encrypt
                 ? root.cose_encrypt_init(&root, &op, &source, &sink, keys, 1u,
                                          &options, &error)
                 : root.cose_encrypt0_init(&root, &op, &source, &sink, keys[0],
                                           NULL, &error);
    assert(status == 0);
    do {
      status = op.step(&op, &error);
    } while (status == 0 || status == C89CBOR_INPUT ||
             status == C89CBOR_OUTPUT);
    assert(status == C89CBOR_DONE && op.cleanup(&op) == 0);
  } else {
    options.record_bytes = 1024u;
    options.header_bytes = 2048u;
    options.step_input = 17u;
    options.step_output = 11u;
    options.step_events = 7u;
    for (i = 0; i < 3u; ++i) {
      io->offset = io->output = io->calls = steps = 0;
      status = stream
                   ? root.cose_decrypt_stream_init(&root, &op, &source, &sink,
                                                   &key[i], &options, &error)
                   : root.cose_decrypt_init(&root, &op, &source, &sink, &key[i],
                                            &options, &error);
      assert(status == 0);
      do {
        status = op.step(&op, &error);
        assert(++steps < 10000u);
      } while (status == 0 || status == C89CBOR_INPUT ||
               status == C89CBOR_OUTPUT);
      assert(op.step(&op, &error) == status);
      assert(op.cleanup(&op) == 0 && op.cleanup(&op) == 0);
    }
  }
  for (i = 0; i < 4u; ++i)
    assert(key[i].cleanup(&key[i]) == 0);
  assert(root.cleanup(&root) == 0);
  free(io);
  return 0;
}
