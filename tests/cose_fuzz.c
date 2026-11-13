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
  c89cbor_cose_key key[7], *keys[1];
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_operation op;
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  unsigned char raw[32] = {0}, public_bytes[32];
  size_t i, steps;
  int status, stream, auth, cwt;
  assert(argc == 2 && io != NULL);
  stream = strstr(argv[1], "stream") != NULL;
  auth = strstr(argv[1], "sign1") != NULL  ? 1
         : strstr(argv[1], "mac0") != NULL ? 2
                                           : 0;
  cwt = strstr(argv[1], "cwt") != NULL;
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
  raw[31] = 1;
  for (i = 4u; i < 7u; ++i)
    assert(root.cose_key_init(&root, &key[i],
                              i == 4u   ? C89CBOR_COSE_ED25519_PRIVATE
                              : i == 5u ? C89CBOR_COSE_P256_PRIVATE
                                        : C89CBOR_COSE_HMAC256,
                              raw, sizeof(raw), NULL, 0, &error) == 0);
  if (cwt) {
    static char issuer[] = "issuer", audience[] = "audience";
    static const char *const algs[] = {"Ed25519", "ES256", "HS256"};
    static const char *const issuers[] = {"issuer"}, *const audiences[] = {
                                                         "audience"};
    lonejson_jwt_claim_policy policy;
    lonejson_jwt_claims claims;
    c89cbor_cwt token;
    c89cbor_cwt_view view;
    size_t j, written;
    assert(root.cwt_init(&root, &token, NULL, &error) == 0);
    memset(&policy, 0, sizeof(policy));
    policy.accepted_algs = algs;
    policy.accepted_alg_count = 3u;
    policy.accepted_issuers = issuers;
    policy.accepted_issuer_count = 1u;
    policy.accepted_audiences = audiences;
    policy.accepted_audience_count = 1u;
    policy.now = 1;
    if (strncmp(argv[1], "seed", 4u) == 0) {
      memset(&claims, 0, sizeof(claims));
      claims.iss = issuer;
      claims.aud = audience;
      claims.exp = 100;
      claims.has_exp = 1;
      assert(token.set_lonejson(&token, &claims, NULL, 0, &error) == 0);
      assert(token.seal(&token,
                        &key[strstr(argv[1], "-p256") != NULL   ? 5u
                             : strstr(argv[1], "-hmac") != NULL ? 6u
                                                                : 4u],
                        NULL, 0, io->bytes, sizeof(io->bytes), &written,
                        &error) == 0);
      assert(fwrite(io->bytes, 1u, written, stdout) == written);
    } else {
      status = token.set_claims(&token, io->bytes, io->length, &error);
      if (status == 0)
        assert(token.view_get(&token, &view) == 0 && !view.authenticated);
      else
        assert(token.view_get(&token, &view) == C89CBOR_INPUT);
      for (i = 4u; i < 7u; ++i)
        for (j = 0; j < 3u; ++j) {
          status = token.verify(&token, io->bytes, io->length, &key[i], &key[j],
                                &policy, &error);
          if (status == 0)
            assert(token.view_get(&token, &view) == 0 && view.authenticated);
          else
            assert(token.view_get(&token, &view) == C89CBOR_INPUT &&
                   view.encoded == NULL);
        }
    }
    assert(token.cleanup(&token) == 0);
  } else if (strncmp(argv[1], "seed", 4u) == 0) {
    io->bytes[0] = 0;
    io->length = 1u;
    sink.write = seed_output;
    keys[0] = strstr(argv[1], "-kw") != NULL  ? &key[1]
              : strstr(argv[1], "-x") != NULL ? &key[3]
                                              : &key[0];
    options.encrypt = keys[0] != &key[0];
    if (auth) {
      c89cbor_cose_key *signing = &key[auth == 2                          ? 6u
                                       : strstr(argv[1], "-p256") != NULL ? 5u
                                                                          : 4u];
      status =
          auth == 2
              ? (stream ? root.cose_mac0_stream_init : root.cose_mac0_init)(
                    &root, &op, &source, &sink, signing, &options, &error)
              : (stream ? root.cose_sign1_stream_init : root.cose_sign1_init)(
                    &root, &op, &source, &sink, signing, &options, &error);
    } else
      status = stream
                   ? root.cose_encrypt_stream_init(&root, &op, &source, &sink,
                                                   keys, 1u, &options, &error)
               : options.encrypt
                   ? root.cose_encrypt_init(&root, &op, &source, &sink, keys,
                                            1u, &options, &error)
                   : root.cose_encrypt0_init(&root, &op, &source, &sink,
                                             keys[0], NULL, &error);
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
    for (i = auth == 1   ? 4u
             : auth == 2 ? 6u
                         : 0;
         i < (auth == 1   ? 6u
              : auth == 2 ? 7u
                          : 3u);
         ++i) {
      io->offset = io->output = io->calls = steps = 0;
      if (auth)
        status =
            auth == 2
                ? (stream ? root.cose_verify_mac0_stream_init
                          : root.cose_verify_mac0_init)(
                      &root, &op, &source, &sink, &key[i], &options, &error)
                : (stream ? root.cose_verify1_stream_init
                          : root.cose_verify1_init)(&root, &op, &source, &sink,
                                                    &key[i], &options, &error);
      else
        status = stream
                     ? root.cose_decrypt_stream_init(&root, &op, &source, &sink,
                                                     &key[i], &options, &error)
                     : root.cose_decrypt_init(&root, &op, &source, &sink,
                                              &key[i], &options, &error);
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
  for (i = 0; i < 7u; ++i)
    assert(key[i].cleanup(&key[i]) == 0);
  assert(root.cleanup(&root) == 0);
  free(io);
  return 0;
}
