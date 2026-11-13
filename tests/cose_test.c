#include <c89cbor/lonejson.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

typedef struct buffer {
  unsigned char bytes[32768];
  size_t length, offset, fragment, calls;
  int pause;
} buffer;
typedef struct fixture {
  c89cbor runtime;
  c89cbor_cose_key content, wrap, private_key, public_key;
  c89cbor_source source;
  c89cbor_sink sink;
  buffer input, wire, output;
} fixture;
static int read_buffer(void *context, void *bytes, size_t capacity,
                       size_t *count) {
  buffer *value = context;
  size_t length = value->length - value->offset;
  *count = 0;
  if (value->pause && ++value->calls % 2u == 1u)
    return C89CBOR_INPUT;
  if (length > capacity)
    length = capacity;
  if (value->fragment != 0 && length > value->fragment)
    length = value->fragment;
  if (length != 0)
    memcpy(bytes, value->bytes + value->offset, length);
  value->offset += length;
  *count = length;
  return C89CBOR_OK;
}
static int write_buffer(void *context, const void *bytes, size_t length,
                        size_t *count) {
  buffer *value = context;
  *count = 0;
  if (value->pause && ++value->calls % 2u == 1u)
    return C89CBOR_OUTPUT;
  if (value->fragment != 0 && length > value->fragment)
    length = value->fragment;
  assert(length <= sizeof(value->bytes) - value->length);
  memcpy(value->bytes + value->length, bytes, length);
  value->length += length;
  *count = length;
  return value->pause ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static int drive(c89cbor_cose_operation *operation) {
  c89cbor_progress before, after;
  c89cbor_error error;
  size_t calls = 0;
  int status;
  do {
    assert(operation->progress(operation, &before) == 0);
    status = operation->step(operation, &error);
    assert(operation->progress(operation, &after) == 0);
    assert(after.input - before.input <= 11u);
    assert(after.output - before.output <= 7u);
    assert(++calls < 100000u);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(operation->step(operation, &error) == status);
  return status;
}
static void endpoints(fixture *f, buffer *input, buffer *output) {
  input->offset = input->calls = 0;
  output->offset = output->length = output->calls = 0;
  f->source.context = input;
  f->source.read = read_buffer;
  f->sink.context = output;
  f->sink.write = write_buffer;
}
static void prepare(fixture *f) {
  unsigned char content[32], wrapping[32], private_bytes[32], public_bytes[32];
  size_t length;
  c89cbor_error error;
  memset(f, 0, sizeof(*f));
  memset(content, 0, sizeof(content));
  memset(wrapping, 0x51, sizeof(wrapping));
  memset(private_bytes, 0x37, sizeof(private_bytes));
  assert(c89cbor_init(&f->runtime, NULL, &error) == 0);
  assert(c89cbor_cose_key_init(&f->runtime, &f->content, C89CBOR_COSE_A256GCM,
                               content, sizeof(content), NULL, 0, &error) == 0);
  assert(c89cbor_cose_key_init(&f->runtime, &f->wrap, C89CBOR_COSE_A256KW,
                               wrapping, sizeof(wrapping), "wrap", 4u,
                               &error) == 0);
  assert(c89cbor_cose_key_init(&f->runtime, &f->private_key,
                               C89CBOR_COSE_X25519_PRIVATE, private_bytes,
                               sizeof(private_bytes), "x", 1u, &error) == 0);
  assert(f->private_key.public_key(&f->private_key, public_bytes,
                                   sizeof(public_bytes), &length) == 0 &&
         length == 32u);
  assert(c89cbor_cose_key_init(&f->runtime, &f->public_key,
                               C89CBOR_COSE_X25519_PUBLIC, public_bytes, length,
                               "x", 1u, &error) == 0);
}
static void cleanup(fixture *f) {
  assert(f->runtime.json == NULL);
  assert(f->public_key.cleanup(&f->public_key) == 0);
  assert(f->private_key.cleanup(&f->private_key) == 0);
  assert(f->wrap.cleanup(&f->wrap) == 0);
  assert(f->content.cleanup(&f->content) == 0);
  assert(f->runtime.cleanup(&f->runtime) == 0);
}
/* Independent Enc_structure and COSE wire construction: no libcbor encoder,
 * parser or encryption helper supplies these expected bytes. OpenSSL is the
 * cryptographic backend under test; its AES-256 ciphertext is also NIST-known.
 */
static void vector(fixture *f) {
  static const unsigned char aad[] = {0x83, 0x68, 'E', 'n', 'c',
                                      'r',  'y',  'p', 't', '0',
                                      0x43, 0xa1, 1,   3,   0x40};
  static const unsigned char ciphertext[] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60,
                                             0x6b, 0x6e, 7,    0x4e, 0xc5, 0xd3,
                                             0xba, 0xf3, 0x9d, 0x18};
  unsigned char key[32], nonce[12], plain[16], encrypted[32], expected[55];
  EVP_CIPHER_CTX *context;
  OSSL_PARAM parameters[2];
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error;
  int length, last;
  memset(key, 0, sizeof(key));
  memset(nonce, 0, sizeof(nonce));
  memset(plain, 0, sizeof(plain));
  context = EVP_CIPHER_CTX_new();
  assert(context != NULL);
  assert(EVP_EncryptInit_ex2(context, EVP_aes_256_gcm(), key, nonce, NULL) ==
         1);
  assert(EVP_EncryptUpdate(context, NULL, &length, aad, sizeof(aad)) == 1);
  assert(EVP_EncryptUpdate(context, encrypted, &length, plain, sizeof(plain)) ==
             1 &&
         length == 16);
  assert(EVP_EncryptFinal_ex(context, encrypted + length, &last) == 1 &&
         last == 0);
  parameters[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    encrypted + 16u, 16u);
  parameters[1] = OSSL_PARAM_construct_end();
  assert(EVP_CIPHER_CTX_get_params(context, parameters) == 1);
  EVP_CIPHER_CTX_free(context);
  assert(memcmp(encrypted, ciphertext, sizeof(ciphertext)) == 0);
  expected[0] = 0xd0;
  expected[1] = 0x83;
  expected[2] = 0x43;
  expected[3] = 0xa1;
  expected[4] = 1;
  expected[5] = 3;
  expected[6] = 0xa1;
  expected[7] = 5;
  expected[8] = 0x4c;
  memcpy(expected + 9u, nonce, 12u);
  expected[21] = 0x58;
  expected[22] = 0x20;
  memcpy(expected + 23u, encrypted, 32u);
  memcpy(f->input.bytes, plain, sizeof(plain));
  f->input.length = sizeof(plain);
  endpoints(f, &f->input, &f->wire);
  options.nonce = nonce;
  assert(f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                  &f->content, &options, &error) == 0);
  assert(f->wire.length == sizeof(expected) &&
         memcmp(f->wire.bytes, expected, sizeof(expected)) == 0);
  memcpy(f->wire.bytes, expected, sizeof(expected));
  endpoints(f, &f->wire, &f->output);
  assert(f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink, &f->content,
                                 NULL, &error) == 0);
  assert(f->output.length == sizeof(plain) &&
         memcmp(f->output.bytes, plain, sizeof(plain)) == 0);
}
static void round_trip(fixture *f, int encrypt, int stream, int pause) {
  c89cbor_cose_key *keys[2];
  c89cbor_cose_operation operation;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error;
  size_t i, count;
  int status;
  f->input.length = stream ? 5003u : 123u;
  for (i = 0; i < f->input.length; ++i)
    f->input.bytes[i] = (unsigned char)i;
  f->input.pause = f->wire.pause = f->output.pause = pause;
  f->input.fragment = 3u;
  f->wire.fragment = 2u;
  f->output.fragment = 1u;
  endpoints(f, &f->input, &f->wire);
  options.step_input = 11u;
  options.step_output = 7u;
  options.step_events = 3u;
  options.encrypt = encrypt;
  keys[0] = encrypt ? &f->wrap : &f->content;
  keys[1] = &f->public_key;
  count = encrypt ? 2u : 1u;
  if (stream)
    status = f->runtime.cose_encrypt_stream_init(&f->runtime, &operation,
                                                 &f->source, &f->sink, keys,
                                                 count, &options, &error);
  else if (encrypt)
    status =
        f->runtime.cose_encrypt_init(&f->runtime, &operation, &f->source,
                                     &f->sink, keys, count, &options, &error);
  else
    status =
        f->runtime.cose_encrypt0_init(&f->runtime, &operation, &f->source,
                                      &f->sink, &f->content, &options, &error);
  assert(status == 0 && f->input.offset == 0 && f->wire.length == 0);
  assert(keys[0]->cleanup(keys[0]) == C89CBOR_BUSY);
  assert(drive(&operation) == C89CBOR_DONE);
  assert(operation.cleanup(&operation) == 0);
  endpoints(f, &f->wire, &f->output);
  if (stream)
    status = f->runtime.cose_decrypt_stream_init(
        &f->runtime, &operation, &f->source, &f->sink,
        encrypt ? &f->private_key : &f->content, &options, &error);
  else
    status = f->runtime.cose_decrypt_init(
        &f->runtime, &operation, &f->source, &f->sink,
        encrypt ? &f->private_key : &f->content, &options, &error);
  assert(status == 0 && f->wire.offset == 0 && f->output.length == 0);
  status = drive(&operation);
  if (status != C89CBOR_DONE)
    fprintf(stderr, "COSE round trip: %d %d %d status %d layer %s\n", encrypt,
            stream, pause, status, operation.conversion.lifetime.error.layer);
  assert(status == C89CBOR_DONE);
  assert(operation.cleanup(&operation) == 0 &&
         operation.cleanup(&operation) == 0);
  assert(f->output.length == f->input.length &&
         memcmp(f->output.bytes, f->input.bytes, f->input.length) == 0);
  if (encrypt) {
    endpoints(f, &f->wire, &f->output);
    if (stream)
      status = f->runtime.cose_decrypt_stream_init(&f->runtime, &operation,
                                                   &f->source, &f->sink,
                                                   &f->wrap, &options, &error);
    else
      status =
          f->runtime.cose_decrypt_init(&f->runtime, &operation, &f->source,
                                       &f->sink, &f->wrap, &options, &error);
    assert(status == 0 && drive(&operation) == C89CBOR_DONE);
    assert(operation.cleanup(&operation) == 0);
    assert(f->output.length == f->input.length &&
           memcmp(f->output.bytes, f->input.bytes, f->input.length) == 0);
  }
}
static void tamper(fixture *f) {
  c89cbor_error error;
  size_t length;
  int status;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  f->input.length = 17u;
  memset(f->input.bytes, 'x', f->input.length);
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                  &f->content, NULL, &error) == 0);
  length = f->wire.length;
  f->wire.bytes[length - 1u] ^= 1u;
  endpoints(f, &f->wire, &f->output);
  status = f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink,
                                   &f->content, NULL, &error);
  assert(status == C89CBOR_AUTH && f->output.length == 0);
  f->wire.bytes[length - 1u] ^= 1u;
  f->wire.bytes[f->wire.length++] = 0;
  endpoints(f, &f->wire, &f->output);
  status = f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink,
                                   &f->content, NULL, &error);
  assert(status == C89CBOR_MALFORMED && f->output.length == 0);
}
#include "cose_stream.inc.h"
#include "cose_reference.inc.h"
#include "cose_security.inc.h"
#include "cose_context.inc.h"
#include "cose_lifetime.inc.h"
#include "cose_transport.inc.h"
#include "cose_counters.inc.h"
#include "cose_concurrency.inc.h"
#include "cose_sign.inc.h"
#include "cwt.inc.h"
#include "cose_udp.inc.h"
static void *run(void *unused) {
  fixture *f = malloc(sizeof(*f));
  int encrypt, stream, pause;
  (void)unused;
  assert(f != NULL);
  prepare(f);
  vector(f);
  cose_reference(f);
  cose_context_reference(f);
  for (encrypt = 0; encrypt < 2; ++encrypt)
    for (stream = 0; stream < 2; ++stream)
      for (pause = 0; pause < 2; ++pause)
        round_trip(f, encrypt, stream, pause);
  tamper(f);
  cose_pipeline(f, 0);
  cose_pipeline(f, 1);
  cose_coalesced(f, 0);
  cose_coalesced(f, 1);
  cose_header_failures(f);
  cose_recipient_attacks(f);
  cose_header_edges(f);
  cose_replay_admission(f);
  cose_stream_attacks(f);
  cose_lifetime(f);
  cose_factory_reentry(f);
  cose_transports(f);
  cose_counters(f);
  cose_concurrency(f);
  cose_authentication(f);
  cwt_tokens(f);
  cwt_claim_edges(f);
  cwt_policy_edges(f);
  cwt_allocations();
  cose_udp_failures(f);
  cleanup(f);
  free(f);
  return NULL;
}
int main(void) {
  pthread_t worker;
  assert(pthread_create(&worker, NULL, run, NULL) == 0);
  assert(pthread_join(worker, NULL) == 0);
  puts("cose: independent Encrypt0 bytes, both recipient families and ordered "
       "backpressure");
  return 0;
}
