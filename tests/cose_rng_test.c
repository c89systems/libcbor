#include <c89cbor/lonejson.h>
#include <openssl/types.h>
#include <assert.h>
#include <string.h>
/* Linker wrapping is confined to this executable, never a product hook. */
int __wrap_RAND_bytes_ex(OSSL_LIB_CTX *, unsigned char *, size_t, unsigned int);
int __real_RAND_bytes_ex(OSSL_LIB_CTX *, unsigned char *, size_t, unsigned int);
int __wrap_RAND_priv_bytes_ex(OSSL_LIB_CTX *, unsigned char *, size_t,
                              unsigned int);
int __real_RAND_priv_bytes_ex(OSSL_LIB_CTX *, unsigned char *, size_t,
                              unsigned int);
static int fail_rng;
int __wrap_RAND_bytes_ex(OSSL_LIB_CTX *context, unsigned char *bytes,
                         size_t length, unsigned int strength) {
  if (fail_rng == 1)
    return 0;
  return __real_RAND_bytes_ex(context, bytes, length, strength);
}
int __wrap_RAND_priv_bytes_ex(OSSL_LIB_CTX *context, unsigned char *bytes,
                              size_t length, unsigned int strength) {
  return fail_rng == 2
             ? 0
             : __real_RAND_priv_bytes_ex(context, bytes, length, strength);
}
static int empty(void *context, void *bytes, size_t capacity, size_t *count) {
  (void)context;
  (void)bytes;
  (void)capacity;
  *count = 0;
  return 0;
}
static int reject_output(void *context, const void *bytes, size_t length,
                         size_t *count) {
  (void)context;
  (void)bytes;
  (void)length;
  (void)count;
  assert(0);
  return C89CBOR_IO;
}
int main(void) {
  c89cbor root;
  c89cbor_cose_key content, wrapping;
  c89cbor_cose_key *key;
  c89cbor_cose_operation operation, *heap = &operation;
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  unsigned char bytes[32] = {0};
  int status;
  source.context = sink.context = NULL;
  source.read = empty;
  sink.write = reject_output;
  assert(c89cbor_init(&root, NULL, &error) == 0);
  assert(root.cose_key_init(&root, &content, C89CBOR_COSE_A256GCM, bytes, 32u,
                            NULL, 0, &error) == 0);
  bytes[0] = 1;
  assert(root.cose_key_init(&root, &wrapping, C89CBOR_COSE_A256KW, bytes, 32u,
                            NULL, 0, &error) == 0);
  fail_rng = 1;
  key = &content;
  assert(root.cose_encrypt_stream_open(&root, &source, &sink, &key, 1u, NULL,
                                       &heap, &error) == C89CBOR_CRYPTO);
  assert(heap == NULL && error.status == C89CBOR_CRYPTO);
  assert(root.cose_encrypt0_init(&root, &operation, &source, &sink, &content,
                                 NULL, &error) == 0);
  do {
    status = operation.step(&operation, &error);
  } while (status == 0);
  assert(status == C89CBOR_CRYPTO && error.status == status);
  assert(operation.step(&operation, &error) == status &&
         operation.cleanup(&operation) == 0);
  key = &wrapping;
  fail_rng = 2;
  assert(root.cose_encrypt(&root, &source, &sink, &key, 1u, NULL, &error) ==
         C89CBOR_CRYPTO);
  assert(content.cleanup(&content) == 0 && wrapping.cleanup(&wrapping) == 0 &&
         root.cleanup(&root) == 0);
  return 0;
}
