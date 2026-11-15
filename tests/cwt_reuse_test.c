#include <c89cbor/lonejson.h>
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct accounting {
  size_t calls, live;
} accounting;
typedef struct worker {
  c89cbor_cwt token;
  unsigned char wire[2048];
} worker;
static void *allocate(void *context, size_t size) {
  accounting *a = context;
  void *p = malloc(size);
  ++a->calls;
  if (p != NULL)
    ++a->live;
  return p;
}
static void release(void *context, void *p) {
  accounting *a = context;
  if (p != NULL) {
    --a->live;
    free(p);
  }
}
static void *exercise(void *context) {
  static const unsigned char claims[] = {0xa3, 1, 0x61, 'i',  3,   0x61,
                                         'a',  4, 0x19, 0x03, 0xe8};
  static const char *const algorithms[] = {"Ed25519", "ES256", "HS256"};
  static const char *const issuers[] = {"i"}, *const audiences[] = {"a"};
  worker *w = context;
  lonejson_jwt_claim_policy policy;
  c89cbor_cwt_view view;
  c89cbor_error error;
  size_t i, length;
  memset(&policy, 0, sizeof(policy));
  policy.now = 100;
  policy.accepted_algs = algorithms;
  policy.accepted_alg_count = 3;
  policy.accepted_issuers = issuers;
  policy.accepted_issuer_count = 1;
  policy.accepted_audiences = audiences;
  policy.accepted_audience_count = 1;
  for (i = 0; i < 25u; ++i) {
    assert(w->token.set_claims(&w->token, claims, sizeof(claims), &error) == 0);
    assert(w->token.seal(&w->token, w->wire, sizeof(w->wire), &length,
                         &error) == 0);
    if (w->token.verify(&w->token, w->wire, length, &policy, &error) != 0) {
      fprintf(stderr, "verify: %d %s %s\n", error.status, error.layer,
              error.message);
      abort();
    }
    assert(w->token.view_get(&w->token, &view) == 0 && view.authenticated);
    w->wire[length - 1u] ^= 1u;
    assert(w->token.verify(&w->token, w->wire, length, &policy, &error) < 0);
    assert(w->token.view_get(&w->token, &view) == C89CBOR_INPUT);
  }
  return NULL;
}
int main(void) {
  static const c89cbor_cose_key_kind kinds[] = {C89CBOR_COSE_ED25519_PRIVATE,
                                                C89CBOR_COSE_P256_PRIVATE,
                                                C89CBOR_COSE_HMAC256};
  c89cbor root;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_cwt_options options;
  c89cbor_cose_key signing, decrypt, recipient;
  c89cbor_cose_key *recipients[1];
  c89cbor_error error;
  accounting a;
  worker *workers;
  pthread_t threads[3];
  unsigned char secret[32], public_bytes[32];
  size_t family, algorithm, i, length, before;
  memset(&a, 0, sizeof(a));
  memset(secret, 0, sizeof(secret));
  secret[31] = 1;
  config.allocator.context = &a;
  config.allocator.alloc = allocate;
  config.allocator.free = release;
  assert(c89cbor_init(&root, &config, &error) == 0);
  workers = calloc(3u, sizeof(*workers));
  assert(workers != NULL);
  for (algorithm = 0; algorithm < 3u; ++algorithm) {
    assert(root.cose_key_init(&root, &signing, kinds[algorithm], secret, 32u,
                              NULL, 0, &error) == 0);
    for (family = 0; family < 4u; ++family) {
      options = root.default_cwt_options(&root);
      options.cose.encrypt = family > 1u;
      if (family != 0) {
        assert(root.cose_key_init(&root, &decrypt,
                                  family == 1   ? C89CBOR_COSE_A256GCM
                                  : family == 2 ? C89CBOR_COSE_A256KW
                                                : C89CBOR_COSE_X25519_PRIVATE,
                                  secret, 32u, NULL, 0, &error) == 0);
        if (family == 3) {
          assert(decrypt.public_key(&decrypt, public_bytes,
                                    sizeof(public_bytes), &length) == 0);
          assert(root.cose_key_init(&root, &recipient,
                                    C89CBOR_COSE_X25519_PUBLIC, public_bytes,
                                    length, NULL, 0, &error) == 0);
          recipients[0] = &recipient;
        } else
          recipients[0] = &decrypt;
      }
      for (i = 0; i < 3u; ++i) {
        assert(root.cwt_init(&root, &workers[i].token, &options, &error) == 0);
        assert(workers[i].token.set_seal_keys(&workers[i].token, &signing,
                                              family ? recipients : NULL,
                                              family ? 1u : 0u, &error) == 0);
        assert(workers[i].token.set_verify_keys(&workers[i].token, &signing,
                                                family ? &decrypt : NULL,
                                                &error) == 0);
        assert(workers[i].token.set_seal_keys(&workers[i].token, NULL,
                                              recipients, 1u,
                                              &error) == C89CBOR_INVALID);
        assert(workers[i].token.set_verify_keys(&workers[i].token, NULL,
                                                family ? &decrypt : &signing,
                                                &error) == C89CBOR_INVALID);
      }
      assert(signing.cleanup(&signing) == C89CBOR_BUSY);
      before = a.calls;
      for (i = 0; i < 3u; ++i)
        assert(pthread_create(&threads[i], NULL, exercise, &workers[i]) == 0);
      for (i = 0; i < 3u; ++i)
        assert(pthread_join(threads[i], NULL) == 0);
      assert(a.calls == before);
      for (i = 0; i < 3u; ++i) {
        assert(workers[i].token.set_seal_keys(&workers[i].token, NULL, NULL, 0,
                                              &error) == 0);
        assert(workers[i].token.set_verify_keys(&workers[i].token, NULL, NULL,
                                                &error) == 0);
        assert(workers[i].token.cleanup(&workers[i].token) == 0);
      }
      if (family == 3)
        assert(recipient.cleanup(&recipient) == 0);
      if (family != 0)
        assert(decrypt.cleanup(&decrypt) == 0);
    }
    assert(signing.cleanup(&signing) == 0);
  }
  free(workers);
  assert(root.cleanup(&root) == 0 && a.live == 0);
  return 0;
}
