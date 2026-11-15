#include "cose_internal.h"
#include <string.h>

int c89_cose_key_valid(const c89cbor_cose_key *key) {
  return key != NULL && key->lifetime.magic == C89_LIFETIME_MAGIC &&
         key->lifetime.live && key->state != NULL;
}
int c89_cose_key_reserve(c89cbor_cose_key *key) {
  c89_cose_key_state *state = key->state;
  int status = C89CBOR_OK;
  if (pthread_mutex_lock(&state->mutex) != 0)
    return C89CBOR_CRYPTO;
  if (state->uses >= (UINT64_C(1) << 24u))
    status = C89CBOR_LIMIT;
  else
    ++state->uses;
  if (pthread_mutex_unlock(&state->mutex) != 0)
    return C89CBOR_CRYPTO;
  return status;
}
int c89cbor_cose_key_metadata(const c89cbor_cose_key *key,
                              c89cbor_cose_key_info *info) {
  const c89_cose_key_state *state;
  if (info != NULL)
    memset(info, 0, sizeof(*info));
  if (!c89_cose_key_valid(key) || info == NULL)
    return C89CBOR_INVALID;
  state = key->state;
  *info = state->info;
  return C89CBOR_OK;
}
int c89cbor_cose_key_public_key(const c89cbor_cose_key *key, void *bytes,
                                size_t capacity, size_t *written) {
  const c89_cose_key_state *state;
  size_t length;
  if (written != NULL)
    *written = 0;
  if (!c89_cose_key_valid(key) || written == NULL ||
      (bytes == NULL && capacity != 0))
    return C89CBOR_INVALID;
  state = key->state;
  if (state->pkey == NULL)
    return C89CBOR_UNSUPPORTED;
  length = state->info.kind == C89CBOR_COSE_P256_PUBLIC ||
                   state->info.kind == C89CBOR_COSE_P256_PRIVATE
               ? 65u
               : 32u;
  if (capacity < length)
    return C89CBOR_LIMIT;
  if ((length == 65u
           ? EVP_PKEY_get_octet_string_param(
                 state->pkey, OSSL_PKEY_PARAM_PUB_KEY, bytes, capacity, &length)
           : EVP_PKEY_get_raw_public_key(state->pkey, bytes, &length)) != 1)
    return C89CBOR_CRYPTO;
  *written = length;
  return C89CBOR_OK;
}
int c89cbor_cose_key_diagnostic(const c89cbor_cose_key *key,
                                c89cbor_error *error) {
  return c89_lifetime_diagnostic(key == NULL ? NULL : &key->lifetime, error);
}
int c89cbor_cose_key_cleanup(c89cbor_cose_key *key) {
  c89_cose_key_state *state;
  c89cbor_allocator allocator;
  if (key == NULL)
    return C89CBOR_OK;
  if (key->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (key->lifetime.busy || key->lifetime.dependents)
    return C89CBOR_BUSY;
  state = key->state;
  key->state = NULL;
  allocator = key->lifetime.allocator;
  key->lifetime.busy = 1;
  if (state != NULL) {
    EVP_PKEY_free(state->pkey);
    EVP_CIPHER_free(state->gcm);
    EVP_CIPHER_free(state->wrap);
    EVP_KDF_free(state->hkdf);
    if (state->mutex_ready)
      (void)pthread_mutex_destroy(&state->mutex);
    OPENSSL_cleanse(state, sizeof(*state));
    allocator.free(allocator.context, state);
  }
  key->lifetime.busy = 0;
  return c89_lifetime_cleanup(&key->lifetime);
}
int c89cbor_cose_key_destroy(c89cbor_cose_key *key) {
  int status;
  if (key == NULL)
    return C89CBOR_OK;
  if (key->lifetime.magic != C89_LIFETIME_MAGIC || !key->lifetime.owned)
    return C89CBOR_INVALID;
  status = c89cbor_cose_key_cleanup(key);
  return status == 0 ? c89_lifetime_destroy(&key->lifetime, key) : status;
}
int c89cbor_cose_key_init(c89cbor *runtime, c89cbor_cose_key *key,
                          c89cbor_cose_key_kind kind, const void *bytes,
                          size_t length, const void *id, size_t id_length,
                          c89cbor_error *error) {
  c89_cose_key_state *state;
  c89cbor_allocator allocator;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (key == NULL)
    return C89CBOR_INVALID;
  memset(key, 0, sizeof(*key));
  key->metadata = c89cbor_cose_key_metadata;
  key->public_key = c89cbor_cose_key_public_key;
  key->diagnostic = c89cbor_cose_key_diagnostic;
  key->cleanup = c89cbor_cose_key_cleanup;
  key->destroy = c89cbor_cose_key_destroy;
  status = c89_lifetime_init(&key->lifetime, runtime, NULL);
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  if (kind < C89CBOR_COSE_A256GCM || kind > C89CBOR_COSE_HMAC256 ||
      bytes == NULL ||
      length != (kind == C89CBOR_COSE_P256_PUBLIC ? 65u : 32u) ||
      id_length > 64u || (id == NULL && id_length != 0)) {
    (void)c89cbor_cose_key_cleanup(key);
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  key->lifetime.busy = 1;
  status =
      c89_allocate(runtime, NULL, sizeof(*state), (void **)&state, &allocator);
  key->lifetime.busy = 0;
  if (status == 0) {
    memset(state, 0, sizeof(*state));
    key->state = state;
    state->info.kind = kind;
    state->info.key_id_length = id_length;
    if (id_length != 0)
      memcpy(state->info.key_id, id, id_length);
    if (kind != C89CBOR_COSE_P256_PUBLIC)
      memcpy(state->secret, bytes, 32u);
    state->gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    state->wrap = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL);
    state->hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    status = state->gcm == NULL || state->wrap == NULL || state->hkdf == NULL
                 ? C89CBOR_UNSUPPORTED
                 : C89CBOR_OK;
    if (pthread_mutex_init(&state->mutex, NULL) == 0)
      state->mutex_ready = 1;
    else
      status = C89CBOR_CRYPTO;
    if (kind == C89CBOR_COSE_X25519_PUBLIC)
      state->pkey =
          EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, bytes, length);
    else if (kind == C89CBOR_COSE_X25519_PRIVATE)
      state->pkey =
          EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, bytes, length);
    else if (kind == C89CBOR_COSE_ED25519_PUBLIC)
      state->pkey =
          EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL, bytes, length);
    else if (kind == C89CBOR_COSE_ED25519_PRIVATE)
      state->pkey =
          EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, bytes, length);
    else if (kind == C89CBOR_COSE_P256_PUBLIC ||
             kind == C89CBOR_COSE_P256_PRIVATE)
      state->pkey =
          c89_cose_p256_import(bytes, kind == C89CBOR_COSE_P256_PRIVATE);
    if ((kind == C89CBOR_COSE_X25519_PUBLIC ||
         kind == C89CBOR_COSE_X25519_PRIVATE ||
         (kind >= C89CBOR_COSE_ED25519_PUBLIC &&
          kind <= C89CBOR_COSE_P256_PRIVATE)) &&
        state->pkey == NULL)
      status = C89CBOR_CRYPTO;
  }
  if (status != 0) {
    c89_error(&key->lifetime, status, "cose-key");
    if (error != NULL)
      *error = key->lifetime.error;
    (void)c89cbor_cose_key_cleanup(key);
  }
  return status;
}
int c89cbor_cose_key_create(c89cbor *runtime, c89cbor_cose_key_kind kind,
                            const void *bytes, size_t length, const void *id,
                            size_t id_length, c89cbor_cose_key **out,
                            c89cbor_error *error) {
  c89cbor_cose_key *key;
  c89cbor_allocator allocator;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(*key), (void **)&key, &allocator);
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  status = c89cbor_cose_key_init(runtime, key, kind, bytes, length, id,
                                 id_length, error);
  if (status != 0) {
    allocator.free(allocator.context, key);
    return status;
  }
  key->lifetime.allocator = allocator;
  key->lifetime.owned = 1;
  *out = key;
  return C89CBOR_OK;
}
