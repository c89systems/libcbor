#include "cose_internal.h"
#include <openssl/params.h>
#include <string.h>
#include <limits.h>

int c89_cose_gcm(c89_cose_key_state *key, EVP_CIPHER_CTX *context, int encrypt,
                 const unsigned char *secret, const unsigned char *nonce,
                 const void *aad, size_t aad_length, const void *input,
                 size_t length, unsigned char *output, size_t *written) {
  const unsigned char *bytes = input;
  unsigned char tag[16];
  OSSL_PARAM parameters[2];
  int first = 0, last = 0, ignored = 0, ok;
  *written = 0;
  if (length > (size_t)INT_MAX - 16u || aad_length > (size_t)INT_MAX)
    return C89CBOR_LIMIT;
  if (!encrypt && length < sizeof(tag))
    return C89CBOR_MALFORMED;
  if (EVP_CIPHER_CTX_reset(context) != 1)
    return C89CBOR_CRYPTO;
  if (encrypt) {
    ok =
        EVP_EncryptInit_ex2(context, key->gcm, secret, nonce, NULL) == 1 &&
        EVP_EncryptUpdate(context, NULL, &ignored, aad, (int)aad_length) == 1 &&
        EVP_EncryptUpdate(context, output, &first, input, (int)length) == 1 &&
        EVP_EncryptFinal_ex(context, output + first, &last) == 1;
    parameters[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
    parameters[1] = OSSL_PARAM_construct_end();
    if (!ok || EVP_CIPHER_CTX_get_params(context, parameters) != 1 ||
        (size_t)(first + last) != length)
      return C89CBOR_CRYPTO;
    memcpy(output + length, tag, sizeof(tag));
    *written = length + sizeof(tag);
    return C89CBOR_OK;
  }
  length -= sizeof(tag);
  memcpy(tag, bytes + length, sizeof(tag));
  parameters[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                    tag, sizeof(tag));
  parameters[1] = OSSL_PARAM_construct_end();
  ok = EVP_DecryptInit_ex2(context, key->gcm, secret, nonce, NULL) == 1 &&
       EVP_CIPHER_CTX_set_params(context, parameters) == 1 &&
       EVP_DecryptUpdate(context, NULL, &ignored, aad, (int)aad_length) == 1 &&
       EVP_DecryptUpdate(context, output, &first, input, (int)length) == 1 &&
       EVP_DecryptFinal_ex(context, output + first, &last) == 1;
  if (!ok || (size_t)(first + last) != length) {
    OPENSSL_cleanse(output, length);
    return C89CBOR_AUTH;
  }
  *written = length;
  return C89CBOR_OK;
}
int c89_cose_wrap(c89_cose_key_state *key, EVP_CIPHER_CTX *context, int encrypt,
                  const unsigned char *secret, const unsigned char *input,
                  size_t length, unsigned char *output, size_t *written) {
  int first = 0, last = 0, ok;
  *written = 0;
  if (length != (encrypt ? 32u : 40u))
    return C89CBOR_MALFORMED;
  if (EVP_CIPHER_CTX_reset(context) != 1)
    return C89CBOR_CRYPTO;
  EVP_CIPHER_CTX_set_flags(context, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  if (encrypt)
    ok = EVP_EncryptInit_ex2(context, key->wrap, secret, NULL, NULL) == 1 &&
         EVP_EncryptUpdate(context, output, &first, input, (int)length) == 1 &&
         EVP_EncryptFinal_ex(context, output + first, &last) == 1;
  else
    ok = EVP_DecryptInit_ex2(context, key->wrap, secret, NULL, NULL) == 1 &&
         EVP_DecryptUpdate(context, output, &first, input, (int)length) == 1 &&
         EVP_DecryptFinal_ex(context, output + first, &last) == 1;
  if (!ok || (size_t)(first + last) != (encrypt ? 40u : 32u)) {
    OPENSSL_cleanse(output, encrypt ? 40u : 32u);
    return encrypt ? C89CBOR_CRYPTO : C89CBOR_AUTH;
  }
  *written = (size_t)(first + last);
  return C89CBOR_OK;
}
static void party_info(c89_cose_writer *writer, const c89_cose_party *info) {
  size_t i;
  c89_cose_emit(writer, C89CBOR_ARRAY, 3);
  for (i = 0; i < 3u; ++i) {
    if (info[i].type == C89CBOR_BYTES)
      c89_cose_bytes(writer, C89CBOR_BYTES, info[i].bytes, info[i].length);
    else
      c89_cose_emit(writer, info[i].type, info[i].argument);
  }
  c89_cose_emit(writer, C89CBOR_END, C89CBOR_ARRAY);
}
int c89_cose_derive(c89_cose_key_state *owner, EVP_PKEY *private_key,
                    EVP_PKEY *peer, const c89_cose_header *header,
                    c89cbor_encoder *encoder, unsigned char *scratch,
                    size_t capacity, unsigned char *output) {
  EVP_PKEY_CTX *agreement = NULL;
  EVP_KDF_CTX *kdf = NULL;
  unsigned char shared[32];
  char digest[] = "SHA256";
  size_t length = sizeof(shared), count = 0;
  int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, status = C89CBOR_CRYPTO;
  c89_cose_writer writer;
  OSSL_PARAM parameters[6];
  c89_cose_writer_init(&writer, encoder, scratch, capacity);
  c89_cose_emit(&writer, C89CBOR_ARRAY, 4);
  c89_cose_emit(&writer, C89CBOR_NEGATIVE, 4);
  party_info(&writer, header->party[0]);
  party_info(&writer, header->party[1]);
  c89_cose_emit(&writer, C89CBOR_ARRAY, 2);
  c89_cose_emit(&writer, C89CBOR_UINT, 256);
  c89_cose_bytes(&writer, C89CBOR_BYTES, header->protected_bytes,
                 header->protected_length);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  status = c89_cose_writer_finish(&writer);
  if (status != 0)
    return status;
  status = C89CBOR_CRYPTO;
  agreement = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
  if (agreement == NULL || EVP_PKEY_derive_init(agreement) != 1 ||
      EVP_PKEY_derive_set_peer(agreement, peer) != 1 ||
      EVP_PKEY_derive(agreement, shared, &length) != 1 ||
      length != sizeof(shared))
    goto done;
  parameters[count++] =
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  parameters[count++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
  parameters[count++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_KEY, shared, sizeof(shared));
  parameters[count++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, scratch, writer.length);
  if (header->salt != NULL)
    parameters[count++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, header->salt, header->salt_length);
  parameters[count] = OSSL_PARAM_construct_end();
  kdf = EVP_KDF_CTX_new(owner->hkdf);
  if (kdf != NULL && EVP_KDF_derive(kdf, output, 32u, parameters) == 1)
    status = C89CBOR_OK;
done:
  EVP_KDF_CTX_free(kdf);
  EVP_PKEY_CTX_free(agreement);
  OPENSSL_cleanse(shared, sizeof(shared));
  return status;
}
