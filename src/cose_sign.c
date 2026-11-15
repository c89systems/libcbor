#include "cose_internal.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/param_build.h>
#include <openssl/obj_mac.h>
#include <string.h>

int c89_cose_auth_algorithm(c89cbor_cose_key_kind kind) {
  if (kind == C89CBOR_COSE_ED25519_PUBLIC ||
      kind == C89CBOR_COSE_ED25519_PRIVATE)
    return -19;
  if (kind == C89CBOR_COSE_P256_PUBLIC || kind == C89CBOR_COSE_P256_PRIVATE)
    return -9;
  return kind == C89CBOR_COSE_HMAC256 ? 5 : 0;
}

EVP_PKEY *c89_cose_p256_import(const void *bytes, int private_key) {
  const unsigned char *raw = bytes;
  unsigned char public_bytes[65];
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *context = NULL, *check = NULL;
  OSSL_PARAM_BLD *builder = NULL;
  OSSL_PARAM *params = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *point = NULL;
  BIGNUM *scalar = NULL, *order = NULL;
  int valid = 0;
  if (private_key) {
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    scalar = BN_secure_new();
    if (scalar != NULL && BN_bin2bn(raw, 32, scalar) == NULL)
      goto done;
    order = BN_new();
    if (group == NULL || scalar == NULL || order == NULL ||
        BN_is_zero(scalar) || EC_GROUP_get_order(group, order, NULL) != 1 ||
        BN_cmp(scalar, order) >= 0)
      goto done;
    BN_set_flags(scalar, BN_FLG_CONSTTIME);
    point = EC_POINT_new(group);
    if (point == NULL ||
        EC_POINT_mul(group, point, scalar, NULL, NULL, NULL) != 1 ||
        EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                           public_bytes, sizeof(public_bytes), NULL) != 65u)
      goto done;
    raw = public_bytes;
  } else if (raw[0] != 4u)
    goto done;
  builder = OSSL_PARAM_BLD_new();
  context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (builder == NULL || context == NULL ||
      !OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME,
                                       "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, raw,
                                        65u) ||
      (private_key &&
       !OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, scalar)))
    goto done;
  params = OSSL_PARAM_BLD_to_param(builder);
  if (params == NULL || EVP_PKEY_fromdata_init(context) != 1 ||
      EVP_PKEY_fromdata(context, &key,
                        private_key ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                        params) != 1)
    goto done;
  check = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if (check != NULL && EVP_PKEY_public_check(check) == 1 &&
      (!private_key || EVP_PKEY_pairwise_check(check) == 1))
    valid = 1;
done:
  if (!valid) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  EVP_PKEY_CTX_free(check);
  EVP_PKEY_CTX_free(context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(builder);
  EC_POINT_free(point);
  EC_GROUP_free(group);
  BN_clear_free(scalar);
  BN_free(order);
  return key;
}

/* COSE uses fixed-width scalars. DER is private OpenSSL interchange only. */
static int p256_signature(unsigned char *raw, unsigned char *der,
                          size_t *der_length, int to_raw) {
  ECDSA_SIG *signature = NULL;
  const BIGNUM *r, *s;
  BIGNUM *rr = NULL, *ss = NULL;
  const unsigned char *read_at = der;
  unsigned char *write_at = der;
  int length, status = C89CBOR_CRYPTO;
  if (to_raw) {
    signature = d2i_ECDSA_SIG(NULL, &read_at, (long)*der_length);
    if (signature == NULL || read_at != der + *der_length)
      goto done;
    ECDSA_SIG_get0(signature, &r, &s);
    if (BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(s, raw + 32u, 32) == 32)
      status = C89CBOR_OK;
  } else {
    rr = BN_bin2bn(raw, 32, NULL);
    ss = BN_bin2bn(raw + 32u, 32, NULL);
    signature = ECDSA_SIG_new();
    if (rr == NULL || ss == NULL || signature == NULL)
      goto done;
    if (ECDSA_SIG_set0(signature, rr, ss) != 1)
      goto done;
    rr = ss = NULL;
    length = i2d_ECDSA_SIG(signature, NULL);
    if (length <= 0 || (size_t)length > *der_length)
      goto done;
    if (i2d_ECDSA_SIG(signature, &write_at) == length) {
      *der_length = (size_t)length;
      status = C89CBOR_OK;
    }
  }
done:
  BN_free(rr);
  BN_free(ss);
  ECDSA_SIG_free(signature);
  return status;
}
static int authenticate(c89_cose_state *state, unsigned char *signature) {
  c89_cose_key_state *key = state->keys[0]->state;
  unsigned char der[80], mac[32];
  EVP_MD_CTX *context = state->digest_context;
  OSSL_PARAM parameters[2];
  size_t length = sizeof(der), mac_length = 0;
  int status = C89CBOR_CRYPTO, result;
  const char *digest = key->info.kind == C89CBOR_COSE_P256_PUBLIC ||
                               key->info.kind == C89CBOR_COSE_P256_PRIVATE
                           ? "SHA256"
                           : NULL;
  if (state->auth == 2) {
    char digest_name[] = "SHA256";
    parameters[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0);
    parameters[1] = OSSL_PARAM_construct_end();
    if (state->mac_context == NULL ||
        EVP_MAC_init(state->mac_context, key->secret, 32u, parameters) != 1 ||
        EVP_MAC_update(state->mac_context, state->aad, state->cipher_length) !=
            1 ||
        EVP_MAC_final(state->mac_context, mac, &mac_length, sizeof(mac)) != 1 ||
        mac_length != sizeof(mac))
      return C89CBOR_CRYPTO;
    if (state->seal)
      memcpy(signature, mac, sizeof(mac));
    else if (CRYPTO_memcmp(signature, mac, sizeof(mac)) != 0)
      status = C89CBOR_AUTH;
    else
      status = C89CBOR_OK;
    if (state->seal)
      status = C89CBOR_OK;
    OPENSSL_cleanse(mac, sizeof(mac));
    return status;
  }
  if (context == NULL)
    return C89CBOR_CRYPTO;
  if (state->seal) {
    if (EVP_DigestSignInit_ex(context, NULL, digest, NULL, NULL, key->pkey,
                              NULL) == 1 &&
        EVP_DigestSign(context, der, &length, state->aad,
                       state->cipher_length) == 1) {
      if (digest != NULL)
        status = p256_signature(signature, der, &length, 1);
      else if (length == 64u) {
        memcpy(signature, der, length);
        status = C89CBOR_OK;
      }
    }
  } else {
    status = C89CBOR_AUTH;
    if (digest != NULL) {
      if (p256_signature(signature, der, &length, 0) != 0)
        goto done;
    } else {
      memcpy(der, signature, 64u);
      length = 64u;
    }
    if (EVP_DigestVerifyInit_ex(context, NULL, digest, NULL, NULL, key->pkey,
                                NULL) != 1)
      status = C89CBOR_CRYPTO;
    else {
      result = EVP_DigestVerify(context, der, length, state->aad,
                                state->cipher_length);
      status = result == 1 ? C89CBOR_OK : C89CBOR_AUTH;
    }
  }
done:
  (void)EVP_MD_CTX_reset(context);
  return status;
}
static int expect_next(c89_cose_cursor *cursor, c89cbor_type type) {
  int status = c89_cose_next(cursor);
  return status == 0
             ? (cursor->token.type == type ? C89CBOR_OK : C89CBOR_MALFORMED)
         : status < 0 ? status
                      : C89CBOR_MALFORMED;
}
static int close_next(c89_cose_cursor *cursor, c89cbor_type type) {
  int status = expect_next(cursor, C89CBOR_END);
  return status == 0 && cursor->token.argument != (uint64_t)type
             ? C89CBOR_MALFORMED
             : status;
}
static int read_authenticated(c89_cose_state *state, unsigned char *signature) {
  c89_cose_cursor cursor;
  size_t length;
  int status, tagged = 0;
  c89_cose_key_state *key = state->keys[0]->state;
  state->arena.length = 0;
  status = c89_cose_cursor_init(&cursor, state->wire, state->wire_length);
  if (status != 0)
    return status;
  status = c89_cose_next(&cursor);
  if (status != 0)
    return C89CBOR_MALFORMED;
  if (state->stream) {
    if (cursor.token.type != C89CBOR_ARRAY)
      return C89CBOR_MALFORMED;
    status = expect_next(&cursor, C89CBOR_BYTES);
    if (status == 0)
      status =
          c89_cose_blob(&cursor, C89CBOR_BYTES, state->record_id, 16u, &length);
    if (status != 0 || length != 16u)
      return status != 0 ? status : C89CBOR_MALFORMED;
    status = expect_next(&cursor, C89CBOR_UINT);
    if (status != 0)
      return status;
    state->record_sequence = cursor.token.argument;
    status = expect_next(&cursor, C89CBOR_BOOL);
    if (status != 0)
      return status;
    state->record_final = cursor.token.argument != 0;
    status = c89_cose_next(&cursor);
    if (status != 0)
      return C89CBOR_MALFORMED;
  }
  if (cursor.token.type == C89CBOR_TAG) {
    if (cursor.token.argument != (state->auth == 1 ? 18u : 17u))
      return C89CBOR_UNSUPPORTED;
    tagged = 1;
    status = c89_cose_next(&cursor);
  }
  if (status != 0 || cursor.token.type != C89CBOR_ARRAY)
    return C89CBOR_MALFORMED;
  status = expect_next(&cursor, C89CBOR_BYTES);
  if (status == 0)
    status = c89_cose_headers(&cursor, &state->body, &state->arena, 2);
  if (status != 0)
    return status;
  if (!state->body.protected_algorithm ||
      state->body.algorithm != c89_cose_auth_algorithm(key->info.kind))
    return C89CBOR_AUTH;
  if (state->body.id_length != 0 && key->info.key_id_length != 0 &&
      (state->body.id_length != key->info.key_id_length ||
       memcmp(state->body.id, key->info.key_id, state->body.id_length) != 0))
    return C89CBOR_AUTH;
  status = c89_cose_next(&cursor);
  if (status == 0 && cursor.token.type == C89CBOR_NULL)
    return C89CBOR_UNSUPPORTED;
  if (status != 0 || cursor.token.type != C89CBOR_BYTES)
    return C89CBOR_MALFORMED;
  status = c89_cose_blob(&cursor, C89CBOR_BYTES, state->plain,
                         state->options.record_bytes, &state->plain_length);
  if (status == 0)
    status = expect_next(&cursor, C89CBOR_BYTES);
  if (status == 0)
    status = c89_cose_blob(&cursor, C89CBOR_BYTES, signature, 64u, &length);
  if (status != 0 || length != (state->auth == 1 ? 64u : 32u))
    return status != 0 ? status : C89CBOR_MALFORMED;
  status = close_next(&cursor, C89CBOR_ARRAY);
  if (status == 0 && tagged)
    status = close_next(&cursor, C89CBOR_TAG);
  if (status == 0 && state->stream)
    status = close_next(&cursor, C89CBOR_ARRAY);
  if (status == 0)
    status = c89_cose_finish(&cursor);
  if (status == 0 &&
      state->wire_length - state->plain_length > state->options.header_bytes)
    status = C89CBOR_LIMIT;
  if (status == 0 && state->stream &&
      ((state->have_id &&
        memcmp(state->record_id, state->stream_id, 16u) != 0) ||
       state->record_sequence != state->sequence))
    status = C89CBOR_AUTH;
  return status;
}
int c89_cose_auth_record(c89_cose_state *state) {
  c89_cose_key_state *key = state->keys[0]->state;
  c89_cose_writer writer;
  unsigned char signature[64];
  int status;
  if (state->stream && state->sequence >= (UINT64_C(1) << 24u))
    return C89CBOR_LIMIT;
  if (state->seal) {
    state->arena.length = 0;
    memset(&state->body, 0, sizeof(state->body));
    memcpy(state->record_id, state->stream_id, 16u);
    state->record_sequence = state->sequence;
    status = c89_cose_make_protected(state, &state->body,
                                     c89_cose_auth_algorithm(key->info.kind),
                                     &key->info);
  } else
    status = read_authenticated(state, signature);
  if (status == 0)
    status = c89_cose_make_aad(state, 0);
  if (status == 0)
    status = authenticate(state, signature);
  if (status != 0)
    return status;
  if (!state->seal) {
    if (state->stream) {
      memcpy(state->stream_id, state->record_id, 16u);
      state->have_id = 1;
      state->seen_family = 0;
    }
    state->output = state->plain;
    state->output_length = state->plain_length;
    state->output_offset = 0;
    return C89CBOR_OK;
  }
  c89_cose_writer_init(&writer, &state->encoder, state->wire,
                       state->wire_capacity);
  if (state->stream) {
    c89_cose_emit(&writer, C89CBOR_ARRAY, 4);
    c89_cose_bytes(&writer, C89CBOR_BYTES, state->record_id, 16u);
    c89_cose_emit(&writer, C89CBOR_UINT, state->sequence);
    c89_cose_emit(&writer, C89CBOR_BOOL, (uint64_t)state->record_final);
  }
  c89_cose_emit(&writer, C89CBOR_TAG, state->auth == 1 ? 18u : 17u);
  c89_cose_emit(&writer, C89CBOR_ARRAY, 4);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->body.protected_bytes,
                 state->body.protected_length);
  c89_cose_emit(&writer, C89CBOR_MAP, 0);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_MAP);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->plain, state->plain_length);
  c89_cose_bytes(&writer, C89CBOR_BYTES, signature,
                 state->auth == 1 ? 64u : 32u);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_TAG);
  if (state->stream)
    c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  status = c89_cose_writer_finish(&writer);
  if (status == 0 &&
      writer.length - state->plain_length > state->options.header_bytes)
    status = C89CBOR_LIMIT;
  if (status == 0) {
    state->output = state->wire;
    state->output_length = writer.length;
    state->output_offset = 0;
  }
  return status;
}
