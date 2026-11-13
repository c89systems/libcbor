#include "cose_internal.h"
#include <string.h>

static void empty_header(c89_cose_header *header) {
  size_t i, j;
  memset(header, 0, sizeof(*header));
  for (i = 0; i < 2u; ++i)
    for (j = 0; j < 3u; ++j)
      header->party[i][j].type = C89CBOR_NULL;
}
int c89_cose_make_protected(c89_cose_state *state, c89_cose_header *header,
                            int algorithm, const c89cbor_cose_key_info *id) {
  c89_cose_writer writer;
  int status;
  header->algorithm = algorithm;
  header->have_algorithm = 1;
  header->protected_bytes = state->arena.bytes + state->arena.length;
  if (algorithm == -5)
    return C89CBOR_OK;
  header->protected_algorithm = 1;
  c89_cose_writer_init(&writer, &state->encoder,
                       state->arena.bytes + state->arena.length,
                       state->arena.capacity - state->arena.length);
  c89_cose_emit(&writer, C89CBOR_MAP,
                id != NULL && id->key_id_length != 0 ? 2u : 1u);
  c89_cose_emit(&writer, C89CBOR_UINT, 1);
  c89_cose_emit(&writer, algorithm < 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT,
                (uint64_t)(algorithm < 0 ? -1 - algorithm : algorithm));
  if (id != NULL && id->key_id_length != 0) {
    c89_cose_emit(&writer, C89CBOR_UINT, 4);
    c89_cose_bytes(&writer, C89CBOR_BYTES, id->key_id, id->key_id_length);
  }
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_MAP);
  status = c89_cose_writer_finish(&writer);
  if (status == 0) {
    header->protected_length = writer.length;
    state->arena.length += writer.length;
  }
  return status;
}
int c89_cose_make_aad(c89_cose_state *state, int encrypt) {
  static const char domain[] = "c89.systems/cbor-stream";
  const void *external = state->options.aad;
  size_t external_length = state->options.aad_length;
  c89_cose_writer writer;
  int status;
  if (state->stream) {
    c89_cose_writer_init(&writer, &state->encoder, state->external,
                         state->external_capacity);
    c89_cose_emit(&writer, C89CBOR_ARRAY, 5);
    c89_cose_bytes(&writer, C89CBOR_TEXT, domain, sizeof(domain) - 1u);
    c89_cose_bytes(&writer, C89CBOR_BYTES, external, external_length);
    c89_cose_bytes(&writer, C89CBOR_BYTES, state->record_id, 16u);
    c89_cose_emit(&writer, C89CBOR_UINT, state->record_sequence);
    c89_cose_emit(&writer, C89CBOR_BOOL, (uint64_t)state->record_final);
    c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
    status = c89_cose_writer_finish(&writer);
    if (status != 0)
      return status;
    external = state->external;
    external_length = writer.length;
  }
  c89_cose_writer_init(&writer, &state->encoder, state->aad,
                       state->aad_capacity);
  c89_cose_emit(&writer, C89CBOR_ARRAY, state->auth ? 4u : 3u);
  c89_cose_bytes(&writer, C89CBOR_TEXT,
                 state->auth == 1   ? "Signature1"
                 : state->auth == 2 ? "MAC0"
                 : encrypt          ? "Encrypt"
                                    : "Encrypt0",
                 state->auth == 1   ? 10u
                 : state->auth == 2 ? 4u
                 : encrypt          ? 7u
                                    : 8u);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->body.protected_bytes,
                 state->body.protected_length);
  c89_cose_bytes(&writer, C89CBOR_BYTES, external, external_length);
  if (state->auth)
    c89_cose_bytes(&writer, C89CBOR_BYTES, state->plain, state->plain_length);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  status = c89_cose_writer_finish(&writer);
  state->cipher_length = writer.length;
  return status;
}
static int make_recipient(c89_cose_state *state, size_t index,
                          const unsigned char *content_key) {
  c89_cose_key_state *key = state->keys[index]->state;
  c89_cose_recipient *recipient = &state->recipients[index];
  EVP_PKEY *ephemeral = NULL;
  unsigned char wrapping_key[32];
  size_t length = 32u;
  int status;
  empty_header(&recipient->header);
  recipient->header.id = key->info.key_id;
  recipient->header.id_length = key->info.key_id_length;
  status = c89_cose_make_protected(
      state, &recipient->header,
      key->info.kind == C89CBOR_COSE_A256KW ? -5 : -31, NULL);
  if (status != 0)
    return status;
  if (key->info.kind == C89CBOR_COSE_A256KW)
    memcpy(wrapping_key, key->secret, 32u);
  else {
    ephemeral = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (ephemeral == NULL ||
        EVP_PKEY_get_raw_public_key(ephemeral, recipient->header.ephemeral,
                                    &length) != 1 ||
        length != 32u)
      status = C89CBOR_CRYPTO;
    else
      status = c89_cose_derive(key, ephemeral, key->pkey, &recipient->header,
                               &state->encoder, state->kdf, state->kdf_capacity,
                               wrapping_key);
    recipient->header.have_ephemeral = 1;
  }
  if (status == 0)
    status =
        c89_cose_wrap(key, state->cipher_context, 1, wrapping_key, content_key,
                      32u, recipient->wrapped, &recipient->wrapped_length);
  EVP_PKEY_free(ephemeral);
  OPENSSL_cleanse(wrapping_key, sizeof(wrapping_key));
  return status;
}
static void write_recipient(c89_cose_writer *writer,
                            const c89_cose_recipient *recipient) {
  const c89_cose_header *header = &recipient->header;
  size_t count = (header->protected_length == 0 ? 1u : 0u) +
                 (header->id_length != 0 ? 1u : 0u) +
                 (header->have_ephemeral ? 1u : 0u);
  c89_cose_emit(writer, C89CBOR_ARRAY, 3);
  c89_cose_bytes(writer, C89CBOR_BYTES, header->protected_bytes,
                 header->protected_length);
  c89_cose_emit(writer, C89CBOR_MAP, count);
  if (header->protected_length == 0) {
    c89_cose_emit(writer, C89CBOR_UINT, 1);
    c89_cose_emit(writer, C89CBOR_NEGATIVE, (uint64_t)(-1 - header->algorithm));
  }
  if (header->id_length != 0) {
    c89_cose_emit(writer, C89CBOR_UINT, 4);
    c89_cose_bytes(writer, C89CBOR_BYTES, header->id, header->id_length);
  }
  if (header->have_ephemeral) {
    c89_cose_emit(writer, C89CBOR_NEGATIVE, 0);
    c89_cose_emit(writer, C89CBOR_MAP, 3);
    c89_cose_emit(writer, C89CBOR_UINT, 1);
    c89_cose_emit(writer, C89CBOR_UINT, 1);
    c89_cose_emit(writer, C89CBOR_NEGATIVE, 0);
    c89_cose_emit(writer, C89CBOR_UINT, 4);
    c89_cose_emit(writer, C89CBOR_NEGATIVE, 1);
    c89_cose_bytes(writer, C89CBOR_BYTES, header->ephemeral, 32u);
    c89_cose_emit(writer, C89CBOR_END, C89CBOR_MAP);
  }
  c89_cose_emit(writer, C89CBOR_END, C89CBOR_MAP);
  c89_cose_bytes(writer, C89CBOR_BYTES, recipient->wrapped,
                 recipient->wrapped_length);
  c89_cose_emit(writer, C89CBOR_END, C89CBOR_ARRAY);
}
int c89_cose_seal_record(c89_cose_state *state) {
  c89_cose_key_state *first = state->keys[0]->state;
  c89_cose_writer writer;
  unsigned char content_key[32];
  size_t i, cipher_length = 0, aad_length;
  int status;
  state->arena.length = 0;
  empty_header(&state->body);
  if (state->stream && state->sequence >= (UINT64_C(1) << 24u))
    return C89CBOR_LIMIT;
  memcpy(state->record_id, state->stream_id, 16u);
  state->record_sequence = state->sequence;
  if (state->encrypt) {
    if (state->stream && state->stream_key_ready)
      memcpy(content_key, state->stream_key, sizeof(content_key));
    else if (RAND_priv_bytes_ex(NULL, content_key, sizeof(content_key), 0) !=
             1) {
      OPENSSL_cleanse(content_key, sizeof(content_key));
      return C89CBOR_CRYPTO;
    }
    if (state->stream && !state->stream_key_ready) {
      memcpy(state->stream_key, content_key, sizeof(content_key));
      state->stream_key_ready = 1;
    }
  } else {
    status = c89_cose_key_reserve(state->keys[0]);
    if (status != 0)
      return status;
    memcpy(content_key, first->secret, sizeof(content_key));
  }
  if (state->options.nonce != NULL)
    memcpy(state->body.nonce, state->options.nonce, 12u);
  else if (RAND_bytes_ex(NULL, state->body.nonce, 12u, 0) != 1) {
    OPENSSL_cleanse(content_key, sizeof(content_key));
    return C89CBOR_CRYPTO;
  }
  status = c89_cose_make_protected(state, &state->body, 3,
                                   state->encrypt ? NULL : &first->info);
  if (status == 0)
    status = c89_cose_make_aad(state, state->encrypt);
  aad_length = state->cipher_length;
  if (status == 0)
    status =
        c89_cose_gcm(first, state->cipher_context, 1, content_key,
                     state->body.nonce, state->aad, aad_length, state->plain,
                     state->plain_length, state->cipher, &cipher_length);
  if (status == 0 && state->encrypt && !state->recipients_ready) {
    for (i = 0; i < state->key_count && status == 0; ++i)
      status = make_recipient(state, i, content_key);
    if (status == 0 && state->stream)
      state->recipients_ready = 1;
  }
  OPENSSL_cleanse(content_key, sizeof(content_key));
  if (status != 0)
    return status;
  c89_cose_writer_init(&writer, &state->encoder, state->wire,
                       state->wire_capacity);
  if (state->stream) {
    c89_cose_emit(&writer, C89CBOR_ARRAY, 4);
    c89_cose_bytes(&writer, C89CBOR_BYTES, state->record_id, 16u);
    c89_cose_emit(&writer, C89CBOR_UINT, state->sequence);
    c89_cose_emit(&writer, C89CBOR_BOOL, (uint64_t)state->record_final);
  }
  c89_cose_emit(&writer, C89CBOR_TAG, state->encrypt ? 96u : 16u);
  c89_cose_emit(&writer, C89CBOR_ARRAY, state->encrypt ? 4u : 3u);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->body.protected_bytes,
                 state->body.protected_length);
  c89_cose_emit(&writer, C89CBOR_MAP, 1);
  c89_cose_emit(&writer, C89CBOR_UINT, 5);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->body.nonce, 12u);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_MAP);
  c89_cose_bytes(&writer, C89CBOR_BYTES, state->cipher, cipher_length);
  if (state->encrypt) {
    c89_cose_emit(&writer, C89CBOR_ARRAY, (uint64_t)state->key_count);
    for (i = 0; i < state->key_count; ++i)
      write_recipient(&writer, &state->recipients[i]);
    c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  }
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_TAG);
  if (state->stream)
    c89_cose_emit(&writer, C89CBOR_END, C89CBOR_ARRAY);
  status = c89_cose_writer_finish(&writer);
  if (status == 0 &&
      writer.length - cipher_length > state->options.header_bytes)
    status = C89CBOR_LIMIT;
  if (status == 0) {
    state->wire_length = writer.length;
    state->output = state->wire;
    state->output_length = writer.length;
    state->output_offset = 0;
  }
  return status;
}
static int expect(c89_cose_cursor *cursor, c89cbor_type type) {
  int status = c89_cose_next(cursor);
  return status == 0
             ? cursor->token.type == type ? C89CBOR_OK : C89CBOR_MALFORMED
         : status < 0 ? status
                      : C89CBOR_MALFORMED;
}
static int close_value(c89_cose_cursor *cursor, c89cbor_type type) {
  int status = expect(cursor, C89CBOR_END);
  return status == 0 && cursor->token.argument != (uint64_t)type
             ? C89CBOR_MALFORMED
             : status;
}
static int read_recipient(c89_cose_state *state, c89_cose_recipient *recipient,
                          const unsigned char *bytes, size_t length) {
  c89_cose_cursor cursor;
  int status;
  c89_cose_cursor_init(&cursor, bytes, length);
  status = expect(&cursor, C89CBOR_ARRAY);
  if (status == 0)
    status = expect(&cursor, C89CBOR_BYTES);
  if (status == 0)
    status = c89_cose_headers(&cursor, &recipient->header, &state->arena, 1);
  if (status == 0 && recipient->header.algorithm != -5 &&
      recipient->header.algorithm != -31)
    return C89CBOR_UNSUPPORTED;
  if (status == 0)
    status = expect(&cursor, C89CBOR_BYTES);
  if (status == 0)
    status = c89_cose_blob(&cursor, C89CBOR_BYTES, recipient->wrapped, 40u,
                           &recipient->wrapped_length);
  if (status == 0) {
    status = c89_cose_next(&cursor);
    if (status == 0 && cursor.token.type == C89CBOR_ARRAY)
      return C89CBOR_UNSUPPORTED;
    if (status == 0 && (cursor.token.type != C89CBOR_END ||
                        cursor.token.argument != C89CBOR_ARRAY))
      status = C89CBOR_MALFORMED;
  }
  if (status == 0)
    status = c89_cose_finish(&cursor);
  if (status != 0)
    return status;
  if (recipient->wrapped_length != 40u)
    return C89CBOR_MALFORMED;
  if (recipient->header.algorithm == -5)
    recipient->usable = recipient->header.protected_empty;
  else if (recipient->header.algorithm == -31)
    recipient->usable = recipient->header.have_ephemeral;
  return C89CBOR_OK;
}
static int read_object(c89_cose_state *state) {
  c89_cose_cursor cursor;
  c89_cose_recipient *recipient;
  size_t length, start, saved;
  int status, tag = -1, family;
  state->arena.length = 0;
  state->recipient_count = 0;
  memset(state->recipients, 0,
         state->options.recipients * sizeof(*state->recipients));
  c89_cose_cursor_init(&cursor, state->wire, state->wire_length);
  status = c89_cose_next(&cursor);
  if (status != 0)
    return status < 0 ? status : C89CBOR_MALFORMED;
  if (state->stream) {
    if (cursor.token.type != C89CBOR_ARRAY)
      return C89CBOR_MALFORMED;
    status = expect(&cursor, C89CBOR_BYTES);
    if (status == 0)
      status =
          c89_cose_blob(&cursor, C89CBOR_BYTES, state->record_id, 16u, &length);
    if (status != 0 || length != 16u)
      return status != 0 ? status : C89CBOR_MALFORMED;
    status = expect(&cursor, C89CBOR_UINT);
    if (status != 0)
      return status;
    state->record_sequence = cursor.token.argument;
    status = expect(&cursor, C89CBOR_BOOL);
    if (status != 0)
      return status;
    state->record_final = cursor.token.argument != 0;
    status = c89_cose_next(&cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
  }
  if (cursor.token.type == C89CBOR_TAG) {
    if (cursor.token.argument != 16u && cursor.token.argument != 96u)
      return C89CBOR_UNSUPPORTED;
    tag = cursor.token.argument == 96u;
    status = c89_cose_next(&cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
  }
  if (cursor.token.type != C89CBOR_ARRAY)
    return C89CBOR_MALFORMED;
  status = expect(&cursor, C89CBOR_BYTES);
  if (status == 0)
    status = c89_cose_headers(&cursor, &state->body, &state->arena, 0);
  if (status != 0)
    return status;
  if (state->body.algorithm != 3 || !state->body.protected_algorithm)
    return C89CBOR_UNSUPPORTED;
  if (!state->body.have_nonce)
    return C89CBOR_MALFORMED;
  status = c89_cose_next(&cursor);
  if (status == 0 && cursor.token.type == C89CBOR_NULL)
    return C89CBOR_UNSUPPORTED;
  if (status == 0 && cursor.token.type != C89CBOR_BYTES)
    return C89CBOR_MALFORMED;
  if (status > 0)
    return C89CBOR_MALFORMED;
  if (status == 0)
    status =
        c89_cose_blob(&cursor, C89CBOR_BYTES, state->cipher,
                      state->options.record_bytes + 16u, &state->cipher_length);
  if (status != 0)
    return status;
  if (state->cipher_length < 16u)
    return C89CBOR_MALFORMED;
  if (state->wire_length - state->cipher_length > state->options.header_bytes)
    return C89CBOR_LIMIT;
  status = c89_cose_next(&cursor);
  if (status != 0)
    return status < 0 ? status : C89CBOR_MALFORMED;
  family = cursor.token.type == C89CBOR_ARRAY;
  if (family) {
    while ((status = c89_cose_next(&cursor)) == 0 &&
           cursor.token.type != C89CBOR_END) {
      if (cursor.token.type != C89CBOR_ARRAY)
        return C89CBOR_MALFORMED;
      if (state->recipient_count == state->options.recipients)
        return C89CBOR_LIMIT;
      start = cursor.start;
      status = c89_cose_skip(&cursor);
      if (status != 0)
        return status;
      recipient = &state->recipients[state->recipient_count++];
      saved = state->arena.length;
      status = read_recipient(state, recipient, state->wire + start,
                              cursor.offset - start);
      recipient->encoded = state->wire + start;
      recipient->encoded_length = cursor.offset - start;
      if (status == C89CBOR_UNSUPPORTED) {
        recipient->usable = 0;
        state->arena.length = saved;
      } else if (status != 0)
        return status;
    }
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
    if (state->recipient_count == 0)
      return C89CBOR_MALFORMED;
    status = close_value(&cursor, C89CBOR_ARRAY);
    if (status != 0)
      return status;
  } else if (cursor.token.type != C89CBOR_END ||
             cursor.token.argument != C89CBOR_ARRAY)
    return C89CBOR_MALFORMED;
  if (tag != -1 && tag != family)
    return C89CBOR_MALFORMED;
  if (tag != -1) {
    status = close_value(&cursor, C89CBOR_TAG);
    if (status != 0)
      return status;
  }
  if (state->stream) {
    status = close_value(&cursor, C89CBOR_ARRAY);
    if (status != 0)
      return status;
    if ((state->have_id &&
         memcmp(state->record_id, state->stream_id, 16u) != 0) ||
        state->record_sequence != state->sequence ||
        (state->seen_family != -1 && state->seen_family != family))
      return C89CBOR_AUTH;
  }
  status = c89_cose_finish(&cursor);
  if (status == 0)
    state->encrypt = family;
  return status;
}
static int unwrap_recipient(c89_cose_state *state,
                            c89_cose_recipient *recipient,
                            unsigned char *content_key) {
  c89_cose_key_state *key = state->keys[0]->state;
  EVP_PKEY *ephemeral = NULL;
  unsigned char wrapping_key[32];
  size_t length;
  int status = C89CBOR_AUTH;
  if (!recipient->usable ||
      (recipient->header.id_length != 0 && key->info.key_id_length != 0 &&
       (recipient->header.id_length != key->info.key_id_length ||
        memcmp(recipient->header.id, key->info.key_id,
               key->info.key_id_length) != 0)))
    return C89CBOR_AUTH;
  if (recipient->header.algorithm == -5 &&
      key->info.kind == C89CBOR_COSE_A256KW) {
    memcpy(wrapping_key, key->secret, 32u);
    status = C89CBOR_OK;
  } else if (recipient->header.algorithm == -31 &&
             key->info.kind == C89CBOR_COSE_X25519_PRIVATE) {
    ephemeral = EVP_PKEY_new_raw_public_key_ex(
        NULL, "X25519", NULL, recipient->header.ephemeral, 32u);
    if (ephemeral != NULL)
      status = c89_cose_derive(key, key->pkey, ephemeral, &recipient->header,
                               &state->encoder, state->kdf, state->kdf_capacity,
                               wrapping_key);
  }
  if (status == 0)
    status = c89_cose_wrap(key, state->cipher_context, 0, wrapping_key,
                           recipient->wrapped, recipient->wrapped_length,
                           content_key, &length);
  OPENSSL_cleanse(wrapping_key, sizeof(wrapping_key));
  EVP_PKEY_free(ephemeral);
  return status;
}
int c89_cose_open_record(c89_cose_state *state) {
  c89_cose_key_state *key = state->keys[0]->state;
  unsigned char content_key[32];
  unsigned char fingerprint[32];
  size_t i, cipher_length, aad_length, fingerprint_length;
  int status = read_object(state), usable = 0;
  if (state->stream && state->sequence >= (UINT64_C(1) << 24u))
    return C89CBOR_LIMIT;
  if (status != 0)
    return status;
  cipher_length = state->cipher_length;
  status = c89_cose_make_aad(state, state->encrypt);
  aad_length = state->cipher_length;
  state->cipher_length = cipher_length;
  if (status != 0)
    return status;
  if (!state->encrypt) {
    if (key->info.kind != C89CBOR_COSE_A256GCM)
      return C89CBOR_AUTH;
    status =
        c89_cose_gcm(key, state->cipher_context, 0, key->secret,
                     state->body.nonce, state->aad, aad_length, state->cipher,
                     cipher_length, state->plain, &state->plain_length);
  } else {
    status = C89CBOR_AUTH;
    for (i = 0; i < state->recipient_count; ++i) {
      c89_cose_recipient *recipient = &state->recipients[i];
      if (!recipient->usable)
        continue;
      usable = 1;
      if (state->stream) {
        if (EVP_Q_digest(NULL, "SHA256", NULL, recipient->encoded,
                         recipient->encoded_length, fingerprint,
                         &fingerprint_length) != 1 ||
            fingerprint_length != 32u) {
          status = C89CBOR_CRYPTO;
          break;
        }
      }
      if (state->stream && state->stream_key_ready &&
          CRYPTO_memcmp(fingerprint, state->recipient_fingerprint, 32u) == 0)
        memcpy(content_key, state->stream_key, 32u);
      else if (unwrap_recipient(state, recipient, content_key) != 0)
        continue;
      if (state->stream && state->stream_key_ready &&
          CRYPTO_memcmp(content_key, state->stream_key, sizeof(content_key)) !=
              0)
        continue;
      status =
          c89_cose_gcm(key, state->cipher_context, 0, content_key,
                       state->body.nonce, state->aad, aad_length, state->cipher,
                       cipher_length, state->plain, &state->plain_length);
      if (status == 0) {
        if (state->stream && !state->stream_key_ready) {
          memcpy(state->stream_key, content_key, sizeof(content_key));
          memcpy(state->recipient_fingerprint, fingerprint, 32u);
          state->stream_key_ready = 1;
        }
        break;
      }
    }
    OPENSSL_cleanse(content_key, sizeof(content_key));
    if (status != 0 && !usable)
      status = C89CBOR_UNSUPPORTED;
  }
  if (status == 0) {
    if (state->stream) {
      memcpy(state->stream_id, state->record_id, 16u);
      state->have_id = 1;
      state->seen_family = state->encrypt;
    }
    state->output = state->plain;
    state->output_length = state->plain_length;
    state->output_offset = 0;
  }
  return status;
}
