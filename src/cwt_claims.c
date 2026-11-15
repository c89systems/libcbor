#include "cwt_internal.h"
#include "number.h"
#include <string.h>
#include <math.h>

void c89_cwt_clear(c89_cwt_state *state) {
  memset(&state->view, 0, sizeof(state->view));
  memset(&state->native, 0, sizeof(state->native));
  OPENSSL_cleanse(state->workspace, state->workspace_size);
  state->arena.length = 0;
}
static int blob(c89_cwt_state *state, c89_cose_cursor *cursor,
                c89cbor_type type, unsigned char **out, size_t *length) {
  int status;
  if (state->arena.length >= state->arena.capacity)
    return C89CBOR_LIMIT;
  *out = state->arena.bytes + state->arena.length;
  status =
      c89_cose_blob(cursor, type, *out,
                    state->arena.capacity - state->arena.length - 1u, length);
  if (status == 0) {
    (*out)[*length] = 0;
    state->arena.length += *length + 1u;
  }
  return status;
}
static int text(c89_cwt_state *state, c89_cose_cursor *cursor, char **out) {
  unsigned char *bytes;
  size_t length;
  int status = blob(state, cursor, C89CBOR_TEXT, &bytes, &length);
  if (status == 0 && memchr(bytes, 0, length) != NULL)
    status = C89CBOR_MALFORMED;
  if (status == 0)
    *out = (char *)bytes;
  return status;
}
static int same_label(const c89cbor_token *a, const c89cbor_token *b) {
  if (a->type != b->type)
    return 0;
  return a->type == C89CBOR_TEXT
             ? a->length == b->length &&
                   (a->length == 0 || memcmp(a->data, b->data, a->length) == 0)
             : a->argument == b->argument;
}
static int label(c89_cwt_state *state, c89_cose_cursor *cursor,
                 c89_cwt_entry *entry) {
  unsigned char *bytes;
  size_t i, length;
  int status = C89CBOR_OK;
  entry->label = cursor->token;
  if (entry->label.type == C89CBOR_TEXT) {
    status = blob(state, cursor, C89CBOR_TEXT, &bytes, &length);
    if (status != 0)
      return status;
    entry->label.data = bytes;
    entry->label.length = length;
  } else if (entry->label.type != C89CBOR_UINT &&
             entry->label.type != C89CBOR_NEGATIVE)
    return C89CBOR_MALFORMED;
  if (status != 0)
    return status;
  for (i = 0; i < state->view.claim_count; ++i)
    if (same_label(&state->entries[i].label, &entry->label))
      return C89CBOR_MALFORMED;
  return C89CBOR_OK;
}
static int field(const c89cbor_token *key) {
  static const char *const names[] = {"nonce", "azp", "scope", "scp"};
  size_t i;
  if (key->type == C89CBOR_UINT && key->argument >= 1u && key->argument <= 7u)
    return (int)key->argument;
  if (key->type == C89CBOR_TEXT)
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
      if (key->length == strlen(names[i]) &&
          memcmp(key->data, names[i], key->length) == 0)
        return 8 + (int)i;
  return 0;
}
static int strings(c89_cwt_state *state, c89_cose_cursor *cursor,
                   lonejson_string_array *array, size_t base) {
  int status;
  array->items = state->strings + base;
  if (cursor->token.type == C89CBOR_TEXT) {
    status = text(state, cursor, &array->items[0]);
    if (status == 0)
      array->count = 1u;
    return status;
  }
  if (cursor->token.type != C89CBOR_ARRAY)
    return C89CBOR_MALFORMED;
  while ((status = c89_cose_next(cursor)) == 0 &&
         cursor->token.type != C89CBOR_END) {
    if (array->count == state->options.audiences)
      return C89CBOR_LIMIT;
    status = text(state, cursor, &array->items[array->count]);
    if (status != 0)
      return status;
    ++array->count;
  }
  return status == 0 && cursor->token.argument == C89CBOR_ARRAY
             ? C89CBOR_OK
             : C89CBOR_MALFORMED;
}
static int date(const c89cbor_token *token, lonejson_int64 *value) {
  double number;
  int status;
  if (token->type == C89CBOR_UINT || token->type == C89CBOR_NEGATIVE) {
    if (token->argument > (uint64_t)INT64_MAX)
      return C89CBOR_LIMIT;
    *value = token->type == C89CBOR_UINT ? (lonejson_int64)token->argument
                                         : -1 - (lonejson_int64)token->argument;
    return C89CBOR_OK;
  }
  status = c89_number_double(token, &number);
  if (status != 0)
    return C89CBOR_MALFORMED;
  if (number < -9223372036854775808.0 || number >= 9223372036854775808.0)
    return C89CBOR_LIMIT;
  *value = (lonejson_int64)ceil(number);
  return C89CBOR_OK;
}
int c89_cwt_parse(c89_cwt_state *state, size_t length) {
  c89_cose_cursor cursor;
  c89_cwt_entry *entry;
  unsigned char *id;
  size_t id_length;
  int status, which;
  OPENSSL_cleanse(state->arena.bytes, state->arena.capacity);
  state->arena.length = 0;
  memset(&state->view, 0, sizeof(state->view));
  memset(&state->native, 0, sizeof(state->native));
  status = c89_cose_cursor_init(&cursor, state->raw, length);
  if (status == 0)
    status = c89_cose_next(&cursor);
  if (status != 0 || cursor.token.type != C89CBOR_MAP)
    return C89CBOR_MALFORMED;
  while ((status = c89_cose_next(&cursor)) == 0 &&
         cursor.token.type != C89CBOR_END) {
    if (state->view.claim_count == state->options.claims)
      return C89CBOR_LIMIT;
    entry = &state->entries[state->view.claim_count];
    status = label(state, &cursor, entry);
    if (status == 0)
      status = c89_cose_next(&cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
    entry->offset = cursor.start;
    which = field(&entry->label);
    switch (which) {
    case 1:
      status = text(state, &cursor, &state->native.iss);
      break;
    case 2:
      status = text(state, &cursor, &state->native.sub);
      break;
    case 3:
      if (cursor.token.type == C89CBOR_TEXT)
        status = text(state, &cursor, &state->native.aud);
      else
        status = strings(state, &cursor, &state->native.aud_array, 0);
      break;
    case 4:
      status = date(&cursor.token, &state->native.exp);
      state->native.has_exp = status == 0;
      break;
    case 5:
      status = date(&cursor.token, &state->native.nbf);
      state->native.has_nbf = status == 0;
      break;
    case 6:
      status = date(&cursor.token, &state->native.iat);
      state->native.has_iat = status == 0;
      break;
    case 7:
      status = blob(state, &cursor, C89CBOR_BYTES, &id, &id_length);
      if (status == 0) {
        state->view.cti = id;
        state->view.cti_length = id_length;
      }
      break;
    case 8:
      status = text(state, &cursor, &state->native.nonce);
      break;
    case 9:
      status = text(state, &cursor, &state->native.azp);
      break;
    case 10:
      status = text(state, &cursor, &state->native.scope);
      break;
    case 11:
      status =
          strings(state, &cursor, &state->native.scp, state->options.audiences);
      break;
    default:
      status = c89_cose_skip(&cursor);
      break;
    }
    if (status != 0)
      return status;
    entry->length = cursor.offset - entry->offset;
    ++state->view.claim_count;
  }
  if (status != 0 || cursor.token.argument != C89CBOR_MAP)
    return C89CBOR_MALFORMED;
  status = c89_cose_finish(&cursor);
  if (status == 0) {
    state->view.encoded = state->raw;
    state->view.encoded_length = length;
    state->view.claims = &state->native;
  }
  return status;
}
int c89cbor_cwt_claim(const c89cbor_cwt *receiver, const c89cbor_token *key,
                      const void **value, size_t *length) {
  const c89_cwt_state *state;
  size_t i;
  if (value != NULL)
    *value = NULL;
  if (length != NULL)
    *length = 0;
  if (receiver == NULL || receiver->lifetime.magic != C89_LIFETIME_MAGIC ||
      !receiver->lifetime.live || value == NULL || length == NULL ||
      key == NULL ||
      (key->type != C89CBOR_UINT && key->type != C89CBOR_NEGATIVE &&
       key->type != C89CBOR_TEXT) ||
      (key->type == C89CBOR_TEXT && key->data == NULL && key->length != 0))
    return C89CBOR_INVALID;
  if (receiver->lifetime.busy)
    return C89CBOR_BUSY;
  state = receiver->state;
  for (i = 0; i < state->view.claim_count && state->view.encoded != NULL; ++i)
    if (same_label(key, &state->entries[i].label)) {
      *value = state->raw + state->entries[i].offset;
      *length = state->entries[i].length;
      return C89CBOR_OK;
    }
  return C89CBOR_INPUT;
}
static void emit_text(c89_cose_writer *writer, const char *text_value) {
  size_t length;
  if (text_value == NULL) {
    writer->status = C89CBOR_INVALID;
    return;
  }
  length = strnlen(text_value, writer->capacity + 1u);
  if (length > writer->capacity) {
    writer->status = C89CBOR_LIMIT;
    return;
  }
  c89_cose_bytes(writer, C89CBOR_TEXT, text_value, length);
}
static void emit_strings(c89_cwt_state *state, c89_cose_writer *writer,
                         const lonejson_string_array *array) {
  size_t i;
  if (array->count > state->options.audiences ||
      (array->count != 0 && array->items == NULL)) {
    writer->status = array->count > state->options.audiences ? C89CBOR_LIMIT
                                                             : C89CBOR_INVALID;
    return;
  }
  c89_cose_emit(writer, C89CBOR_ARRAY, (uint64_t)array->count);
  for (i = 0; i < array->count; ++i)
    emit_text(writer, array->items[i]);
  c89_cose_emit(writer, C89CBOR_END, C89CBOR_ARRAY);
}
int c89_cwt_encode(c89_cwt_state *state, const lonejson_jwt_claims *claims,
                   const void *id, size_t id_length, size_t *length) {
  c89_cose_writer writer;
  if (claims == NULL || (id == NULL && id_length != 0) ||
      (claims->aud != NULL && claims->aud_array.count != 0))
    return C89CBOR_INVALID;
  c89_cose_writer_init(&writer, &state->encoder, state->inner,
                       state->options.cose.record_bytes);
  c89_cose_emit(&writer, C89CBOR_MAP,
                (claims->iss != NULL) + (claims->sub != NULL) +
                    (claims->aud != NULL || claims->aud_array.count != 0) +
                    !!claims->has_exp + !!claims->has_nbf + !!claims->has_iat +
                    (id != NULL) + (claims->nonce != NULL) +
                    (claims->azp != NULL) + (claims->scope != NULL) +
                    (claims->scp.count != 0));
#define STRING_CLAIM(number, member)                                           \
  if (claims->member != NULL) {                                                \
    c89_cose_emit(&writer, C89CBOR_UINT, number);                              \
    emit_text(&writer, claims->member);                                        \
  }
  STRING_CLAIM(1, iss)
  STRING_CLAIM(2, sub)
#undef STRING_CLAIM
  if (claims->aud != NULL || claims->aud_array.count != 0) {
    c89_cose_emit(&writer, C89CBOR_UINT, 3);
    if (claims->aud != NULL)
      emit_text(&writer, claims->aud);
    else
      emit_strings(state, &writer, &claims->aud_array);
  }
#define DATE_CLAIM(number, member)                                             \
  if (claims->has_##member) {                                                  \
    c89_cose_emit(&writer, C89CBOR_UINT, number);                              \
    c89_cose_emit(&writer,                                                     \
                  claims->member < 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT,        \
                  (uint64_t)(claims->member < 0 ? -(claims->member + 1)        \
                                                : claims->member));            \
  }
  DATE_CLAIM(4, exp)
  DATE_CLAIM(5, nbf)
  DATE_CLAIM(6, iat)
#undef DATE_CLAIM
  if (id != NULL) {
    c89_cose_emit(&writer, C89CBOR_UINT, 7);
    c89_cose_bytes(&writer, C89CBOR_BYTES, id, id_length);
  }
#define EXTENSION(member)                                                      \
  if (claims->member != NULL) {                                                \
    c89_cose_bytes(&writer, C89CBOR_TEXT, #member, sizeof(#member) - 1u);      \
    emit_text(&writer, claims->member);                                        \
  }
  EXTENSION(nonce)
  EXTENSION(azp)
  EXTENSION(scope)
#undef EXTENSION
  if (claims->scp.count != 0) {
    c89_cose_bytes(&writer, C89CBOR_TEXT, "scp", 3u);
    emit_strings(state, &writer, &claims->scp);
  }
  c89_cose_emit(&writer, C89CBOR_END, C89CBOR_MAP);
  *length = writer.length;
  return c89_cose_writer_finish(&writer);
}
