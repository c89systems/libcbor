#include "cose_internal.h"
#include <string.h>
#include <limits.h>

int c89_cose_cursor_init(c89_cose_cursor *cursor, const void *bytes,
                         size_t length) {
  memset(cursor, 0, sizeof(*cursor));
  cursor->bytes = bytes;
  cursor->length = length;
  return c89cbor_decoder_init(NULL, &cursor->decoder, NULL, 0, 0);
}
int c89_cose_next(c89_cose_cursor *cursor) {
  size_t used;
  int status;
  cursor->start = cursor->offset;
  status = c89cbor_decoder_next(
      &cursor->decoder, cursor->bytes + cursor->offset,
      cursor->length - cursor->offset, &used, &cursor->token);
  cursor->offset += used;
  if (status == C89CBOR_TOKEN)
    return C89CBOR_OK;
  return status == C89CBOR_INPUT ? C89CBOR_MALFORMED : status;
}
int c89_cose_finish(c89_cose_cursor *cursor) {
  int status = c89_cose_next(cursor);
  if (status == C89CBOR_DONE && cursor->offset == cursor->length)
    status = c89cbor_decoder_finish(&cursor->decoder);
  else if (status >= 0)
    status = C89CBOR_MALFORMED;
  (void)c89cbor_decoder_cleanup(&cursor->decoder);
  return status;
}
int c89_cose_skip(c89_cose_cursor *cursor) {
  size_t depth = 0;
  int status;
  do {
    if (cursor->token.type >= C89CBOR_BYTES &&
        cursor->token.type <= C89CBOR_TAG)
      ++depth;
    else if (cursor->token.type == C89CBOR_END) {
      if (depth == 0)
        return C89CBOR_MALFORMED;
      --depth;
    }
    if (depth == 0)
      return C89CBOR_OK;
    status = c89_cose_next(cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
  } while (1);
}
int c89_cose_blob(c89_cose_cursor *cursor, c89cbor_type kind, void *bytes,
                  size_t capacity, size_t *length) {
  size_t depth = 1;
  unsigned char *out = bytes;
  int status;
  *length = 0;
  if (cursor->token.type != kind)
    return C89CBOR_MALFORMED;
  while (depth != 0) {
    status = c89_cose_next(cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
    if (cursor->token.type == C89CBOR_DATA) {
      if (cursor->token.length > capacity - *length)
        return C89CBOR_LIMIT;
      if (cursor->token.length != 0)
        memcpy(out + *length, cursor->token.data, cursor->token.length);
      *length += cursor->token.length;
    } else if (cursor->token.type == kind)
      ++depth;
    else if (cursor->token.type == C89CBOR_END &&
             cursor->token.argument == (uint64_t)kind)
      --depth;
    else
      return C89CBOR_MALFORMED;
  }
  return C89CBOR_OK;
}
static void write_token(c89_cose_writer *writer, const c89cbor_token *token) {
  size_t written;
  int status;
  if (writer->status != 0)
    return;
  writer->status = c89cbor_encoder_put(writer->encoder, token);
  if (writer->status != 0)
    return;
  do {
    status =
        c89cbor_encoder_read(writer->encoder, writer->bytes + writer->length,
                             writer->capacity - writer->length, &written);
    writer->length += written;
    if (status < 0) {
      writer->status = status;
      return;
    }
    if (status == C89CBOR_OUTPUT && writer->length == writer->capacity) {
      writer->status = C89CBOR_LIMIT;
      return;
    }
  } while (status == C89CBOR_OUTPUT);
}
void c89_cose_writer_init(c89_cose_writer *writer, c89cbor_encoder *encoder,
                          void *bytes, size_t capacity) {
  memset(writer, 0, sizeof(*writer));
  writer->encoder = encoder;
  writer->bytes = bytes;
  writer->capacity = capacity;
  writer->status = c89cbor_encoder_init(NULL, encoder, NULL, 0, 0);
}
void c89_cose_emit(c89_cose_writer *writer, c89cbor_type type,
                   uint64_t argument) {
  c89cbor_token token;
  memset(&token, 0, sizeof(token));
  token.type = type;
  token.argument = argument;
  write_token(writer, &token);
}
void c89_cose_bytes(c89_cose_writer *writer, c89cbor_type type,
                    const void *bytes, size_t length) {
  c89cbor_token token;
  c89_cose_emit(writer, type, (uint64_t)length);
  if (length != 0) {
    memset(&token, 0, sizeof(token));
    token.type = C89CBOR_DATA;
    token.data = bytes;
    token.length = length;
    write_token(writer, &token);
  }
  c89_cose_emit(writer, C89CBOR_END, (uint64_t)type);
}
int c89_cose_writer_finish(c89_cose_writer *writer) {
  if (writer->status == 0)
    writer->status = c89cbor_encoder_finish(writer->encoder);
  (void)c89cbor_encoder_cleanup(writer->encoder);
  return writer->status;
}

typedef struct label {
  c89cbor_type type;
  uint64_t argument;
  unsigned char *bytes;
  size_t length;
  int protected_value, known;
} label;
typedef struct header_labels {
  label seen[64], critical[32];
  size_t count, critical_count;
} header_labels;
static int blob_arena(c89_cose_cursor *cursor, c89cbor_type kind,
                      c89_cose_arena *arena, unsigned char **bytes,
                      size_t *length) {
  int status;
  *bytes = arena->bytes + arena->length;
  status = c89_cose_blob(cursor, kind, arena->bytes + arena->length,
                         arena->capacity - arena->length, length);
  if (status == 0)
    arena->length += *length;
  return status;
}
static int read_label(c89_cose_cursor *cursor, label *value,
                      c89_cose_arena *arena) {
  memset(value, 0, sizeof(*value));
  value->type = cursor->token.type;
  value->argument = cursor->token.argument;
  if (value->type == C89CBOR_UINT || value->type == C89CBOR_NEGATIVE)
    return C89CBOR_OK;
  if (value->type == C89CBOR_TEXT)
    return blob_arena(cursor, C89CBOR_TEXT, arena, &value->bytes,
                      &value->length);
  return C89CBOR_MALFORMED;
}
static int equal_label(const label *a, const label *b) {
  return a->type == b->type &&
         (a->type == C89CBOR_TEXT
              ? a->length == b->length &&
                    (a->length == 0 ||
                     memcmp(a->bytes, b->bytes, a->length) == 0)
              : a->argument == b->argument);
}
static int label_number(const label *value, int number) {
  c89cbor_type type = number < 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT;
  return value->type == type &&
         value->argument == (uint64_t)(number < 0 ? -1 - number : number);
}
static int insert_label(header_labels *labels, const label *value) {
  size_t i;
  for (i = 0; i < labels->count; ++i)
    if (equal_label(&labels->seen[i], value))
      return C89CBOR_MALFORMED;
  if (labels->count == 64u)
    return C89CBOR_LIMIT;
  labels->seen[labels->count++] = *value;
  return C89CBOR_OK;
}
static int signed_algorithm(const c89cbor_token *token, int *value) {
  if (token->type != C89CBOR_UINT && token->type != C89CBOR_NEGATIVE)
    return token->type == C89CBOR_TEXT ? C89CBOR_UNSUPPORTED
                                       : C89CBOR_MALFORMED;
  if (token->argument > (uint64_t)INT_MAX)
    return C89CBOR_UNSUPPORTED;
  *value = token->type == C89CBOR_UINT ? (int)token->argument
                                       : -1 - (int)token->argument;
  return C89CBOR_OK;
}
static int ephemeral(c89_cose_cursor *cursor, unsigned char *public_bytes,
                     c89_cose_arena *arena) {
  header_labels labels;
  label key;
  size_t length;
  int status, kty = 0, curve = 0, have_x = 0, algorithm, unsupported = 0;
  memset(&labels, 0, sizeof(labels));
  if (cursor->token.type != C89CBOR_MAP)
    return C89CBOR_MALFORMED;
  while ((status = c89_cose_next(cursor)) == 0 &&
         cursor->token.type != C89CBOR_END) {
    status = read_label(cursor, &key, arena);
    if (status == 0)
      status = insert_label(&labels, &key);
    if (status == 0)
      status = c89_cose_next(cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
    if (label_number(&key, 1) || label_number(&key, -1)) {
      if (cursor->token.type != C89CBOR_UINT)
        return C89CBOR_MALFORMED;
      if (label_number(&key, 1))
        kty = cursor->token.argument == 1u;
      else
        curve = cursor->token.argument == 4u;
    } else if (label_number(&key, -2)) {
      status = c89_cose_blob(cursor, C89CBOR_BYTES, public_bytes, 32u, &length);
      if (status != 0)
        return status;
      have_x = length == 32u;
    } else if (label_number(&key, -4))
      return C89CBOR_MALFORMED;
    else if (label_number(&key, 3)) {
      status = signed_algorithm(&cursor->token, &algorithm);
      if (status == C89CBOR_MALFORMED)
        return status;
      if (status != 0 || algorithm != -31) {
        unsupported = 1;
        status = c89_cose_skip(cursor);
        if (status != 0)
          return status;
      }
    } else if (label_number(&key, 4)) {
      if (cursor->token.type != C89CBOR_ARRAY)
        return C89CBOR_MALFORMED;
      while ((status = c89_cose_next(cursor)) == 0 &&
             cursor->token.type != C89CBOR_END) {
        unsupported = 1;
        status = c89_cose_skip(cursor);
        if (status != 0)
          return status;
      }
      if (status != 0)
        return status < 0 ? status : C89CBOR_MALFORMED;
    } else {
      status = c89_cose_skip(cursor);
      if (status != 0)
        return status;
    }
  }
  if (status != 0)
    return status < 0 ? status : C89CBOR_MALFORMED;
  return kty && curve && have_x && !unsupported ? C89CBOR_OK
                                                : C89CBOR_UNSUPPORTED;
}
static int header_map(c89_cose_cursor *cursor, c89_cose_header *header,
                      c89_cose_arena *arena, header_labels *labels,
                      int protected_value, int recipient) {
  label key;
  c89_cose_party *party;
  size_t i, index;
  int status, number;
  if (cursor->token.type != C89CBOR_MAP)
    return C89CBOR_MALFORMED;
  while ((status = c89_cose_next(cursor)) == 0 &&
         cursor->token.type != C89CBOR_END) {
    status = read_label(cursor, &key, arena);
    key.protected_value = protected_value;
    key.known =
        key.type != C89CBOR_TEXT &&
        ((key.type == C89CBOR_UINT &&
          (key.argument == 1u || key.argument == 2u || key.argument == 4u ||
           (recipient == 0 && key.argument == 5u))) ||
         (recipient == 1 && key.type == C89CBOR_NEGATIVE &&
          (key.argument == 0u ||
           (key.argument >= 19u && key.argument <= 25u))));
    if (status == 0)
      status = insert_label(labels, &key);
    if (status == 0)
      status = c89_cose_next(cursor);
    if (status != 0)
      return status < 0 ? status : C89CBOR_MALFORMED;
    if (label_number(&key, 1)) {
      status = signed_algorithm(&cursor->token, &header->algorithm);
      if (status == C89CBOR_MALFORMED)
        return status;
      if (status != 0) {
        header->unsupported = 1;
        status = c89_cose_skip(cursor);
        if (status != 0)
          return status;
      }
      header->have_algorithm = 1;
      header->protected_algorithm = protected_value;
    } else if (label_number(&key, 2)) {
      if (!protected_value || cursor->token.type != C89CBOR_ARRAY)
        return C89CBOR_MALFORMED;
      while ((status = c89_cose_next(cursor)) == 0 &&
             cursor->token.type != C89CBOR_END) {
        if (labels->critical_count == 32u)
          return C89CBOR_LIMIT;
        status = read_label(cursor, &labels->critical[labels->critical_count],
                            arena);
        if (status != 0)
          return status;
        for (i = 0; i < labels->critical_count; ++i)
          if (equal_label(&labels->critical[i],
                          &labels->critical[labels->critical_count]))
            return C89CBOR_MALFORMED;
        ++labels->critical_count;
      }
      if (status != 0 || labels->critical_count == 0)
        return status < 0 ? status : C89CBOR_MALFORMED;
    } else if (label_number(&key, 3)) {
      if (cursor->token.type != C89CBOR_UINT &&
          cursor->token.type != C89CBOR_TEXT)
        return C89CBOR_MALFORMED;
      status = c89_cose_skip(cursor);
      if (status != 0)
        return status;
    } else if (label_number(&key, 4)) {
      status = blob_arena(cursor, C89CBOR_BYTES, arena, &header->id,
                          &header->id_length);
      if (status != 0 || header->id_length > 64u)
        return status != 0 ? status : C89CBOR_LIMIT;
    } else if (recipient == 0 && label_number(&key, 5)) {
      status = c89_cose_blob(cursor, C89CBOR_BYTES, header->nonce, 12u, &index);
      if (status != 0 || index != 12u)
        return status != 0 ? status : C89CBOR_MALFORMED;
      header->have_nonce = 1;
    } else if (recipient == 1 && label_number(&key, -1)) {
      status = ephemeral(cursor, header->ephemeral, arena);
      if (status == C89CBOR_UNSUPPORTED)
        header->unsupported = 1;
      else if (status != 0)
        return status;
      header->have_ephemeral = 1;
    } else if (recipient == 1 && label_number(&key, -20)) {
      status = blob_arena(cursor, C89CBOR_BYTES, arena, &header->salt,
                          &header->salt_length);
      if (status != 0)
        return status;
    } else if (recipient == 1 && key.type == C89CBOR_NEGATIVE &&
               key.argument >= 20u && key.argument <= 25u) {
      number = (int)key.argument - 20;
      index = (size_t)number % 3u;
      party = &header->party[(size_t)number / 3u][index];
      party->type = cursor->token.type;
      party->argument = cursor->token.argument;
      if (party->type == C89CBOR_BYTES) {
        status = blob_arena(cursor, C89CBOR_BYTES, arena, &party->bytes,
                            &party->length);
        if (status != 0)
          return status;
      } else if (index != 1u || (party->type != C89CBOR_UINT &&
                                 party->type != C89CBOR_NEGATIVE))
        return C89CBOR_MALFORMED;
    } else {
      if (label_number(&key, 6) || label_number(&key, 7) ||
          label_number(&key, 9))
        header->unsupported = 1;
      status = c89_cose_skip(cursor);
      if (status != 0)
        return status;
    }
  }
  return status < 0 ? status : status == 0 ? C89CBOR_OK : C89CBOR_MALFORMED;
}
int c89_cose_headers(c89_cose_cursor *cursor, c89_cose_header *header,
                     c89_cose_arena *arena, int recipient) {
  c89_cose_cursor protected_cursor;
  header_labels labels;
  size_t i, j;
  int status;
  memset(header, 0, sizeof(*header));
  memset(&labels, 0, sizeof(labels));
  for (i = 0; i < 2u; ++i)
    for (j = 0; j < 3u; ++j)
      header->party[i][j].type = C89CBOR_NULL;
  status = blob_arena(cursor, C89CBOR_BYTES, arena, &header->protected_bytes,
                      &header->protected_length);
  if (status != 0)
    return status;
  if (header->protected_length != 0) {
    c89_cose_cursor_init(&protected_cursor, header->protected_bytes,
                         header->protected_length);
    status = c89_cose_next(&protected_cursor);
    if (status == 0)
      status =
          header_map(&protected_cursor, header, arena, &labels, 1, recipient);
    if (status == 0)
      status = c89_cose_finish(&protected_cursor);
    if (status != 0)
      return status;
  }
  header->protected_empty = labels.count == 0;
  status = c89_cose_next(cursor);
  if (status == 0)
    status = header_map(cursor, header, arena, &labels, 0, recipient);
  if (status != 0)
    return status;
  for (i = 0; i < labels.critical_count; ++i) {
    for (j = 0; j < labels.count; ++j)
      if (equal_label(&labels.critical[i], &labels.seen[j]))
        break;
    if (j == labels.count || !labels.seen[j].protected_value)
      return C89CBOR_MALFORMED;
    if (!labels.seen[j].known)
      header->unsupported = 1;
  }
  return header->have_algorithm && !header->unsupported ? C89CBOR_OK
                                                        : C89CBOR_UNSUPPORTED;
}
