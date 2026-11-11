#define _GNU_SOURCE
#include "map.h"
#include <string.h>

#define ALIGN_PROBE(name, type)                                                \
  typedef struct name {                                                        \
    char prefix;                                                               \
    type value;                                                                \
  } name
ALIGN_PROBE(pointer_alignment, void *);
ALIGN_PROBE(integer_alignment, lonejson_int64);
ALIGN_PROBE(double_alignment, double);
ALIGN_PROBE(bool_alignment, bool);
ALIGN_PROBE(spool_alignment, lonejson_spooled);
ALIGN_PROBE(source_alignment, lonejson_source);
ALIGN_PROBE(json_alignment, lonejson_json_value);
ALIGN_PROBE(array_alignment, lonejson_object_array);
ALIGN_PROBE(string_stream_alignment, lonejson_string_array_stream);
ALIGN_PROBE(object_stream_alignment, lonejson_mapped_array_stream);
#undef ALIGN_PROBE

size_t c89_map_field_size(const lonejson_field *field) {
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING:
    return field->storage == LONEJSON_STORAGE_FIXED ? field->fixed_capacity
                                                    : sizeof(char *);
  case LONEJSON_FIELD_KIND_I64:
    return sizeof(lonejson_int64);
  case LONEJSON_FIELD_KIND_U64:
    return sizeof(lonejson_uint64);
  case LONEJSON_FIELD_KIND_F64:
    return sizeof(double);
  case LONEJSON_FIELD_KIND_BOOL:
    return sizeof(bool);
  case LONEJSON_FIELD_KIND_STRING_STREAM:
  case LONEJSON_FIELD_KIND_BASE64_STREAM:
    return sizeof(lonejson_spooled);
  case LONEJSON_FIELD_KIND_STRING_SOURCE:
  case LONEJSON_FIELD_KIND_BASE64_SOURCE:
    return sizeof(lonejson_source);
  case LONEJSON_FIELD_KIND_JSON_VALUE:
    return sizeof(lonejson_json_value);
  case LONEJSON_FIELD_KIND_OBJECT:
    return field->submap == NULL ? 0 : field->submap->struct_size;
  case LONEJSON_FIELD_KIND_STRING_ARRAY:
    return sizeof(lonejson_string_array);
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    return sizeof(lonejson_i64_array);
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    return sizeof(lonejson_u64_array);
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    return sizeof(lonejson_f64_array);
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    return sizeof(lonejson_bool_array);
  case LONEJSON_FIELD_KIND_OBJECT_ARRAY:
    return sizeof(lonejson_object_array);
  case LONEJSON_FIELD_KIND_STRING_ARRAY_STREAM:
    return sizeof(lonejson_string_array_stream);
  case LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM:
    return sizeof(lonejson_mapped_array_stream);
  default:
    return 0;
  }
}
static size_t field_alignment(const lonejson_field *field) {
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING:
    return field->storage == LONEJSON_STORAGE_FIXED
               ? 1
               : offsetof(pointer_alignment, value);
  case LONEJSON_FIELD_KIND_I64:
  case LONEJSON_FIELD_KIND_U64:
    return offsetof(integer_alignment, value);
  case LONEJSON_FIELD_KIND_F64:
    return offsetof(double_alignment, value);
  case LONEJSON_FIELD_KIND_BOOL:
    return offsetof(bool_alignment, value);
  case LONEJSON_FIELD_KIND_STRING_STREAM:
  case LONEJSON_FIELD_KIND_BASE64_STREAM:
    return offsetof(spool_alignment, value);
  case LONEJSON_FIELD_KIND_STRING_SOURCE:
  case LONEJSON_FIELD_KIND_BASE64_SOURCE:
    return offsetof(source_alignment, value);
  case LONEJSON_FIELD_KIND_JSON_VALUE:
    return offsetof(json_alignment, value);
  case LONEJSON_FIELD_KIND_STRING_ARRAY_STREAM:
    return offsetof(string_stream_alignment, value);
  case LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM:
    return offsetof(object_stream_alignment, value);
  case LONEJSON_FIELD_KIND_OBJECT:
    return 1;
  default:
    return offsetof(array_alignment, value);
  }
}
static size_t element_size(const lonejson_field *field) {
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING_ARRAY:
    return sizeof(char *);
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    return sizeof(lonejson_int64);
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    return sizeof(lonejson_uint64);
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    return sizeof(double);
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    return sizeof(bool);
  case LONEJSON_FIELD_KIND_OBJECT_ARRAY:
    return field->submap == NULL ? 0 : field->submap->struct_size;
  default:
    return 0;
  }
}
/* Verify the alignment of every inline member at each array stride. Schemas
 * have already been checked for inline cycles before calling this walker. */
static int layout_alignment(const lonejson_map *map, size_t base, size_t stride,
                            size_t remaining) {
  size_t i, alignment;
  const lonejson_field *field;
  if (remaining == 0)
    return 0;
  for (i = 0; i < map->field_count; ++i) {
    field = &map->fields[i];
    alignment = field_alignment(field);
    if ((base % alignment + field->struct_offset % alignment) % alignment !=
            0 ||
        stride % alignment != 0)
      return 0;
    if (field->kind == LONEJSON_FIELD_KIND_OBJECT &&
        !layout_alignment(field->submap, base + field->struct_offset, stride,
                          remaining - 1u))
      return 0;
  }
  return 1;
}
static int validate_key(const lonejson_field *field) {
  c89cbor_encoder encoder;
  c89cbor_token token;
  c89cbor_frame frame;
  const void *bytes;
  size_t length;
  int status;
  status = c89cbor_encoder_init(NULL, &encoder, &frame, 1, C89CBOR_CHUNK);
  if (status != 0)
    return status;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_TEXT;
  token.argument = (uint64_t)field->json_key_len;
  status = encoder.put(&encoder, &token);
  if (status != 0)
    return status;
  while (encoder.peek(&encoder, &bytes, &length) == C89CBOR_OUTPUT)
    (void)encoder.advance(&encoder, length);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_DATA;
  token.data = field->json_key;
  token.length = field->json_key_len;
  status = encoder.put(&encoder, &token);
  if (status != 0)
    return status;
  while ((status = encoder.peek(&encoder, &bytes, &length)) == C89CBOR_OUTPUT)
    (void)encoder.advance(&encoder, length);
  if (status != 0)
    return status;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_END;
  token.argument = C89CBOR_TEXT;
  return encoder.put(&encoder, &token);
}
static int validate_map(c89_map_state *state, const lonejson_map *map,
                        const void *record, size_t extent, size_t depth) {
  const lonejson_field *field;
  const lonejson_map *child;
  const void *child_record;
  const lonejson_mapped_array_stream *stream;
  size_t i, j, k, size, alignment, stride;
  int status;
  unsigned int allowed =
      LONEJSON_FIELD_REQUIRED | LONEJSON_FIELD_OMIT_NULL |
      LONEJSON_FIELD_OMIT_EMPTY | LONEJSON_FIELD_HAS_PRESENCE |
      LONEJSON_FIELD_ACCEPT_NULL | LONEJSON_FIELD_JSON_VALUE_DEFAULT_CAPTURE;
  if (map == NULL || map->struct_size == 0 || map->struct_size > extent ||
      map->field_count > (size_t)-1 / sizeof(lonejson_field) ||
      (map->field_count != 0 && map->fields == NULL))
    return c89_map_fail(state, C89CBOR_INVALID, "invalid mapped record extent");
  if (depth == state->options.depth)
    return c89_map_fail(state, C89CBOR_LIMIT, "schema exceeds nesting limit");
  state->schema_path[depth] = map;
  if (state->max_fields < map->field_count)
    state->max_fields = map->field_count;
  for (i = 0; i < map->field_count; ++i) {
    field = &map->fields[i];
    state->error_field = field;
    if (field->json_key == NULL ||
        field->json_key_len > state->options.key_bytes ||
        strlen(field->json_key) != field->json_key_len ||
        validate_key(field) != 0)
      return c89_map_fail(state, C89CBOR_INVALID, "invalid UTF-8 schema key");
    for (j = 0; j < i; ++j) {
      if (map->fields[j].json_key_len == field->json_key_len &&
          memcmp(map->fields[j].json_key, field->json_key,
                 field->json_key_len) == 0)
        return c89_map_fail(state, C89CBOR_INVALID, "duplicate schema key");
    }
    size = c89_map_field_size(field);
    alignment = field_alignment(field);
    if (size == 0 || field->struct_offset > map->struct_size ||
        size > map->struct_size - field->struct_offset ||
        field->struct_offset % alignment != 0 ||
        (field->flags & ~allowed) != 0 ||
        field->storage < LONEJSON_STORAGE_DYNAMIC ||
        field->storage > LONEJSON_STORAGE_FIXED ||
        field->overflow_policy < LONEJSON_OVERFLOW_FAIL ||
        field->overflow_policy > LONEJSON_OVERFLOW_TRUNCATE_SILENT)
      return c89_map_fail(state, C89CBOR_INVALID,
                          "invalid mapped field layout");
    if (record != NULL &&
        ((uintptr_t)record + field->struct_offset) % alignment != 0)
      return c89_map_fail(state, C89CBOR_INVALID,
                          "misaligned mapped record storage");
    if (lonejson_field_has_presence(field) &&
        (field->presence_offset > map->struct_size ||
         sizeof(int) > map->struct_size - field->presence_offset ||
         field->presence_offset % offsetof(bool_alignment, value) != 0))
      return c89_map_fail(state, C89CBOR_INVALID,
                          "invalid presence flag offset");
    stride = element_size(field);
    if (stride != 0 && field->kind != LONEJSON_FIELD_KIND_STRING_ARRAY &&
        (field->elem_size < stride ||
         (field->kind != LONEJSON_FIELD_KIND_OBJECT_ARRAY &&
          field->elem_size != stride)))
      return c89_map_fail(state, C89CBOR_INVALID,
                          "invalid mapped array stride");
    child = NULL;
    child_record = NULL;
    if (field->kind == LONEJSON_FIELD_KIND_OBJECT ||
        field->kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY) {
      child = field->submap;
      if (child == NULL)
        return c89_map_fail(state, C89CBOR_INVALID,
                            "nested field requires a schema");
      if (record != NULL && field->kind == LONEJSON_FIELD_KIND_OBJECT)
        child_record = (const unsigned char *)record + field->struct_offset;
    } else if (field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM &&
               record != NULL) {
      stream =
          (const lonejson_mapped_array_stream *)((const unsigned char *)record +
                                                 field->struct_offset);
      child = stream->handler.item_map;
      child_record = stream->handler.item_dst;
    }
    if (child != NULL) {
      for (j = 0; j <= depth && state->schema_path[j] != child; ++j) {
      }
      if (j <= depth) {
        for (k = j + 1u; k <= depth && state->schema_inline[k]; ++k) {
        }
        if (field->kind == LONEJSON_FIELD_KIND_OBJECT && k > depth)
          return c89_map_fail(state, C89CBOR_INVALID, "inline schema cycle");
      } else {
        if (depth + 1u == state->options.depth)
          return c89_map_fail(state, C89CBOR_LIMIT,
                              "schema exceeds nesting limit");
        state->schema_inline[depth + 1u] =
            field->kind == LONEJSON_FIELD_KIND_OBJECT;
        status = validate_map(state, child, child_record, child->struct_size,
                              depth + 1u);
        if (status != 0)
          return status;
      }
      if (field->kind == LONEJSON_FIELD_KIND_OBJECT &&
          !layout_alignment(child, field->struct_offset, 0,
                            state->options.depth))
        return c89_map_fail(state, C89CBOR_INVALID, "misaligned inline object");
      if (field->kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY &&
          !layout_alignment(child, 0, field->elem_size, state->options.depth))
        return c89_map_fail(state, C89CBOR_INVALID,
                            "misaligned object array stride");
    }
  }
  return C89CBOR_OK;
}
int c89_map_schema(c89_map_state *state, const lonejson_map *map, size_t extent,
                   size_t depth) {
  const void *record =
      state->encode ? state->record.input : state->record.output;
  return validate_map(state, map, record, extent, depth);
}
int c89_map_omit(c89_map_state *state, const lonejson_field *field,
                 const void *record, size_t depth, int *omit) {
  const unsigned char *slot =
      (const unsigned char *)record + field->struct_offset;
  const char *text;
  int present;
  size_t count;
  *omit = 0;
  if ((field->flags & LONEJSON_FIELD_REQUIRED) != 0)
    return C89CBOR_OK;
  if (lonejson_field_has_presence(field)) {
    memcpy(&present, (const unsigned char *)record + field->presence_offset,
           sizeof(present));
    if (!present) {
      *omit = 1;
      return C89CBOR_OK;
    }
  }
  if ((field->flags & (LONEJSON_FIELD_OMIT_NULL | LONEJSON_FIELD_OMIT_EMPTY)) ==
      0)
    return C89CBOR_OK;
  if (field->kind == LONEJSON_FIELD_KIND_STRING &&
      field->storage == LONEJSON_STORAGE_DYNAMIC) {
    memcpy(&text, slot, sizeof(text));
    *omit = text == NULL || ((field->flags & LONEJSON_FIELD_OMIT_EMPTY) != 0 &&
                             text[0] == '\0');
    return C89CBOR_OK;
  }
  if (field->kind == LONEJSON_FIELD_KIND_STRING_SOURCE ||
      field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE) {
    *omit = ((const lonejson_source *)slot)->kind == LONEJSON_SOURCE_NONE;
    return C89CBOR_OK;
  }
  if (field->kind == LONEJSON_FIELD_KIND_JSON_VALUE) {
    *omit =
        ((const lonejson_json_value *)slot)->kind == LONEJSON_JSON_VALUE_NULL;
    return C89CBOR_OK;
  }
  if ((field->flags & LONEJSON_FIELD_OMIT_EMPTY) == 0)
    return C89CBOR_OK;
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING:
    *omit = slot[0] == 0;
    break;
  case LONEJSON_FIELD_KIND_STRING_STREAM:
  case LONEJSON_FIELD_KIND_BASE64_STREAM:
    *omit = lonejson_spooled_size((const lonejson_spooled *)slot) == 0;
    break;
  case LONEJSON_FIELD_KIND_OBJECT:
    if (depth == state->options.depth)
      return c89_map_fail(state, C89CBOR_LIMIT, "record exceeds nesting limit");
    if (c89_map_count(state, field->submap, slot, depth + 1u, &count) != 0)
      return state->owner->lifetime.error.status;
    *omit = count == 0;
    break;
  case LONEJSON_FIELD_KIND_STRING_ARRAY:
    *omit = ((const lonejson_string_array *)slot)->count == 0;
    break;
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    *omit = ((const lonejson_i64_array *)slot)->count == 0;
    break;
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    *omit = ((const lonejson_u64_array *)slot)->count == 0;
    break;
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    *omit = ((const lonejson_f64_array *)slot)->count == 0;
    break;
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    *omit = ((const lonejson_bool_array *)slot)->count == 0;
    break;
  case LONEJSON_FIELD_KIND_OBJECT_ARRAY:
    *omit = ((const lonejson_object_array *)slot)->count == 0;
    break;
  default:
    break;
  }
  return C89CBOR_OK;
}
int c89_map_count(c89_map_state *state, const lonejson_map *map,
                  const void *record, size_t depth, size_t *count) {
  size_t i;
  int omit, status;
  *count = 0;
  for (i = 0; i < map->field_count; ++i) {
    status = c89_map_omit(state, &map->fields[i], record, depth, &omit);
    if (status != 0)
      return status;
    if (!omit)
      ++*count;
  }
  return C89CBOR_OK;
}
