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
  size_t i, mask;
  const lonejson_field *field;
  if (remaining == 0)
    return 0;
  for (i = 0; i < map->field_count; ++i) {
    field = &map->fields[i];
    /* All supported ABIs use power-of-two native member alignments. */
    mask = field_alignment(field) - 1u;
    if ((((base & mask) + (field->struct_offset & mask)) & mask) != 0 ||
        (stride & mask) != 0)
      return 0;
    if (field->kind == LONEJSON_FIELD_KIND_OBJECT &&
        !layout_alignment(field->submap, base + field->struct_offset, stride,
                          remaining - 1u))
      return 0;
  }
  return 1;
}
static int validate_key(const lonejson_field *field) {
  c89cbor_frame frame;
  const unsigned char *key = (const unsigned char *)field->json_key;
  size_t i;
  for (i = 0; i < field->json_key_len; ++i) {
    if (key[i] == 0)
      return C89CBOR_MALFORMED;
    if (key[i] >= 128u) {
      if (strlen(field->json_key) != field->json_key_len)
        return C89CBOR_MALFORMED;
      memset(&frame, 0, sizeof(frame));
      return c89_utf8(&frame, key, field->json_key_len) && frame.utf8 == 0
                 ? C89CBOR_OK
                 : C89CBOR_MALFORMED;
    }
  }
  return key[i] == 0 ? C89CBOR_OK : C89CBOR_MALFORMED;
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
    if (depth == 0 && (field->flags & LONEJSON_FIELD_REQUIRED) == 0)
      state->root_required = 0;
    if (field->json_key == NULL ||
        field->json_key_len > state->options.key_bytes ||
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
        (field->struct_offset & (alignment - 1u)) != 0 ||
        (field->flags & ~allowed) != 0 ||
        field->storage < LONEJSON_STORAGE_DYNAMIC ||
        field->storage > LONEJSON_STORAGE_FIXED ||
        field->overflow_policy < LONEJSON_OVERFLOW_FAIL ||
        field->overflow_policy > LONEJSON_OVERFLOW_TRUNCATE_SILENT)
      return c89_map_fail(state, C89CBOR_INVALID,
                          "invalid mapped field layout");
    if (record != NULL &&
        (((uintptr_t)record + field->struct_offset) & (alignment - 1u)) != 0)
      return c89_map_fail(state, C89CBOR_INVALID,
                          "misaligned mapped record storage");
    if ((field->flags & LONEJSON_FIELD_HAS_PRESENCE) != 0 &&
        (field->presence_offset > map->struct_size ||
         sizeof(int) > map->struct_size - field->presence_offset ||
         (field->presence_offset & (offsetof(bool_alignment, value) - 1u)) !=
             0))
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
/* Lonejson singleton identity and generation cookies mark immutable schemas.
 * Retain only identity numbers and layout facts, never schema/record pointers.
 * An owned schema's next generation invalidates a recycled address. Cache leaf
 * layouts only: submaps and record-supplied handlers still traverse on every
 * construction. Plain descriptor copies never match self identity. */
typedef struct schema_cache_entry {
  uintptr_t identity, fields;
  lonejson_uint64 cookie;
  size_t struct_size, field_count, depth, key_bytes, alignment;
  int known, root_required;
} schema_cache_entry;
static schema_cache_entry *schema_slot(const lonejson_map *map) {
#if defined(__GNUC__) || defined(__clang__)
  static __thread schema_cache_entry cache[16];
  schema_cache_entry *entry;
  uintptr_t bits;
  if (map == NULL || map->_map_identity != map)
    return NULL;
  bits = (uintptr_t)map;
  entry = &cache[((bits >> 4u) ^ (bits >> 9u)) & 15u];
  if (entry->identity != bits || entry->cookie != map->_map_cookie ||
      entry->fields != (uintptr_t)map->fields ||
      entry->struct_size != map->struct_size ||
      entry->field_count != map->field_count) {
    entry->identity = bits;
    entry->cookie = map->_map_cookie;
    entry->fields = (uintptr_t)map->fields;
    entry->struct_size = map->struct_size;
    entry->field_count = map->field_count;
    entry->known = 0;
  }
  return entry;
#else
  (void)map;
  return NULL;
#endif
}
int c89_map_schema(c89_map_state *state, const lonejson_map *map, size_t extent,
                   size_t depth) {
  const void *record =
      state->encode ? state->record.input : state->record.output;
  schema_cache_entry *entry = depth == 0 ? schema_slot(map) : NULL;
  size_t i, alignment;
  int status;
  if (entry != NULL && entry->known == 1 &&
      entry->depth == state->options.depth &&
      entry->key_bytes == state->options.key_bytes &&
      extent >= map->struct_size &&
      ((uintptr_t)record & (entry->alignment - 1u)) == 0) {
    state->max_fields = map->field_count;
    state->root_required = entry->root_required;
    return C89CBOR_OK;
  }
  state->root_required = 1;
  status = validate_map(state, map, record, extent, depth);
  if (status != 0 || entry == NULL || entry->known == -1)
    return status;
  alignment = 1;
  for (i = 0; i < map->field_count; ++i) {
    const lonejson_field *field = &map->fields[i];
    size_t member_alignment = field_alignment(field);
    if (field->kind == LONEJSON_FIELD_KIND_OBJECT ||
        field->kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY ||
        field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM) {
      entry->known = -1;
      return C89CBOR_OK;
    }
    if (alignment < member_alignment)
      alignment = member_alignment;
  }
  entry->alignment = alignment;
  entry->root_required = state->root_required;
  entry->depth = state->options.depth;
  entry->key_bytes = state->options.key_bytes;
  entry->known = 1;
  return C89CBOR_OK;
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
  if ((field->flags & LONEJSON_FIELD_HAS_PRESENCE) != 0) {
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
  if (map == state->map && state->root_required) {
    *count = map->field_count;
    return C89CBOR_OK;
  }
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
