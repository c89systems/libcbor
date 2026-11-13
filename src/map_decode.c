#define _GNU_SOURCE
#include "map.h"
#include <errno.h>
#include <fenv.h>
#include <string.h>

enum text_mode {
  TEXT_MATERIALIZED,
  TEXT_SPOOLED,
  TEXT_BOUND,
  TEXT_ARRAY_STREAM,
  TEXT_DISCARD
};
static int frame_seen(const c89_map_frame *frame, size_t index) {
  return (frame->seen[index / 8u] & (1u << (index % 8u))) != 0;
}
static void mark_seen(c89_map_frame *frame, size_t index) {
  frame->seen[index / 8u] |= (unsigned char)(1u << (index % 8u));
}
static int callback_result(c89_map_state *state, lonejson_status status) {
  if (status == LONEJSON_STATUS_PAUSED) {
    state->consumer_paused = 1;
    return C89CBOR_OK;
  }
  return c89_map_dependency(state, status);
}
static int complete_value(c89_map_state *state) {
  c89_map_frame *parent;
  if (state->depth == 0) {
    state->complete = 1;
    return C89CBOR_OK;
  }
  parent = &state->frames[state->depth - 1u];
  if (parent->kind == C89_MAP_OBJECT) {
    parent->needs_key = 1;
    parent->field = NULL;
  } else if (parent->kind == C89_MAP_ARRAY) {
    if (parent->index == UINT64_MAX)
      return c89_map_fail(state, C89CBOR_LIMIT, "mapped array index overflow");
    ++parent->index;
  }
  return C89CBOR_OK;
}
static int record_double(c89_map_state *state, const c89cbor_token *token,
                         double *value) {
  uint64_t magnitude;
  double number;
  int status = C89CBOR_OK;
  fenv_t environment;
  if (token->type >= C89CBOR_FLOAT16 && token->type <= C89CBOR_FLOAT64) {
    status = c89_number_double(token, value);
    return status == 0 ? 0
                       : c89_map_fail(state, C89CBOR_SCHEMA,
                                      "mapped double must be finite");
  }
  if (token->type != C89CBOR_UINT && token->type != C89CBOR_NEGATIVE)
    return c89_map_fail(state, C89CBOR_SCHEMA,
                        "expected an integer or finite float");
  if (fegetenv(&environment) != 0)
    return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                        "floating environment is unavailable");
  if (fesetround(FE_TONEAREST) != 0) {
    (void)fesetenv(&environment);
    return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                        "round-to-nearest is unavailable");
  }
  if (token->type == C89CBOR_NEGATIVE && token->argument == UINT64_MAX) {
    number = -18446744073709551616.0;
  } else {
    magnitude = token->type == C89CBOR_NEGATIVE ? token->argument + 1u
                                                : token->argument;
    number = (double)magnitude;
    if (number >= 18446744073709551616.0 || (uint64_t)number != magnitude)
      status = C89CBOR_SCHEMA;
    if (token->type == C89CBOR_NEGATIVE)
      number = -number;
  }
  (void)fesetenv(&environment);
  if (status != 0)
    return c89_map_fail(state, status,
                        "integer cannot be represented exactly as a double");
  *value = number;
  return C89CBOR_OK;
}
static int scalar_value(c89_map_state *state, const c89cbor_token *token,
                        lonejson_field_kind kind, void *slot) {
  lonejson_int64 signed_value;
  lonejson_uint64 unsigned_value;
  double number;
  bool boolean;
  int status;
  if (kind == LONEJSON_FIELD_KIND_I64) {
    if ((token->type != C89CBOR_UINT && token->type != C89CBOR_NEGATIVE) ||
        token->argument > (uint64_t)INT64_MAX)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "expected a signed 64-bit integer");
    signed_value = token->type == C89CBOR_NEGATIVE
                       ? (lonejson_int64)(-1 - (int64_t)token->argument)
                       : (lonejson_int64)token->argument;
    memcpy(slot, &signed_value, sizeof(signed_value));
  } else if (kind == LONEJSON_FIELD_KIND_U64) {
    if (token->type != C89CBOR_UINT)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "expected an unsigned 64-bit integer");
    unsigned_value = (lonejson_uint64)token->argument;
    memcpy(slot, &unsigned_value, sizeof(unsigned_value));
  } else if (kind == LONEJSON_FIELD_KIND_F64) {
    status = record_double(state, token, &number);
    if (status != 0)
      return status;
    memcpy(slot, &number, sizeof(number));
  } else if (kind == LONEJSON_FIELD_KIND_BOOL) {
    if (token->type != C89CBOR_BOOL)
      return c89_map_fail(state, C89CBOR_SCHEMA, "expected a CBOR boolean");
    boolean = token->argument != 0;
    memcpy(slot, &boolean, sizeof(boolean));
  } else {
    return c89_map_fail(state, C89CBOR_SCHEMA, "expected a mapped scalar");
  }
  return C89CBOR_OK;
}
static int match_field(c89_map_state *state, c89_map_frame *object) {
  const lonejson_field *field;
  c89_map_key *unknown;
  size_t i;
  state->error_key = 1;
  for (i = 0; i < object->map->field_count; ++i) {
    field = &object->map->fields[i];
    if (field->json_key_len == state->key_length &&
        memcmp(field->json_key, state->key, state->key_length) == 0) {
      state->error_field = field;
      state->error_key = 0;
      if (frame_seen(object, i))
        return c89_map_fail(state, C89CBOR_SCHEMA, "duplicate mapped key");
      mark_seen(object, i);
      object->field = field;
      object->needs_key = 0;
      return C89CBOR_OK;
    }
  }
  if (!state->options.allow_unknown_fields)
    return c89_map_fail(state, C89CBOR_SCHEMA, "unknown mapped field");
  for (i = object->unknown_start; i < state->unknown_count; ++i) {
    unknown = &state->unknown_keys[i];
    if (unknown->length == state->key_length &&
        memcmp(state->unknown_storage + unknown->offset, state->key,
               state->key_length) == 0)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "duplicate unknown mapped key");
  }
  if (state->unknown_count == state->options.active_keys ||
      state->key_length >
          state->options.active_key_bytes - state->unknown_length)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "unknown key tracking exceeds its budget");
  unknown = &state->unknown_keys[state->unknown_count++];
  unknown->offset = state->unknown_length;
  unknown->length = state->key_length;
  memcpy(state->unknown_storage + state->unknown_length, state->key,
         state->key_length);
  state->unknown_length += state->key_length;
  object->field = NULL;
  object->needs_key = 0;
  return C89CBOR_OK;
}
static int collect_key(c89_map_state *state, const c89cbor_token *token) {
  if (token->length > state->options.key_bytes - state->key_length)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "mapped key exceeds its byte limit");
  memcpy(state->key + state->key_length, token->data, token->length);
  state->key_length += token->length;
  return C89CBOR_OK;
}
static int array_room(const lonejson_field *field, const void *slot) {
#define ROOM(type)                                                             \
  do {                                                                         \
    const type *a = slot;                                                      \
    return (a->flags & LONEJSON_ARRAY_FIXED_CAPACITY) == 0 ||                  \
           a->count < a->capacity;                                             \
  } while (0)
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING_ARRAY:
    ROOM(lonejson_string_array);
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    ROOM(lonejson_i64_array);
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    ROOM(lonejson_u64_array);
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    ROOM(lonejson_f64_array);
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    ROOM(lonejson_bool_array);
  default:
    return 1;
  }
#undef ROOM
}
static int append_scalar(c89_map_state *state, c89_map_frame *array,
                         const c89cbor_token *token) {
  const lonejson_field *field = array->field;
  unsigned char *slot =
      (unsigned char *)array->record.output + field->struct_offset;
  lonejson_int64 signed_value = 0;
  lonejson_uint64 unsigned_value = 0;
  double number = 0;
  bool boolean = 0;
  lonejson_status result;
  int status, store = array_room(field, slot);
  size_t before, after;
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    status = scalar_value(state, token, LONEJSON_FIELD_KIND_I64, &signed_value);
    if (status != 0)
      return status;
    before = ((lonejson_i64_array *)slot)->count;
    status = store ? c89_map_budget(state, sizeof(signed_value), 1) : 0;
    if (status != 0)
      return status;
    result = lonejson_record_array_append_i64(
        state->json, array->map, array->record.output, field,
        (lonejson_i64_array *)slot, signed_value, &state->json_error);
    after = ((lonejson_i64_array *)slot)->count;
    break;
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    status =
        scalar_value(state, token, LONEJSON_FIELD_KIND_U64, &unsigned_value);
    if (status != 0)
      return status;
    before = ((lonejson_u64_array *)slot)->count;
    status = store ? c89_map_budget(state, sizeof(unsigned_value), 1) : 0;
    if (status != 0)
      return status;
    result = lonejson_record_array_append_u64(
        state->json, array->map, array->record.output, field,
        (lonejson_u64_array *)slot, unsigned_value, &state->json_error);
    after = ((lonejson_u64_array *)slot)->count;
    break;
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    status = scalar_value(state, token, LONEJSON_FIELD_KIND_F64, &number);
    if (status != 0)
      return status;
    before = ((lonejson_f64_array *)slot)->count;
    status = store ? c89_map_budget(state, sizeof(number), 1) : 0;
    if (status != 0)
      return status;
    result = lonejson_record_array_append_f64(
        state->json, array->map, array->record.output, field,
        (lonejson_f64_array *)slot, number, &state->json_error);
    after = ((lonejson_f64_array *)slot)->count;
    break;
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    status = scalar_value(state, token, LONEJSON_FIELD_KIND_BOOL, &boolean);
    if (status != 0)
      return status;
    before = ((lonejson_bool_array *)slot)->count;
    status = store ? c89_map_budget(state, sizeof(boolean), 1) : 0;
    if (status != 0)
      return status;
    result = lonejson_record_array_append_bool(
        state->json, array->map, array->record.output, field,
        (lonejson_bool_array *)slot, boolean, &state->json_error);
    after = ((lonejson_bool_array *)slot)->count;
    break;
  default:
    return c89_map_fail(state, C89CBOR_SCHEMA,
                        "array item has the wrong CBOR type");
  }
  if (store && result == LONEJSON_STATUS_OK && after == before &&
      state->json_error.truncated) {
    --state->stored_elements;
    state->stored_bytes -= field->elem_size;
  }
  status = c89_map_dependency(state, result);
  return status == 0 ? complete_value(state) : status;
}
static int start_object(c89_map_state *state, const lonejson_map *map,
                        void *record, size_t parent,
                        const lonejson_field *field, uint64_t index) {
  c89_map_frame *frame;
  int status;
  if (map->field_count > state->max_fields)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "item schema exceeds prepared field workspace");
  status = c89_map_push(state, C89_MAP_OBJECT, parent, field, index);
  if (status != 0)
    return status;
  frame = &state->frames[state->depth - 1u];
  frame->map = map;
  frame->record.output = record;
  return C89CBOR_OK;
}

static int append_string(c89_map_state *state, c89_map_frame *array,
                         const char *data, size_t length) {
  const lonejson_field *field = array->field;
  lonejson_string_array *destination =
      (lonejson_string_array *)((unsigned char *)array->record.output +
                                field->struct_offset);
  size_t before = destination->count;
  int store = array_room(field, destination);
  int status =
      store ? c89_map_budget(state, length + 1u + sizeof(char *), 1) : 0;
  lonejson_status result;
  if (status != 0)
    return status;
  result = lonejson_record_array_append_string(
      state->json, array->map, array->record.output, field, destination, data,
      length, &state->json_error);
  if (store && result == LONEJSON_STATUS_OK && destination->count == before &&
      state->json_error.truncated) {
    --state->stored_elements;
    state->stored_bytes -= length + 1u + sizeof(char *);
  }
  return c89_map_dependency(state, result);
}
static size_t string_limit(c89_map_state *state, const c89_map_frame *frame) {
  const lonejson_field *field = frame->field;
  size_t limit = state->options.field_bytes;
  if (field->kind == LONEJSON_FIELD_KIND_STRING &&
      field->storage == LONEJSON_STORAGE_FIXED &&
      field->fixed_capacity - 1u < limit)
    limit = field->fixed_capacity - 1u;
  return limit;
}
static size_t complete_utf8_prefix(const unsigned char *data, size_t length) {
  size_t begin = length, needed;
  unsigned char byte;
  if (length == 0)
    return 0;
  do {
    --begin;
  } while (begin != 0 && (data[begin] & 0xc0u) == 0x80u);
  byte = data[begin];
  needed = byte >= 0xf0u ? 4u : byte >= 0xe0u ? 3u : byte >= 0xc0u ? 2u : 1u;
  return length - begin < needed ? begin : length;
}
static int collect_text(c89_map_state *state, c89_map_frame *frame,
                        const c89cbor_token *token) {
  size_t limit = string_limit(state, frame), take = token->length;
  int may_truncate =
      frame->field->kind == LONEJSON_FIELD_KIND_STRING &&
      frame->field->storage == LONEJSON_STORAGE_FIXED &&
      frame->field->overflow_policy != LONEJSON_OVERFLOW_FAIL &&
      frame->field->fixed_capacity - 1u <= state->options.field_bytes;
  if (memchr(token->data, 0, token->length) != NULL)
    return c89_map_fail(state, C89CBOR_SCHEMA,
                        "C string cannot contain an embedded NUL");
  if (token->length > UINT64_MAX - frame->text_seen)
    return c89_map_fail(state, C89CBOR_LIMIT, "mapped string length overflow");
  frame->text_seen += (uint64_t)token->length;
  if (!may_truncate && frame->text_seen > (uint64_t)limit)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "mapped string exceeds its storage limit");
  if (take > limit - frame->materialized) {
    take = limit - frame->materialized;
    frame->truncated = 1;
  }
  if (!frame->indefinite && frame->text_seen == frame->expected &&
      frame->materialized == 0 && token->length == frame->expected) {
    frame->borrowed = token->data;
    frame->materialized = take;
    return C89CBOR_OK;
  }
  if (take != 0) {
    if (state->scratch == NULL) {
      state->scratch = c89_map_allocate(state, state->options.field_bytes, 1);
      if (state->scratch == NULL)
        return state->owner->lifetime.error.status;
      state->scratch_capacity = state->options.field_bytes;
    }
    memcpy(state->scratch + frame->materialized, token->data, take);
    frame->materialized += take;
  }
  return C89CBOR_OK;
}
static int start_text(c89_map_state *state, const c89cbor_token *token,
                      c89_map_frame *parent) {
  const lonejson_field *field = parent->field;
  c89_map_frame *frame;
  lonejson_string_array_stream *stream;
  size_t parent_index = state->depth - 1u;
  int status;
  if (state->pending_phase == 0) {
    status = c89_map_push(state, C89_MAP_TEXT, parent_index,
                          parent->kind == C89_MAP_OBJECT ? field : NULL,
                          parent->index);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->field = field;
    frame->map = parent->map;
    frame->record.output = parent->record.output;
    frame->target = token->type;
    frame->expected = token->argument;
    frame->indefinite = token->indefinite;
    frame->binding = c89_map_binding(state, state->depth - 1u);
    if (frame->binding != NULL) {
      if (frame->binding->payload != (token->type == C89CBOR_BYTES
                                          ? C89CBOR_PAYLOAD_BYTES
                                          : C89CBOR_PAYLOAD_TEXT))
        return c89_map_fail(state, C89CBOR_SCHEMA,
                            "field sink has the wrong payload representation");
      frame->phase = TEXT_BOUND;
    } else if (field->kind == LONEJSON_FIELD_KIND_STRING_STREAM ||
               field->kind == LONEJSON_FIELD_KIND_BASE64_STREAM) {
      frame->phase = TEXT_SPOOLED;
    } else if (field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY_STREAM) {
      frame->phase = TEXT_ARRAY_STREAM;
    } else if (field->kind == LONEJSON_FIELD_KIND_STRING_SOURCE ||
               field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE) {
      return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                          "inbound source field requires a field sink");
    } else {
      frame->phase = TEXT_MATERIALIZED;
      if (!token->indefinite &&
          token->argument > (uint64_t)string_limit(state, frame) &&
          !(field->kind == LONEJSON_FIELD_KIND_STRING &&
            field->storage == LONEJSON_STORAGE_FIXED &&
            field->overflow_policy != LONEJSON_OVERFLOW_FAIL &&
            field->fixed_capacity - 1u <= state->options.field_bytes))
        return c89_map_fail(state, C89CBOR_LIMIT,
                            "mapped string exceeds its storage limit");
    }
    state->pending_phase = 1;
  }
  frame = &state->frames[state->depth - 1u];
  if (frame->phase == TEXT_BOUND && frame->binding->begin != NULL) {
    status = frame->binding->begin(frame->binding->sink.context, token);
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "field sink rejected value begin");
  } else if (frame->phase == TEXT_ARRAY_STREAM) {
    stream =
        (lonejson_string_array_stream *)((unsigned char *)frame->record.output +
                                         field->struct_offset);
    if (stream->handler.chunk == NULL)
      return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                          "string array stream has no chunk handler");
    if (stream->handler.begin != NULL) {
      status = callback_result(
          state, stream->handler.begin(stream->user, &state->json_error));
      if (status != 0)
        return status;
    }
  }
  state->pending_phase = 0;
  state->pending_valid = 0;
  return C89CBOR_OK;
}
static int text_data(c89_map_state *state, c89_map_frame *frame,
                     const c89cbor_token *token) {
  lonejson_spooled *spool;
  lonejson_string_array_stream *stream;
  const unsigned char *bytes = token->data;
  size_t length = token->length - state->pending_offset, consumed = 0;
  int status;
  if (frame->phase == TEXT_BOUND) {
    if (length > state->options.step_output - state->step_written)
      length = state->options.step_output - state->step_written;
    status = frame->binding->sink.write(frame->binding->sink.context,
                                        bytes + state->pending_offset, length,
                                        &consumed);
    if (consumed > length)
      return c89_map_fail(state, C89CBOR_IO,
                          "field sink exceeded offered payload");
    state->pending_offset += consumed;
    state->step_written += consumed;
    state->owner->lifetime.progress.output += (uint64_t)consumed;
    if (state->pending_offset == token->length)
      state->pending_valid = 0;
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0 || consumed == 0)
      return c89_map_fail(state, C89CBOR_IO,
                          "field sink rejected payload bytes");
    return C89CBOR_OK;
  }
  if (frame->phase == TEXT_SPOOLED) {
    spool = (lonejson_spooled *)((unsigned char *)frame->record.output +
                                 frame->field->struct_offset);
    status = c89_map_dependency(
        state, lonejson_spooled_append(spool, bytes, token->length,
                                       &state->json_error));
  } else if (frame->phase == TEXT_ARRAY_STREAM) {
    stream =
        (lonejson_string_array_stream *)((unsigned char *)frame->record.output +
                                         frame->field->struct_offset);
    status = callback_result(
        state, stream->handler.chunk(stream->user, (const char *)bytes,
                                     token->length, &state->json_error));
    if (status == 0)
      state->owner->lifetime.progress.output += (uint64_t)token->length;
  } else {
    status = collect_text(state, frame, token);
  }
  if (status == 0)
    state->pending_valid = 0;
  return status;
}
static int finish_text(c89_map_state *state, c89_map_frame *frame) {
  c89_map_frame *parent = &state->frames[frame->parent];
  const lonejson_field *field = frame->field;
  const char *text =
      frame->borrowed == NULL ? (const char *)state->scratch : frame->borrowed;
  lonejson_string_array_stream *stream;
  size_t length = frame->materialized;
  int status = C89CBOR_OK;
  if (frame->phase == TEXT_BOUND && frame->binding->end != NULL) {
    status = frame->binding->end(frame->binding->sink.context);
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "field sink rejected value end");
  } else if (frame->phase == TEXT_ARRAY_STREAM) {
    stream =
        (lonejson_string_array_stream *)((unsigned char *)frame->record.output +
                                         field->struct_offset);
    if (stream->handler.end != NULL)
      status = callback_result(
          state, stream->handler.end(stream->user, &state->json_error));
  } else if (frame->phase == TEXT_MATERIALIZED) {
    if (text == NULL)
      text = "";
    if (frame->truncated)
      length = complete_utf8_prefix((const unsigned char *)text, length);
    if (parent->kind == C89_MAP_ARRAY) {
      status = append_string(state, parent, text, length);
    } else {
      status = c89_map_budget(state,
                              field->storage == LONEJSON_STORAGE_FIXED &&
                                      length >= field->fixed_capacity
                                  ? field->fixed_capacity
                                  : length + 1u,
                              0);
      if (status == 0)
        status = c89_map_dependency(
            state, lonejson_record_assign_string(
                       state->json, frame->map, frame->record.output, field,
                       text, length, &state->json_error));
    }
    if (status == 0 && frame->truncated) {
      state->owner->lifetime.error.truncated = 1;
      if (field->overflow_policy == LONEJSON_OVERFLOW_TRUNCATE) {
        status =
            c89_map_fail(state, C89CBOR_LIMIT, "fixed string was truncated");
        state->owner->lifetime.error.cause = LONEJSON_STATUS_TRUNCATED;
      }
    }
  }
  if (status != 0)
    return status;
  --state->depth;
  state->pending_valid = 0;
  return complete_value(state);
}

static int mark_presence(c89_map_frame *frame) {
  lonejson_field_set_presence(frame->record.output, frame->field, 1);
  return C89CBOR_OK;
}
static int finish_object(c89_map_state *state, c89_map_frame *frame) {
  lonejson_mapped_array_stream *stream;
  c89_map_frame *array;
  size_t i;
  int status;
  for (i = 0; i < frame->map->field_count; ++i) {
    if ((frame->map->fields[i].flags & LONEJSON_FIELD_REQUIRED) != 0 &&
        !frame_seen(frame, i)) {
      state->error_field = &frame->map->fields[i];
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "required mapped field is missing");
    }
  }
  if (frame->streaming) {
    array = &state->frames[frame->parent];
    stream =
        (lonejson_mapped_array_stream *)((unsigned char *)array->record.output +
                                         array->field->struct_offset);
    status = callback_result(state, stream->handler.item(stream->handler.user,
                                                         frame->record.output,
                                                         &state->json_error));
    if (status != 0)
      return status;
    status = c89_map_dependency(state, lonejson_reset(state->json, frame->map,
                                                      frame->record.output,
                                                      &state->json_error));
    if (status != 0)
      return status;
    state->stored_bytes = frame->saved_bytes;
    state->stored_elements = frame->saved_elements;
  }
  state->unknown_count = frame->unknown_start;
  state->unknown_length = frame->unknown_bytes;
  --state->depth;
  state->pending_valid = 0;
  return complete_value(state);
}
static int start_array_object(c89_map_state *state, c89_map_frame *array) {
  const lonejson_field *field = array->field;
  lonejson_object_array *destination;
  lonejson_mapped_array_stream *stream;
  const lonejson_map *map = field->submap;
  void *record;
  c89_map_frame *child;
  size_t parent = state->depth - 1u, i, saved_bytes = state->stored_bytes;
  size_t saved_elements = state->stored_elements;
  int status;
  if (field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM) {
    stream =
        (lonejson_mapped_array_stream *)((unsigned char *)array->record.output +
                                         field->struct_offset);
    map = stream->handler.item_map;
    record = stream->handler.item_dst;
    if (map == NULL || record == NULL || stream->handler.item == NULL)
      return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                          "mapped array stream requires an item handler");
    for (i = 0; i < state->depth; ++i) {
      if (state->frames[i].record.output == record)
        return c89_map_fail(state, C89CBOR_INVALID,
                            "stream item aliases an active record");
    }
    status = c89_map_dependency(
        state, lonejson_reset(state->json, map, record, &state->json_error));
    if (status != 0)
      return status;
  } else {
    destination =
        (lonejson_object_array *)((unsigned char *)array->record.output +
                                  field->struct_offset);
    if ((destination->flags & LONEJSON_ARRAY_FIXED_CAPACITY) != 0 &&
        destination->count == destination->capacity &&
        field->overflow_policy != LONEJSON_OVERFLOW_FAIL) {
      record = lonejson_record_object_array_append_slot(
          state->json, array->map, array->record.output, field, destination,
          &state->json_error);
      (void)record;
      status = c89_map_dependency(state, state->json_error.code);
      if (status != 0)
        return status;
      state->skip_depth = 1;
      state->pending_valid = 0;
      return C89CBOR_OK;
    }
    status = c89_map_budget(state, field->elem_size, 1);
    if (status != 0)
      return status;
    record = lonejson_record_object_array_append_slot(
        state->json, array->map, array->record.output, field, destination,
        &state->json_error);
    if (record == NULL)
      return c89_map_dependency(state, state->json_error.code);
    status = c89_map_dependency(
        state, lonejson_init(state->json, map, record, &state->json_error));
    if (status != 0) {
      --destination->count;
      return status;
    }
  }
  status = start_object(state, map, record, parent, NULL, array->index);
  if (status != 0)
    return status;
  child = &state->frames[state->depth - 1u];
  child->streaming = field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM;
  child->saved_bytes = saved_bytes;
  child->saved_elements = saved_elements;
  state->pending_valid = 0;
  return C89CBOR_OK;
}
static int json_sink(void *context, const void *bytes, size_t length,
                     size_t *count) {
  c89_map_state *state = context;
  c89_map_frame *frame = &state->frames[state->depth - 1u];
  lonejson_json_value *value =
      (lonejson_json_value *)((unsigned char *)frame->record.output +
                              frame->field->struct_offset);
  int status;
  *count = 0;
  if (frame->binding != NULL) {
    status = frame->binding->sink.write(frame->binding->sink.context, bytes,
                                        length, count);
    if (*count <= length)
      state->owner->lifetime.progress.output += (uint64_t)*count;
    return status;
  }
  if (value->parse_mode == LONEJSON_JSON_VALUE_PARSE_SINK) {
    status =
        callback_result(state, value->parse_sink(value->parse_sink_user, bytes,
                                                 length, &state->json_error));
    if (status != 0)
      return status;
    *count = length;
    state->owner->lifetime.progress.output += (uint64_t)length;
    return state->consumer_paused ? C89CBOR_OUTPUT : C89CBOR_OK;
  }
  if (length > state->options.field_bytes - state->scratch_length)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "captured JSON exceeds its field limit");
  if (state->scratch == NULL) {
    state->scratch = c89_map_allocate(state, state->options.field_bytes, 1);
    if (state->scratch == NULL)
      return C89CBOR_NOMEM;
    state->scratch_capacity = state->options.field_bytes;
  }
  memcpy(state->scratch + state->scratch_length, bytes, length);
  state->scratch_length += length;
  *count = length;
  return C89CBOR_OK;
}
static int start_json(c89_map_state *state, c89_map_frame *parent) {
  c89_map_frame *frame;
  lonejson_json_value *value;
  c89cbor_sink sink;
  c89cbor_error error;
  size_t parent_index = state->depth - 1u;
  int status;
  if (state->pending_phase == 0) {
    status = c89_map_push(state, C89_MAP_JSON, parent_index, parent->field, 0);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->record.output = parent->record.output;
    frame->map = parent->map;
    frame->binding = c89_map_binding(state, state->depth - 1u);
    value = (lonejson_json_value *)((unsigned char *)frame->record.output +
                                    frame->field->struct_offset);
    if (frame->binding != NULL) {
      if (frame->binding->payload != C89CBOR_PAYLOAD_JSON)
        return c89_map_fail(state, C89CBOR_SCHEMA,
                            "JSON field sink requires JSON representation");
    } else if (value->parse_mode == LONEJSON_JSON_VALUE_PARSE_NONE &&
               state->pending.type == C89CBOR_NULL) {
      status = c89_map_dependency(
          state, lonejson_record_assign_null(
                     state->json, parent->map, parent->record.output,
                     parent->field, &state->json_error));
      if (status != 0)
        return status;
      --state->depth;
      state->pending_valid = 0;
      return complete_value(state);
    } else if (value->parse_mode == LONEJSON_JSON_VALUE_PARSE_VISITOR ||
               value->parse_mode == LONEJSON_JSON_VALUE_PARSE_PATH_VISITOR ||
               (value->parse_mode != LONEJSON_JSON_VALUE_PARSE_CAPTURE &&
                value->parse_mode != LONEJSON_JSON_VALUE_PARSE_SINK &&
                !(frame->field->flags &
                  LONEJSON_FIELD_JSON_VALUE_DEFAULT_CAPTURE))) {
      return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                          "JSON field requires a sink or explicit capture");
    }
    if (value->parse_mode == LONEJSON_JSON_VALUE_PARSE_SINK &&
        value->parse_sink == NULL)
      return c89_map_fail(state, C89CBOR_INVALID, "JSON field sink is missing");
    state->pending_phase = 1;
  }
  frame = &state->frames[state->depth - 1u];
  if (frame->binding != NULL && frame->binding->begin != NULL) {
    status =
        frame->binding->begin(frame->binding->sink.context, &state->pending);
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "JSON field begin failed");
  }
  status = c89_map_json_runtime(state);
  if (status != 0)
    return status;
  sink.context = state;
  sink.write = json_sink;
  status = c89_json_decode_init(&state->bridge_runtime, &state->bridge, &sink,
                                &state->options, &error);
  if (status != 0)
    return c89_map_bridge_status(state, status, &error);
  state->scratch_length = 0;
  state->bridge_ready = 1;
  state->pending_phase = 0;
  return C89CBOR_OK;
}
static int drive_json(c89_map_state *state) {
  c89_map_frame *frame = &state->frames[state->depth - 1u];
  lonejson_json_value *value =
      (lonejson_json_value *)((unsigned char *)frame->record.output +
                              frame->field->struct_offset);
  c89cbor_error error;
  int status;
  if (!state->bridge_started) {
    status = state->bridge.step(&state->bridge, &error);
    if (status < 0)
      return c89_map_bridge_status(state, status, &error);
    if (status == C89CBOR_DONE)
      state->bridge_started = 1;
    else if (status == C89CBOR_INPUT)
      return C89CBOR_INPUT;
    else
      return status == C89CBOR_OUTPUT || state->consumer_paused ? C89CBOR_OUTPUT
                                                                : C89CBOR_OK;
  }
  if (frame->binding != NULL && frame->binding->end != NULL) {
    status = frame->binding->end(frame->binding->sink.context);
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "JSON field end failed");
  }
  if (frame->binding == NULL &&
      value->parse_mode != LONEJSON_JSON_VALUE_PARSE_SINK) {
    status = c89_map_budget(state, state->scratch_length + 1u, 0);
    if (status != 0)
      return status;
    status = c89_map_dependency(state,
                                lonejson_json_value_set_buffer(
                                    value, (const char *)state->scratch,
                                    state->scratch_length, &state->json_error));
    if (status != 0)
      return status;
  }
  lonejson_field_set_presence(frame->record.output, frame->field, 1);
  (void)state->bridge.cleanup(&state->bridge);
  state->bridge_ready = state->bridge_started = 0;
  --state->depth;
  return complete_value(state);
}
static int null_value(c89_map_state *state, c89_map_frame *parent) {
  c89_map_frame *frame;
  const lonejson_field *field = parent->field;
  c89cbor_payload payload;
  size_t index = state->depth - 1u;
  int status;
  if (state->pending_phase == 0) {
    status = c89_map_dependency(
        state, lonejson_record_assign_null(state->json, parent->map,
                                           parent->record.output, field,
                                           &state->json_error));
    if (status != 0)
      return status;
    if (state->options.field_sink_count == 0 ||
        field->kind > LONEJSON_FIELD_KIND_BASE64_SOURCE) {
      state->pending_valid = 0;
      return complete_value(state);
    }
    status = c89_map_push(state, C89_MAP_NULL, index, field, 0);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->binding = c89_map_binding(state, state->depth - 1u);
    if (frame->binding == NULL) {
      --state->depth;
      state->pending_valid = 0;
      return complete_value(state);
    }
    payload = field->kind == LONEJSON_FIELD_KIND_BASE64_STREAM ||
                      field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE
                  ? C89CBOR_PAYLOAD_BYTES
                  : C89CBOR_PAYLOAD_TEXT;
    if (frame->binding->payload != payload)
      return c89_map_fail(
          state, C89CBOR_SCHEMA,
          "null field sink has the wrong payload representation");
    state->pending_phase = 1;
  }
  frame = &state->frames[state->depth - 1u];
  if (frame->phase == 0) {
    if (frame->binding->begin != NULL) {
      status =
          frame->binding->begin(frame->binding->sink.context, &state->pending);
      if (status == C89CBOR_OUTPUT)
        return status;
      if (status != 0)
        return c89_map_fail(state, C89CBOR_IO,
                            "field sink rejected null begin");
    }
    frame->phase = 1;
  }
  if (frame->binding->end != NULL) {
    status = frame->binding->end(frame->binding->sink.context);
    if (status == C89CBOR_OUTPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "field sink rejected null end");
  }
  --state->depth;
  state->pending_phase = state->pending_valid = 0;
  return complete_value(state);
}
static int typed_value(c89_map_state *state, c89_map_frame *parent) {
  const c89cbor_token *token = &state->pending;
  const lonejson_field *field = parent->field;
  unsigned char *slot =
      (unsigned char *)parent->record.output + field->struct_offset;
  c89_map_frame *frame;
  size_t parent_index = state->depth - 1u;
  int status, bytes;
  if (parent->kind == C89_MAP_OBJECT &&
      field->kind == LONEJSON_FIELD_KIND_JSON_VALUE)
    return start_json(state, parent);
  if (parent->kind == C89_MAP_ARRAY) {
    if (field->kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY ||
        field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM) {
      if (token->type != C89CBOR_MAP)
        return c89_map_fail(state, C89CBOR_SCHEMA,
                            "expected an object array item");
      return start_array_object(state, parent);
    }
    if (field->kind != LONEJSON_FIELD_KIND_STRING_ARRAY &&
        field->kind != LONEJSON_FIELD_KIND_STRING_ARRAY_STREAM) {
      status = append_scalar(state, parent, token);
      if (status == 0)
        state->pending_valid = 0;
      return status;
    }
    if (token->type == C89CBOR_NULL &&
        field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY) {
      status = append_string(state, parent, "", 0);
      if (status != 0)
        return status;
      state->pending_valid = 0;
      return complete_value(state);
    }
    if (token->type != C89CBOR_TEXT)
      return c89_map_fail(state, C89CBOR_SCHEMA, "expected a text array item");
    return start_text(state, token, parent);
  }
  if (token->type == C89CBOR_NULL)
    return null_value(state, parent);
  if (field->kind >= LONEJSON_FIELD_KIND_I64 &&
      field->kind <= LONEJSON_FIELD_KIND_BOOL) {
    status = scalar_value(state, token, field->kind, slot);
    if (status != 0)
      return status;
    (void)mark_presence(parent);
    state->pending_valid = 0;
    return complete_value(state);
  }
  if (field->kind == LONEJSON_FIELD_KIND_OBJECT) {
    if (token->type != C89CBOR_MAP)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "expected an inline mapped object");
    (void)mark_presence(parent);
    status = start_object(state, field->submap, slot, parent_index, field, 0);
    if (status == 0)
      state->pending_valid = 0;
    return status;
  }
  if (field->kind >= LONEJSON_FIELD_KIND_STRING_ARRAY &&
      field->kind <= LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM) {
    if (token->type != C89CBOR_ARRAY)
      return c89_map_fail(state, C89CBOR_SCHEMA, "expected a mapped array");
    (void)mark_presence(parent);
    status = c89_map_push(state, C89_MAP_ARRAY, parent_index, field, 0);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->map = parent->map;
    frame->record.output = parent->record.output;
    state->pending_valid = 0;
    return C89CBOR_OK;
  }
  bytes = field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE ||
          field->kind == LONEJSON_FIELD_KIND_BASE64_STREAM;
  if (token->type != (bytes ? C89CBOR_BYTES : C89CBOR_TEXT))
    return c89_map_fail(state, C89CBOR_SCHEMA,
                        "field has the wrong CBOR string representation");
  (void)mark_presence(parent);
  return start_text(state, token, parent);
}
static int dispatch_token(c89_map_state *state) {
  const c89cbor_token *token = &state->pending;
  c89cbor_error error;
  c89_map_frame *frame, *target;
  size_t parent;
  int status;
  if (state->skip_depth != 0) {
    if (token->type == C89CBOR_END)
      --state->skip_depth;
    else if (token->type >= C89CBOR_BYTES && token->type <= C89CBOR_TAG)
      ++state->skip_depth;
    state->pending_valid = 0;
    return state->skip_depth == 0 ? complete_value(state) : C89CBOR_OK;
  }
  if (state->depth == 0) {
    if (state->complete || token->type != C89CBOR_MAP)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "expected exactly one mapped object");
    status = start_object(state, state->map, state->record.output, (size_t)-1,
                          NULL, 0);
    if (status == 0)
      state->pending_valid = 0;
    return status;
  }
  frame = &state->frames[state->depth - 1u];
  state->error_frame = state->depth - 1u;
  state->error_field = NULL;
  state->error_key = 0;
  if (state->pending_phase != 0) {
    target = &state->frames[frame->parent];
    if (frame->kind == C89_MAP_NULL)
      return null_value(state, target);
    return frame->kind == C89_MAP_JSON ? start_json(state, target)
                                       : start_text(state, token, target);
  }
  if (frame->kind == C89_MAP_JSON) {
    status = c89_json_decode_put(&state->bridge, token, &error);
    if (status == 0)
      state->pending_valid = 0;
    return c89_map_bridge_status(state, status, &error);
  }
  if (frame->kind == C89_MAP_KEY || frame->kind == C89_MAP_TEXT ||
      frame->kind == C89_MAP_CHUNK) {
    target =
        frame->kind == C89_MAP_CHUNK ? &state->frames[frame->target] : frame;
    if (token->type == C89CBOR_DATA) {
      if (target->kind == C89_MAP_KEY) {
        status = collect_key(state, token);
        if (status == 0)
          state->pending_valid = 0;
        return status;
      }
      return text_data(state, target, token);
    }
    if (token->type == C89CBOR_END) {
      if (frame->kind == C89_MAP_CHUNK) {
        --state->depth;
        state->pending_valid = 0;
        return C89CBOR_OK;
      }
      if (frame->kind == C89_MAP_TEXT)
        return finish_text(state, frame);
      parent = frame->parent;
      --state->depth;
      state->error_frame = parent;
      status = match_field(state, &state->frames[parent]);
      if (status == 0)
        state->pending_valid = 0;
      return status;
    }
    if (token->type == C89CBOR_TEXT || token->type == C89CBOR_BYTES) {
      parent = state->depth - 1u;
      status = c89_map_push(state, C89_MAP_CHUNK, parent, NULL, 0);
      if (status != 0)
        return status;
      state->frames[state->depth - 1u].path_kind = C89_PATH_ROOT;
      state->frames[state->depth - 1u].target = parent;
      state->pending_valid = 0;
      return C89CBOR_OK;
    }
    return c89_map_fail(state, C89CBOR_SCHEMA, "invalid string event");
  }
  if (token->type == C89CBOR_END) {
    if (frame->kind == C89_MAP_OBJECT)
      return finish_object(state, frame);
    --state->depth;
    state->pending_valid = 0;
    return complete_value(state);
  }
  if (frame->kind == C89_MAP_OBJECT && frame->needs_key) {
    if (token->type != C89CBOR_TEXT)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "mapped object key must be text");
    parent = state->depth - 1u;
    status = c89_map_push(state, C89_MAP_KEY, parent, NULL, 0);
    if (status != 0)
      return status;
    state->frames[state->depth - 1u].path_kind = C89_PATH_ROOT;
    state->key_length = 0;
    state->pending_valid = 0;
    return C89CBOR_OK;
  }
  if (frame->kind == C89_MAP_OBJECT && frame->field == NULL) {
    state->skip_depth =
        token->type >= C89CBOR_BYTES && token->type <= C89CBOR_TAG ? 1u : 0u;
    state->pending_valid = 0;
    return state->skip_depth == 0 ? complete_value(state) : C89CBOR_OK;
  }
  state->error_field = frame->kind == C89_MAP_OBJECT ? frame->field : NULL;
  return typed_value(state, frame);
}
int c89_map_decode_step(void *context) {
  c89_map_state *state = context;
  size_t events = 0, consumed, count, capacity;
  int status;
  if (state->done)
    return C89CBOR_DONE;
  state->read_attempted = 0;
  state->consumer_paused = 0;
  state->step_written = 0;
  while (events < state->options.step_events) {
    if (state->bridge_ready) {
      status = drive_json(state);
      if (status != C89CBOR_INPUT) {
        if (status != 0 || state->consumer_paused)
          return state->consumer_paused && status >= 0 ? C89CBOR_OUTPUT
                                                       : status;
        if (state->bridge_ready)
          return C89CBOR_OK;
        ++events;
        continue;
      }
    }
    if (state->pending_valid) {
      status = dispatch_token(state);
      ++events;
      if (status != 0 || state->consumer_paused)
        return state->consumer_paused && status >= 0 ? C89CBOR_OUTPUT : status;
      if (state->step_written == state->options.step_output)
        return C89CBOR_OK;
      continue;
    }
    status = state->decoder.next(
        &state->decoder, state->input + state->input_offset,
        state->input_length - state->input_offset, &consumed, &state->pending);
    state->input_offset += consumed;
    if (status < 0)
      return c89_map_fail(state, status, "invalid CBOR mapped input");
    if (status == C89CBOR_TOKEN) {
      state->pending_valid = 1;
      state->pending_offset = 0;
      continue;
    }
    if (status == C89CBOR_DONE && state->input_offset != state->input_length)
      return c89_map_fail(state, C89CBOR_MALFORMED,
                          "trailing bytes after mapped record");
    if (state->eof) {
      status = state->decoder.finish(&state->decoder);
      if (status != 0)
        return c89_map_fail(state, status, "incomplete CBOR mapped input");
      if (!state->complete)
        return c89_map_fail(state, C89CBOR_SCHEMA, "incomplete mapped record");
      state->done = 1;
      state->owner->lifetime.progress.records = 1;
      return C89CBOR_DONE;
    }
    if (state->read_attempted)
      return C89CBOR_OK;
    capacity = state->options.chunk < state->options.step_input
                   ? state->options.chunk
                   : state->options.step_input;
    state->read_attempted = 1;
    count = 0;
    status = state->source.read(state->source.context, state->input, capacity,
                                &count);
    if (count <= capacity)
      state->owner->lifetime.progress.input += (uint64_t)count;
    if (count > capacity ||
        (status != C89CBOR_OK && (status != C89CBOR_INPUT || count != 0)))
      return c89_map_fail(state, C89CBOR_IO, "mapped source read failed");
    state->input_offset = 0;
    state->input_length = count;
    if (count == 0 && status == C89CBOR_INPUT)
      return status;
    if (count == 0)
      state->eof = 1;
  }
  return C89CBOR_OK;
}
