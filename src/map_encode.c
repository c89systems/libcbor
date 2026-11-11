#define _GNU_SOURCE
#include "map.h"
#include <errno.h>
#include <string.h>

/* Every generated token is accepted once, then drained before its source is
 * reused. Small spans share a bounded output chunk; large DATA spans borrow
 * the record or input fragment directly. */
enum encode_phase {
  ENCODE_BEGIN,
  ENCODE_NEXT,
  ENCODE_KEY_DATA,
  ENCODE_KEY_END,
  ENCODE_VALUE,
  ENCODE_READ,
  ENCODE_CHUNK,
  ENCODE_DATA,
  ENCODE_CHUNK_END,
  ENCODE_END
};
static void token_init(c89cbor_token *token, c89cbor_type type,
                       uint64_t argument) {
  memset(token, 0, sizeof(*token));
  token->type = type;
  token->argument = argument;
}
static void field_complete(c89_map_state *state) {
  c89_map_frame *parent;
  --state->depth;
  if (state->depth == 0)
    return;
  parent = &state->frames[state->depth - 1u];
  parent->phase = ENCODE_NEXT;
  if (parent->kind == C89_MAP_ARRAY)
    ++parent->index;
}
static int scalar_token(c89_map_state *state, lonejson_field_kind kind,
                        const void *slot, c89cbor_token *token) {
  lonejson_int64 signed_value;
  lonejson_uint64 unsigned_value;
  double number;
  bool boolean;
  int status;
  if (kind == LONEJSON_FIELD_KIND_I64) {
    memcpy(&signed_value, slot, sizeof(signed_value));
    token_init(token, signed_value < 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT,
               signed_value < 0 ? (uint64_t)(-(signed_value + 1))
                                : (uint64_t)signed_value);
  } else if (kind == LONEJSON_FIELD_KIND_U64) {
    memcpy(&unsigned_value, slot, sizeof(unsigned_value));
    token_init(token, C89CBOR_UINT, (uint64_t)unsigned_value);
  } else if (kind == LONEJSON_FIELD_KIND_BOOL) {
    memcpy(&boolean, slot, sizeof(boolean));
    token_init(token, C89CBOR_BOOL, boolean != 0);
  } else if (kind == LONEJSON_FIELD_KIND_F64) {
    memcpy(&number, slot, sizeof(number));
    status = c89cbor_float64_set(NULL, token, number);
    if (status != 0)
      return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                          "unsupported native floating representation");
    if (((token->argument >> 52u) & 2047u) == 2047u)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "mapped double must be finite");
  } else {
    return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                        "unsupported mapped scalar");
  }
  return C89CBOR_TOKEN;
}
static int array_info(c89_map_state *state, const lonejson_field *field,
                      const void *slot, const void **items, size_t *count) {
  size_t capacity = 0, stride = field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY
                                    ? sizeof(char *)
                                    : field->elem_size;
  *items = NULL;
  *count = 0;
#define ARRAY_INFO(type)                                                       \
  do {                                                                         \
    const type *array = slot;                                                  \
    *items = array->items;                                                     \
    *count = array->count;                                                     \
    capacity = array->capacity;                                                \
  } while (0)
  switch (field->kind) {
  case LONEJSON_FIELD_KIND_STRING_ARRAY:
    ARRAY_INFO(lonejson_string_array);
    break;
  case LONEJSON_FIELD_KIND_I64_ARRAY:
    ARRAY_INFO(lonejson_i64_array);
    break;
  case LONEJSON_FIELD_KIND_U64_ARRAY:
    ARRAY_INFO(lonejson_u64_array);
    break;
  case LONEJSON_FIELD_KIND_F64_ARRAY:
    ARRAY_INFO(lonejson_f64_array);
    break;
  case LONEJSON_FIELD_KIND_BOOL_ARRAY:
    ARRAY_INFO(lonejson_bool_array);
    break;
  case LONEJSON_FIELD_KIND_OBJECT_ARRAY:
    ARRAY_INFO(lonejson_object_array);
    if (*count != 0 &&
        ((const lonejson_object_array *)slot)->elem_size != stride)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "object array stride differs from schema");
    break;
  default:
    return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                        "stream handler is an inbound destination");
  }
#undef ARRAY_INFO
  if (*count > capacity || (*count != 0 && *items == NULL) || stride == 0 ||
      *count > (size_t)-1 / stride)
    return c89_map_fail(state, C89CBOR_SCHEMA, "invalid mapped array storage");
  return C89CBOR_OK;
}
static int push_text(c89_map_state *state, size_t parent,
                     const lonejson_field *field, uint64_t index,
                     const void *data, size_t length) {
  c89_map_frame *frame;
  int status = c89_map_push(state, C89_MAP_TEXT, parent, field, index);
  if (status != 0)
    return status;
  frame = &state->frames[state->depth - 1u];
  frame->data = data;
  frame->length = length;
  frame->expected = (uint64_t)length;
  frame->target = C89CBOR_TEXT;
  return C89CBOR_OK;
}
static int prepare_source(c89_map_state *state, c89_map_frame *frame,
                          const lonejson_field *field, const void *slot) {
  const lonejson_source *source;
  const lonejson_json_value *json;
  int status;
  c89_map_payload_close(state);
  frame->streaming = 1;
  frame->indefinite = 1;
  if (field->kind == LONEJSON_FIELD_KIND_STRING_STREAM ||
      field->kind == LONEJSON_FIELD_KIND_BASE64_STREAM) {
    state->payload.cursor = *(const lonejson_spooled *)slot;
    state->payload.spool = 1;
    frame->indefinite = 0;
    frame->expected = (uint64_t)lonejson_spooled_size(slot);
    if (frame->expected == 0)
      return C89CBOR_OK;
    status = c89_map_dependency(
        state,
        lonejson_spooled_rewind(&state->payload.cursor, &state->json_error));
    return status;
  }
  if (field->kind == LONEJSON_FIELD_KIND_JSON_VALUE) {
    json = slot;
    switch (json->kind) {
    case LONEJSON_JSON_VALUE_BUFFER:
      state->payload.memory = (const unsigned char *)json->json;
      state->payload.length = json->len;
      break;
    case LONEJSON_JSON_VALUE_READER:
      state->payload.reader = json->reader;
      state->payload.reader_context = json->reader_user;
      break;
    case LONEJSON_JSON_VALUE_FILE:
      state->payload.file = json->fp;
      break;
    case LONEJSON_JSON_VALUE_FD:
      state->payload.descriptor = json->fd;
      break;
    case LONEJSON_JSON_VALUE_PATH:
      state->payload.path = json->path;
      break;
    default:
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "invalid embedded JSON source");
    }
    return C89CBOR_OK;
  }
  source = slot;
  switch (source->kind) {
  case LONEJSON_SOURCE_FILE:
    state->payload.file = source->fp;
    break;
  case LONEJSON_SOURCE_FD:
    state->payload.descriptor = source->fd;
    break;
  case LONEJSON_SOURCE_PATH:
    state->payload.path = source->path;
    break;
  default:
    return c89_map_fail(state, C89CBOR_SCHEMA, "invalid mapped source kind");
  }
  return C89CBOR_OK;
}
static int select_field(c89_map_state *state, c89_map_frame *parent,
                        c89cbor_token *token) {
  const lonejson_field *field = parent->field;
  const unsigned char *slot =
      (const unsigned char *)parent->record.input + field->struct_offset;
  const void *items;
  const char *text;
  const void *terminator;
  size_t count, index = state->depth - 1u, length;
  int present, status;
  c89_map_frame *frame;
  state->error_field = field;
  if (lonejson_field_has_presence(field)) {
    memcpy(&present,
           (const unsigned char *)parent->record.input + field->presence_offset,
           sizeof(present));
    if (!present) {
      if ((field->flags & LONEJSON_FIELD_ACCEPT_NULL) == 0)
        return c89_map_fail(state, C89CBOR_SCHEMA,
                            "required primitive has no value");
      token_init(token, C89CBOR_NULL, 0);
      parent->phase = ENCODE_NEXT;
      return C89CBOR_TOKEN;
    }
  }
  if (field->kind >= LONEJSON_FIELD_KIND_I64 &&
      field->kind <= LONEJSON_FIELD_KIND_BOOL) {
    status = scalar_token(state, field->kind, slot, token);
    if (status == C89CBOR_TOKEN)
      parent->phase = ENCODE_NEXT;
    return status;
  }
  if (field->kind == LONEJSON_FIELD_KIND_STRING) {
    if (field->storage == LONEJSON_STORAGE_DYNAMIC) {
      memcpy(&text, slot, sizeof(text));
      if (text == NULL) {
        token_init(token, C89CBOR_NULL, 0);
        parent->phase = ENCODE_NEXT;
        return C89CBOR_TOKEN;
      }
      length = strlen(text);
    } else {
      terminator = memchr(slot, 0, field->fixed_capacity);
      if (terminator == NULL)
        return c89_map_fail(state, C89CBOR_SCHEMA,
                            "fixed string has no terminator");
      text = (const char *)slot;
      length = (size_t)((const unsigned char *)terminator - slot);
    }
    return push_text(state, index, field, 0, text, length);
  }
  if (field->kind == LONEJSON_FIELD_KIND_OBJECT) {
    status = c89_map_push(state, C89_MAP_OBJECT, index, field, 0);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->map = field->submap;
    frame->record.input = slot;
    return C89CBOR_OK;
  }
  if (field->kind >= LONEJSON_FIELD_KIND_STRING_ARRAY &&
      field->kind <= LONEJSON_FIELD_KIND_OBJECT_ARRAY) {
    status = array_info(state, field, slot, &items, &count);
    if (status != 0)
      return status;
    status = c89_map_push(state, C89_MAP_ARRAY, index, field, 0);
    if (status != 0)
      return status;
    frame = &state->frames[state->depth - 1u];
    frame->data = items;
    frame->count = count;
    return C89CBOR_OK;
  }
  if ((field->kind == LONEJSON_FIELD_KIND_STRING_SOURCE ||
       field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE) &&
      ((const lonejson_source *)slot)->kind == LONEJSON_SOURCE_NONE) {
    token_init(token, C89CBOR_NULL, 0);
    parent->phase = ENCODE_NEXT;
    return C89CBOR_TOKEN;
  }
  if (field->kind == LONEJSON_FIELD_KIND_JSON_VALUE &&
      ((const lonejson_json_value *)slot)->kind == LONEJSON_JSON_VALUE_NULL) {
    token_init(token, C89CBOR_NULL, 0);
    parent->phase = ENCODE_NEXT;
    return C89CBOR_TOKEN;
  }
  if (field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY_STREAM ||
      field->kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM)
    return c89_map_fail(state, C89CBOR_UNSUPPORTED,
                        "array stream handler is an inbound destination");
  status =
      c89_map_push(state,
                   field->kind == LONEJSON_FIELD_KIND_JSON_VALUE ? C89_MAP_JSON
                                                                 : C89_MAP_TEXT,
                   index, field, 0);
  if (status != 0)
    return status;
  frame = &state->frames[state->depth - 1u];
  frame->target = field->kind == LONEJSON_FIELD_KIND_BASE64_SOURCE ||
                          field->kind == LONEJSON_FIELD_KIND_BASE64_STREAM
                      ? C89CBOR_BYTES
                      : C89CBOR_TEXT;
  return prepare_source(state, frame, field, slot);
}
static int object_token(c89_map_state *state, c89_map_frame *frame,
                        c89cbor_token *token) {
  const lonejson_field *field;
  int omit, status;
  switch (frame->phase) {
  case ENCODE_BEGIN:
    status = c89_map_count(state, frame->map, frame->record.input, state->depth,
                           &frame->count);
    if (status != 0)
      return status;
    token_init(token, C89CBOR_MAP, (uint64_t)frame->count);
    frame->phase = ENCODE_NEXT;
    return C89CBOR_TOKEN;
  case ENCODE_NEXT:
    if (frame->next_field == frame->map->field_count) {
      token_init(token, C89CBOR_END, C89CBOR_MAP);
      field_complete(state);
      return C89CBOR_TOKEN;
    }
    field = &frame->map->fields[frame->next_field++];
    status =
        c89_map_omit(state, field, frame->record.input, state->depth, &omit);
    if (status != 0 || omit)
      return status;
    frame->field = field;
    token_init(token, C89CBOR_TEXT, (uint64_t)field->json_key_len);
    frame->phase = ENCODE_KEY_DATA;
    return C89CBOR_TOKEN;
  case ENCODE_KEY_DATA:
    token_init(token, C89CBOR_DATA, 0);
    token->data = frame->field->json_key;
    token->length = frame->field->json_key_len;
    frame->phase = ENCODE_KEY_END;
    return C89CBOR_TOKEN;
  case ENCODE_KEY_END:
    token_init(token, C89CBOR_END, C89CBOR_TEXT);
    frame->phase = ENCODE_VALUE;
    return C89CBOR_TOKEN;
  default:
    return select_field(state, frame, token);
  }
}
static int array_token(c89_map_state *state, c89_map_frame *frame,
                       c89cbor_token *token) {
  const unsigned char *slot;
  const char *text;
  size_t parent = state->depth - 1u;
  lonejson_field_kind scalar_kind;
  int status;
  if (frame->phase == ENCODE_BEGIN) {
    token_init(token, C89CBOR_ARRAY, (uint64_t)frame->count);
    frame->phase = ENCODE_NEXT;
    return C89CBOR_TOKEN;
  }
  if (frame->index == (uint64_t)frame->count) {
    token_init(token, C89CBOR_END, C89CBOR_ARRAY);
    field_complete(state);
    return C89CBOR_TOKEN;
  }
  slot =
      frame->data + (size_t)frame->index *
                        (frame->field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY
                             ? sizeof(char *)
                             : frame->field->elem_size);
  if (frame->field->kind == LONEJSON_FIELD_KIND_STRING_ARRAY) {
    memcpy(&text, slot, sizeof(text));
    if (text == NULL) {
      token_init(token, C89CBOR_NULL, 0);
      ++frame->index;
      return C89CBOR_TOKEN;
    }
    return push_text(state, parent, NULL, frame->index, text, strlen(text));
  }
  if (frame->field->kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY) {
    status = c89_map_push(state, C89_MAP_OBJECT, parent, NULL, frame->index);
    if (status != 0)
      return status;
    state->frames[state->depth - 1u].map = frame->field->submap;
    state->frames[state->depth - 1u].record.input = slot;
    return C89CBOR_OK;
  }
  scalar_kind = frame->field->kind == LONEJSON_FIELD_KIND_I64_ARRAY
                    ? LONEJSON_FIELD_KIND_I64
                : frame->field->kind == LONEJSON_FIELD_KIND_U64_ARRAY
                    ? LONEJSON_FIELD_KIND_U64
                : frame->field->kind == LONEJSON_FIELD_KIND_F64_ARRAY
                    ? LONEJSON_FIELD_KIND_F64
                    : LONEJSON_FIELD_KIND_BOOL;
  status = scalar_token(state, scalar_kind, slot, token);
  if (status == C89CBOR_TOKEN)
    ++frame->index;
  return status;
}
static size_t utf8_prefix(const unsigned char *bytes, size_t length) {
  size_t start = length, needed;
  unsigned char lead;
  if (length == 0)
    return 0;
  do {
    --start;
  } while (start != 0 && (bytes[start] & 0xc0u) == 0x80u);
  lead = bytes[start];
  needed = lead >= 0xf0u && lead <= 0xf4u   ? 4u
           : lead >= 0xe0u && lead <= 0xefu ? 3u
           : lead >= 0xc2u && lead <= 0xdfu ? 2u
                                            : 1u;
  return length - start < needed ? start : length;
}
static int text_token(c89_map_state *state, c89_map_frame *frame,
                      c89cbor_token *token) {
  size_t take, count = 0, prefix;
  int status;
  if (frame->phase == ENCODE_BEGIN) {
    token_init(token, (c89cbor_type)frame->target, frame->expected);
    token->indefinite = frame->indefinite;
    frame->phase = frame->streaming ? ENCODE_READ : ENCODE_DATA;
    return C89CBOR_TOKEN;
  }
  if (frame->phase == ENCODE_READ) {
    if (state->read_attempted)
      return C89CBOR_OK;
    if (!frame->indefinite && frame->text_seen == frame->expected) {
      frame->phase = ENCODE_END;
      return C89CBOR_OK;
    }
    memcpy(state->input, state->payload.carry, state->payload.carry_length);
    take = state->input_capacity - state->payload.carry_length;
    if (take > state->options.chunk)
      take = state->options.chunk;
    status = c89_map_payload_read(
        state, state->input + state->payload.carry_length, take, &count);
    if (count > take)
      return c89_map_fail(state, C89CBOR_IO,
                          "source exceeded offered capacity");
    state->owner->lifetime.progress.input += (uint64_t)count;
    if (status == C89CBOR_INPUT)
      return status;
    if (status != 0)
      return c89_map_fail(state, C89CBOR_IO, "mapped source read failed");
    take = state->payload.carry_length + count;
    if (count == 0) {
      if (take != 0 ||
          (!frame->indefinite && frame->text_seen != frame->expected))
        return c89_map_fail(state, C89CBOR_MALFORMED,
                            "truncated mapped payload");
      frame->phase = ENCODE_END;
      return C89CBOR_OK;
    }
    prefix = frame->indefinite && frame->target == C89CBOR_TEXT
                 ? utf8_prefix(state->input, take)
                 : take;
    state->payload.carry_length = take - prefix;
    if (state->payload.carry_length > sizeof(state->payload.carry))
      return c89_map_fail(state, C89CBOR_MALFORMED,
                          "invalid mapped UTF-8 source");
    memcpy(state->payload.carry, state->input + prefix,
           state->payload.carry_length);
    if (prefix == 0)
      return C89CBOR_OK;
    frame->data = state->input;
    frame->length = prefix;
    frame->offset = 0;
    frame->text_seen += (uint64_t)prefix;
    frame->phase = frame->indefinite ? ENCODE_CHUNK : ENCODE_DATA;
  }
  if (frame->phase == ENCODE_CHUNK) {
    token_init(token, (c89cbor_type)frame->target, (uint64_t)frame->length);
    frame->phase = ENCODE_DATA;
    return C89CBOR_TOKEN;
  }
  if (frame->phase == ENCODE_DATA) {
    if (frame->offset == frame->length) {
      frame->phase = !frame->streaming   ? ENCODE_END
                     : frame->indefinite ? ENCODE_CHUNK_END
                                         : ENCODE_READ;
      return C89CBOR_OK;
    }
    take = frame->length - frame->offset;
    if (take > state->options.chunk)
      take = state->options.chunk;
    token_init(token, C89CBOR_DATA, 0);
    token->data = frame->data + frame->offset;
    token->length = take;
    frame->offset += take;
    return C89CBOR_TOKEN;
  }
  if (frame->phase == ENCODE_CHUNK_END) {
    token_init(token, C89CBOR_END, frame->target);
    frame->phase = ENCODE_READ;
    return C89CBOR_TOKEN;
  }
  if (frame->phase == ENCODE_END) {
    token_init(token, C89CBOR_END, frame->target);
    if (frame->streaming)
      c89_map_payload_close(state);
    field_complete(state);
    return C89CBOR_TOKEN;
  }
  return C89CBOR_OK;
}
static int nested_sink(void *context, const void *bytes, size_t length,
                       size_t *count) {
  c89_map_state *state = context;
  int status = state->sink.write(state->sink.context, bytes, length, count);
  if (*count <= length)
    state->owner->lifetime.progress.output += (uint64_t)*count;
  return status;
}
static int begin_json_field(c89_map_state *state) {
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_error error;
  int status = c89_map_json_runtime(state);
  if (status != 0)
    return status;
  source.context = state;
  source.read = c89_map_payload_read;
  sink.context = state;
  sink.write = nested_sink;
  status =
      c89_json_encode_init(&state->bridge_runtime, &state->bridge, &source,
                           &sink, &state->options, &state->encoder, &error);
  if (status != 0)
    return c89_map_bridge_status(state, status, &error);
  state->bridge_ready = 1;
  state->bridge_input = 0;
  return C89CBOR_OK;
}
static int flush_map(c89_map_state *state, const void *bytes, size_t length,
                     int queued) {
  size_t count = 0;
  int status;
  if (length > state->options.step_output)
    length = state->options.step_output;
  status = state->sink.write(state->sink.context, bytes, length, &count);
  if (count > length)
    return c89_map_fail(state, C89CBOR_IO, "mapped sink exceeded offered span");
  state->owner->lifetime.progress.output += (uint64_t)count;
  if (queued) {
    state->output_offset += count;
    if (state->output_offset == state->output_length)
      state->output_offset = state->output_length = 0;
  } else {
    (void)state->encoder.advance(&state->encoder, count);
  }
  if (status == C89CBOR_OUTPUT)
    return status;
  if (status != 0 || count == 0)
    return c89_map_fail(state, C89CBOR_IO, "mapped sink write failed");
  return C89CBOR_OK;
}
int c89_map_encode_step(void *context) {
  c89_map_state *state = context;
  c89_map_frame *frame;
  c89cbor_token token;
  c89cbor_progress progress;
  c89cbor_error error;
  const void *bytes;
  size_t length, events = 0;
  int status;
  if (state->done)
    return C89CBOR_DONE;
  state->read_attempted = 0;
  if (state->output_offset != 0)
    return flush_map(state, state->output + state->output_offset,
                     state->output_length - state->output_offset, 1);
  if (state->bridge_ready) {
    status = state->bridge.step(&state->bridge, &error);
    (void)state->bridge.progress(&state->bridge, &progress);
    state->owner->lifetime.progress.input +=
        progress.input - state->bridge_input;
    state->bridge_input = progress.input;
    if (status == C89CBOR_DONE) {
      (void)state->bridge.cleanup(&state->bridge);
      state->bridge_ready = 0;
      c89_map_payload_close(state);
      field_complete(state);
      return C89CBOR_OK;
    }
    return c89_map_bridge_status(state, status, &error);
  }
  while (events < state->options.step_events) {
    status = state->encoder.peek(&state->encoder, &bytes, &length);
    if (status < 0)
      return c89_map_fail(state, status, "invalid mapped CBOR output");
    if (status == C89CBOR_OUTPUT) {
      if (length <= state->options.chunk - state->output_length &&
          (length < state->options.chunk / 2u || state->output_length != 0)) {
        memcpy(state->output + state->output_length, bytes, length);
        state->output_length += length;
        (void)state->encoder.advance(&state->encoder, length);
      } else {
        if (state->output_length != 0)
          return flush_map(state, state->output, state->output_length, 1);
        return flush_map(state, bytes, length, 0);
      }
      if (state->output_length == state->options.chunk)
        return flush_map(state, state->output, state->output_length, 1);
      continue;
    }
    if (state->depth == 0) {
      if (state->output_length != 0)
        return flush_map(state, state->output, state->output_length, 1);
      status = state->encoder.finish(&state->encoder);
      if (status != 0)
        return c89_map_fail(state, status, "incomplete mapped CBOR output");
      state->done = 1;
      state->owner->lifetime.progress.records = 1;
      return C89CBOR_DONE;
    }
    frame = &state->frames[state->depth - 1u];
    state->error_frame = state->depth - 1u;
    state->error_field = NULL;
    if ((frame->kind == C89_MAP_TEXT && frame->phase == ENCODE_READ) ||
        frame->kind == C89_MAP_JSON) {
      if (state->output_length != 0)
        return flush_map(state, state->output, state->output_length, 1);
      if (state->read_attempted)
        return C89CBOR_OK;
    }
    if (frame->kind == C89_MAP_OBJECT)
      status = object_token(state, frame, &token);
    else if (frame->kind == C89_MAP_ARRAY)
      status = array_token(state, frame, &token);
    else if (frame->kind == C89_MAP_JSON)
      return begin_json_field(state);
    else
      status = text_token(state, frame, &token);
    ++events;
    if (status == C89CBOR_INPUT) {
      if (state->output_length != 0)
        return flush_map(state, state->output, state->output_length, 1);
      return status;
    }
    if (status < 0)
      return status;
    if (status == C89CBOR_TOKEN) {
      status = state->encoder.put(&state->encoder, &token);
      if (status != 0)
        return c89_map_fail(state, status, "invalid mapped CBOR token");
    }
  }
  if (state->output_length != 0)
    return flush_map(state, state->output, state->output_length, 1);
  return C89CBOR_OK;
}
