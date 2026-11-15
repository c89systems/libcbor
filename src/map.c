#define _GNU_SOURCE
#include "map.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t path_chain(c89_map_state *state, size_t frame) {
  size_t count = 0;
  while (frame != (size_t)-1 && count < state->frame_capacity) {
    state->path_stack[count++] = frame;
    frame = state->frames[frame].parent;
  }
  return count;
}
static size_t index_text(uint64_t index, char text[64]) {
  c89cbor_token token;
  size_t length = 0;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_UINT;
  token.argument = index;
  (void)c89_number_format(&token, text, &length, (locale_t)0);
  return length;
}
static int match_component(const char **path, const char *text, size_t length) {
  size_t i;
  const char *cursor = *path;
  if (*cursor++ != '/')
    return 0;
  for (i = 0; i < length; ++i) {
    if (text[i] == '~' || text[i] == '/') {
      if (cursor[0] != '~' || cursor[1] != (text[i] == '~' ? '0' : '1'))
        return 0;
      cursor += 2;
    } else {
      if (*cursor == '\0' || *cursor++ != text[i])
        return 0;
    }
  }
  *path = cursor;
  return 1;
}
const c89cbor_field_sink *c89_map_binding(c89_map_state *state, size_t frame) {
  const c89cbor_field_sink *binding;
  const c89_map_frame *node;
  const char *cursor;
  char number[64];
  size_t i, j, count, length;
  int matches;
  if (state->options.field_sink_count == 0)
    return NULL;
  count = path_chain(state, frame);
  for (i = 0; i < state->options.field_sink_count; ++i) {
    binding = &state->options.field_sinks[i];
    cursor = binding->path;
    matches = 1;
    for (j = count; j != 0 && matches; --j) {
      node = &state->frames[state->path_stack[j - 1u]];
      if (node->path_kind == C89_PATH_FIELD) {
        matches = match_component(&cursor, node->path_field->json_key,
                                  node->path_field->json_key_len);
      } else if (node->path_kind == C89_PATH_INDEX) {
        length = index_text(node->path_index, number);
        matches = match_component(&cursor, number, length);
      }
    }
    if (matches && *cursor == '\0')
      return binding;
  }
  return NULL;
}
static void diagnostic_component(c89cbor_error *error, size_t *used,
                                 const char *text, size_t length) {
  size_t i;
  char byte;
  if (*used + 1u < sizeof(error->path))
    error->path[(*used)++] = '/';
  else
    error->shortened = 1;
  for (i = 0; i < length; ++i) {
    byte = text[i];
    if (*used + (byte == '/' || byte == '~' ? 2u : 1u) >= sizeof(error->path)) {
      error->shortened = 1;
      break;
    }
    if (byte == '/' || byte == '~') {
      error->path[(*used)++] = '~';
      error->path[(*used)++] = byte == '~' ? '0' : '1';
    } else {
      error->path[(*used)++] = byte;
    }
  }
  error->path[*used] = '\0';
}
int c89_map_fail(c89_map_state *state, int status, const char *message) {
  c89cbor_error *error = &state->owner->lifetime.error;
  const c89_map_frame *frame;
  size_t count = 0, used = 0, i, length;
  char number[64];
  if (error->status != 0)
    return status;
  c89_error(&state->owner->lifetime, status, "mapped-record");
  error->status = status;
  error->offset = state->encode ? state->owner->lifetime.progress.input
                                : state->codec.decoder.lifetime.progress.input;
  strncpy(error->message, message, sizeof(error->message) - 1u);
  if (state->depth != 0 && state->error_frame < state->depth)
    count = path_chain(state, state->error_frame);
  for (i = count; i != 0; --i) {
    frame = &state->frames[state->path_stack[i - 1u]];
    if (frame->path_kind == C89_PATH_FIELD) {
      diagnostic_component(error, &used, frame->path_field->json_key,
                           frame->path_field->json_key_len);
    } else if (frame->path_kind == C89_PATH_INDEX) {
      length = index_text(frame->path_index, number);
      diagnostic_component(error, &used, number, length);
    }
  }
  if (state->error_field != NULL && state->error_field->json_key != NULL)
    diagnostic_component(error, &used, state->error_field->json_key,
                         strlen(state->error_field->json_key));
  else if (state->error_key && state->key_data != NULL)
    diagnostic_component(error, &used, state->key_data, state->key_length);
  return status;
}
int c89_map_dependency(c89_map_state *state, lonejson_status status) {
  c89cbor_error *error = &state->owner->lifetime.error;
  int mapped;
  if (state->json_error.truncated)
    error->truncated = 1;
  if (status == LONEJSON_STATUS_OK)
    return C89CBOR_OK;
  if (status == LONEJSON_STATUS_ALLOCATION_FAILED)
    mapped = C89CBOR_NOMEM;
  else if (status == LONEJSON_STATUS_OVERFLOW ||
           status == LONEJSON_STATUS_TRUNCATED)
    mapped = C89CBOR_LIMIT;
  else if (status == LONEJSON_STATUS_IO_ERROR ||
           status == LONEJSON_STATUS_CALLBACK_FAILED)
    mapped = C89CBOR_IO;
  else if (status == LONEJSON_STATUS_UNSUPPORTED)
    mapped = C89CBOR_UNSUPPORTED;
  else
    mapped = C89CBOR_SCHEMA;
  c89_map_fail(state, mapped,
               state->json_error.message[0] == '\0'
                   ? "lonejson record operation failed"
                   : state->json_error.message);
  error->cause = status;
  error->system_errno = state->json_error.system_errno;
  return mapped;
}
void *c89_map_allocate(c89_map_state *state, size_t count, size_t size) {
  void *storage;
  if (state->owner->lifetime.error.status != 0)
    return NULL;
  if (size == 0 || count > (size_t)-1 / size) {
    c89_map_fail(state, C89CBOR_LIMIT, "mapped workspace size overflow");
    return NULL;
  }
  storage = state->allocator.alloc(state->allocator.context, count * size);
  if (storage == NULL) {
    c89_map_fail(state, C89CBOR_NOMEM, "mapped workspace allocation failed");
  }
  /* Traversal frames and bitsets initialize on push; byte buffers initialize
   * only their written spans. No reader may depend on fresh allocator bytes. */
  return storage;
}
int c89_map_push(c89_map_state *state, c89_map_kind kind, size_t parent,
                 const lonejson_field *field, uint64_t index) {
  c89_map_frame *frame;
  if (state->depth == state->frame_capacity)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "mapped value exceeds nesting limit");
  frame = &state->frames[state->depth];
  memset(frame, 0, sizeof(*frame));
  frame->kind = kind;
  frame->parent = parent;
  frame->path_kind = field != NULL ? C89_PATH_FIELD : C89_PATH_INDEX;
  frame->path_field = field;
  frame->path_index = index;
  frame->field = field;
  frame->needs_key = kind == C89_MAP_OBJECT;
  if (!state->encode) {
    if (state->seen != NULL) {
      frame->seen = state->seen + state->depth * state->seen_stride;
      memset(frame->seen, 0, state->seen_stride);
    } else {
      frame->seen = (unsigned char *)&frame->seen_bits;
    }
  }
  frame->unknown_start = state->unknown_count;
  frame->unknown_bytes = state->unknown_length;
  if (parent == (size_t)-1)
    frame->path_kind = C89_PATH_ROOT;
  ++state->depth;
  state->error_frame = state->depth - 1u;
  state->error_field = NULL;
  return C89CBOR_OK;
}
int c89_map_budget(c89_map_state *state, size_t bytes, size_t elements) {
  if (bytes > state->options.record_bytes - state->stored_bytes ||
      elements > state->options.array_elements - state->stored_elements)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "mapped destination exceeds storage budget");
  state->stored_bytes += bytes;
  state->stored_elements += elements;
  return C89CBOR_OK;
}
int c89_map_json_runtime(c89_map_state *state) {
  c89cbor_config config;
  c89cbor_error error;
  int status;
  if (state->bridge_runtime_ready)
    return C89CBOR_OK;
  if (state->json_bridge == NULL) {
    state->json_bridge =
        c89_map_allocate(state, 1, sizeof(*state->json_bridge));
    if (state->json_bridge == NULL)
      return state->owner->lifetime.error.status;
    memset(state->json_bridge, 0, sizeof(*state->json_bridge));
  }
  config = c89cbor_default_config();
  config.allocator = state->allocator;
  config.json = state->json;
  config.step_input = state->options.step_input;
  config.step_output = state->options.step_output;
  config.step_events = state->options.step_events;
  status = c89cbor_init(&state->json_bridge->runtime, &config, &error);
  if (status != 0)
    return status;
  state->bridge_runtime_ready = 1;
  return C89CBOR_OK;
}
int c89_map_bridge_status(c89_map_state *state, int status,
                          const c89cbor_error *error) {
  c89cbor_error *destination = &state->owner->lifetime.error;
  if (status >= 0)
    return status;
  if (destination->status != 0)
    return destination->status;
  c89_map_fail(state, status,
               error->message[0] == '\0' ? "embedded JSON conversion failed"
                                         : error->message);
  destination->cause = error->cause;
  destination->system_errno = error->system_errno;
  return status;
}
void c89_map_payload_close(c89_map_state *state) {
  if (state->payload == NULL)
    return;
  if (state->payload->fd_ready)
    (void)state->payload->fd.cleanup(&state->payload->fd);
  if (state->payload->owned_file && state->payload->file != NULL)
    (void)fclose(state->payload->file);
  memset(state->payload, 0, sizeof(*state->payload));
  state->payload->descriptor = -1;
}
int c89_map_payload_read(void *context, void *buffer, size_t capacity,
                         size_t *count) {
  c89_map_state *state = context;
  c89_map_payload *source = state->payload;
  lonejson_read_result result;
  size_t take;
  int status, saved_errno;
  *count = 0;
  state->read_attempted = 1;
  if (capacity > state->options.step_input)
    capacity = state->options.step_input;
  if (source->spool) {
    result = lonejson_spooled_read(&source->cursor, buffer, capacity);
  } else if (source->reader != NULL) {
    if (source->reader_eof)
      return C89CBOR_OK;
    result = source->reader(source->reader_context, buffer, capacity);
    if (result.bytes_read > capacity)
      return c89_map_fail(state, C89CBOR_IO,
                          "source reader exceeded offered capacity");
    source->reader_eof = result.eof;
  } else if (source->memory != NULL) {
    take = source->length - source->offset;
    if (take > capacity)
      take = capacity;
    memcpy(buffer, source->memory + source->offset, take);
    source->offset += take;
    *count = take;
    return C89CBOR_OK;
  } else {
    if (source->path != NULL && source->file == NULL) {
      source->file = fopen(source->path, "rb");
      if (source->file == NULL)
        return c89_map_fail(state, C89CBOR_IO,
                            "could not open mapped source path");
      source->owned_file = 1;
    }
    if (source->file != NULL) {
      do {
        saved_errno = 0;
        errno = 0;
        *count = fread(buffer, 1, capacity, source->file);
        if (ferror(source->file)) {
          saved_errno = errno;
          clearerr(source->file);
        }
      } while (*count == 0 && saved_errno == EINTR);
      if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
        return *count == 0 ? C89CBOR_INPUT : C89CBOR_OK;
      return saved_errno == 0 ? C89CBOR_OK : C89CBOR_IO;
    }
    if (source->descriptor < 0)
      return c89_map_fail(state, C89CBOR_SCHEMA,
                          "mapped source has no readable endpoint");
    if (!source->fd_ready) {
      status = c89cbor_fd_init(NULL, &source->fd, source->descriptor,
                               &source->fd_source, NULL);
      if (status != 0)
        return status;
      source->fd_ready = 1;
    }
    return source->fd_source.read(source->fd_source.context, buffer, capacity,
                                  count);
  }
  if (result.bytes_read > capacity)
    return c89_map_fail(state, C89CBOR_IO,
                        "mapped source exceeded offered capacity");
  *count = result.bytes_read;
  if (result.error_code != 0) {
    errno = result.error_code;
    return C89CBOR_IO;
  }
  if (result.would_block && result.bytes_read == 0)
    return C89CBOR_INPUT;
  if (result.bytes_read == 0 && !result.eof)
    return c89_map_fail(state, C89CBOR_IO, "mapped reader made no progress");
  return C89CBOR_OK;
}
static void release_map(void *context) {
  c89_map_state *state = context;
  c89cbor_allocator allocator = state->allocator;
  if (state->bridge_ready)
    (void)state->json_bridge->conversion.cleanup(
        &state->json_bridge->conversion);
  if (state->bridge_runtime_ready)
    (void)state->json_bridge->runtime.cleanup(&state->json_bridge->runtime);
  c89_map_payload_close(state);
#define RELEASE_PART(member)                                                   \
  if (state->member != NULL)                                                   \
  allocator.free(allocator.context, state->member)
  RELEASE_PART(json_bridge);
  RELEASE_PART(seen);
  RELEASE_PART(scratch);
#undef RELEASE_PART
  allocator.free(allocator.context, state);
}
static int validate_bindings(c89_map_state *state) {
  const c89cbor_field_sink *binding;
  const char *cursor;
  size_t i, j;
  if (state->options.field_sink_count != 0 &&
      state->options.field_sinks == NULL)
    return c89_map_fail(state, C89CBOR_INVALID, "field sink array is required");
  if (state->encode && state->options.field_sink_count != 0)
    return c89_map_fail(state, C89CBOR_INVALID,
                        "field sinks apply to mapped decoding");
  for (i = 0; i < state->options.field_sink_count; ++i) {
    binding = &state->options.field_sinks[i];
    if (binding->path == NULL || binding->path[0] != '/' ||
        binding->sink.write == NULL ||
        binding->payload < C89CBOR_PAYLOAD_TEXT ||
        binding->payload > C89CBOR_PAYLOAD_JSON)
      return c89_map_fail(state, C89CBOR_INVALID, "invalid mapped field sink");
    for (cursor = binding->path; *cursor != '\0'; ++cursor) {
      if (*cursor == '~' && cursor[1] != '0' && cursor[1] != '1')
        return c89_map_fail(state, C89CBOR_INVALID,
                            "invalid JSON Pointer escape");
    }
    for (j = 0; j < i; ++j) {
      if (strcmp(binding->path, state->options.field_sinks[j].path) == 0)
        return c89_map_fail(state, C89CBOR_INVALID,
                            "duplicate field sink binding");
    }
  }
  return C89CBOR_OK;
}

/* Allocate the traversal workspace once. Each slice has the strongest
 * alignment required by its members; all arithmetic is checked before the
 * allocator callback. Contents initialize when their frames/spans are used. */
typedef union workspace_alignment {
  c89_map_frame mapped;
  c89_map_payload payload;
  c89cbor_frame wire;
  c89_map_key key;
  const lonejson_map *schema;
  size_t index;
} workspace_alignment;
typedef struct workspace_probe {
  char prefix;
  workspace_alignment value;
} workspace_probe;
typedef struct workspace_layout {
  size_t total, wire_frames, frames, schema_path, schema_inline, path_stack;
  size_t input, output, key, unknown_keys, unknown_storage, payload;
} workspace_layout;
/* The compiler supplies native slice alignment for the usual bounds. This is
 * a heap layout, never a stack object; other bounds use the checked layout. */
typedef struct default_workspace {
  c89_map_state state;
  c89_map_frame frames[C89CBOR_DEPTH];
  const lonejson_map *schema_path[C89CBOR_DEPTH];
  unsigned char schema_inline[C89CBOR_DEPTH];
  size_t path_stack[C89CBOR_DEPTH];
  unsigned char buffer[C89CBOR_CHUNK];
  unsigned char input[C89CBOR_CHUNK];
  c89_map_payload payload;
} default_workspace;
#define LEAF_DEPTH 4u
typedef struct leaf_workspace {
  c89_map_state state;
  c89_map_frame frames[LEAF_DEPTH];
  const lonejson_map *schema_path[LEAF_DEPTH];
  unsigned char schema_inline[LEAF_DEPTH];
  size_t path_stack[LEAF_DEPTH];
  unsigned char buffer[C89CBOR_CHUNK];
  unsigned char input[C89CBOR_CHUNK];
  c89_map_payload payload;
} leaf_workspace;
#define WORKSPACE_LAYOUT(type)                                                 \
  {sizeof(type),                                                               \
   0,                                                                          \
   offsetof(type, frames),                                                     \
   offsetof(type, schema_path),                                                \
   offsetof(type, schema_inline),                                              \
   offsetof(type, path_stack),                                                 \
   offsetof(type, input),                                                      \
   offsetof(type, buffer),                                                     \
   offsetof(type, buffer),                                                     \
   0,                                                                          \
   0,                                                                          \
   offsetof(type, payload)}
static const workspace_layout default_layout =
    WORKSPACE_LAYOUT(default_workspace);
static const workspace_layout leaf_layout = WORKSPACE_LAYOUT(leaf_workspace);
#undef WORKSPACE_LAYOUT
/* A leaf record needs at most object/array/text/chunk mapped frames. Unknown
 * values and embedded JSON still use the full independent wire-depth budget.
 * This sizes storage only; normal schema and value validation remains
 * mandatory. */
static size_t mapped_capacity(const lonejson_map *map, size_t extent,
                              size_t depth, int *payload) {
  size_t i;
  *payload = 0;
  if (map->struct_size == 0 || map->struct_size > extent ||
      (map->fields == NULL && map->field_count != 0) ||
      map->field_count > (size_t)-1 / sizeof(*map->fields))
    return depth;
  for (i = 0; i < map->field_count; ++i) {
    lonejson_field_kind kind = map->fields[i].kind;
    if (kind == LONEJSON_FIELD_KIND_OBJECT ||
        kind == LONEJSON_FIELD_KIND_OBJECT_ARRAY ||
        kind == LONEJSON_FIELD_KIND_MAPPED_ARRAY_STREAM) {
      *payload = 1;
      return depth;
    }
    if (kind == LONEJSON_FIELD_KIND_STRING_STREAM ||
        kind == LONEJSON_FIELD_KIND_BASE64_STREAM ||
        kind == LONEJSON_FIELD_KIND_STRING_SOURCE ||
        kind == LONEJSON_FIELD_KIND_BASE64_SOURCE ||
        kind == LONEJSON_FIELD_KIND_JSON_VALUE)
      *payload = 1;
  }
  return depth < LEAF_DEPTH ? depth : LEAF_DEPTH;
}
static int layout_workspace(const c89cbor_options *options, int encode,
                            size_t frame_capacity, int payload,
                            workspace_layout *layout) {
  size_t used = sizeof(c89_map_state), count, size, padding;
  size_t alignment = offsetof(workspace_probe, value);
  if (options->depth == C89CBOR_DEPTH && options->chunk == C89CBOR_CHUNK &&
      (encode || (!options->allow_unknown_fields &&
                  options->key_bytes == C89CBOR_CHUNK))) {
    *layout = frame_capacity == LEAF_DEPTH ? leaf_layout : default_layout;
    if (!payload) {
      layout->total = layout->payload;
      layout->payload = 0;
    }
    if (encode && !payload)
      layout->total = layout->input;
    return C89CBOR_OK;
  }
  if (options->depth == (size_t)-1 || options->chunk > (size_t)-1 - 4u)
    return C89CBOR_LIMIT;
#define PART(member, length)                                                   \
  do {                                                                         \
    count = (length);                                                          \
    size = sizeof(*((c89_map_state *)0)->member);                              \
    padding = (alignment - used % alignment) % alignment;                      \
    if (padding > (size_t)-1 - used ||                                         \
        count > ((size_t)-1 - used - padding) / size)                          \
      return C89CBOR_LIMIT;                                                    \
    used += padding;                                                           \
    layout->member = used;                                                     \
    used += count * size;                                                      \
  } while (0)
  if (options->depth > C89CBOR_DEPTH) {
    PART(wire_frames, options->depth);
  }
  PART(frames, frame_capacity);
  PART(schema_path, frame_capacity);
  PART(schema_inline, frame_capacity);
  PART(path_stack, frame_capacity);
  if (encode) {
    PART(output, options->chunk);
  }
  if (!encode || payload) {
    PART(input, options->chunk < 4u ? 4u : options->chunk);
  }
  if (!encode) {
    PART(key, options->key_bytes);
    if (options->allow_unknown_fields) {
      PART(unknown_keys, options->active_keys);
      PART(unknown_storage, options->active_key_bytes);
    }
  }
  if (payload) {
    PART(payload, 1);
  }
#undef PART
  layout->total = used;
  return C89CBOR_OK;
}
static void attach_workspace(c89_map_state *state,
                             const workspace_layout *layout) {
#define PART(member)                                                           \
  state->member = (void *)((unsigned char *)state + layout->member)
  if (state->options.depth > C89CBOR_DEPTH) {
    PART(wire_frames);
  } else {
    state->wire_frames = state->encode
                             ? state->codec.encoder.state.local_frames
                             : state->codec.decoder.state.local_frames;
  }
  PART(frames);
  PART(schema_path);
  PART(schema_inline);
  PART(path_stack);
  if (layout->payload != 0) {
    PART(payload);
    memset(state->payload, 0, sizeof(*state->payload));
    state->payload->descriptor = -1;
  }
  if (!state->encode || state->payload != NULL) {
    PART(input);
  }
  if (state->encode) {
    PART(output);
  } else {
    PART(key);
    if (state->options.allow_unknown_fields) {
      PART(unknown_keys);
      PART(unknown_storage);
    }
  }
#undef PART
}
static int prepare_map(c89_map_state *state, size_t extent) {
  c89cbor *runtime = state->runtime;
  int status;
  state->key_data = state->key;
  status = c89_map_schema(state, state->map, extent, 0);
  if (status != 0)
    return status;
  state->error_field = NULL;
  state->error_frame = (size_t)-1;
  if (state->max_fields > (size_t)-1 - 7u)
    return c89_map_fail(state, C89CBOR_LIMIT,
                        "mapped field tracking size overflow");
  state->seen_stride = (state->max_fields + 7u) / 8u;
  if (state->seen_stride == 0)
    state->seen_stride = 1;
  if (!state->encode &&
      state->seen_stride > sizeof(state->frames[0].seen_bits)) {
    state->seen =
        c89_map_allocate(state, state->frame_capacity, state->seen_stride);
  }
  if (state->owner->lifetime.error.status != 0)
    return state->owner->lifetime.error.status;
  status = validate_bindings(state);
  if (status != 0)
    return status;
  if (state->json == NULL) {
    if (runtime->json == NULL) {
      runtime->json = lonejson_new(&runtime->json_config, &state->json_error);
      if (runtime->json == NULL)
        return c89_map_dependency(state, state->json_error.code);
      runtime->json_owned = 1;
    }
    state->json = runtime->json;
  }
  if (state->encode) {
    status =
        c89cbor_encoder_init(NULL, &state->codec.encoder, state->wire_frames,
                             state->options.depth, state->options.chunk);
    if (status != 0)
      return c89_map_fail(state, status, "could not initialize mapped encoder");
    status = c89_map_push(state, C89_MAP_OBJECT, (size_t)-1, NULL, 0);
    if (status != 0)
      return status;
    state->frames[0].map = state->map;
    state->frames[0].record.input = state->record.input;
  } else {
    status =
        c89cbor_decoder_init(NULL, &state->codec.decoder, state->wire_frames,
                             state->options.depth, state->options.chunk);
    if (status != 0)
      return c89_map_fail(state, status, "could not initialize mapped decoder");
  }
  return C89CBOR_OK;
}
static int initialize_map(c89cbor *runtime, c89cbor_conversion *conversion,
                          const c89cbor_source *source, const lonejson_map *map,
                          const void *input_record, void *output_record,
                          size_t extent, const c89cbor_sink *sink,
                          const c89cbor_options *options, lonejson *json,
                          int encode, c89cbor_error *error) {
  c89_map_state *state;
  c89cbor_options resolved;
  workspace_layout layout = {0};
  size_t frame_capacity;
  int payload, status = c89_conversion_prepare(runtime, conversion, error);
  if (status != 0)
    return status;
  if (map == NULL || (encode ? input_record == NULL : output_record == NULL) ||
      (encode ? sink == NULL || sink->write == NULL
              : source == NULL || source->read == NULL)) {
    (void)conversion->cleanup(conversion);
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  conversion->lifetime.busy = 1;
  c89_options_resolve(runtime, options, &resolved);
  frame_capacity = mapped_capacity(map, extent, resolved.depth, &payload);
  status = layout_workspace(&resolved, encode, frame_capacity,
                            encode && payload, &layout);
  state = status == 0
              ? conversion->lifetime.allocator.alloc(
                    conversion->lifetime.allocator.context, layout.total)
              : NULL;
  if (state == NULL) {
    status = c89_error(&conversion->lifetime,
                       status == 0 ? C89CBOR_NOMEM : status, "mapped-record");
  } else {
    /* Only the selected codec is initialized below. Its embedded frames also
     * supply the usual wire-depth budget without a duplicate frame array. */
    memset(state, 0, offsetof(c89_map_state, codec));
    memset((unsigned char *)state + offsetof(c89_map_state, wire_frames), 0,
           sizeof(*state) - offsetof(c89_map_state, wire_frames));
    state->codec.decoder.lifetime.progress.input = 0;
    conversion->state = state;
    state->operation.step = encode ? c89_map_encode_step : c89_map_decode_step;
    state->operation.release = release_map;
    state->owner = conversion;
    state->runtime = runtime;
    state->allocator = conversion->lifetime.allocator;
    state->map = map;
    state->json = json;
    state->encode = encode;
    state->error_frame = (size_t)-1;
    state->frame_capacity = frame_capacity;
    if (encode) {
      state->sink = *sink;
      state->record.input = input_record;
    } else {
      state->source = *source;
      state->record.output = output_record;
    }
    state->options = resolved;
    state->input_capacity = resolved.chunk < 4u ? 4u : resolved.chunk;
    attach_workspace(state, &layout);
    status = prepare_map(state, extent);
  }
  conversion->lifetime.busy = 0;
  if (error != NULL)
    *error = conversion->lifetime.error;
  if (status != 0)
    (void)conversion->cleanup(conversion);
  return status;
}
static int valid_view(const lonejson_record_view *view) {
  return view != NULL && view->size >= sizeof(*view) &&
         view->abi_version == LONEJSON_VIEW_ABI_VERSION && view->flags == 0 &&
         view->schema.size >= sizeof(view->schema) &&
         view->schema.abi_version == LONEJSON_VIEW_ABI_VERSION &&
         view->schema.flags == 0 && view->schema.map != NULL &&
         view->schema.runtime != NULL && view->record != NULL &&
         view->schema.record_size >= view->schema.map->struct_size;
}
static int initialize_view(c89cbor *runtime, c89cbor_conversion *conversion,
                           const c89cbor_source *source,
                           const lonejson_record_view *view,
                           const c89cbor_sink *sink,
                           const c89cbor_options *options, int encode,
                           c89cbor_error *error) {
  int status;
  if (!valid_view(view)) {
    status = c89_conversion_prepare(runtime, conversion, error);
    if (status == 0)
      (void)conversion->cleanup(conversion);
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  return initialize_map(runtime, conversion, source, view->schema.map,
                        encode ? view->record : NULL,
                        encode ? NULL : view->record, view->schema.record_size,
                        sink, options, view->schema.runtime, encode, error);
}
static int open_map(c89cbor *runtime, const c89cbor_source *source,
                    const lonejson_map *map, const void *input_record,
                    void *output_record, size_t extent,
                    const lonejson_record_view *view, const c89cbor_sink *sink,
                    const c89cbor_options *options, int encode, int using_view,
                    c89cbor_conversion **out, c89cbor_error *error) {
  c89cbor_allocator allocator;
  void *storage;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(**out), &storage, &allocator);
  if (status == 0) {
    status = using_view ? initialize_view(runtime, storage, source, view, sink,
                                          options, encode, error)
                        : initialize_map(runtime, storage, source, map,
                                         input_record, output_record, extent,
                                         sink, options, NULL, encode, error);
    if (status == 0) {
      *out = storage;
      (*out)->lifetime.owned = 1;
    } else {
      allocator.free(allocator.context, storage);
    }
  }
  if (error != NULL && error->status == 0)
    error->status = status;
  return status;
}

int c89cbor_encode_map_init(c89cbor *runtime, c89cbor_conversion *conversion,
                            const lonejson_map *map, const void *record,
                            size_t extent, const c89cbor_sink *sink,
                            const c89cbor_options *options,
                            c89cbor_error *error) {
  return initialize_map(runtime, conversion, NULL, map, record, NULL, extent,
                        sink, options, NULL, 1, error);
}
int c89cbor_encode_map_open(c89cbor *runtime, const lonejson_map *map,
                            const void *record, size_t extent,
                            const c89cbor_sink *sink,
                            const c89cbor_options *options,
                            c89cbor_conversion **out, c89cbor_error *error) {
  return open_map(runtime, NULL, map, record, NULL, extent, NULL, sink, options,
                  1, 0, out, error);
}
int c89cbor_encode_map(c89cbor *runtime, const lonejson_map *map,
                       const void *record, size_t extent,
                       const c89cbor_sink *sink, const c89cbor_options *options,
                       c89cbor_error *error) {
  c89cbor_conversion conversion;
  int status = c89cbor_encode_map_init(runtime, &conversion, map, record,
                                       extent, sink, options, error);
  return status == 0 ? c89_conversion_run(&conversion, error) : status;
}

int c89cbor_encode_map_view_init(c89cbor *runtime,
                                 c89cbor_conversion *conversion,
                                 const lonejson_record_view *view,
                                 const c89cbor_sink *sink,
                                 const c89cbor_options *options,
                                 c89cbor_error *error) {
  return initialize_view(runtime, conversion, NULL, view, sink, options, 1,
                         error);
}
int c89cbor_encode_map_view_open(c89cbor *runtime,
                                 const lonejson_record_view *view,
                                 const c89cbor_sink *sink,
                                 const c89cbor_options *options,
                                 c89cbor_conversion **out,
                                 c89cbor_error *error) {
  return open_map(runtime, NULL, NULL, NULL, NULL, 0, view, sink, options, 1, 1,
                  out, error);
}
int c89cbor_encode_map_view(c89cbor *runtime, const lonejson_record_view *view,
                            const c89cbor_sink *sink,
                            const c89cbor_options *options,
                            c89cbor_error *error) {
  c89cbor_conversion conversion;
  int status = c89cbor_encode_map_view_init(runtime, &conversion, view, sink,
                                            options, error);
  return status == 0 ? c89_conversion_run(&conversion, error) : status;
}

int c89cbor_decode_map_init(c89cbor *runtime, c89cbor_conversion *conversion,
                            const c89cbor_source *source,
                            const lonejson_map *map, void *record,
                            size_t extent, const c89cbor_options *options,
                            c89cbor_error *error) {
  return initialize_map(runtime, conversion, source, map, NULL, record, extent,
                        NULL, options, NULL, 0, error);
}
int c89cbor_decode_map_open(c89cbor *runtime, const c89cbor_source *source,
                            const lonejson_map *map, void *record,
                            size_t extent, const c89cbor_options *options,
                            c89cbor_conversion **out, c89cbor_error *error) {
  return open_map(runtime, source, map, NULL, record, extent, NULL, NULL,
                  options, 0, 0, out, error);
}
int c89cbor_decode_map(c89cbor *runtime, const c89cbor_source *source,
                       const lonejson_map *map, void *record, size_t extent,
                       const c89cbor_options *options, c89cbor_error *error) {
  c89cbor_conversion conversion;
  int status = c89cbor_decode_map_init(runtime, &conversion, source, map,
                                       record, extent, options, error);
  return status == 0 ? c89_conversion_run(&conversion, error) : status;
}

int c89cbor_decode_map_view_init(c89cbor *runtime,
                                 c89cbor_conversion *conversion,
                                 const c89cbor_source *source,
                                 const lonejson_record_view *view,
                                 const c89cbor_options *options,
                                 c89cbor_error *error) {
  return initialize_view(runtime, conversion, source, view, NULL, options, 0,
                         error);
}
int c89cbor_decode_map_view_open(c89cbor *runtime, const c89cbor_source *source,
                                 const lonejson_record_view *view,
                                 const c89cbor_options *options,
                                 c89cbor_conversion **out,
                                 c89cbor_error *error) {
  return open_map(runtime, source, NULL, NULL, NULL, 0, view, NULL, options, 0,
                  1, out, error);
}
int c89cbor_decode_map_view(c89cbor *runtime, const c89cbor_source *source,
                            const lonejson_record_view *view,
                            const c89cbor_options *options,
                            c89cbor_error *error) {
  c89cbor_conversion conversion;
  int status = c89cbor_decode_map_view_init(runtime, &conversion, source, view,
                                            options, error);
  return status == 0 ? c89_conversion_run(&conversion, error) : status;
}
