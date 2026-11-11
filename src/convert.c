#define _GNU_SOURCE
#include "number.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* A queue holds bounded writer events, never a complete value. */
typedef struct conversion_frame {
  c89cbor_type type;
  size_t keys_start;
  size_t bytes_start;
  int indefinite;
  int key_text;
  int needs_key;
} conversion_frame;
typedef struct conversion_key {
  size_t offset;
  size_t length;
} conversion_key;
typedef struct conversion_state {
  c89_operation operation;
  c89cbor_encoder *encoder_target;
  int token_mode;
  c89cbor_conversion *owner;
  c89cbor_options options;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_allocator allocator;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_frame *wire_frames;
  conversion_frame *frames;
  conversion_key *keys;
  unsigned char *input;
  unsigned char *output;
  char *key;
  char *key_storage;
  char *number;
  size_t depth;
  size_t key_count;
  size_t key_storage_length;
  size_t key_length;
  size_t number_length;
  size_t input_offset;
  size_t input_length;
  size_t output_offset;
  size_t output_length;
  size_t output_capacity;
  size_t event_reserve;
  size_t events;
  int from_json;
  int eof;
  int root_complete;
  int done;
  int writer_ready;
  lonejson_value_visitor_stream *visitor;
  lonejson_writer writer;
  lonejson_error json_error;
  locale_t locale;
} conversion_state;

c89cbor_options c89cbor_default_options(void) {
  c89cbor_options options;
  memset(&options, 0, sizeof(options));
  return options;
}
c89cbor_options c89cbor_runtime_default_options(c89cbor *runtime) {
  (void)runtime;
  return c89cbor_default_options();
}
static int fail_conversion(conversion_state *state, int status,
                           const char *layer) {
  int first = state->owner->lifetime.error.status == 0;
  c89_error(&state->owner->lifetime, status, layer);
  if (first && status < 0 && !state->from_json)
    state->owner->lifetime.error.offset =
        state->decoder.lifetime.progress.input;
  return status;
}
static int dependency_result(conversion_state *state, lonejson_status status) {
  c89cbor_error *error = &state->owner->lifetime.error;
  int mapped;
  int existing = error->status != 0;
  if (status == LONEJSON_STATUS_OK || status == LONEJSON_STATUS_PAUSED)
    return C89CBOR_OK;
  if (status == LONEJSON_STATUS_ALLOCATION_FAILED)
    mapped = C89CBOR_NOMEM;
  else if (status == LONEJSON_STATUS_OVERFLOW ||
           status == LONEJSON_STATUS_TRUNCATED)
    mapped = C89CBOR_LIMIT;
  else if (status == LONEJSON_STATUS_UNSUPPORTED)
    mapped = C89CBOR_UNSUPPORTED;
  else if (status == LONEJSON_STATUS_IO_ERROR ||
           status == LONEJSON_STATUS_CALLBACK_FAILED)
    mapped = C89CBOR_IO;
  else
    mapped = C89CBOR_MALFORMED;
  if (error->status == 0)
    fail_conversion(state, mapped, "lonejson");
  error->cause = (int)status;
  error->system_errno = state->json_error.system_errno;
  if (state->json_error.offset != 0)
    error->offset = (uint64_t)state->json_error.offset;
  if (!existing && state->json_error.message[0] != '\0') {
    strncpy(error->message, state->json_error.message,
            sizeof(error->message) - 1u);
    error->message[sizeof(error->message) - 1u] = '\0';
  }
  return error->status;
}
static int append_output(conversion_state *state, const void *bytes,
                         size_t length) {
  if (length > state->output_capacity - state->output_length)
    return fail_conversion(state, C89CBOR_LIMIT, "output-queue");
  if (length != 0)
    memcpy(state->output + state->output_length, bytes, length);
  state->output_length += length;
  return C89CBOR_OK;
}
static lonejson_status writer_sink(void *context, const void *bytes,
                                   size_t length, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  return append_output(state, bytes, length) == 0 ? LONEJSON_STATUS_OK
                                                  : LONEJSON_STATUS_OVERFLOW;
}
static int encode_token(conversion_state *state, const c89cbor_token *token) {
  const void *bytes;
  size_t length;
  int status = state->encoder_target->put(state->encoder_target, token);
  if (status != 0)
    return fail_conversion(state, status, "encoder");
  while ((status = state->encoder_target->peek(state->encoder_target, &bytes,
                                               &length)) == C89CBOR_OUTPUT) {
    status = append_output(state, bytes, length);
    if (status != 0)
      return status;
    status = state->encoder_target->advance(state->encoder_target, length);
    if (status < 0)
      return fail_conversion(state, status, "encoder");
  }
  return status < 0 ? fail_conversion(state, status, "encoder") : C89CBOR_OK;
}
static int emit(conversion_state *state, c89cbor_type type, uint64_t argument,
                int indefinite, const void *data, size_t length) {
  c89cbor_token token;
  memset(&token, 0, sizeof(token));
  token.type = type;
  token.argument = argument;
  token.indefinite = indefinite;
  token.data = data;
  token.length = length;
  return encode_token(state, &token);
}
static int push_frame(conversion_state *state, c89cbor_type type,
                      int indefinite, int key_text) {
  conversion_frame *frame;
  if (state->depth == state->options.depth)
    return fail_conversion(state, C89CBOR_LIMIT, "conversion-depth");
  frame = &state->frames[state->depth++];
  memset(frame, 0, sizeof(*frame));
  frame->type = type;
  frame->indefinite = indefinite;
  frame->key_text = key_text;
  frame->needs_key = type == C89CBOR_MAP;
  frame->keys_start = state->key_count;
  frame->bytes_start = state->key_storage_length;
  return C89CBOR_OK;
}
static void value_complete(conversion_state *state) {
  if (state->depth != 0 && state->frames[state->depth - 1u].type == C89CBOR_MAP)
    state->frames[state->depth - 1u].needs_key = 1;
}
static void pop_frame(conversion_state *state) {
  conversion_frame *frame = &state->frames[state->depth - 1u];
  if (frame->type == C89CBOR_MAP) {
    state->key_count = frame->keys_start;
    state->key_storage_length = frame->bytes_start;
  }
  --state->depth;
}
static int append_key(conversion_state *state, const void *bytes,
                      size_t length) {
  if (length > state->options.key_bytes - state->key_length)
    return fail_conversion(state, C89CBOR_LIMIT, "object-key");
  if (length != 0)
    memcpy(state->key + state->key_length, bytes, length);
  state->key_length += length;
  return C89CBOR_OK;
}
static int commit_key(conversion_state *state, conversion_frame *frame) {
  size_t i;
  conversion_key *key;
  for (i = frame->keys_start; i < state->key_count; ++i) {
    key = &state->keys[i];
    if (key->length == state->key_length &&
        memcmp(state->key_storage + key->offset, state->key, key->length) == 0)
      return fail_conversion(state, C89CBOR_SCHEMA, "duplicate-key");
  }
  if (state->key_count == state->options.active_keys ||
      state->key_length >
          state->options.active_key_bytes - state->key_storage_length)
    return fail_conversion(state, C89CBOR_LIMIT, "active-keys");
  key = &state->keys[state->key_count++];
  key->offset = state->key_storage_length;
  key->length = state->key_length;
  memcpy(state->key_storage + key->offset, state->key, key->length);
  state->key_storage_length += key->length;
  frame->needs_key = 0;
  return C89CBOR_OK;
}
static lonejson_status callback_result(conversion_state *state, int status) {
  if (status != 0)
    return LONEJSON_STATUS_CALLBACK_FAILED;
  ++state->events;
  if (state->events >= state->options.step_events ||
      state->output_capacity - state->output_length < state->event_reserve)
    return LONEJSON_STATUS_PAUSED;
  return LONEJSON_STATUS_OK;
}
static int begin_json_container(conversion_state *state, c89cbor_type type) {
  int status = emit(state, type, 0, 1, NULL, 0);
  return status == 0 ? push_frame(state, type, 1, 0) : status;
}
static lonejson_status object_begin(void *context, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  return callback_result(state, begin_json_container(state, C89CBOR_MAP));
}
static lonejson_status array_begin(void *context, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  return callback_result(state, begin_json_container(state, C89CBOR_ARRAY));
}
static lonejson_status container_end(void *context, lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = emit(state, C89CBOR_END, state->frames[state->depth - 1u].type, 0,
                NULL, 0);
  if (status == 0) {
    pop_frame(state);
    value_complete(state);
  }
  return callback_result(state, status);
}
static lonejson_status key_begin(void *context, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  state->key_length = 0;
  return callback_result(state, C89CBOR_OK);
}
static lonejson_status key_chunk(void *context, const char *data, size_t length,
                                 lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  return callback_result(state, append_key(state, data, length));
}
static lonejson_status key_end(void *context, lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = commit_key(state, &state->frames[state->depth - 1u]);
  if (status == 0)
    status = emit(state, C89CBOR_TEXT, (uint64_t)state->key_length, 0, NULL, 0);
  if (status == 0)
    status = emit(state, C89CBOR_DATA, 0, 0, state->key, state->key_length);
  if (status == 0)
    status = emit(state, C89CBOR_END, C89CBOR_TEXT, 0, NULL, 0);
  return callback_result(state, status);
}
static lonejson_status string_begin(void *context, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  return callback_result(state, emit(state, C89CBOR_TEXT, 0, 1, NULL, 0));
}
static lonejson_status string_chunk(void *context, const char *data,
                                    size_t length, lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = emit(state, C89CBOR_TEXT, (uint64_t)length, 0, NULL, 0);
  if (status == 0)
    status = emit(state, C89CBOR_DATA, 0, 0, data, length);
  if (status == 0)
    status = emit(state, C89CBOR_END, C89CBOR_TEXT, 0, NULL, 0);
  return callback_result(state, status);
}
static lonejson_status string_end(void *context, lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = emit(state, C89CBOR_END, C89CBOR_TEXT, 0, NULL, 0);
  value_complete(state);
  return callback_result(state, status);
}
static lonejson_status number_begin(void *context, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  state->number_length = 0;
  return callback_result(state, C89CBOR_OK);
}
static lonejson_status number_chunk(void *context, const char *data,
                                    size_t length, lonejson_error *error) {
  conversion_state *state = context;
  (void)error;
  if (length > state->options.number_bytes - state->number_length) {
    fail_conversion(state, C89CBOR_LIMIT, "number");
    return LONEJSON_STATUS_CALLBACK_FAILED;
  }
  memcpy(state->number + state->number_length, data, length);
  state->number_length += length;
  state->number[state->number_length] = '\0';
  return callback_result(state, C89CBOR_OK);
}
static lonejson_status number_end(void *context, lonejson_error *error) {
  conversion_state *state = context;
  c89cbor_token token;
  int status;
  (void)error;
  status = c89_number_read(state->number, state->number_length, &token,
                           state->locale);
  if (status == 0)
    status = encode_token(state, &token);
  if (status != 0)
    fail_conversion(state, status, "number");
  value_complete(state);
  return callback_result(state, status);
}
static lonejson_status boolean_value(void *context, int value,
                                     lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = emit(state, C89CBOR_BOOL, value != 0, 0, NULL, 0);
  value_complete(state);
  return callback_result(state, status);
}
static lonejson_status null_value(void *context, lonejson_error *error) {
  conversion_state *state = context;
  int status;
  (void)error;
  status = emit(state, C89CBOR_NULL, 0, 0, NULL, 0);
  value_complete(state);
  return callback_result(state, status);
}

static int write_cbor_token(conversion_state *state,
                            const c89cbor_token *token) {
  conversion_frame *parent =
      state->depth == 0 ? NULL : &state->frames[state->depth - 1u];
  conversion_frame frame;
  lonejson_status status;
  int result, nested, is_key;
  char number[64];
  size_t length;
  if (token->type == C89CBOR_END) {
    if (parent == NULL)
      return fail_conversion(state, C89CBOR_MALFORMED, "container");
    frame = *parent;
    pop_frame(state);
    if (frame.type == C89CBOR_TEXT) {
      nested = state->depth != 0 &&
               state->frames[state->depth - 1u].type == C89CBOR_TEXT;
      if (nested)
        return C89CBOR_OK;
      if (frame.key_text) {
        parent = &state->frames[state->depth - 1u];
        result = commit_key(state, parent);
        if (result != 0)
          return result;
        status = lonejson_writer_key(&state->writer, state->key,
                                     state->key_length, &state->json_error);
        return dependency_result(state, status);
      }
      status = lonejson_writer_string_end(&state->writer, &state->json_error);
    } else if (frame.type == C89CBOR_MAP) {
      status = lonejson_writer_end_object(&state->writer, &state->json_error);
    } else if (frame.type == C89CBOR_ARRAY) {
      status = lonejson_writer_end_array(&state->writer, &state->json_error);
    } else {
      return fail_conversion(state, C89CBOR_UNSUPPORTED, "plain-json");
    }
    value_complete(state);
    return dependency_result(state, status);
  }
  if (token->type == C89CBOR_DATA) {
    if (parent == NULL || parent->type != C89CBOR_TEXT)
      return fail_conversion(state, C89CBOR_UNSUPPORTED, "plain-json");
    if (parent->key_text)
      return append_key(state, token->data, token->length);
    status = lonejson_writer_string_chunk(&state->writer, token->data,
                                          token->length, &state->json_error);
    return dependency_result(state, status);
  }
  is_key = parent != NULL && parent->type == C89CBOR_MAP && parent->needs_key;
  if (is_key && token->type != C89CBOR_TEXT)
    return fail_conversion(state, C89CBOR_UNSUPPORTED, "non-text-key");
  if (token->type == C89CBOR_TEXT) {
    nested = parent != NULL && parent->type == C89CBOR_TEXT;
    if (nested)
      is_key = parent->key_text;
    if (!nested) {
      if (is_key) {
        state->key_length = 0;
      } else {
        status =
            lonejson_writer_string_begin(&state->writer, &state->json_error);
        result = dependency_result(state, status);
        if (result != 0)
          return result;
      }
    }
    return push_frame(state, C89CBOR_TEXT, token->indefinite, is_key);
  }
  if (token->type == C89CBOR_MAP || token->type == C89CBOR_ARRAY) {
    status =
        token->type == C89CBOR_MAP
            ? lonejson_writer_begin_object(&state->writer, &state->json_error)
            : lonejson_writer_begin_array(&state->writer, &state->json_error);
    result = dependency_result(state, status);
    return result == 0 ? push_frame(state, token->type, token->indefinite, 0)
                       : result;
  }
  if (token->type == C89CBOR_BOOL) {
    status = lonejson_writer_bool(&state->writer, token->argument != 0,
                                  &state->json_error);
  } else if (token->type == C89CBOR_NULL) {
    status = lonejson_writer_null(&state->writer, &state->json_error);
  } else if (token->type == C89CBOR_UINT || token->type == C89CBOR_NEGATIVE ||
             (token->type >= C89CBOR_FLOAT16 &&
              token->type <= C89CBOR_FLOAT64)) {
    result = c89_number_format(token, number, &length, state->locale);
    if (result != 0)
      return fail_conversion(state, result, "number");
    status = lonejson_writer_number_text(&state->writer, number, length,
                                         &state->json_error);
  } else {
    return fail_conversion(state, C89CBOR_UNSUPPORTED, "plain-json");
  }
  value_complete(state);
  return dependency_result(state, status);
}

static int read_input(conversion_state *state) {
  size_t count = 0;
  size_t offered = state->options.chunk;
  int status, saved_errno = errno, endpoint_errno;
  if (offered > state->options.step_input)
    offered = state->options.step_input;
  errno = 0;
  status =
      state->source.read(state->source.context, state->input, offered, &count);
  endpoint_errno = errno;
  errno = saved_errno;
  if (count > offered || (status == C89CBOR_INPUT && count != 0))
    return fail_conversion(state, C89CBOR_IO, "source-contract");
  state->owner->lifetime.progress.input += (uint64_t)count;
  state->input_offset = 0;
  state->input_length = count;
  if (status == C89CBOR_INPUT)
    return status;
  if (status != C89CBOR_OK) {
    fail_conversion(state, C89CBOR_IO, "source");
    state->owner->lifetime.error.cause = status;
    state->owner->lifetime.error.system_errno = endpoint_errno;
    return C89CBOR_IO;
  }
  if (count == 0)
    state->eof = 1;
  return C89CBOR_OK;
}
static int flush_output(conversion_state *state) {
  size_t offered = state->output_length - state->output_offset, count = 0;
  int status, saved_errno = errno, endpoint_errno;
  if (offered > state->options.step_output)
    offered = state->options.step_output;
  errno = 0;
  status =
      state->sink.write(state->sink.context,
                        state->output + state->output_offset, offered, &count);
  endpoint_errno = errno;
  errno = saved_errno;
  if (count > offered)
    return fail_conversion(state, C89CBOR_IO, "sink-contract");
  state->output_offset += count;
  state->owner->lifetime.progress.output += (uint64_t)count;
  if (state->output_offset == state->output_length)
    state->output_offset = state->output_length = 0;
  if (status == C89CBOR_OUTPUT)
    return status;
  if (status != C89CBOR_OK || count == 0) {
    fail_conversion(state, C89CBOR_IO, "sink");
    state->owner->lifetime.error.cause = status;
    state->owner->lifetime.error.system_errno = endpoint_errno;
    return C89CBOR_IO;
  }
  return C89CBOR_OK;
}
static int drive_json(conversion_state *state) {
  lonejson_status status;
  size_t consumed = 0;
  int result;
  state->events = 0;
  if (state->input_offset == state->input_length && !state->eof) {
    status = state->visitor->push(state->visitor, NULL, 0, &consumed,
                                  &state->json_error);
    result = dependency_result(state, status);
    if (result != 0)
      return result;
    if (status == LONEJSON_STATUS_PAUSED || state->output_length != 0)
      return C89CBOR_OK;
    result = read_input(state);
    if (result != 0)
      return result;
  }
  if (state->eof) {
    status = state->visitor->finish(state->visitor, &state->json_error);
    result = dependency_result(state, status);
    if (result != 0)
      return result;
    if (status == LONEJSON_STATUS_OK) {
      result = state->encoder_target == &state->encoder
                   ? state->encoder.finish(&state->encoder)
                   : C89CBOR_OK;
      if (result != 0)
        return fail_conversion(state, result, "encoder");
      state->root_complete = 1;
    }
  } else {
    status =
        state->visitor->push(state->visitor, state->input + state->input_offset,
                             state->input_length - state->input_offset,
                             &consumed, &state->json_error);
    state->input_offset += consumed;
    result = dependency_result(state, status);
    if (result != 0)
      return result;
  }
  return C89CBOR_OK;
}
static int drive_cbor(conversion_state *state) {
  c89cbor_token token;
  size_t consumed;
  int status, result, read_done = 0;
  state->events = 0;
  while (state->events < state->options.step_events &&
         state->output_capacity - state->output_length >=
             state->event_reserve) {
    status = state->decoder.next(
        &state->decoder, state->input + state->input_offset,
        state->input_length - state->input_offset, &consumed, &token);
    state->input_offset += consumed;
    if (status < 0) {
      fail_conversion(state, status, "decoder");
      state->owner->lifetime.error.offset =
          state->decoder.lifetime.progress.input;
      return status;
    }
    if (status == C89CBOR_TOKEN) {
      result = write_cbor_token(state, &token);
      if (result != 0)
        return result;
      ++state->events;
    } else if (status == C89CBOR_DONE) {
      if (state->input_offset != state->input_length)
        return fail_conversion(state, C89CBOR_MALFORMED, "trailing-cbor");
      if (!state->eof && !read_done) {
        result = read_input(state);
        if (result != 0)
          return result;
        if (state->input_length != 0)
          return fail_conversion(state, C89CBOR_MALFORMED, "trailing-cbor");
      }
      if (state->eof) {
        result = state->decoder.finish(&state->decoder);
        if (result != 0)
          return fail_conversion(state, result, "decoder");
        result = dependency_result(
            state, lonejson_writer_finish(&state->writer, &state->json_error));
        if (result != 0)
          return result;
        state->root_complete = 1;
      }
      return C89CBOR_OK;
    } else {
      if (state->eof)
        return fail_conversion(state, C89CBOR_MALFORMED, "truncated-cbor");
      if (read_done)
        return C89CBOR_OK;
      result = read_input(state);
      read_done = 1;
      if (result != 0)
        return result;
    }
  }
  return C89CBOR_OK;
}

static int advance_json(void *context) {
  conversion_state *state = context;
  c89cbor_conversion *conversion = state->owner;
  int status;
  if (state->done)
    return C89CBOR_DONE;
  if (state->output_length != 0) {
    status = flush_output(state);
  } else if (state->root_complete) {
    status = C89CBOR_OK;
  } else if (state->token_mode) {
    status = C89CBOR_INPUT;
  } else {
    status = state->from_json ? drive_json(state) : drive_cbor(state);
    if (status == 0 && state->output_length != 0)
      status = flush_output(state);
  }
  if ((status == C89CBOR_OK || status == C89CBOR_OUTPUT) &&
      state->root_complete && state->output_length == 0) {
    state->done = 1;
    conversion->lifetime.progress.records = 1;
    status = C89CBOR_DONE;
  }
  return status;
}
int c89cbor_conversion_step(c89cbor_conversion *conversion,
                            c89cbor_error *error) {
  c89_operation *operation;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (conversion == NULL || conversion->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (conversion->lifetime.busy)
    return C89CBOR_BUSY;
  if (conversion->lifetime.error.status != 0) {
    if (error != NULL)
      *error = conversion->lifetime.error;
    return conversion->lifetime.error.status;
  }
  operation = conversion->state;
  if (!conversion->lifetime.live || operation == NULL)
    return C89CBOR_INVALID;
  conversion->lifetime.busy = 1;
  status = operation->step(conversion->state);
  conversion->lifetime.busy = 0;
  if (error != NULL)
    *error = conversion->lifetime.error;
  return status;
}
int c89cbor_conversion_progress(const c89cbor_conversion *conversion,
                                c89cbor_progress *progress) {
  if (progress != NULL)
    memset(progress, 0, sizeof(*progress));
  if (conversion == NULL || progress == NULL ||
      conversion->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  *progress = conversion->lifetime.progress;
  return C89CBOR_OK;
}
int c89cbor_conversion_diagnostic(const c89cbor_conversion *conversion,
                                  c89cbor_error *error) {
  return c89_lifetime_diagnostic(
      conversion == NULL ? NULL : &conversion->lifetime, error);
}
static void release_state(void *context) {
  conversion_state *state = context;
  c89cbor_allocator allocator = state->allocator;
  if (state->visitor != NULL)
    state->visitor->close(state->visitor);
  if (state->writer_ready)
    lonejson_writer_cleanup(&state->writer);
  if (state->locale != (locale_t)0)
    freelocale(state->locale);
  if (state->wire_frames != NULL)
    allocator.free(allocator.context, state->wire_frames);
  if (state->frames != NULL)
    allocator.free(allocator.context, state->frames);
  if (state->keys != NULL)
    allocator.free(allocator.context, state->keys);
  if (state->input != NULL)
    allocator.free(allocator.context, state->input);
  if (state->output != NULL)
    allocator.free(allocator.context, state->output);
  if (state->key != NULL)
    allocator.free(allocator.context, state->key);
  if (state->key_storage != NULL)
    allocator.free(allocator.context, state->key_storage);
  if (state->number != NULL)
    allocator.free(allocator.context, state->number);
  allocator.free(allocator.context, state);
}
int c89cbor_conversion_cleanup(c89cbor_conversion *conversion) {
  c89_operation *operation;
  void *state;
  int status;
  if (conversion == NULL)
    return C89CBOR_OK;
  if (conversion->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (conversion->lifetime.busy || conversion->lifetime.dependents)
    return C89CBOR_BUSY;
  state = conversion->state;
  conversion->state = NULL;
  if (state != NULL) {
    operation = state;
    operation->release(state);
  }
  status = c89_lifetime_cleanup(&conversion->lifetime);
  return status;
}
int c89cbor_conversion_destroy(c89cbor_conversion *conversion) {
  int status;
  if (conversion == NULL)
    return C89CBOR_OK;
  if (!conversion->lifetime.owned)
    return C89CBOR_INVALID;
  status = c89cbor_conversion_cleanup(conversion);
  return status == 0 ? c89_lifetime_destroy(&conversion->lifetime, conversion)
                     : status;
}

static void *allocate_part(conversion_state *state, size_t count, size_t size) {
  void *storage;
  if (state->owner->lifetime.error.status != 0)
    return NULL;
  if (count > (size_t)-1 / size) {
    fail_conversion(state, C89CBOR_LIMIT, "workspace-size");
    return NULL;
  }
  storage = state->allocator.alloc(state->allocator.context, count * size);
  if (storage == NULL)
    fail_conversion(state, C89CBOR_NOMEM, "workspace");
  return storage;
}
static int prepare_state(conversion_state *state, c89cbor *runtime) {
  size_t largest;
  lonejson_status json_status;
  lonejson_value_visitor visitor = lonejson_default_value_visitor();
  int status;
  if (state->options.chunk > (size_t)-1 - 4u ||
      state->options.number_bytes == (size_t)-1)
    return fail_conversion(state, C89CBOR_LIMIT, "workspace-size");
  largest = state->options.chunk + 4u;
  if (largest < state->options.key_bytes)
    largest = state->options.key_bytes;
  if (largest > ((size_t)-1 - 64u) / 6u)
    return fail_conversion(state, C89CBOR_LIMIT, "workspace-size");
  state->output_capacity = largest * 6u + 64u;
  state->event_reserve = largest + 32u;
  if (!state->from_json)
    state->event_reserve = state->output_capacity;
  state->wire_frames =
      allocate_part(state, state->options.depth, sizeof(*state->wire_frames));
  state->frames =
      allocate_part(state, state->options.depth, sizeof(*state->frames));
  state->keys =
      allocate_part(state, state->options.active_keys, sizeof(*state->keys));
  state->input = allocate_part(state, state->options.chunk, 1);
  state->output = allocate_part(state, state->output_capacity, 1);
  state->key = allocate_part(state, state->options.key_bytes, 1);
  state->key_storage = allocate_part(state, state->options.active_key_bytes, 1);
  state->number = allocate_part(state, state->options.number_bytes + 1u, 1);
  if (state->owner->lifetime.error.status != 0)
    return state->owner->lifetime.error.status;
  state->locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  if (state->locale == (locale_t)0)
    return fail_conversion(
        state, errno == ENOMEM ? C89CBOR_NOMEM : C89CBOR_UNSUPPORTED,
        "numeric-locale");
  if (runtime->json == NULL) {
    runtime->json = lonejson_new(&runtime->json_config, &state->json_error);
    if (runtime->json == NULL)
      return dependency_result(state, state->json_error.code);
    runtime->json_owned = 1;
  }
  if (state->from_json) {
    status = c89cbor_encoder_init(NULL, &state->encoder, state->wire_frames,
                                  state->options.depth, state->options.chunk);
    if (status != 0)
      return fail_conversion(state, status, "encoder");
    visitor.object_begin = object_begin;
    visitor.object_end = container_end;
    visitor.array_begin = array_begin;
    visitor.array_end = container_end;
    visitor.object_key_begin = key_begin;
    visitor.object_key_chunk = key_chunk;
    visitor.object_key_end = key_end;
    visitor.string_begin = string_begin;
    visitor.string_chunk = string_chunk;
    visitor.string_end = string_end;
    visitor.number_begin = number_begin;
    visitor.number_chunk = number_chunk;
    visitor.number_end = number_end;
    visitor.boolean_value = boolean_value;
    visitor.null_value = null_value;
    state->visitor = runtime->json->value_visitor_stream_open(
        runtime->json, &visitor, state, &state->json_error);
    if (state->visitor == NULL)
      return dependency_result(state, state->json_error.code);
  } else {
    status = c89cbor_decoder_init(NULL, &state->decoder, state->wire_frames,
                                  state->options.depth, state->options.chunk);
    if (status != 0)
      return fail_conversion(state, status, "decoder");
    json_status = lonejson_writer_init_sink(
        runtime->json, &state->writer, writer_sink, state, &state->json_error);
    if (json_status != LONEJSON_STATUS_OK)
      return dependency_result(state, json_status);
    state->writer_ready = 1;
  }
  return C89CBOR_OK;
}
int c89_conversion_prepare(c89cbor *runtime, c89cbor_conversion *conversion,
                           c89cbor_error *error) {
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (conversion == NULL) {
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  memset(conversion, 0, sizeof(*conversion));
  conversion->step = c89cbor_conversion_step;
  conversion->progress = c89cbor_conversion_progress;
  conversion->diagnostic = c89cbor_conversion_diagnostic;
  conversion->cleanup = c89cbor_conversion_cleanup;
  conversion->destroy = c89cbor_conversion_destroy;
  status = c89_lifetime_init(&conversion->lifetime, runtime, NULL);
  if (status == 0 && runtime == NULL) {
    (void)c89_lifetime_cleanup(&conversion->lifetime);
    status = C89CBOR_INVALID;
  }
  if (status != 0 && error != NULL)
    error->status = status;
  return status;
}

static int initialize_conversion(c89cbor *runtime,
                                 c89cbor_conversion *conversion,
                                 const c89cbor_source *source,
                                 const c89cbor_sink *sink,
                                 const c89cbor_options *options, int from_json,
                                 c89cbor_error *error) {
  conversion_state *state;
  int status;
  status = c89_conversion_prepare(runtime, conversion, error);
  if (status != 0)
    return status;
  if (runtime == NULL || source == NULL || sink == NULL ||
      source->read == NULL || sink->write == NULL) {
    (void)c89cbor_conversion_cleanup(conversion);
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  state = conversion->lifetime.allocator.alloc(
      conversion->lifetime.allocator.context, sizeof(*state));
  if (state == NULL) {
    status = c89_error(&conversion->lifetime, C89CBOR_NOMEM, "conversion");
  } else {
    memset(state, 0, sizeof(*state));
    conversion->state = state;
    state->operation.step = advance_json;
    state->operation.release = release_state;
    state->encoder_target = &state->encoder;
    state->owner = conversion;
    state->allocator = conversion->lifetime.allocator;
    state->source = *source;
    state->sink = *sink;
    state->from_json = from_json;
    c89_options_resolve(runtime, options, &state->options);
    status = prepare_state(state, runtime);
  }
  if (status != 0)
    (void)c89cbor_conversion_cleanup(conversion);
  if (error != NULL)
    *error = conversion->lifetime.error;
  return status;
}
static int open_conversion(c89cbor *runtime, const c89cbor_source *source,
                           const c89cbor_sink *sink,
                           const c89cbor_options *options, int from_json,
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
    status = initialize_conversion(runtime, storage, source, sink, options,
                                   from_json, error);
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
int c89_conversion_run(c89cbor_conversion *conversion, c89cbor_error *error) {
  int status;
  do {
    status = conversion->step(conversion, error);
  } while (status == C89CBOR_OK);
  if (status == C89CBOR_INPUT || status == C89CBOR_OUTPUT) {
    status =
        c89_error(&conversion->lifetime, C89CBOR_IO, "synchronous-endpoint");
    if (error != NULL)
      *error = conversion->lifetime.error;
  }
  (void)conversion->cleanup(conversion);
  return status == C89CBOR_DONE ? C89CBOR_OK : status;
}
static int synchronous_conversion(c89cbor *runtime,
                                  const c89cbor_source *source,
                                  const c89cbor_sink *sink,
                                  const c89cbor_options *options, int from_json,
                                  c89cbor_error *error) {
  c89cbor_conversion conversion;
  int status = initialize_conversion(runtime, &conversion, source, sink,
                                     options, from_json, error);
  return status == 0 ? c89_conversion_run(&conversion, error) : status;
}
int c89cbor_json_to_cbor_init(c89cbor *runtime, c89cbor_conversion *conversion,
                              const c89cbor_source *source,
                              const c89cbor_sink *sink,
                              const c89cbor_options *options,
                              c89cbor_error *error) {
  return initialize_conversion(runtime, conversion, source, sink, options, 1,
                               error);
}
int c89cbor_cbor_to_json_init(c89cbor *runtime, c89cbor_conversion *conversion,
                              const c89cbor_source *source,
                              const c89cbor_sink *sink,
                              const c89cbor_options *options,
                              c89cbor_error *error) {
  return initialize_conversion(runtime, conversion, source, sink, options, 0,
                               error);
}
int c89cbor_json_to_cbor_open(c89cbor *runtime, const c89cbor_source *source,
                              const c89cbor_sink *sink,
                              const c89cbor_options *options,
                              c89cbor_conversion **out, c89cbor_error *error) {
  return open_conversion(runtime, source, sink, options, 1, out, error);
}
int c89cbor_cbor_to_json_open(c89cbor *runtime, const c89cbor_source *source,
                              const c89cbor_sink *sink,
                              const c89cbor_options *options,
                              c89cbor_conversion **out, c89cbor_error *error) {
  return open_conversion(runtime, source, sink, options, 0, out, error);
}
int c89cbor_json_to_cbor(c89cbor *runtime, const c89cbor_source *source,
                         const c89cbor_sink *sink,
                         const c89cbor_options *options, c89cbor_error *error) {
  return synchronous_conversion(runtime, source, sink, options, 1, error);
}
int c89cbor_cbor_to_json(c89cbor *runtime, const c89cbor_source *source,
                         const c89cbor_sink *sink,
                         const c89cbor_options *options, c89cbor_error *error) {
  return synchronous_conversion(runtime, source, sink, options, 0, error);
}

int c89_json_encode_init(c89cbor *runtime, c89cbor_conversion *conversion,
                         const c89cbor_source *source, const c89cbor_sink *sink,
                         const c89cbor_options *options,
                         c89cbor_encoder *encoder, c89cbor_error *error) {
  conversion_state *state;
  int status = initialize_conversion(runtime, conversion, source, sink, options,
                                     1, error);
  if (status != 0)
    return status;
  if (encoder == NULL || encoder->state.frames == NULL) {
    (void)conversion->cleanup(conversion);
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  state = conversion->state;
  state->encoder_target = encoder;
  return C89CBOR_OK;
}
static int await_tokens(void *context, void *buffer, size_t capacity,
                        size_t *count) {
  (void)context;
  (void)buffer;
  (void)capacity;
  *count = 0;
  return C89CBOR_INPUT;
}
int c89_json_decode_init(c89cbor *runtime, c89cbor_conversion *conversion,
                         const c89cbor_sink *sink,
                         const c89cbor_options *options, c89cbor_error *error) {
  c89cbor_source source;
  conversion_state *state;
  int status;
  source.context = NULL;
  source.read = await_tokens;
  status = initialize_conversion(runtime, conversion, &source, sink, options, 0,
                                 error);
  if (status != 0)
    return status;
  state = conversion->state;
  state->token_mode = 1;
  return C89CBOR_OK;
}
int c89_json_decode_put(c89cbor_conversion *conversion,
                        const c89cbor_token *token, c89cbor_error *error) {
  conversion_state *state;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (conversion == NULL || conversion->state == NULL || token == NULL)
    return C89CBOR_INVALID;
  state = conversion->state;
  if (!state->token_mode || state->root_complete)
    return C89CBOR_INVALID;
  if (conversion->lifetime.error.status != 0)
    return conversion->lifetime.error.status;
  if (state->output_length != 0)
    return C89CBOR_OUTPUT;
  status = write_cbor_token(state, token);
  if (status == 0 && state->depth == 0) {
    status = dependency_result(
        state, lonejson_writer_finish(&state->writer, &state->json_error));
    if (status == 0)
      state->root_complete = 1;
  }
  if (error != NULL)
    *error = conversion->lifetime.error;
  return status;
}
