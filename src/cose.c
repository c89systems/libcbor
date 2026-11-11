#include "cose_internal.h"
#include <string.h>
#include <limits.h>
#include <errno.h>

c89cbor_cose_options c89cbor_default_cose_options(void) {
  c89cbor_cose_options options;
  memset(&options, 0, sizeof(options));
  options.record_bytes = C89CBOR_CHUNK;
  options.header_bytes = C89CBOR_CHUNK;
  options.recipients = 8u;
  return options;
}
c89cbor_cose_options c89cbor_runtime_default_cose_options(c89cbor *runtime) {
  (void)runtime;
  return c89cbor_default_cose_options();
}
static int fail(c89_cose_state *state, int status, const char *layer) {
  if (state->workspace != NULL)
    OPENSSL_cleanse(state->workspace, state->workspace_size);
  OPENSSL_cleanse(state->stream_key, sizeof(state->stream_key));
  OPENSSL_cleanse(state->input, sizeof(state->input));
  if (state->cipher_context != NULL)
    (void)EVP_CIPHER_CTX_reset(state->cipher_context);
  return c89_error(&state->owner->lifetime, status, layer);
}
static void release(void *context) {
  c89_cose_state *state = context;
  c89cbor_allocator allocator = state->allocator;
  size_t i;
  EVP_CIPHER_CTX_free(state->cipher_context);
  (void)c89cbor_decoder_cleanup(&state->framer);
  for (i = 0; i < state->key_count; ++i)
    --state->keys[i]->lifetime.dependents;
  if (state->workspace != NULL) {
    OPENSSL_cleanse(state->workspace, state->workspace_size);
    allocator.free(allocator.context, state->workspace);
  }
  if (state->recipients != NULL) {
    OPENSSL_cleanse(state->recipients,
                    state->options.recipients * sizeof(*state->recipients));
    allocator.free(allocator.context, state->recipients);
  }
  OPENSSL_cleanse(state, sizeof(*state));
  allocator.free(allocator.context, state);
}
static int read_input(c89_cose_state *state, size_t *budget, int *waiting) {
  size_t count = 0, offered = sizeof(state->input);
  int status;
  if (*waiting)
    return C89CBOR_INPUT;
  if (*budget == 0)
    return C89CBOR_OK;
  if (offered > *budget)
    offered = *budget;
  if (UINT64_MAX - state->owner->lifetime.progress.input < (uint64_t)offered)
    offered = (size_t)(UINT64_MAX - state->owner->lifetime.progress.input);
  if (offered == 0)
    return fail(state, C89CBOR_LIMIT, "cose-input-count");
  status =
      state->source.read(state->source.context, state->input, offered, &count);
  if (count > offered || (status > 0 && status != C89CBOR_INPUT))
    return fail(state, C89CBOR_IO, "cose-source-contract");
  state->input_length = count;
  state->input_offset = 0;
  state->owner->lifetime.progress.input += (uint64_t)count;
  *budget -= count;
  if (status < 0) {
    state->owner->lifetime.error.system_errno = errno;
    return fail(state, C89CBOR_IO, "cose-source");
  }
  if (status == C89CBOR_INPUT)
    *waiting = 1;
  else if (count == 0)
    state->eof = 1;
  return C89CBOR_OK;
}
static int drain_output(c89_cose_state *state, size_t *budget) {
  size_t offered = state->output_length - state->output_offset, count = 0;
  int status;
  if (offered == 0)
    return C89CBOR_DONE;
  if (*budget == 0)
    return C89CBOR_OK;
  if (offered > *budget)
    offered = *budget;
  if (UINT64_MAX - state->owner->lifetime.progress.output < (uint64_t)offered)
    offered = (size_t)(UINT64_MAX - state->owner->lifetime.progress.output);
  if (offered == 0)
    return fail(state, C89CBOR_LIMIT, "cose-output-count");
  status =
      state->sink.write(state->sink.context,
                        state->output + state->output_offset, offered, &count);
  if (count > offered || (status > 0 && status != C89CBOR_OUTPUT) ||
      (status == C89CBOR_OK && count == 0))
    return fail(state, C89CBOR_IO, "cose-sink-contract");
  state->output_offset += count;
  *budget -= count;
  state->owner->lifetime.progress.output += (uint64_t)count;
  if (status < 0) {
    state->owner->lifetime.error.system_errno = errno;
    return fail(state, C89CBOR_IO, "cose-sink");
  }
  return status;
}
static int reset_record(c89_cose_state *state) {
  state->ready = 0;
  state->wire_length = 0;
  state->plain_length = 0;
  state->output_length = state->output_offset = 0;
  if (state->sequence == UINT64_MAX)
    return fail(state, C89CBOR_LIMIT, "cose-sequence");
  ++state->sequence;
  (void)c89cbor_decoder_cleanup(&state->framer);
  return c89cbor_decoder_init(NULL, &state->framer, NULL, 0, 0);
}
static int advance(void *context) {
  c89_cose_state *state = context;
  size_t input_budget = state->options.step_input,
         output_budget = state->options.step_output;
  size_t events = state->options.step_events, take, used;
  c89cbor_token token;
  int status, waiting = 0;
  if (state->finished)
    return C89CBOR_DONE;
  while (events != 0) {
    if (state->ready == 2) {
      if (state->input_offset != state->input_length)
        return fail(state, C89CBOR_MALFORMED, "cose-trailing-input");
      if (!state->eof) {
        if (input_budget == 0)
          return C89CBOR_OK;
        status = read_input(state, &input_budget, &waiting);
        if (status != 0)
          return status;
        if (state->input_length != 0)
          return fail(state, C89CBOR_MALFORMED, "cose-trailing-input");
        if (!state->eof)
          return C89CBOR_INPUT;
      }
      state->ready = 1;
    }
    if (state->ready == 1) {
      if (state->owner->lifetime.progress.records == UINT64_MAX)
        return fail(state, C89CBOR_LIMIT, "cose-record-count");
      status = drain_output(state, &output_budget);
      if (status == C89CBOR_OUTPUT || status < 0)
        return status;
      if (state->output_offset != state->output_length)
        return C89CBOR_OK;
      ++state->owner->lifetime.progress.records;
      --events;
      if (state->after_output) {
        state->finished = 1;
        return C89CBOR_DONE;
      }
      status = reset_record(state);
      if (status != 0)
        return status;
      continue;
    }
    if (state->seal) {
      take = state->input_length - state->input_offset;
      if (take > state->options.record_bytes - state->plain_length)
        take = state->options.record_bytes - state->plain_length;
      if (take != 0) {
        memcpy(state->plain + state->plain_length,
               state->input + state->input_offset, take);
        state->plain_length += take;
        state->input_offset += take;
      }
      if (state->plain_length == state->options.record_bytes &&
          !state->stream && state->input_offset != state->input_length)
        return fail(state, C89CBOR_LIMIT, "cose-plaintext-limit");
      if ((state->stream &&
           state->plain_length == state->options.record_bytes) ||
          state->eof) {
        state->record_final = state->eof;
        if (state->stream && state->sequence == UINT64_MAX &&
            !state->record_final)
          return fail(state, C89CBOR_LIMIT, "cose-sequence");
        status = c89_cose_seal_record(state);
        if (status != 0)
          return fail(state, status, "cose-seal");
        state->after_output = !state->stream || state->record_final;
        state->ready = 1;
        --events;
        continue;
      }
    } else {
      status = c89cbor_decoder_next(
          &state->framer, state->input + state->input_offset,
          state->input_length - state->input_offset, &used, &token);
      if (used > state->wire_capacity - state->wire_length)
        return fail(state, C89CBOR_LIMIT, "cose-wire-limit");
      if (used != 0)
        memcpy(state->wire + state->wire_length,
               state->input + state->input_offset, used);
      state->wire_length += used;
      state->input_offset += used;
      if (status < 0)
        return fail(state, status, "cose-framing");
      if (status == C89CBOR_TOKEN) {
        --events;
        continue;
      }
      if (status == C89CBOR_DONE) {
        status = c89_cose_open_record(state);
        if (status != 0) {
          OPENSSL_cleanse(state->plain, state->options.record_bytes + 16u);
          return fail(state, status, "cose-open");
        }
        state->after_output = !state->stream || state->record_final;
        state->ready = state->after_output && state->require_eof ? 2 : 1;
        --events;
        continue;
      }
      if (state->input_offset != state->input_length)
        return fail(state, C89CBOR_MALFORMED, "cose-framing-progress");
      if (state->eof)
        return fail(state, C89CBOR_MALFORMED, "cose-truncated-input");
    }
    if (state->input_offset == state->input_length) {
      if (waiting)
        return C89CBOR_INPUT;
      if (input_budget == 0)
        return C89CBOR_OK;
      status = read_input(state, &input_budget, &waiting);
      if (status != 0)
        return status;
    }
  }
  return C89CBOR_OK;
}
static int resolve(c89cbor *runtime, const c89cbor_cose_options *options,
                   c89cbor_cose_options *out) {
  *out = options == NULL ? c89cbor_default_cose_options() : *options;
  if (out->record_bytes == 0)
    out->record_bytes = C89CBOR_CHUNK;
  if (out->header_bytes == 0)
    out->header_bytes = C89CBOR_CHUNK;
  if (out->recipients == 0)
    out->recipients = 8u;
  if (out->step_input == 0)
    out->step_input = runtime->step_input;
  if (out->step_output == 0)
    out->step_output = runtime->step_output;
  if (out->step_events == 0)
    out->step_events = runtime->step_events;
  if (out->recipients > C89_COSE_MAX_RECIPIENTS ||
      out->record_bytes > (size_t)INT_MAX - 16u ||
      out->record_bytes > ((size_t)-1 - 432u) / 3u ||
      out->header_bytes > ((size_t)-1 - 432u - out->record_bytes * 3u) / 8u)
    return C89CBOR_LIMIT;
  if ((out->aad == NULL && out->aad_length != 0) ||
      out->aad_length > out->header_bytes)
    return out->aad_length > out->header_bytes ? C89CBOR_LIMIT
                                               : C89CBOR_INVALID;
  return C89CBOR_OK;
}
static int allocate_workspace(c89_cose_state *state) {
  c89cbor_allocator selected;
  unsigned char *at;
  size_t record = state->options.record_bytes,
         header = state->options.header_bytes;
  int status;
  state->workspace_size = record * 3u + header * 8u + 432u;
  status = c89_allocate(state->runtime, NULL, state->workspace_size,
                        (void **)&state->workspace, &selected);
  if (status != 0)
    return status;
  at = state->workspace;
  state->plain = at;
  at += record + 16u;
  state->cipher = at;
  at += record + 16u;
  state->wire = at;
  state->wire_capacity = record + 16u + header;
  at += state->wire_capacity;
  state->arena.bytes = at;
  state->arena.capacity = header * 2u;
  at += state->arena.capacity;
  state->aad = at;
  state->aad_capacity = header * 2u + 128u;
  at += state->aad_capacity;
  state->external = at;
  state->external_capacity = header + 128u;
  at += state->external_capacity;
  state->kdf = at;
  state->kdf_capacity = header * 2u + 128u;
  status = c89_allocate(state->runtime, NULL,
                        state->options.recipients * sizeof(*state->recipients),
                        (void **)&state->recipients, &selected);
  if (status != 0)
    return status;
  state->cipher_context = EVP_CIPHER_CTX_new();
  if (state->cipher_context == NULL)
    return C89CBOR_NOMEM;
  return c89cbor_decoder_init(NULL, &state->framer, NULL, 0, 0);
}
int c89cbor_cose_operation_step(c89cbor_cose_operation *operation,
                                c89cbor_error *error) {
  return c89cbor_conversion_step(
      operation == NULL ? NULL : &operation->conversion, error);
}
int c89cbor_cose_operation_progress(const c89cbor_cose_operation *operation,
                                    c89cbor_progress *progress) {
  return c89cbor_conversion_progress(
      operation == NULL ? NULL : &operation->conversion, progress);
}
int c89cbor_cose_operation_diagnostic(const c89cbor_cose_operation *operation,
                                      c89cbor_error *error) {
  return c89cbor_conversion_diagnostic(
      operation == NULL ? NULL : &operation->conversion, error);
}
int c89cbor_cose_operation_cleanup(c89cbor_cose_operation *operation) {
  return c89cbor_conversion_cleanup(operation == NULL ? NULL
                                                      : &operation->conversion);
}
int c89cbor_cose_operation_destroy(c89cbor_cose_operation *operation) {
  int status;
  if (operation == NULL)
    return C89CBOR_OK;
  if (operation->conversion.lifetime.magic != C89_LIFETIME_MAGIC ||
      !operation->owned)
    return C89CBOR_INVALID;
  status = c89cbor_cose_operation_cleanup(operation);
  if (status == 0)
    operation->conversion.lifetime.owned = 1;
  return status == 0
             ? c89_lifetime_destroy(&operation->conversion.lifetime, operation)
             : status;
}
int c89cbor_cose_operation_next(c89cbor_cose_operation *operation,
                                const c89cbor_sink *sink,
                                const c89cbor_cose_options *options,
                                c89cbor_error *error) {
  c89_cose_state *state;
  c89cbor_cose_options resolved;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (operation == NULL ||
      operation->conversion.lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (operation->conversion.lifetime.busy)
    return C89CBOR_BUSY;
  state = operation->conversion.state;
  if (state == NULL || !operation->conversion.lifetime.live ||
      operation->conversion.lifetime.error.status != 0 || !state->finished ||
      state->require_eof || (sink != NULL && sink->write == NULL))
    return C89CBOR_INVALID;
  if (state->seal)
    return C89CBOR_UNSUPPORTED;
  resolved = state->options;
  resolved.stream_id = NULL;
  if (options != NULL) {
    status = resolve(state->runtime, options, &resolved);
    if (status != 0)
      return status;
    if (resolved.record_bytes != state->options.record_bytes ||
        resolved.header_bytes != state->options.header_bytes ||
        resolved.recipients != state->options.recipients)
      return C89CBOR_INVALID;
  }
  state->options = resolved;
  if (sink != NULL)
    state->sink = *sink;
  state->have_id = resolved.stream_id != NULL;
  if (state->have_id)
    memcpy(state->stream_id, resolved.stream_id, 16u);
  state->sequence = 0;
  OPENSSL_cleanse(state->stream_key, sizeof(state->stream_key));
  state->stream_key_ready = state->recipients_ready = 0;
  state->seen_family = -1;
  state->finished = state->after_output = state->ready = 0;
  state->wire_length = state->plain_length = state->output_length =
      state->output_offset = 0;
  (void)c89cbor_decoder_cleanup(&state->framer);
  return c89cbor_decoder_init(NULL, &state->framer, NULL, 0, 0);
}
static int run_operation(c89cbor_cose_operation *operation,
                         c89cbor_error *error) {
  c89_cose_state *state = operation->conversion.state;
  int status;
  state->require_eof = !state->seal;
  do {
    status = operation->step(operation, error);
  } while (status == C89CBOR_OK);
  if (status == C89CBOR_INPUT || status == C89CBOR_OUTPUT) {
    status = c89_error(&operation->conversion.lifetime, C89CBOR_IO,
                       "synchronous-endpoint");
    if (error != NULL)
      *error = operation->conversion.lifetime.error;
  }
  (void)operation->cleanup(operation);
  return status == C89CBOR_DONE ? C89CBOR_OK : status;
}
int c89cbor_cose_operation_stream_info(const c89cbor_cose_operation *operation,
                                       c89cbor_cose_stream_info *info) {
  const c89_cose_state *state;
  if (info != NULL)
    memset(info, 0, sizeof(*info));
  if (operation == NULL || info == NULL ||
      operation->conversion.lifetime.magic != C89_LIFETIME_MAGIC ||
      !operation->conversion.lifetime.live ||
      operation->conversion.state == NULL)
    return C89CBOR_INVALID;
  state = operation->conversion.state;
  if (!state->stream || state->seal)
    return C89CBOR_UNSUPPORTED;
  if (state->seen_family < 0)
    return C89CBOR_INPUT;
  memcpy(info->stream_id, state->stream_id, 16u);
  info->encrypt = state->seen_family;
  info->complete = state->finished;
  return C89CBOR_OK;
}
static int initialize(c89cbor *runtime, c89cbor_cose_operation *conversion,
                      const c89cbor_source *source, const c89cbor_sink *sink,
                      c89cbor_cose_key *const *keys, size_t count,
                      const c89cbor_cose_options *options, int seal, int stream,
                      int encrypt, c89cbor_error *error) {
  c89_cose_state *state = NULL;
  c89cbor_conversion *driver;
  c89cbor_cose_options resolved;
  c89cbor_allocator selected;
  c89_cose_key_state *key;
  size_t i;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (conversion == NULL)
    return C89CBOR_INVALID;
  memset(conversion, 0, sizeof(*conversion));
  conversion->step = c89cbor_cose_operation_step;
  conversion->next = c89cbor_cose_operation_next;
  conversion->progress = c89cbor_cose_operation_progress;
  conversion->stream_info = c89cbor_cose_operation_stream_info;
  conversion->diagnostic = c89cbor_cose_operation_diagnostic;
  conversion->cleanup = c89cbor_cose_operation_cleanup;
  conversion->destroy = c89cbor_cose_operation_destroy;
  driver = &conversion->conversion;
  status = c89_conversion_prepare(runtime, driver, error);
  if (status != 0)
    return status;
  if (runtime == NULL || source == NULL || sink == NULL ||
      source->read == NULL || sink->write == NULL || keys == NULL ||
      count == 0 || count > C89_COSE_MAX_RECIPIENTS) {
    status = C89CBOR_INVALID;
    goto failed;
  }
  status = resolve(runtime, options, &resolved);
  if (status != 0)
    goto failed;
  if (stream && seal && resolved.nonce != NULL) {
    status = C89CBOR_INVALID;
    goto failed;
  }
  if (count > resolved.recipients || ((!seal || !encrypt) && count != 1u)) {
    status = count > resolved.recipients ? C89CBOR_LIMIT : C89CBOR_INVALID;
    goto failed;
  }
  for (i = 0; i < count; ++i) {
    if (!c89_cose_key_valid(keys[i])) {
      status = C89CBOR_INVALID;
      goto failed;
    }
    key = keys[i]->state;
    if (keys[i]->lifetime.busy || keys[i]->lifetime.dependents == (size_t)-1) {
      status = C89CBOR_BUSY;
      goto failed;
    }
    if ((seal && !encrypt && key->info.kind != C89CBOR_COSE_A256GCM) ||
        (seal && encrypt && key->info.kind != C89CBOR_COSE_A256KW &&
         key->info.kind != C89CBOR_COSE_X25519_PUBLIC) ||
        (!seal && key->info.kind == C89CBOR_COSE_X25519_PUBLIC)) {
      status = C89CBOR_INVALID;
      goto failed;
    }
  }
  driver->lifetime.busy = 1;
  status =
      c89_allocate(runtime, NULL, sizeof(*state), (void **)&state, &selected);
  if (status != 0)
    goto failed;
  memset(state, 0, sizeof(*state));
  driver->state = state;
  state->operation.step = advance;
  state->operation.release = release;
  state->owner = driver;
  state->runtime = runtime;
  state->allocator = driver->lifetime.allocator;
  state->source = *source;
  state->sink = *sink;
  state->options = resolved;
  state->seal = seal;
  state->stream = stream;
  state->encrypt = encrypt;
  state->seen_family = -1;
  if (options != NULL && options->stream_id != NULL) {
    memcpy(state->stream_id, options->stream_id, 16u);
    state->have_id = 1;
  } else if (stream && seal) {
    if (RAND_bytes_ex(NULL, state->stream_id, 16u, 0) != 1) {
      status = C89CBOR_CRYPTO;
      goto failed;
    }
    state->have_id = 1;
  }
  for (i = 0; i < count; ++i) {
    if (keys[i]->lifetime.dependents == (size_t)-1) {
      status = C89CBOR_LIMIT;
      goto failed;
    }
    state->keys[state->key_count++] = keys[i];
    ++keys[i]->lifetime.dependents;
  }
  status = allocate_workspace(state);
  if (status != 0)
    goto failed;
  driver->lifetime.busy = 0;
  return C89CBOR_OK;
failed:
  driver->lifetime.busy = 0;
  c89_error(&driver->lifetime, status, "cose-open");
  if (error != NULL) {
    *error = driver->lifetime.error;
    if (error->status == 0)
      error->status = status;
  }
  (void)c89cbor_conversion_cleanup(driver);
  return status;
}
static int open_operation(c89cbor *runtime, const c89cbor_source *source,
                          const c89cbor_sink *sink,
                          c89cbor_cose_key *const *keys, size_t count,
                          const c89cbor_cose_options *options, int seal,
                          int stream, int encrypt, c89cbor_cose_operation **out,
                          c89cbor_error *error) {
  c89cbor_cose_operation *conversion;
  c89cbor_allocator selected;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(*conversion),
                        (void **)&conversion, &selected);
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  status = initialize(runtime, conversion, source, sink, keys, count, options,
                      seal, stream, encrypt, error);
  if (status != 0) {
    selected.free(selected.context, conversion);
    return status;
  }
  conversion->owned = 1;
  *out = conversion;
  return C89CBOR_OK;
}
#define SINGLE_OPERATION(name, seal_value, stream_value)                       \
  int c89cbor_cose_##name##_init(                                              \
      c89cbor *runtime, c89cbor_cose_operation *conversion,                    \
      const c89cbor_source *source, const c89cbor_sink *sink,                  \
      c89cbor_cose_key *key, const c89cbor_cose_options *options,              \
      c89cbor_error *error) {                                                  \
    return initialize(runtime, conversion, source, sink, &key, 1u, options,    \
                      seal_value, stream_value, 0, error);                     \
  }                                                                            \
  int c89cbor_cose_##name##_open(                                              \
      c89cbor *runtime, const c89cbor_source *source,                          \
      const c89cbor_sink *sink, c89cbor_cose_key *key,                         \
      const c89cbor_cose_options *options, c89cbor_cose_operation **out,       \
      c89cbor_error *error) {                                                  \
    return open_operation(runtime, source, sink, &key, 1u, options,            \
                          seal_value, stream_value, 0, out, error);            \
  }                                                                            \
  int c89cbor_cose_##name(c89cbor *runtime, const c89cbor_source *source,      \
                          const c89cbor_sink *sink, c89cbor_cose_key *key,     \
                          const c89cbor_cose_options *options,                 \
                          c89cbor_error *error) {                              \
    c89cbor_cose_operation conversion;                                         \
    int status = c89cbor_cose_##name##_init(runtime, &conversion, source,      \
                                            sink, key, options, error);        \
    return status == 0 ? run_operation(&conversion, error) : status;           \
  }
SINGLE_OPERATION(encrypt0, 1, 0)
SINGLE_OPERATION(decrypt, 0, 0)
SINGLE_OPERATION(decrypt_stream, 0, 1)
#undef SINGLE_OPERATION
#define MULTI_OPERATION(name, stream_value)                                    \
  int c89cbor_cose_##name##_init(                                              \
      c89cbor *runtime, c89cbor_cose_operation *conversion,                    \
      const c89cbor_source *source, const c89cbor_sink *sink,                  \
      c89cbor_cose_key *const *keys, size_t count,                             \
      const c89cbor_cose_options *options, c89cbor_error *error) {             \
    return initialize(                                                         \
        runtime, conversion, source, sink, keys, count, options, 1,            \
        stream_value,                                                          \
        stream_value ? (options != NULL && options->encrypt) : 1, error);      \
  }                                                                            \
  int c89cbor_cose_##name##_open(                                              \
      c89cbor *runtime, const c89cbor_source *source,                          \
      const c89cbor_sink *sink, c89cbor_cose_key *const *keys, size_t count,   \
      const c89cbor_cose_options *options, c89cbor_cose_operation **out,       \
      c89cbor_error *error) {                                                  \
    return open_operation(                                                     \
        runtime, source, sink, keys, count, options, 1, stream_value,          \
        stream_value ? (options != NULL && options->encrypt) : 1, out, error); \
  }                                                                            \
  int c89cbor_cose_##name(                                                     \
      c89cbor *runtime, const c89cbor_source *source,                          \
      const c89cbor_sink *sink, c89cbor_cose_key *const *keys, size_t count,   \
      const c89cbor_cose_options *options, c89cbor_error *error) {             \
    c89cbor_cose_operation conversion;                                         \
    int status = c89cbor_cose_##name##_init(                                   \
        runtime, &conversion, source, sink, keys, count, options, error);      \
    return status == 0 ? run_operation(&conversion, error) : status;           \
  }
MULTI_OPERATION(encrypt, 0)
MULTI_OPERATION(encrypt_stream, 1)
#undef MULTI_OPERATION

void c89_cose_runtime_methods(c89cbor *runtime) {
  runtime->default_cose_options = c89cbor_runtime_default_cose_options;
  runtime->cose_key_init = c89cbor_cose_key_init;
  runtime->cose_key_create = c89cbor_cose_key_create;
  runtime->cose_encrypt0 = c89cbor_cose_encrypt0;
  runtime->cose_encrypt0_open = c89cbor_cose_encrypt0_open;
  runtime->cose_encrypt0_init = c89cbor_cose_encrypt0_init;
  runtime->cose_encrypt = c89cbor_cose_encrypt;
  runtime->cose_encrypt_open = c89cbor_cose_encrypt_open;
  runtime->cose_encrypt_init = c89cbor_cose_encrypt_init;
  runtime->cose_decrypt = c89cbor_cose_decrypt;
  runtime->cose_decrypt_open = c89cbor_cose_decrypt_open;
  runtime->cose_decrypt_init = c89cbor_cose_decrypt_init;
  runtime->cose_encrypt_stream = c89cbor_cose_encrypt_stream;
  runtime->cose_encrypt_stream_open = c89cbor_cose_encrypt_stream_open;
  runtime->cose_encrypt_stream_init = c89cbor_cose_encrypt_stream_init;
  runtime->cose_decrypt_stream = c89cbor_cose_decrypt_stream;
  runtime->cose_decrypt_stream_open = c89cbor_cose_decrypt_stream_open;
  runtime->cose_decrypt_stream_init = c89cbor_cose_decrypt_stream_init;
}
