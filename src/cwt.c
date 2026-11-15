#include "cwt_internal.h"
#include <string.h>
#include <limits.h>

/* These bounded memory operations reuse a private COSE engine. Key ownership
 * changes only during setup, never in the concurrent token processing path. */
static int crypt(c89_cwt_state *state, int seal, int auth,
                 c89cbor_cose_key *const *keys, size_t count, const void *input,
                 size_t length, void *output, size_t capacity, size_t bound,
                 size_t *written) {
  c89_cose_state *engine = &state->crypto;
  int status;
  *written = 0;
  /* Constructor and the preceding call already cleared scratch and counters.
   * Keep the single post-operation wipe on every success/failure path. */
  engine->options = state->options.cose;
  engine->options.record_bytes = bound;
  if (auth)
    engine->options.nonce = NULL;
  engine->seal = seal;
  engine->auth = auth;
  engine->encrypt = auth ? 0 : state->options.cose.encrypt;
  engine->seen_family = 0;
  engine->key_count = count;
  memcpy(engine->keys, keys, count * sizeof(*keys));
  if (seal) {
    memcpy(engine->plain, input, length);
    engine->plain_length = length;
  } else {
    memcpy(engine->wire, input, length);
    engine->wire_length = length;
  }
  status = auth   ? c89_cose_auth_record(engine)
           : seal ? c89_cose_seal_record(engine)
                  : c89_cose_open_record(engine);
  if (status == 0 && engine->output_length > capacity)
    status = C89CBOR_LIMIT;
  if (status == 0) {
    memcpy(output, engine->output, engine->output_length);
    *written = engine->output_length;
  }
  c89_cose_workspace_clear(engine);
  return status;
}
static int auth_key(c89cbor_cose_key *key, int seal) {
  c89cbor_cose_key_kind kind;
  if (!c89_cose_key_valid(key))
    return C89CBOR_INVALID;
  kind = ((c89_cose_key_state *)key->state)->info.kind;
  if (c89_cose_auth_algorithm(kind) == 0 ||
      (seal && (kind == C89CBOR_COSE_ED25519_PUBLIC ||
                kind == C89CBOR_COSE_P256_PUBLIC)))
    return C89CBOR_INVALID;
  return C89CBOR_OK;
}
c89cbor_cwt_options c89cbor_default_cwt_options(void) {
  c89cbor_cwt_options options;
  memset(&options, 0, sizeof(options));
  options.cose = c89cbor_default_cose_options();
  options.claims = 64u;
  options.audiences = 32u;
  return options;
}
c89cbor_cwt_options c89cbor_runtime_default_cwt_options(c89cbor *runtime) {
  (void)runtime;
  return c89cbor_default_cwt_options();
}
static int begin(c89cbor_cwt *receiver, c89cbor_error *error) {
  int status = C89CBOR_OK;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (receiver == NULL || receiver->lifetime.magic != C89_LIFETIME_MAGIC ||
      !receiver->lifetime.live || receiver->state == NULL)
    status = C89CBOR_INVALID;
  else if (receiver->lifetime.busy)
    status = C89CBOR_BUSY;
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  receiver->lifetime.busy = 1;
  memset(&receiver->lifetime.error, 0, sizeof(receiver->lifetime.error));
  return C89CBOR_OK;
}
static int finish(c89cbor_cwt *receiver, int status, c89cbor_error *error) {
  if (status != 0)
    (void)c89_error(&receiver->lifetime, status, "cwt");
  if (status != 0 && receiver->lifetime.error.status == 0) {
    receiver->lifetime.error.status = status;
    strcpy(receiver->lifetime.error.layer, "cwt");
  }
  if (error != NULL)
    *error = receiver->lifetime.error;
  receiver->lifetime.busy = 0;
  return status;
}
static void untrust(c89_cwt_state *state) {
  state->view.authenticated = 0;
  state->view.algorithm = 0;
}
int c89cbor_cwt_set_seal_keys(c89cbor_cwt *receiver, c89cbor_cose_key *signing,
                              c89cbor_cose_key *const *recipients, size_t count,
                              c89cbor_error *error) {
  c89cbor_cose_key *held[C89_COSE_MAX_RECIPIENTS + 1u];
  c89_cwt_state *state;
  c89cbor_cose_key_kind kind;
  size_t i, total = 0;
  int status = begin(receiver, error);
  if (status != 0)
    return status;
  state = receiver->state;
  if ((count != 0 && (recipients == NULL || signing == NULL)) ||
      (count == 0 && recipients != NULL))
    status = C89CBOR_INVALID;
  else if (count > state->options.cose.recipients)
    status = C89CBOR_LIMIT;
  else if (signing != NULL)
    status = auth_key(signing, 1);
  if (status == 0 && !state->options.cose.encrypt && count > 1u)
    status = C89CBOR_INVALID;
  for (i = 0; status == 0 && i < count; ++i) {
    if (!c89_cose_key_valid(recipients[i])) {
      status = C89CBOR_INVALID;
      break;
    }
    kind = ((c89_cose_key_state *)recipients[i]->state)->info.kind;
    if ((!state->options.cose.encrypt && kind != C89CBOR_COSE_A256GCM) ||
        (state->options.cose.encrypt && kind != C89CBOR_COSE_A256KW &&
         kind != C89CBOR_COSE_X25519_PUBLIC))
      status = C89CBOR_INVALID;
  }
  if (status == 0 && signing != NULL) {
    status = c89_cose_keys_hold(&signing, 1u, held);
    if (status == 0)
      total = 1u;
    if (status == 0 && count != 0) {
      status = c89_cose_keys_hold(recipients, count, held + 1u);
      if (status == 0)
        total += count;
    }
  }
  if (status == 0) {
    EVP_MAC_CTX *mac = EVP_MAC_CTX_new(state->crypto.mac);
    if (mac == NULL)
      status = C89CBOR_NOMEM;
    else {
      EVP_MAC_CTX_free(state->crypto.mac_context);
      state->crypto.mac_context = mac;
      c89_cose_keys_unhold(state->seal_keys, state->seal_count);
      memcpy(state->seal_keys, held, total * sizeof(*held));
      state->seal_count = total;
      total = 0;
      untrust(state);
    }
  }
  c89_cose_keys_unhold(held, total);
  return finish(receiver, status, error);
}
int c89cbor_cwt_set_verify_keys(c89cbor_cwt *receiver,
                                c89cbor_cose_key *verification,
                                c89cbor_cose_key *decryption,
                                c89cbor_error *error) {
  c89cbor_cose_key *keys[2], *held[2];
  c89_cwt_state *state;
  c89cbor_cose_key_kind kind;
  size_t count = verification == NULL ? 0u : decryption == NULL ? 1u : 2u;
  int status = begin(receiver, error);
  if (status != 0)
    return status;
  state = receiver->state;
  if (verification != NULL)
    status = auth_key(verification, 0);
  else if (decryption != NULL)
    status = C89CBOR_INVALID;
  if (status == 0 && decryption != NULL) {
    if (!c89_cose_key_valid(decryption))
      status = C89CBOR_INVALID;
    else {
      kind = ((c89_cose_key_state *)decryption->state)->info.kind;
      if (kind != C89CBOR_COSE_A256GCM && kind != C89CBOR_COSE_A256KW &&
          kind != C89CBOR_COSE_X25519_PRIVATE)
        status = C89CBOR_INVALID;
    }
  }
  keys[0] = verification;
  keys[1] = decryption;
  if (status == 0 && count != 0)
    status = c89_cose_keys_hold(keys, count, held);
  else
    count = 0;
  if (status == 0) {
    EVP_MAC_CTX *mac = EVP_MAC_CTX_new(state->crypto.mac);
    if (mac == NULL)
      status = C89CBOR_NOMEM;
    else {
      EVP_MAC_CTX_free(state->crypto.mac_context);
      state->crypto.mac_context = mac;
      c89_cose_keys_unhold(state->verify_keys, state->verify_count);
      memcpy(state->verify_keys, held, count * sizeof(*held));
      state->verify_count = count;
      count = 0;
      untrust(state);
    }
  } else
    count = 0;
  c89_cose_keys_unhold(held, count);
  return finish(receiver, status, error);
}
int c89cbor_cwt_view_get(const c89cbor_cwt *receiver, c89cbor_cwt_view *view) {
  const c89_cwt_state *state;
  if (view != NULL)
    memset(view, 0, sizeof(*view));
  if (receiver == NULL || receiver->lifetime.magic != C89_LIFETIME_MAGIC ||
      !receiver->lifetime.live || receiver->state == NULL || view == NULL)
    return C89CBOR_INVALID;
  if (receiver->lifetime.busy)
    return C89CBOR_BUSY;
  state = receiver->state;
  if (state->view.encoded == NULL)
    return C89CBOR_INPUT;
  *view = state->view;
  return C89CBOR_OK;
}
int c89cbor_cwt_set_claims(c89cbor_cwt *receiver, const void *bytes,
                           size_t length, c89cbor_error *error) {
  c89_cwt_state *state;
  int status = begin(receiver, error);
  if (status != 0)
    return status;
  state = receiver->state;
  if (bytes == NULL || length == 0)
    status = C89CBOR_INVALID;
  else if (length > state->options.cose.record_bytes)
    status = C89CBOR_LIMIT;
  else {
    memmove(state->raw, bytes, length);
    status = c89_cwt_parse(state, length);
  }
  if (status != 0)
    c89_cwt_clear(state);
  return finish(receiver, status, error);
}
int c89cbor_cwt_set_lonejson(c89cbor_cwt *receiver,
                             const lonejson_jwt_claims *claims, const void *id,
                             size_t id_length, c89cbor_error *error) {
  c89_cwt_state *state;
  size_t length;
  int status = begin(receiver, error);
  if (status != 0)
    return status;
  state = receiver->state;
  status = c89_cwt_encode(state, claims, id, id_length, &length);
  if (status == 0) {
    memcpy(state->raw, state->inner, length);
    status = c89_cwt_parse(state, length);
  }
  if (status != 0)
    c89_cwt_clear(state);
  return finish(receiver, status, error);
}
int c89cbor_cwt_seal(c89cbor_cwt *receiver, void *bytes, size_t capacity,
                     size_t *written, c89cbor_error *error) {
  c89_cwt_state *state;
  c89cbor_cose_key_info info;
  c89cbor_cose_key *signing;
  const unsigned char *token;
  size_t length;
  int status;
  if (written != NULL)
    *written = 0;
  status = begin(receiver, error);
  if (status != 0)
    return status;
  state = receiver->state;
  if (written == NULL || bytes == NULL || state->view.encoded == NULL ||
      state->seal_count == 0)
    return finish(receiver, C89CBOR_INVALID, error);
  signing = state->seal_keys[0];
  status = signing->metadata(signing, &info);
  if (status != 0)
    return finish(receiver, status, error);
  status =
      crypt(state, 1, info.kind == C89CBOR_COSE_HMAC256 ? 2 : 1, &signing, 1u,
            state->raw, state->view.encoded_length, state->inner,
            state->token_capacity, state->options.cose.record_bytes, &length);
  token = state->inner;
  if (status == 0 && state->seal_count > 1u) {
    status = crypt(state, 1, 0, state->seal_keys + 1u, state->seal_count - 1u,
                   state->inner, length, state->outer, state->token_capacity,
                   state->token_capacity, &length);
    token = state->outer;
  }
  if (status == 0 && capacity < length + 2u)
    status = C89CBOR_LIMIT;
  if (status == 0) {
    unsigned char *out = bytes;
    out[0] = 0xd8;
    out[1] = 0x3d;
    memcpy(out + 2u, token, length);
    *written = length + 2u;
  }
  OPENSSL_cleanse(state->inner, state->token_capacity);
  OPENSSL_cleanse(state->outer, state->token_capacity);
  return finish(receiver, status, error);
}
/* Only inspect framing here. No field is admitted before crypto and policy. */
static int object(const void *bytes, size_t length, int outer, size_t *offset,
                  int *tag) {
  c89_cose_cursor cursor;
  int status, cwt_tag = 0;
  *offset = 0;
  *tag = 0;
  status = c89_cose_cursor_init(&cursor, bytes, length);
  if (status == 0)
    status = c89_cose_next(&cursor);
  if (status != 0)
    return C89CBOR_MALFORMED;
  if (cursor.token.type == C89CBOR_TAG && cursor.token.argument == 61u &&
      outer) {
    cwt_tag = 1;
    *offset = cursor.offset;
    status = c89_cose_next(&cursor);
  }
  if (status != 0)
    return C89CBOR_MALFORMED;
  if (cursor.token.type == C89CBOR_TAG) {
    if (cursor.token.argument == 16u || cursor.token.argument == 96u ||
        cursor.token.argument == 17u || cursor.token.argument == 18u)
      *tag = (int)cursor.token.argument;
    else
      return C89CBOR_UNSUPPORTED;
  } else if (cursor.token.type != C89CBOR_ARRAY || cwt_tag || !outer)
    return C89CBOR_MALFORMED;
  return c89cbor_decoder_cleanup(&cursor.decoder);
}
int c89cbor_cwt_verify(c89cbor_cwt *receiver, const void *bytes, size_t length,
                       const lonejson_jwt_claim_policy *policy,
                       c89cbor_error *error) {
  c89_cwt_state *state;
  c89cbor_cose_key_info info;
  c89cbor_cose_key *verification, *decryption;
  lonejson_jwt_header header;
  lonejson_error json_error;
  lonejson_status json_status;
  const unsigned char *token = bytes;
  size_t offset, message_length;
  char name[8];
  int status = begin(receiver, error), tag, algorithm;
  if (status != 0)
    return status;
  state = receiver->state;
  c89_cwt_clear(state);
  verification = state->verify_count ? state->verify_keys[0] : NULL;
  decryption = state->verify_count > 1u ? state->verify_keys[1] : NULL;
  if (bytes == NULL || length == 0 || policy == NULL ||
      !c89_cose_key_valid(verification)) {
    status = C89CBOR_INVALID;
    goto done;
  }
  if (length > state->token_capacity) {
    status = C89CBOR_LIMIT;
    goto done;
  }
  status = verification->metadata(verification, &info);
  if (status != 0)
    goto done;
  algorithm = c89_cose_auth_algorithm(info.kind);
  if (algorithm == 0) {
    status = C89CBOR_INVALID;
    goto done;
  }
  status = object(token, length, 1, &offset, &tag);
  if (status != 0)
    goto done;
  token += offset;
  length -= offset;
  if (state->options.require_encryption && tag != 16 && tag != 96) {
    status = C89CBOR_AUTH;
    goto done;
  }
  if (tag == 16 || tag == 96) {
    if (!c89_cose_key_valid(decryption)) {
      status = C89CBOR_INVALID;
      goto done;
    }
    status = crypt(state, 0, 0, &decryption, 1u, token, length, state->inner,
                   state->token_capacity, state->token_capacity, &length);
    if (status != 0)
      goto done;
    token = state->inner;
    status = object(token, length, 0, &offset, &tag);
    if (status != 0)
      goto done;
  }
  if (tag != 0 && tag != (algorithm == 5 ? 17 : 18)) {
    status = C89CBOR_AUTH;
    goto done;
  }
  status = crypt(state, 0, algorithm == 5 ? 2 : 1, &verification, 1u, token,
                 length, state->raw, state->options.cose.record_bytes,
                 state->options.cose.record_bytes, &length);
  if (status != 0)
    goto done;
  status = c89_cwt_parse(state, length);
  if (status != 0)
    goto done;
  memset(&header, 0, sizeof(header));
  strcpy(name, algorithm == -19  ? "Ed25519"
               : algorithm == -9 ? "ES256"
                                 : "HS256");
  header.alg = name;
  json_status = lonejson_jwt_validate_claims(&header, &state->native, policy,
                                             &json_error);
  if (json_status != LONEJSON_STATUS_OK) {
    (void)c89_error(&receiver->lifetime, C89CBOR_AUTH, "cwt-policy");
    receiver->lifetime.error.cause = (int)json_status;
    message_length = strnlen(json_error.message,
                             sizeof(receiver->lifetime.error.message) - 1u);
    memcpy(receiver->lifetime.error.message, json_error.message,
           message_length);
    receiver->lifetime.error.message[message_length] = 0;
    status = C89CBOR_AUTH;
    goto done;
  }
  if (state->options.require_cti && state->view.cti_length == 0) {
    status = C89CBOR_AUTH;
    goto done;
  }
  state->view.authenticated = 1;
  state->view.algorithm = algorithm;
  if (state->options.admit != NULL &&
      state->options.admit(state->options.context, &state->view) != 0)
    status = C89CBOR_AUTH;
done:
  if (status != 0)
    c89_cwt_clear(state);
  else {
    OPENSSL_cleanse(state->inner, state->token_capacity);
    OPENSSL_cleanse(state->outer, state->token_capacity);
  }
  return finish(receiver, status, error);
}
int c89cbor_cwt_diagnostic(const c89cbor_cwt *receiver, c89cbor_error *error) {
  return c89_lifetime_diagnostic(receiver == NULL ? NULL : &receiver->lifetime,
                                 error);
}
int c89cbor_cwt_cleanup(c89cbor_cwt *receiver) {
  c89_cwt_state *state;
  c89cbor_allocator allocator;
  c89cbor_cose_key *held[C89_COSE_MAX_RECIPIENTS + 3u];
  size_t count = 0;
  if (receiver == NULL)
    return C89CBOR_OK;
  if (receiver->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (receiver->lifetime.busy || receiver->lifetime.dependents)
    return C89CBOR_BUSY;
  receiver->lifetime.busy = 1;
  state = receiver->state;
  receiver->state = NULL;
  allocator = receiver->lifetime.allocator;
  if (state != NULL) {
    count = state->seal_count + state->verify_count;
    memcpy(held, state->seal_keys, state->seal_count * sizeof(*held));
    memcpy(held + state->seal_count, state->verify_keys,
           state->verify_count * sizeof(*held));
    c89_cose_workspace_cleanup(&state->crypto);
    if (state->workspace != NULL) {
      OPENSSL_cleanse(state->workspace, state->workspace_size);
      allocator.free(allocator.context, state->workspace);
    }
    if (state->entries != NULL)
      allocator.free(allocator.context, state->entries);
    if (state->strings != NULL)
      allocator.free(allocator.context, state->strings);
    OPENSSL_cleanse(state, sizeof(*state));
    allocator.free(allocator.context, state);
  }
  c89_cose_keys_unhold(held, count);
  receiver->lifetime.busy = 0;
  return c89_lifetime_cleanup(&receiver->lifetime);
}
int c89cbor_cwt_destroy(c89cbor_cwt *receiver) {
  int status;
  if (receiver == NULL)
    return C89CBOR_OK;
  if (receiver->lifetime.magic != C89_LIFETIME_MAGIC ||
      !receiver->lifetime.owned)
    return C89CBOR_INVALID;
  status = c89cbor_cwt_cleanup(receiver);
  return status == 0 ? c89_lifetime_destroy(&receiver->lifetime, receiver)
                     : status;
}
int c89cbor_cwt_init(c89cbor *runtime, c89cbor_cwt *receiver,
                     const c89cbor_cwt_options *options, c89cbor_error *error) {
  c89_cwt_state *state = NULL;
  c89cbor_cwt_options resolved;
  c89cbor_allocator selected;
  size_t record, header;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (receiver == NULL)
    return C89CBOR_INVALID;
  memset(receiver, 0, sizeof(*receiver));
  receiver->set_claims = c89cbor_cwt_set_claims;
  receiver->set_lonejson = c89cbor_cwt_set_lonejson;
  receiver->set_seal_keys = c89cbor_cwt_set_seal_keys;
  receiver->set_verify_keys = c89cbor_cwt_set_verify_keys;
  receiver->seal = c89cbor_cwt_seal;
  receiver->verify = c89cbor_cwt_verify;
  receiver->view_get = c89cbor_cwt_view_get;
  receiver->claim = c89cbor_cwt_claim;
  receiver->diagnostic = c89cbor_cwt_diagnostic;
  receiver->cleanup = c89cbor_cwt_cleanup;
  receiver->destroy = c89cbor_cwt_destroy;
  status = c89_lifetime_init(&receiver->lifetime, runtime, NULL);
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  receiver->lifetime.busy = 1;
  resolved = options == NULL ? c89cbor_default_cwt_options() : *options;
  if (runtime == NULL) {
    status = C89CBOR_INVALID;
    goto failed;
  }
  status = c89_cose_options_resolve(runtime, &resolved.cose, &resolved.cose);
  if (status != 0)
    goto failed;
  if (resolved.claims == 0)
    resolved.claims = 64u;
  if (resolved.audiences == 0)
    resolved.audiences = 32u;
  record = resolved.cose.record_bytes;
  header = resolved.cose.header_bytes;
  if (record > ((size_t)INT_MAX - 1024u) / 8u ||
      header > ((size_t)INT_MAX - 1024u) / 8u ||
      resolved.claims > (size_t)-1 / sizeof(c89_cwt_entry) ||
      resolved.audiences > (size_t)-1 / sizeof(char *) / 2u ||
      resolved.cose.aad_length > header) {
    status = C89CBOR_LIMIT;
    goto failed;
  }
  status =
      c89_allocate(runtime, NULL, sizeof(*state), (void **)&state, &selected);
  if (status != 0)
    goto failed;
  memset(state, 0, sizeof(*state));
  receiver->state = state;
  state->runtime = runtime;
  state->options = resolved;
  state->token_capacity = record + header * 2u + 16u;
  state->workspace_size = record * 3u + 1u + state->token_capacity * 2u;
  status = c89_allocate(runtime, NULL, state->workspace_size,
                        (void **)&state->workspace, &selected);
  if (status != 0)
    goto failed;
  state->raw = state->workspace;
  state->arena.bytes = state->raw + record;
  state->arena.capacity = record * 2u + 1u;
  state->inner = state->arena.bytes + state->arena.capacity;
  state->outer = state->inner + state->token_capacity;
  c89_cwt_clear(state);
  status =
      c89_allocate(runtime, NULL, resolved.claims * sizeof(*state->entries),
                   (void **)&state->entries, &selected);
  if (status == 0)
    status =
        c89_allocate(runtime, NULL, resolved.audiences * sizeof(char *) * 2u,
                     (void **)&state->strings, &selected);
  if (status == 0) {
    state->crypto.runtime = runtime;
    state->crypto.allocator = receiver->lifetime.allocator;
    state->crypto.options = resolved.cose;
    state->crypto.options.record_bytes = state->token_capacity;
    state->crypto.auth = -1;
    status = c89_cose_options_resolve(runtime, &state->crypto.options,
                                      &state->crypto.options);
    if (status == 0)
      status = c89_cose_workspace_init(&state->crypto);
    if (status == 0)
      c89_cose_workspace_clear(&state->crypto);
  }
  if (status == 0) {
    receiver->lifetime.busy = 0;
    return C89CBOR_OK;
  }
failed:
  (void)c89_error(&receiver->lifetime, status, "cwt-init");
  receiver->lifetime.error.status = status;
  if (error != NULL)
    *error = receiver->lifetime.error;
  receiver->lifetime.busy = 0;
  (void)c89cbor_cwt_cleanup(receiver);
  return status;
}
int c89cbor_cwt_create(c89cbor *runtime, const c89cbor_cwt_options *options,
                       c89cbor_cwt **out, c89cbor_error *error) {
  c89cbor_cwt *receiver;
  c89cbor_allocator allocator;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(*receiver), (void **)&receiver,
                        &allocator);
  if (status == 0) {
    status = c89cbor_cwt_init(runtime, receiver, options, error);
    if (status == 0) {
      receiver->lifetime.owned = 1;
      *out = receiver;
    } else
      allocator.free(allocator.context, receiver);
  } else if (error != NULL)
    error->status = status;
  return status;
}
void c89_cwt_runtime_methods(c89cbor *runtime) {
  runtime->default_cwt_options = c89cbor_runtime_default_cwt_options;
  runtime->cwt_init = c89cbor_cwt_init;
  runtime->cwt_create = c89cbor_cwt_create;
}
