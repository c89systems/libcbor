/* COSE facade: native endpoints carry payload bytes. Lua handles configuration,
 * key import and scheduling; it never shuffles each CBOR token across the VM.
 */
static int default_cose_options(lua_State *L) {
  c89cbor_cose_options options = c89cbor_default_cose_options();
  lua_newtable(L);
#define COSE_OPTION(field)                                                     \
  push_integer(L, options.field);                                              \
  lua_setfield(L, -2, #field)
  COSE_OPTION(record_bytes);
  COSE_OPTION(header_bytes);
  COSE_OPTION(recipients);
  COSE_OPTION(step_input);
  COSE_OPTION(step_output);
  COSE_OPTION(step_events);
#undef COSE_OPTION
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "encrypt");
  return 1;
}
/* Snapshot scalar fields and pin the actual string/span owners. Keeping only
 * the user's mutable options table would leave old pointers dangling. */
static c89cbor_cose_options *cose_options_snapshot(lua_State *L, int index) {
  c89cbor_cose_options *native, *options;
  handle *h;
  size_t length;
  int object, slot;
  const void *bytes;
  static const char *const names[] = {"aad", "nonce", "stream_id"};
  index = lua_absindex(L, index);
  native = check_cose_options(L, index);
  if (native != NULL) {
    lua_pushvalue(L, index);
    return native;
  }
  if (!lua_isnoneornil(L, index))
    luaL_checktype(L, index, LUA_TTABLE);
  h = new_handle(L, COSE_OPTIONS, sizeof(*options));
  /* Private snapshots have no public owner; drop their byte pins immediately
   * when the operation releases its last borrow. */
  h->gc_pending = 1;
  options = h->ptr;
  *options = c89cbor_default_cose_options();
  object = lua_gettop(L);
  if (lua_isnoneornil(L, index))
    return options;
#define COSE_SIZE(field)                                                       \
  options->field = table_size(L, index, #field, options->field)
  COSE_SIZE(record_bytes);
  COSE_SIZE(header_bytes);
  COSE_SIZE(recipients);
  COSE_SIZE(step_input);
  COSE_SIZE(step_output);
  COSE_SIZE(step_events);
#undef COSE_SIZE
  lua_getfield(L, index, "encrypt");
  options->encrypt = lua_toboolean(L, -1);
  lua_pop(L, 1);
  for (slot = 1; slot <= 3; ++slot) {
    lua_getfield(L, index, names[slot - 1]);
    bytes = input(L, -1, &length);
    if (slot != 1 && bytes != NULL && length != (slot == 2 ? 12u : 16u))
      luaL_argerror(L, index,
                    "nonce must be 12 bytes; stream_id must be 16 bytes");
    if (slot == 1) {
      options->aad = bytes;
      options->aad_length = length;
    } else if (slot == 2)
      options->nonce = bytes;
    else
      options->stream_id = bytes;
    if (!lua_isnil(L, -1)) {
      handle *parent = any_handle(L, -1);
      if (parent != NULL) {
        ++parent->borrowers;
        h->parent[slot - 1] = parent;
      }
      lua_setiuservalue(L, object, slot);
    } else
      lua_pop(L, 1);
  }
  return options;
}
/* Key imports copy exactly 32 bytes. Only public X25519 bytes can be exported.
 */
static int cose_key_factory(lua_State *L, int create) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0, status;
  uint64_t kind = integer(L, 1 + base);
  size_t length, id_length;
  const void *bytes = input(L, 2 + base, &length);
  const void *id = input(L, 3 + base, &id_length);
  c89cbor_cose_key *key = NULL;
  c89cbor_error error;
  handle *h;
  if (kind > C89CBOR_COSE_X25519_PRIVATE)
    return luaL_argerror(L, 1 + base, "unknown COSE key kind");
  if (base && checked(L, 1, ROOT)->active) {
    lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  h = new_handle(L, COSE_KEY, create ? 0 : sizeof(*key));
  if (base)
    pin(L, h, 1, 1);
  h->active = 1;
  if (base)
    checked(L, 1, ROOT)->active = 1;
  if (create) {
    status =
        c89cbor_cose_key_create(runtime, (c89cbor_cose_key_kind)kind, bytes,
                                length, id, id_length, &key, &error);
    h->ptr = key;
    h->heap_kind = 8;
  } else
    status = c89cbor_cose_key_init(runtime, h->ptr, (c89cbor_cose_key_kind)kind,
                                   bytes, length, id, id_length, &error);
  if (base)
    checked(L, 1, ROOT)->active = 0;
  h->active = 0;
  if (status != 0) {
    (void)release_handle(h);
    lua_pushnil(L);
    result(L, status);
    diagnostic_table(L, &error);
    return 3;
  }
  return 1;
}
static int cose_key_init(lua_State *L) { return cose_key_factory(L, 0); }
static int cose_key_create(lua_State *L) { return cose_key_factory(L, 1); }
static int cose_key_metadata(lua_State *L) {
  c89cbor_cose_key_info info;
  int status = c89cbor_cose_key_metadata(checked(L, 1, COSE_KEY)->ptr, &info);
  result(L, status);
  lua_newtable(L);
  push_integer(L, info.kind);
  lua_setfield(L, -2, "kind");
  lua_pushlstring(L, (const char *)info.key_id, info.key_id_length);
  lua_setfield(L, -2, "key_id");
  return 2;
}
static int cose_key_public_key(lua_State *L) {
  unsigned char bytes[32];
  size_t length;
  int status = c89cbor_cose_key_public_key(checked(L, 1, COSE_KEY)->ptr, bytes,
                                           sizeof(bytes), &length);
  result(L, status);
  if (status == 0)
    lua_pushlstring(L, (const char *)bytes, length);
  else
    lua_pushnil(L);
  return 2;
}
enum cose_kind { COSE_E0, COSE_E, COSE_D, COSE_ES, COSE_DS };
/* source, sink, key-or-recipient-array, options follow the root. A private
 * recipient snapshot pins each wrapper even if the input table is mutated. */
static int runtime_cose(lua_State *L, enum cose_kind kind, int mode) {
  handle *root = checked(L, 1, ROOT), *h;
  c89cbor *runtime = root->ptr;
  c89cbor_source *source = checked(L, 2, SOURCE)->ptr;
  c89cbor_sink *sink = checked(L, 3, SINK)->ptr;
  c89cbor_cose_key *keys[32];
  handle *parents[32];
  size_t count = 1u, i;
  int snapshot, option_index, status;
  c89cbor_cose_options *options;
  c89cbor_cose_operation *operation = NULL;
  c89cbor_error error;
  if (root->active)
    return result(L, C89CBOR_BUSY);
  lua_settop(L, 5);
  if (kind == COSE_E || kind == COSE_ES) {
    luaL_checktype(L, 4, LUA_TTABLE);
    count = lua_rawlen(L, 4);
    if (count == 0 || count > 32u)
      return luaL_argerror(L, 4, "expected one to 32 COSE recipient keys");
  }
  lua_createtable(L, (int)count, 0);
  snapshot = lua_gettop(L);
  for (i = 0; i < count; ++i) {
    if (kind == COSE_E || kind == COSE_ES)
      lua_rawgeti(L, 4, (lua_Integer)i + 1);
    else
      lua_pushvalue(L, 4);
    parents[i] = checked(L, -1, COSE_KEY);
    keys[i] = parents[i]->ptr;
    lua_rawseti(L, snapshot, (lua_Integer)i + 1);
  }
  options = cose_options_snapshot(L, 5);
  option_index = lua_gettop(L);
  h = new_handle(L, COSE_OPERATION,
                 sizeof(*operation) + count * sizeof(handle *));
  h->key_parents = (handle **)((unsigned char *)(h + 1) + sizeof(*operation));
  h->heap_kind = 0;
  pin(L, h, 1, 1);
  pin(L, h, 2, 2);
  pin(L, h, 3, 3);
  pin(L, h, snapshot, 4);
  pin(L, h, option_index, 5);
  for (i = 0; i < count; ++i) {
    h->key_parents[h->key_parent_count++] = parents[i];
    ++parents[i]->borrowers;
  }
  root->active = h->active = 1;
  if (mode == 1) {
    h->ptr = NULL;
    if (kind == COSE_E0)
      status = runtime->cose_encrypt0(runtime, source, sink, keys[0], options,
                                      &error);
    else if (kind == COSE_E)
      status = runtime->cose_encrypt(runtime, source, sink, keys, count,
                                     options, &error);
    else if (kind == COSE_D)
      status = runtime->cose_decrypt(runtime, source, sink, keys[0], options,
                                     &error);
    else if (kind == COSE_ES)
      status = runtime->cose_encrypt_stream(runtime, source, sink, keys, count,
                                            options, &error);
    else
      status = runtime->cose_decrypt_stream(runtime, source, sink, keys[0],
                                            options, &error);
  } else if (mode == 2) {
    operation = h->ptr;
    h->heap_kind = -9;
    if (kind == COSE_E0)
      status = runtime->cose_encrypt0_init(runtime, operation, source, sink,
                                           keys[0], options, &error);
    else if (kind == COSE_E)
      status = runtime->cose_encrypt_init(runtime, operation, source, sink,
                                          keys, count, options, &error);
    else if (kind == COSE_D)
      status = runtime->cose_decrypt_init(runtime, operation, source, sink,
                                          keys[0], options, &error);
    else if (kind == COSE_ES)
      status = runtime->cose_encrypt_stream_init(
          runtime, operation, source, sink, keys, count, options, &error);
    else
      status = runtime->cose_decrypt_stream_init(
          runtime, operation, source, sink, keys[0], options, &error);
  } else {
    h->ptr = NULL;
    h->heap_kind = 9;
    if (kind == COSE_E0)
      status = runtime->cose_encrypt0_open(runtime, source, sink, keys[0],
                                           options, &operation, &error);
    else if (kind == COSE_E)
      status = runtime->cose_encrypt_open(runtime, source, sink, keys, count,
                                          options, &operation, &error);
    else if (kind == COSE_D)
      status = runtime->cose_decrypt_open(runtime, source, sink, keys[0],
                                          options, &operation, &error);
    else if (kind == COSE_ES)
      status = runtime->cose_encrypt_stream_open(
          runtime, source, sink, keys, count, options, &operation, &error);
    else
      status = runtime->cose_decrypt_stream_open(runtime, source, sink, keys[0],
                                                 options, &operation, &error);
    h->ptr = operation;
  }
  root->active = h->active = 0;
  if (mode == 1 || status != 0) {
    (void)release_handle(h);
    if (mode != 1)
      lua_pushnil(L);
    result(L, status);
    diagnostic_table(L, &error);
    return mode == 1 ? 2 : 3;
  }
  return 1;
}
#define COSE_FACTORY(name, kind)                                               \
  static int cose_##name(lua_State *L) { return runtime_cose(L, kind, 1); }    \
  static int cose_##name##_init(lua_State *L) {                                \
    return runtime_cose(L, kind, 2);                                           \
  }                                                                            \
  static int cose_##name##_open(lua_State *L) {                                \
    return runtime_cose(L, kind, 0);                                           \
  }
COSE_FACTORY(encrypt0, COSE_E0)
COSE_FACTORY(encrypt, COSE_E)
COSE_FACTORY(decrypt, COSE_D)
COSE_FACTORY(encrypt_stream, COSE_ES)
COSE_FACTORY(decrypt_stream, COSE_DS)
#undef COSE_FACTORY
/* run stops on backpressure, and never polls a blocked native endpoint. */
static int cose_operation_drive(lua_State *L, int run) {
  handle *h = checked(L, 1, COSE_OPERATION);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  do {
    status = c89cbor_cose_operation_step(h->ptr, &error);
  } while (run && status == C89CBOR_OK);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int cose_operation_step(lua_State *L) {
  return cose_operation_drive(L, 0);
}
static int cose_operation_run(lua_State *L) {
  return cose_operation_drive(L, 1);
}
static void cose_replace_pin(lua_State *L, handle *h, int index, int slot) {
  handle *parent = any_handle(L, index);
  if (parent != NULL)
    ++parent->borrowers;
  if (h->parent[slot - 1] != NULL)
    drop_parent(h->parent[slot - 1]);
  h->parent[slot - 1] = parent;
  lua_pushvalue(L, index);
  lua_setiuservalue(L, 1, slot);
}
/* next keeps read-ahead and keys; only replace borrowed owners after success.
 */
static int cose_operation_next(lua_State *L) {
  handle *h = checked(L, 1, COSE_OPERATION);
  c89cbor_sink *sink = NULL;
  c89cbor_cose_options *options = NULL;
  c89cbor_error error;
  int option_index = 0, status;
  lua_settop(L, 3);
  if (!lua_isnil(L, 2))
    sink = checked(L, 2, SINK)->ptr;
  if (!lua_isnil(L, 3)) {
    options = cose_options_snapshot(L, 3);
    option_index = lua_gettop(L);
  }
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_cose_operation_next(h->ptr, sink, options, &error);
  h->active = 0;
  if (status == 0) {
    if (sink != NULL)
      cose_replace_pin(L, h, 2, 3);
    if (options != NULL)
      cose_replace_pin(L, h, option_index, 5);
  }
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
/* Authenticated metadata can be queried even for an empty completed stream. */
static int cose_operation_stream_info(lua_State *L) {
  c89cbor_cose_stream_info info;
  int status = c89cbor_cose_operation_stream_info(
      checked(L, 1, COSE_OPERATION)->ptr, &info);
  result(L, status);
  if (status != 0)
    lua_pushnil(L);
  else {
    lua_newtable(L);
    lua_pushlstring(L, (const char *)info.stream_id, 16u);
    lua_setfield(L, -2, "stream_id");
    lua_pushboolean(L, info.encrypt);
    lua_setfield(L, -2, "encrypt");
    lua_pushboolean(L, info.complete);
    lua_setfield(L, -2, "complete");
  }
  return 2;
}
