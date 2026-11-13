/* Bounded token facade. Native claim/policy handles avoid crossing the Lua VM
 * for application records. Tables and strings are explicit convenience copies.
 */
static int default_cwt_options(lua_State *L) {
  c89cbor_cwt_options options = c89cbor_default_cwt_options();
  lua_newtable(L);
  push_integer(L, options.claims);
  lua_setfield(L, -2, "claims");
  push_integer(L, options.audiences);
  lua_setfield(L, -2, "audiences");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "require_cti");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "require_encryption");
  default_cose_options(L);
  lua_setfield(L, -2, "cose");
  return 1;
}
static int cwt_factory(lua_State *L, int create) {
  handle *root = checked(L, 1, ROOT), *h, *snapshot;
  c89cbor_cwt_options options = c89cbor_default_cwt_options(), *native;
  c89cbor_cwt *receiver = NULL;
  c89cbor_error error;
  int status, option_index;
  lua_settop(L, 2);
  native = check_cwt_options(L, 2);
  if (native != NULL)
    options = *native;
  else if (!lua_isnil(L, 2)) {
    luaL_checktype(L, 2, LUA_TTABLE);
    options.claims = table_size(L, 2, "claims", options.claims);
    options.audiences = table_size(L, 2, "audiences", options.audiences);
    lua_getfield(L, 2, "require_cti");
    options.require_cti = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, 2, "require_encryption");
    options.require_encryption = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, 2, "cose");
    options.cose = *cose_options_snapshot(L, -1);
  } else
    (void)cose_options_snapshot(L, 2);
  option_index = lua_gettop(L);
  snapshot = new_handle(L, CWT_OPTIONS, sizeof(options));
  snapshot->gc_pending = 1;
  *(c89cbor_cwt_options *)snapshot->ptr = options;
  pin(L, snapshot, native != NULL ? 2 : option_index, 1);
  option_index = lua_gettop(L);
  if (root->active) {
    lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  h = new_handle(L, CWT, create ? 0 : sizeof(*receiver));
  pin(L, h, 1, 1);
  pin(L, h, option_index, 2);
  root->active = h->active = 1;
  if (create) {
    status = c89cbor_cwt_create(root->ptr, &options, &receiver, &error);
    h->ptr = receiver;
    h->heap_kind = 10;
  } else
    status = c89cbor_cwt_init(root->ptr, h->ptr, &options, &error);
  root->active = h->active = 0;
  if (status != 0) {
    (void)release_handle(h);
    lua_pushnil(L);
  } else
    h->count = (options.cose.record_bytes ? options.cose.record_bytes
                                          : C89CBOR_CHUNK) +
               (options.cose.header_bytes ? options.cose.header_bytes
                                          : C89CBOR_CHUNK) *
                   2u +
               18u;
  result(L, status);
  diagnostic_table(L, &error);
  return 3;
}
static int cwt_init(lua_State *L) { return cwt_factory(L, 0); }
static int cwt_create(lua_State *L) { return cwt_factory(L, 1); }
static int cwt_set_claims(lua_State *L) {
  handle *h = checked(L, 1, CWT);
  size_t length;
  const void *bytes = input(L, 2, &length);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_cwt_set_claims(h->ptr, bytes, length, &error);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int cwt_set_lonejson(lua_State *L) {
  handle *h = checked(L, 1, CWT);
  lonejson_jwt_claims *claims = checked(L, 2, JWT_CLAIMS)->ptr;
  size_t length;
  const void *id = input(L, 3, &length);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_cwt_set_lonejson(h->ptr, claims, id, length, &error);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
/* Bind keys once. A private snapshot keeps the actual owners alive even when
 * callers subsequently mutate their recipient table. Replacement is atomic. */
static int cwt_bind_keys(lua_State *L, int sealing) {
  handle *h = checked(L, 1, CWT), *snapshot, *owner;
  c89cbor_cose_key *keys[33];
  c89cbor_error error;
  size_t count = 0, recipients = 0, i;
  int status, snapshot_index, pins;
  lua_settop(L, 3);
  if (!lua_isnil(L, 2)) {
    keys[count++] = checked(L, 2, COSE_KEY)->ptr;
  }
  if (sealing && !lua_isnil(L, 3)) {
    luaL_checktype(L, 3, LUA_TTABLE);
    recipients = lua_rawlen(L, 3);
    if (count == 0 || recipients == 0 || recipients > 32u)
      return luaL_argerror(L, 3,
                           "expected signing key and one to 32 recipients");
    for (i = 0; i < recipients; ++i) {
      lua_rawgeti(L, 3, (lua_Integer)i + 1);
      keys[count++] = checked(L, -1, COSE_KEY)->ptr;
      lua_pop(L, 1);
    }
  } else if (!sealing && !lua_isnil(L, 3)) {
    if (count == 0)
      return luaL_argerror(L, 2, "verification key is required");
    keys[count++] = checked(L, 3, COSE_KEY)->ptr;
  }
  if (h->active)
    return result(L, C89CBOR_BUSY);
  snapshot = new_handle(L, KEY_PINS, (count + 1u) * sizeof(handle *));
  snapshot->gc_pending = 1;
  snapshot->key_parents = snapshot->ptr;
  snapshot_index = lua_gettop(L);
  lua_newtable(L);
  pins = lua_gettop(L);
  for (i = 0; i < count; ++i) {
    if (i == 0)
      lua_pushvalue(L, 2);
    else if (sealing)
      lua_rawgeti(L, 3, (lua_Integer)i);
    else
      lua_pushvalue(L, 3);
    owner = checked(L, -1, COSE_KEY);
    ++owner->borrowers;
    snapshot->key_parents[snapshot->key_parent_count++] = owner;
    lua_rawseti(L, pins, (lua_Integer)i + 1);
  }
  lua_setiuservalue(L, snapshot_index, 1);
  h->active = 1;
  status = sealing ? c89cbor_cwt_set_seal_keys(h->ptr, count ? keys[0] : NULL,
                                               recipients ? keys + 1u : NULL,
                                               recipients, &error)
                   : c89cbor_cwt_set_verify_keys(h->ptr, count ? keys[0] : NULL,
                                                 count > 1u ? keys[1] : NULL,
                                                 &error);
  h->active = 0;
  if (status == 0)
    cose_replace_pin(L, h, snapshot_index, sealing ? 3 : 4);
  else
    (void)release_handle(snapshot);
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int cwt_set_seal_keys(lua_State *L) { return cwt_bind_keys(L, 1); }
static int cwt_set_verify_keys(lua_State *L) { return cwt_bind_keys(L, 0); }
/* Return an owned output span. Converting it to a Lua string is explicit. */
static int cwt_seal(lua_State *L) {
  handle *h = checked(L, 1, CWT);
  handle *wire;
  span *output;
  c89cbor_error error;
  unsigned char *bytes;
  size_t written, capacity;
  int status, wire_index;
  capacity = size_arg(L, 2, h->count ? h->count : 6162u);
  if (capacity > (size_t)-1 - sizeof(handle) - sizeof(span))
    return luaL_argerror(L, 2, "output capacity is too large");
  if (h->active)
    return result(L, C89CBOR_BUSY);
  wire = new_handle(L, SPAN, sizeof(*output) + capacity);
  wire_index = lua_gettop(L);
  output = wire->ptr;
  bytes = (unsigned char *)(output + 1);
  output->bytes = bytes;
  h->active = 1;
  status = c89cbor_cwt_seal(h->ptr, bytes, capacity, &written, &error);
  h->active = 0;
  result(L, status);
  if (status == 0) {
    output->length = written;
    lua_pushvalue(L, wire_index);
  } else {
    (void)release_handle(wire);
    lua_pushnil(L);
  }
  diagnostic_table(L, &error);
  return 3;
}
/* Policy tables are snapshotted, including their actual immutable strings. A
 * native policy handle is borrowed just for the synchronous verification call.
 */
static lonejson_jwt_claim_policy *cwt_policy(lua_State *L, int index) {
  static const char *const names[] = {"accepted_algs",      "accepted_issuers",
                                      "accepted_audiences", "accepted_crit",
                                      "required_scopes",    "required_claims"};
  lonejson_jwt_claim_policy *policy = check_jwt_policy(L, index);
  handle *snapshot;
  const char **arrays;
  const char *value;
  size_t counts[6], total = 0, offset = 0, i, j;
  int object, pins;
  index = lua_absindex(L, index);
  if (policy != NULL)
    return policy;
  luaL_checktype(L, index, LUA_TTABLE);
  lua_getfield(L, index, "now");
  (void)luaL_checkinteger(L, -1);
  lua_pop(L, 1);
  for (i = 0; i < 6u; ++i) {
    lua_getfield(L, index, names[i]);
    if (!lua_isnil(L, -1))
      luaL_checktype(L, -1, LUA_TTABLE);
    counts[i] = lua_isnil(L, -1) ? 0 : lua_rawlen(L, -1);
    lua_pop(L, 1);
    if (counts[i] >
        ((size_t)INT_MAX - sizeof(*policy)) / sizeof(char *) - total)
      luaL_argerror(L, index, "policy is too large");
    total += counts[i];
  }
  snapshot =
      new_handle(L, JWT_POLICY, sizeof(*policy) + total * sizeof(char *));
  object = lua_gettop(L);
  policy = snapshot->ptr;
  arrays = (const char **)(policy + 1);
  lua_newtable(L);
  pins = lua_gettop(L);
  for (i = 0; i < 6u; ++i) {
    lua_getfield(L, index, names[i]);
    for (j = 0; j < counts[i]; ++j) {
      lua_rawgeti(L, -1, (lua_Integer)j + 1);
      value = luaL_checkstring(L, -1);
      if (strlen(value) != lua_rawlen(L, -1))
        luaL_argerror(L, index, "policy strings cannot contain NUL");
      arrays[offset + j] = value;
      lua_rawseti(L, pins, (lua_Integer)(offset + j + 1u));
    }
    lua_pop(L, 1);
    switch (i) {
    case 0:
      policy->accepted_algs = arrays + offset;
      policy->accepted_alg_count = counts[i];
      break;
    case 1:
      policy->accepted_issuers = arrays + offset;
      policy->accepted_issuer_count = counts[i];
      break;
    case 2:
      policy->accepted_audiences = arrays + offset;
      policy->accepted_audience_count = counts[i];
      break;
    case 3:
      policy->accepted_crit = arrays + offset;
      policy->accepted_crit_count = counts[i];
      break;
    case 4:
      policy->required_scopes = arrays + offset;
      policy->required_scope_count = counts[i];
      break;
    default:
      policy->required_claims = arrays + offset;
      policy->required_claim_count = counts[i];
      break;
    }
    offset += counts[i];
  }
#define POLICY_TIME(field)                                                     \
  lua_getfield(L, index, #field);                                              \
  policy->field =                                                              \
      lua_isnil(L, -1) ? 0 : (lonejson_int64)luaL_checkinteger(L, -1);         \
  lua_pop(L, 1)
  POLICY_TIME(now);
  POLICY_TIME(allowed_clock_skew);
#undef POLICY_TIME
#define POLICY_BOOL(field)                                                     \
  lua_getfield(L, index, #field);                                              \
  policy->field = lua_toboolean(L, -1);                                        \
  lua_pop(L, 1)
  POLICY_BOOL(require_all_audiences_accepted);
  POLICY_BOOL(require_azp_when_multiple_audiences);
#undef POLICY_BOOL
#define POLICY_STRING(field, slot)                                             \
  lua_getfield(L, index, #field);                                              \
  if (!lua_isnil(L, -1)) {                                                     \
    policy->field = luaL_checkstring(L, -1);                                   \
    if (strlen(policy->field) != lua_rawlen(L, -1))                            \
      luaL_argerror(L, index, "policy strings cannot contain NUL");            \
  }                                                                            \
  lua_rawseti(L, pins, (lua_Integer)total + slot)
  POLICY_STRING(expected_nonce, 1);
  POLICY_STRING(expected_azp, 2);
#undef POLICY_STRING
  lua_setiuservalue(L, object, 1);
  return policy;
}
static int cwt_verify(lua_State *L) {
  handle *h = checked(L, 1, CWT);
  size_t length;
  const void *bytes = input(L, 2, &length);
  lonejson_jwt_claim_policy *policy = cwt_policy(L, 3);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_cwt_verify(h->ptr, bytes, length, policy, &error);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int cwt_view_get(lua_State *L) {
  c89cbor_cwt_view view;
  size_t i;
  int status = c89cbor_cwt_view_get(checked(L, 1, CWT)->ptr, &view);
  result(L, status);
  if (status != 0) {
    lua_pushnil(L);
    return 2;
  }
  lua_newtable(L);
  lua_pushlstring(L, view.encoded, view.encoded_length);
  lua_setfield(L, -2, "encoded");
  if (view.cti != NULL) {
    lua_pushlstring(L, view.cti, view.cti_length);
    lua_setfield(L, -2, "cti");
  }
  lua_pushboolean(L, view.authenticated);
  lua_setfield(L, -2, "authenticated");
  lua_pushinteger(L, view.algorithm);
  lua_setfield(L, -2, "algorithm");
  push_integer(L, view.claim_count);
  lua_setfield(L, -2, "claim_count");
  lua_newtable(L);
#define VIEW_TEXT(field)                                                       \
  if (view.claims->field != NULL) {                                            \
    lua_pushstring(L, view.claims->field);                                     \
    lua_setfield(L, -2, #field);                                               \
  }
  VIEW_TEXT(iss);
  VIEW_TEXT(sub);
  VIEW_TEXT(aud);
  VIEW_TEXT(nonce);
  VIEW_TEXT(azp);
  VIEW_TEXT(scope);
#undef VIEW_TEXT
#define VIEW_DATE(field)                                                       \
  if (view.claims->has_##field) {                                              \
    lua_pushinteger(L, (lua_Integer)view.claims->field);                       \
    lua_setfield(L, -2, #field);                                               \
  }
  VIEW_DATE(exp);
  VIEW_DATE(nbf);
  VIEW_DATE(iat);
#undef VIEW_DATE
#define VIEW_ARRAY(field)                                                      \
  lua_newtable(L);                                                             \
  for (i = 0; i < view.claims->field.count; ++i) {                             \
    lua_pushstring(L, view.claims->field.items[i]);                            \
    lua_rawseti(L, -2, (lua_Integer)i + 1);                                    \
  }                                                                            \
  lua_setfield(L, -2, #field)
  VIEW_ARRAY(aud_array);
  VIEW_ARRAY(scp);
#undef VIEW_ARRAY
  lua_setfield(L, -2, "claims");
  return 2;
}
static int cwt_claim(lua_State *L) {
  c89cbor_token key, *native;
  const void *bytes;
  size_t length;
  lua_Integer number;
  int status;
  native =
      luaL_testudata(L, 2, TOKEN) == NULL ? NULL : checked(L, 2, TOKEN)->ptr;
  memset(&key, 0, sizeof(key));
  if (native != NULL)
    key = *native;
  else if (lua_type(L, 2) == LUA_TSTRING) {
    key.type = C89CBOR_TEXT;
    key.data = (const unsigned char *)lua_tolstring(L, 2, &key.length);
  } else {
    number = luaL_checkinteger(L, 2);
    key.type = number < 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT;
    key.argument = (uint64_t)(number < 0 ? -(number + 1) : number);
  }
  status = c89cbor_cwt_claim(checked(L, 1, CWT)->ptr, &key, &bytes, &length);
  result(L, status);
  if (status == 0)
    lua_pushlstring(L, bytes, length);
  else
    lua_pushnil(L);
  return 2;
}
