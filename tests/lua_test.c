#include <c89cbor/lua.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

typedef int (*binding_init_fn)(c89cbor_lua *, lua_State *,
                               const c89cbor_allocator *, c89cbor_error *);
typedef int (*binding_create_fn)(lua_State *, const c89cbor_allocator *,
                                 c89cbor_lua **, c89cbor_error *);
typedef struct native_stream {
  size_t offset;
  uint64_t produced, consumed, limit;
  uint64_t reads, writes;
  unsigned char record[1027];
} native_stream;
typedef struct test_buffer {
  unsigned char bytes[4096];
  size_t length, offset, calls;
  int pause;
} test_buffer;
typedef struct test_record {
  lonejson_int64 id;
  char *name;
} test_record;
static const lonejson_field test_fields[] = {
    LONEJSON_FIELD_I64_REQ(test_record, id, "id"),
    LONEJSON_FIELD_STRING_ALLOC_REQ(test_record, name, "name")};
LONEJSON_MAP_DEFINE(test_map, test_record, test_fields);
typedef struct conversion_fixture {
  c89cbor_lua *binding;
  lonejson *json;
  test_record input, output;
  lonejson_record_view input_view, output_view;
  c89cbor_source source;
  c89cbor_sink sink;
  test_buffer json_input, wire, json_output;
  c89cbor_allocator allocator;
  lonejson_jwt_claims jwt_claims;
  lonejson_jwt_claim_policy jwt_policy;
  size_t live;
} conversion_fixture;
static int native_cwt_case(lua_State *L) {
  static char issuer[] = "issuer", subject[] = "subject",
              audience[] = "service";
  static const char *const algorithms[] = {"Ed25519", "ES256", "HS256"};
  static const char *const issuers[] = {"issuer"}, *const audiences[] = {
                                                       "service"};
  conversion_fixture *fixture = lua_touserdata(L, lua_upvalueindex(1));
  memset(&fixture->jwt_claims, 0, sizeof(fixture->jwt_claims));
  fixture->jwt_claims.iss = issuer;
  fixture->jwt_claims.sub = subject;
  fixture->jwt_claims.aud = audience;
  fixture->jwt_claims.exp = 1000;
  fixture->jwt_claims.has_exp = 1;
  memset(&fixture->jwt_policy, 0, sizeof(fixture->jwt_policy));
  fixture->jwt_policy.accepted_algs = algorithms;
  fixture->jwt_policy.accepted_alg_count = 3u;
  fixture->jwt_policy.accepted_issuers = issuers;
  fixture->jwt_policy.accepted_issuer_count = 1u;
  fixture->jwt_policy.accepted_audiences = audiences;
  fixture->jwt_policy.accepted_audience_count = 1u;
  fixture->jwt_policy.now = 100;
  assert(fixture->binding->push_jwt_claims(fixture->binding,
                                           &fixture->jwt_claims, 0) == 0);
  assert(fixture->binding->push_jwt_policy(fixture->binding,
                                           &fixture->jwt_policy, 0) == 0);
  return 2;
}
static void *count_allocate(void *context, size_t size) {
  conversion_fixture *fixture = context;
  void *memory = malloc(size);
  if (memory != NULL)
    ++fixture->live;
  return memory;
}
static void count_free(void *context, void *memory) {
  conversion_fixture *fixture = context;
  if (memory != NULL) {
    assert(fixture->live != 0);
    --fixture->live;
    free(memory);
  }
}
static int buffer_read(void *context, void *bytes, size_t capacity,
                       size_t *count) {
  test_buffer *buffer = context;
  size_t take = buffer->length - buffer->offset;
  *count = 0;
  if (buffer->pause && (++buffer->calls % 2u) != 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > 7u)
    take = 7u;
  memcpy(bytes, buffer->bytes + buffer->offset, take);
  buffer->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int buffer_write(void *context, const void *bytes, size_t length,
                        size_t *count) {
  test_buffer *buffer = context;
  size_t take = length < 5u ? length : 5u;
  assert(take <= sizeof(buffer->bytes) - buffer->length);
  memcpy(buffer->bytes + buffer->length, bytes, take);
  buffer->length += take;
  *count = take;
  return buffer->pause ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static int native_case(lua_State *L) {
  conversion_fixture *fixture = lua_touserdata(L, lua_upvalueindex(1));
  int mode = (int)luaL_checkinteger(L, 1);
  int pause = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  lonejson_error error;
  fixture->json_input.pause = fixture->wire.pause = fixture->json_output.pause =
      pause;
  fixture->source.read = buffer_read;
  fixture->sink.write = buffer_write;
  if (mode == 1 || mode == 3) {
    fixture->wire.length = fixture->wire.offset = fixture->wire.calls = 0;
    fixture->sink.context = &fixture->wire;
    if (mode == 1) {
      fixture->json_input.offset = fixture->json_input.calls = 0;
      fixture->source.context = &fixture->json_input;
      assert(fixture->binding->push_source(fixture->binding, &fixture->source,
                                           0) == 0);
    } else
      assert(fixture->binding->push_record_view(fixture->binding,
                                                &fixture->input_view, 0) == 0);
    assert(fixture->binding->push_sink(fixture->binding, &fixture->sink, 0) ==
           0);
  } else {
    fixture->wire.offset = fixture->wire.calls = 0;
    fixture->source.context = &fixture->wire;
    assert(fixture->binding->push_source(fixture->binding, &fixture->source,
                                         0) == 0);
    if (mode == 2) {
      fixture->json_output.length = fixture->json_output.offset = 0;
      fixture->sink.context = &fixture->json_output;
      assert(fixture->binding->push_sink(fixture->binding, &fixture->sink, 0) ==
             0);
    } else {
      assert(fixture->json->reset(fixture->json, &test_map, &fixture->output,
                                  &error) == LONEJSON_STATUS_OK);
      assert(fixture->binding->push_record_view(fixture->binding,
                                                &fixture->output_view, 0) == 0);
    }
  }
  return 2;
}
static void prepare_fixture(conversion_fixture *fixture, c89cbor_lua *binding) {
  static const char document[] = "{\"id\":42,\"name\":\"native record\"}";
  lonejson_error error;
  lonejson_record_view *view;
  size_t i;
  memset(fixture, 0, sizeof(*fixture));
  fixture->binding = binding;
  fixture->json = lonejson_new(NULL, &error);
  assert(fixture->json != NULL);
  assert(lonejson_init(fixture->json, &test_map, &fixture->input, &error) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_init(fixture->json, &test_map, &fixture->output, &error) ==
         LONEJSON_STATUS_OK);
  assert(lonejson_parse_cstr(fixture->json, &test_map, &fixture->input,
                             document, &error) == LONEJSON_STATUS_OK);
  for (i = 0; i < 2; ++i) {
    view = i == 0 ? &fixture->input_view : &fixture->output_view;
    view->size = sizeof(*view);
    view->abi_version = LONEJSON_VIEW_ABI_VERSION;
    view->schema.size = sizeof(view->schema);
    view->schema.abi_version = LONEJSON_VIEW_ABI_VERSION;
    view->schema.runtime = fixture->json;
    view->schema.map = &test_map;
    view->schema.record_size = sizeof(test_record);
    view->record = i == 0 ? &fixture->input : &fixture->output;
  }
  memcpy(fixture->json_input.bytes, document, sizeof(document) - 1u);
  fixture->json_input.length = sizeof(document) - 1u;
  fixture->json_input.pause = fixture->wire.pause = fixture->json_output.pause =
      1;
  lua_pushlightuserdata(binding->state, fixture);
  lua_pushcclosure(binding->state, native_case, 1);
  lua_setglobal(binding->state, "native_case");
  lua_pushlightuserdata(binding->state, fixture);
  lua_pushcclosure(binding->state, native_cwt_case, 1);
  lua_setglobal(binding->state, "native_cwt_case");
  fixture->allocator.context = fixture;
  fixture->allocator.alloc = count_allocate;
  fixture->allocator.free = count_free;
  assert(binding->push_allocator(binding, &fixture->allocator, 0) == 0);
  lua_setglobal(binding->state, "counting_allocator");
}
typedef struct sync_probe {
  lua_State *state;
  c89cbor_source source;
  c89cbor_sink sink;
  size_t calls;
  int finalized;
} sync_probe;
static int finalize_sync_owner(lua_State *L) {
  sync_probe **owner = lua_touserdata(L, 1);
  ++(*owner)->finalized;
  return 0;
}
static void probe_sync_arguments(sync_probe *probe) {
  assert(
      luaL_dostring(
          probe->state,
          "local c=require('cbor'); "
          "assert(sync_left:close()==c.INVALID); "
          "assert(sync_right:close()==c.INVALID); "
          "assert(sync_options:close()==c.INVALID); "
          "assert(sync_root:close()==c.INVALID); collectgarbage('collect')") ==
      LUA_OK);
  assert(probe->finalized == 0);
  ++probe->calls;
}
static int sync_read(void *context, void *bytes, size_t capacity,
                     size_t *count) {
  sync_probe *probe = context;
  probe_sync_arguments(probe);
  return probe->source.read(probe->source.context, bytes, capacity, count);
}
static int sync_write(void *context, const void *bytes, size_t length,
                      size_t *count) {
  sync_probe *probe = context;
  probe_sync_arguments(probe);
  return probe->sink.write(probe->sink.context, bytes, length, count);
}
static void synchronous_reentry(c89cbor_lua *binding) {
  static const char *const methods[] = {"json_to_cbor", "cbor_to_json",
                                        "encode_map", "decode_map"};
  lua_State *L = binding->state;
  sync_probe probe, **owner;
  c89cbor_source source;
  c89cbor_sink sink;
  lonejson_record_view *view;
  c89cbor_options options = c89cbor_default_options();
  char script[640];
  int mode, pause, owner_index, status;
  for (pause = 0; pause < 2; ++pause)
    for (mode = 1; mode <= 4; ++mode) {
      memset(&probe, 0, sizeof(probe));
      probe.state = L;
      lua_getglobal(L, "native_case");
      lua_pushinteger(L, mode);
      lua_pushboolean(L, pause);
      assert(lua_pcall(L, 2, 2, 0) == LUA_OK);
      view = NULL;
      if (mode == 3)
        view = binding->check_record_view(binding, -2);
      else
        probe.source = *binding->check_source(binding, -2);
      if (mode == 4)
        view = binding->check_record_view(binding, -1);
      else
        probe.sink = *binding->check_sink(binding, -1);
      lua_pop(L, 2);
      owner = lua_newuserdatauv(L, sizeof(*owner), 0);
      *owner = &probe;
      lua_newtable(L);
      lua_pushcfunction(L, finalize_sync_owner);
      lua_setfield(L, -2, "__gc");
      lua_setmetatable(L, -2);
      owner_index = lua_gettop(L);
      source.context = sink.context = &probe;
      source.read = sync_read;
      sink.write = sync_write;
      if (mode == 3)
        assert(binding->push_record_view(binding, view, owner_index) == 0);
      else
        assert(binding->push_source(binding, &source, owner_index) == 0);
      lua_setglobal(L, "sync_left");
      if (mode == 4)
        assert(binding->push_record_view(binding, view, owner_index) == 0);
      else
        assert(binding->push_sink(binding, &sink, owner_index) == 0);
      lua_setglobal(L, "sync_right");
      assert(binding->push_options(binding, &options, owner_index) == 0);
      lua_setglobal(L, "sync_options");
      lua_pop(L, 1);
      status = snprintf(
          script, sizeof(script),
          "local c=require('cbor'); sync_root=c.create(); "
          "assert(sync_root:%s(sync_left,sync_right,sync_options)==c.%s); "
          "assert(sync_left:close()==c.OK); assert(sync_right:close()==c.OK); "
          "assert(sync_options:close()==c.OK); "
          "assert(sync_root:close()==c.OK); "
          "sync_left=nil; sync_right=nil; sync_options=nil; sync_root=nil; "
          "collectgarbage('collect')",
          methods[mode - 1], pause ? "IO" : "OK");
      assert(status > 0 && (size_t)status < sizeof(script));
      assert(luaL_dostring(L, script) == LUA_OK);
      assert(probe.calls != 0 && probe.finalized == 1);
    }
}
static int close_at(lua_State *L, int index) {
  int status;
  index = lua_absindex(L, index);
  lua_getfield(L, index, "close");
  lua_pushvalue(L, index);
  assert(lua_pcall(L, 1, 1, 0) == LUA_OK);
  status = (int)luaL_checkinteger(L, -1);
  lua_pop(L, 1);
  return status;
}
typedef struct key_import_probe {
  lua_State *state;
  size_t calls, fail_at, live;
  int armed, finalized;
} key_import_probe;
typedef struct key_input_owner {
  key_import_probe *probe;
  void *bytes;
} key_input_owner;
static int finalize_key_input(lua_State *L) {
  key_input_owner *owner = lua_touserdata(L, 1);
  free(owner->bytes);
  ++owner->probe->finalized;
  return 0;
}
static void *key_import_allocate(void *context, size_t size) {
  key_import_probe *probe = context;
  void *memory;
  if (probe->armed) {
    ++probe->calls;
    assert(luaL_dostring(probe->state,
                         "local c=require('cbor'); "
                         "assert(import_bytes:close()==c.INVALID); "
                         "assert(import_id:close()==c.INVALID); "
                         "assert(import_root:close()==c.INVALID); "
                         "collectgarbage('collect')") == LUA_OK);
    assert(probe->finalized == 0);
    if (probe->calls == probe->fail_at)
      return NULL;
  }
  memory = malloc(size);
  if (memory != NULL)
    ++probe->live;
  return memory;
}
static void key_import_free(void *context, void *memory) {
  key_import_probe *probe = context;
  if (memory != NULL) {
    assert(probe->live != 0);
    --probe->live;
    free(memory);
  }
}
static void push_key_input(c89cbor_lua *binding, key_import_probe *probe,
                           const char *name) {
  lua_State *L = binding->state;
  key_input_owner *owner = lua_newuserdatauv(L, sizeof(*owner), 0);
  owner->probe = probe;
  owner->bytes = malloc(32);
  assert(owner->bytes != NULL);
  memset(owner->bytes, 'k', 32);
  lua_newtable(L);
  lua_pushcfunction(L, finalize_key_input);
  lua_setfield(L, -2, "__gc");
  lua_setmetatable(L, -2);
  assert(binding->push_span(binding, owner->bytes, 32, lua_gettop(L)) == 0);
  lua_setglobal(L, name);
  lua_pop(L, 1);
}
static void key_import_reentry(c89cbor_lua *binding) {
  lua_State *L = binding->state;
  key_import_probe probe;
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  char script[640];
  int create, status;
  size_t fail_at;
  for (create = 0; create < 2; ++create)
    for (fail_at = 0; fail_at <= (size_t)create + 1u; ++fail_at) {
      memset(&probe, 0, sizeof(probe));
      probe.state = L;
      probe.fail_at = fail_at;
      config.allocator.context = &probe;
      config.allocator.alloc = key_import_allocate;
      config.allocator.free = key_import_free;
      assert(c89cbor_init(&runtime, &config, &error) == 0);
      assert(binding->push_runtime(binding, &runtime, 0) == 0);
      lua_setglobal(L, "import_root");
      push_key_input(binding, &probe, "import_bytes");
      push_key_input(binding, &probe, "import_id");
      probe.armed = 1;
      status = snprintf(
          script, sizeof(script),
          "local c=require('cbor'); "
          "local key,why=import_root:cose_key_%s(c.COSE_A256GCM,"
          "import_bytes,import_id); import_key=key; %s "
          "assert(import_bytes:close()==c.OK); "
          "assert(import_id:close()==c.OK); "
          "import_bytes=nil; import_id=nil; collectgarbage('collect')",
          create ? "create" : "init",
          fail_at ? "assert(key==nil and why==c.NOMEM);"
                  : "assert(key); local s,info=key:metadata(); "
                    "assert(s==c.OK and info.key_id==string.rep('k',32));");
      assert(status > 0 && (size_t)status < sizeof(script));
      assert(luaL_dostring(L, script) == LUA_OK);
      assert(probe.calls == (fail_at ? fail_at : (size_t)create + 1u));
      assert(probe.finalized == 2);
      assert(
          luaL_dostring(
              L,
              "local c=require('cbor'); "
              "if import_key then assert(import_key:close()==c.OK) end; "
              "assert(import_root:close()==c.OK); "
              "import_key=nil; import_root=nil; collectgarbage('collect')") ==
          LUA_OK);
      assert(probe.live == 0);
      assert(runtime.cleanup(&runtime) == 0);
    }
}
static void typed_interop(c89cbor_lua *binding, conversion_fixture *fixture) {
  lua_State *L = binding->state;
  c89cbor runtime;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_reader reader;
  c89cbor_fd descriptor;
  c89cbor_transfer transfer;
  c89cbor_conversion operation;
  c89cbor_cose_key cose_key;
  c89cbor_cose_operation cose_operation;
  c89cbor_cose_options cose_options = c89cbor_default_cose_options();
  c89cbor_cwt cwt;
  c89cbor_datagram datagram;
  int datagram_pair[2];
  c89cbor_cwt_options cwt_options = c89cbor_default_cwt_options();
  lonejson_jwt_claims jwt_claims;
  lonejson_jwt_claim_policy jwt_policy;
  unsigned char key[32] = {0};
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  const void *bytes;
  size_t length;
  int owner = lua_gettop(L) + 1;
  source.context = &fixture->wire;
  source.read = buffer_read;
  sink.context = &fixture->json_output;
  sink.write = buffer_write;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(binding->push_runtime(binding, &runtime, 0) == 0 &&
         binding->check_runtime(binding, -1) == &runtime);
  assert(runtime.encoder_init(&runtime, &encoder, NULL, 0, 0) == 0);
  assert(runtime.decoder_init(&runtime, &decoder, NULL, 0, 0) == 0);
  assert(runtime.reader_init(&runtime, &reader, C89CBOR_SINGLE, 0) == 0);
  assert(runtime.fd_init(&runtime, &descriptor, 0, NULL, &sink) == 0);
  sink.context = &fixture->json_output;
  sink.write = buffer_write;
  assert(runtime.transfer_init(&runtime, &transfer, &source, &sink,
                               C89CBOR_SINGLE, 0) == 0);
  assert(runtime.cbor_to_json_init(&runtime, &operation, &source, &sink, NULL,
                                   &error) == 0);
  assert(runtime.cose_key_init(&runtime, &cose_key, C89CBOR_COSE_A256GCM, key,
                               sizeof(key), NULL, 0, &error) == 0);
  assert(runtime.cose_encrypt0_init(&runtime, &cose_operation, &source, &sink,
                                    &cose_key, NULL, &error) == 0);
#define CHECK_BRIDGE(name, value)                                              \
  do {                                                                         \
    assert(binding->push_##name(binding, &(value), owner) == 0);               \
    assert(binding->check_##name(binding, -1) == &(value));                    \
    assert(close_at(L, owner) == C89CBOR_INVALID);                             \
    assert(close_at(L, -1) == 0);                                              \
    lua_pop(L, 1);                                                             \
  } while (0)
  CHECK_BRIDGE(encoder, encoder);
  CHECK_BRIDGE(decoder, decoder);
  CHECK_BRIDGE(reader, reader);
  CHECK_BRIDGE(fd, descriptor);
  CHECK_BRIDGE(transfer, transfer);
  CHECK_BRIDGE(conversion, operation);
  CHECK_BRIDGE(source, source);
  CHECK_BRIDGE(sink, sink);
  CHECK_BRIDGE(options, options);
  CHECK_BRIDGE(config, config);
  CHECK_BRIDGE(cose_key, cose_key);
  CHECK_BRIDGE(cose_operation, cose_operation);
  CHECK_BRIDGE(cose_options, cose_options);
  assert(runtime.cwt_init(&runtime, &cwt, &cwt_options, &error) == 0);
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, datagram_pair) == 0);
  assert(runtime.datagram_init(&runtime, &datagram, datagram_pair[0], 0,
                               &error) == 0);
  CHECK_BRIDGE(datagram, datagram);
  memset(&jwt_claims, 0, sizeof(jwt_claims));
  memset(&jwt_policy, 0, sizeof(jwt_policy));
  CHECK_BRIDGE(cwt, cwt);
  CHECK_BRIDGE(cwt_options, cwt_options);
  CHECK_BRIDGE(jwt_claims, jwt_claims);
  CHECK_BRIDGE(jwt_policy, jwt_policy);
#undef CHECK_BRIDGE
  assert(binding->push_record_view(binding, &fixture->input_view, owner) == 0);
  assert(binding->check_record_view(binding, -1)->record == &fixture->input);
  assert(close_at(L, -1) == 0);
  lua_pop(L, 1);
  assert(binding->push_span(binding, "abc", 3, owner) == 0);
  assert(binding->check_span(binding, -1, &bytes, &length) == 0 &&
         length == 3 && memcmp(bytes, "abc", 3) == 0);
  assert(close_at(L, -1) == 0);
  assert(binding->check_span(binding, -1, &bytes, &length) == C89CBOR_INVALID &&
         bytes == NULL && length == 0);
  lua_pop(L, 1);
  assert(close_at(L, owner) == 0);
  lua_pop(L, 1);
  assert(operation.cleanup(&operation) == 0 &&
         transfer.cleanup(&transfer) == 0);
  assert(cose_operation.cleanup(&cose_operation) == 0);
  assert(cose_key.cleanup(&cose_key) == 0);
  assert(cwt.cleanup(&cwt) == 0);
  assert(datagram.cleanup(&datagram) == 0);
  assert(close(datagram_pair[0]) == 0 && close(datagram_pair[1]) == 0);
  assert(descriptor.cleanup(&descriptor) == 0 && reader.cleanup(&reader) == 0);
  assert(decoder.cleanup(&decoder) == 0 && encoder.cleanup(&encoder) == 0 &&
         runtime.cleanup(&runtime) == 0);
}
static int produce(void *ctx, void *out, size_t capacity, size_t *count) {
  native_stream *s = ctx;
  unsigned char *p = out;
  size_t at = 0, take, n = capacity;
  ++s->reads;
  if ((uint64_t)n > s->limit - s->produced)
    n = (size_t)(s->limit - s->produced);
  while (at < n) {
    take = sizeof(s->record) - s->offset;
    if (take > n - at)
      take = n - at;
    memcpy(p + at, s->record + s->offset, take);
    at += take;
    s->offset += take;
    if (s->offset == sizeof(s->record))
      s->offset = 0;
  }
  s->produced += n;
  *count = n;
  assert(s->produced - s->consumed <= C89CBOR_CHUNK);
  return 0;
}
static int consume(void *ctx, const void *bytes, size_t n, size_t *count) {
  native_stream *s = ctx;
  const unsigned char *p = bytes;
  size_t i;
  ++s->writes;
  for (i = 0; i < n; ++i)
    assert(p[i] == s->record[(size_t)((s->consumed + i) % sizeof(s->record))]);
  s->consumed += n;
  *count = n;
  return 0;
}
typedef struct arguments {
  const char *module;
  const char *script;
} arguments;
static void *run(void *ctx) {
  arguments *args = ctx;
  void *module = dlopen(args->module, RTLD_NOW | RTLD_LOCAL), *symbol;
  lua_CFunction opener;
  binding_init_fn binding_init;
  binding_create_fn binding_create;
  c89cbor_lua binding;
  c89cbor_lua *heap_binding;
  c89cbor_error error;
  conversion_fixture fixture;
  lonejson_error jerror;
  lua_State *L;
  native_stream stream;
  c89cbor_source source;
  c89cbor_sink sink;
  int rc, datagram_pair[2];
  struct timespec begin, end, cpu_begin, cpu_end;
  if (module == NULL)
    fprintf(stderr, "dlopen: %s\n", dlerror());
  assert(module != NULL);
  symbol = dlsym(module, "luaopen_cbor");
  assert(symbol != NULL && sizeof(symbol) == sizeof(opener));
  memcpy(&opener, &symbol, sizeof(opener));
  symbol = dlsym(module, "c89cbor_lua_init");
  assert(symbol != NULL);
  memcpy(&binding_init, &symbol, sizeof(binding_init));
  symbol = dlsym(module, "c89cbor_lua_create");
  assert(symbol != NULL);
  memcpy(&binding_create, &symbol, sizeof(binding_create));
  L = luaL_newstate();
  assert(L != NULL);
  luaL_openlibs(L);
  lua_pushstring(L, c89cbor_version(NULL));
  lua_setglobal(L, "expected_version");
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, datagram_pair) == 0);
  assert(fcntl(datagram_pair[0], F_SETFL, O_NONBLOCK) == 0);
  assert(fcntl(datagram_pair[1], F_SETFL, O_NONBLOCK) == 0);
  lua_pushinteger(L, datagram_pair[0]);
  lua_setglobal(L, "datagram_fd_a");
  lua_pushinteger(L, datagram_pair[1]);
  lua_setglobal(L, "datagram_fd_b");
  luaL_requiref(L, "cbor", opener, 1);
  lua_pop(L, 1);
  assert(binding_init(&binding, L, NULL, &error) == 0);
  prepare_fixture(&fixture, &binding);
  if (strstr(args->script, "lua_test.lua") != NULL) {
    synchronous_reentry(&binding);
    key_import_reentry(&binding);
  }
  typed_interop(&binding, &fixture);
  assert(binding.destroy(&binding) == C89CBOR_INVALID);
  assert(binding_create(L, &fixture.allocator, &heap_binding, &error) == 0);
  assert(heap_binding->destroy(heap_binding) == 0 && fixture.live == 0);
  memset(&stream, 0, sizeof(stream));
  stream.record[0] = 0x59;
  stream.record[1] = 4;
  memset(stream.record + 3, 'x', sizeof(stream.record) - 3);
  stream.limit = UINT64_C(1027) * 65536U;
  source.context = &stream;
  source.read = produce;
  sink.context = &stream;
  sink.write = consume;
  assert(binding.push_source(&binding, &source, 0) == 0);
  assert(binding.check_source(&binding, -1) == &source);
  assert(binding.check_sink(&binding, -1) == NULL);
  lua_setglobal(L, "native_source");
  assert(binding.push_sink(&binding, &sink, 0) == 0);
  lua_setglobal(L, "native_sink");
  assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
  assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_begin) == 0);
  if (strcmp(args->script, "--native") == 0) {
    c89cbor_transfer transfer;
    assert(c89cbor_transfer_init(NULL, &transfer, &source, &sink,
                                 C89CBOR_SEQUENCE, 0) == 0);
    do {
      rc = c89cbor_transfer_step(&transfer);
    } while (rc == C89CBOR_OK);
    assert(rc == C89CBOR_DONE);
    assert(c89cbor_transfer_cleanup(&transfer) == 0);
    rc = 0;
  } else {
    rc = luaL_dofile(L, args->script);
    if (rc != 0)
      fprintf(stderr, "lua: %s\n", lua_tostring(L, -1));
  }
  assert(rc == 0 && stream.produced == stream.limit &&
         stream.consumed == stream.limit);
  assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end) == 0);
  printf("{\"case\":\"%s-native-transfer\",\"bytes\":%lu,\"seconds\":%.9f,"
         "\"cpu_seconds\":%.9f,\"source_calls\":%lu,\"sink_calls\":%lu,"
         "\"endpoint_copied_bytes\":%lu,\"verified\":true}\n",
         strcmp(args->script, "--native") == 0 ? "c" : "lua",
         (unsigned long)stream.limit,
         (double)(end.tv_sec - begin.tv_sec) +
             (double)(end.tv_nsec - begin.tv_nsec) / 1e9,
         (double)(cpu_end.tv_sec - cpu_begin.tv_sec) +
             (double)(cpu_end.tv_nsec - cpu_begin.tv_nsec) / 1e9,
         (unsigned long)stream.reads, (unsigned long)stream.writes,
         (unsigned long)stream.produced);
  assert(binding.cleanup(&binding) == 0);
  assert(binding.cleanup(&binding) == 0 &&
         binding.check_runtime(&binding, 1) == NULL);
  lua_close(L);
  assert(close(datagram_pair[0]) == 0 && close(datagram_pair[1]) == 0);
  assert(fixture.live == 0);
  if (strstr(args->script, "lua_test.lua") != NULL) {
    assert(fixture.output.id == 42 &&
           strcmp(fixture.output.name, "native record") == 0);
    assert(fixture.json_output.length == fixture.json_input.length &&
           memcmp(fixture.json_output.bytes, fixture.json_input.bytes,
                  fixture.json_input.length) == 0);
  }
  assert(fixture.json->cleanup(fixture.json, &test_map, &fixture.input,
                               &jerror) == LONEJSON_STATUS_OK);
  assert(fixture.json->cleanup(fixture.json, &test_map, &fixture.output,
                               &jerror) == LONEJSON_STATUS_OK);
  lonejson_free(fixture.json);
  assert(dlclose(module) == 0);
  return NULL;
}
int main(int argc, char **argv) {
  arguments args;
  pthread_t worker;
  assert(argc == 3);
  args.module = argv[1];
  args.script = argv[2];
  assert(pthread_create(&worker, NULL, run, &args) == 0);
  assert(pthread_join(worker, NULL) == 0);
  return 0;
}
