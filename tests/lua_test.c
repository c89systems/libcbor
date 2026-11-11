#include <c89cbor/lua.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int (*binding_init_fn)(c89cbor_lua *, cpkt_lua_state *,
                               const c89cbor_allocator *, c89cbor_error *);
typedef int (*binding_create_fn)(cpkt_lua_state *, const c89cbor_allocator *,
                                 c89cbor_lua **, c89cbor_error *);
typedef struct native_stream {
  size_t offset;
  uint64_t produced, consumed, limit;
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
  size_t live;
} conversion_fixture;
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
static int native_case(cpkt_lua_state *L) {
  conversion_fixture *fixture =
      cpkt_lua_touserdata(L, cpkt_lua_upvalueindex(1));
  int mode = (int)cpkt_lua_l_checkinteger(L, 1).low;
  int pause = cpkt_lua_isnoneornil(L, 2) ? 1 : cpkt_lua_toboolean(L, 2);
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
  cpkt_lua_pushlightuserdata(binding->state, fixture);
  cpkt_lua_pushcclosure(binding->state, native_case, 1);
  cpkt_lua_setglobal(binding->state, "native_case");
  fixture->allocator.context = fixture;
  fixture->allocator.alloc = count_allocate;
  fixture->allocator.free = count_free;
  assert(binding->push_allocator(binding, &fixture->allocator, 0) == 0);
  cpkt_lua_setglobal(binding->state, "counting_allocator");
}
static int close_at(cpkt_lua_state *L, int index) {
  int status;
  index = cpkt_lua_absindex(L, index);
  cpkt_lua_getfield(L, index, "close");
  cpkt_lua_pushvalue(L, index);
  assert(cpkt_lua_pcall(L, 1, 1, 0) == CPKT_LUA_OK);
  status = (int)(int32_t)cpkt_lua_l_checkinteger(L, -1).low;
  cpkt_lua_pop(L, 1);
  return status;
}
static void typed_interop(c89cbor_lua *binding, conversion_fixture *fixture) {
  cpkt_lua_state *L = binding->state;
  c89cbor runtime;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_reader reader;
  c89cbor_fd descriptor;
  c89cbor_transfer transfer;
  c89cbor_conversion operation;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_options options = c89cbor_default_options();
  c89cbor_error error;
  c89cbor_source source;
  c89cbor_sink sink;
  const void *bytes;
  size_t length;
  int owner = cpkt_lua_gettop(L) + 1;
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
#define CHECK_BRIDGE(name, value)                                              \
  do {                                                                         \
    assert(binding->push_##name(binding, &(value), owner) == 0);               \
    assert(binding->check_##name(binding, -1) == &(value));                    \
    assert(close_at(L, owner) == C89CBOR_INVALID);                             \
    assert(close_at(L, -1) == 0);                                              \
    cpkt_lua_pop(L, 1);                                                        \
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
#undef CHECK_BRIDGE
  assert(binding->push_record_view(binding, &fixture->input_view, owner) == 0);
  assert(binding->check_record_view(binding, -1)->record == &fixture->input);
  assert(close_at(L, -1) == 0);
  cpkt_lua_pop(L, 1);
  assert(binding->push_span(binding, "abc", 3, owner) == 0);
  assert(binding->check_span(binding, -1, &bytes, &length) == 0 &&
         length == 3 && memcmp(bytes, "abc", 3) == 0);
  assert(close_at(L, -1) == 0);
  assert(binding->check_span(binding, -1, &bytes, &length) == C89CBOR_INVALID &&
         bytes == NULL && length == 0);
  cpkt_lua_pop(L, 1);
  assert(close_at(L, owner) == 0);
  cpkt_lua_pop(L, 1);
  assert(operation.cleanup(&operation) == 0 &&
         transfer.cleanup(&transfer) == 0);
  assert(descriptor.cleanup(&descriptor) == 0 && reader.cleanup(&reader) == 0);
  assert(decoder.cleanup(&decoder) == 0 && encoder.cleanup(&encoder) == 0 &&
         runtime.cleanup(&runtime) == 0);
}
static int produce(void *ctx, void *out, size_t capacity, size_t *count) {
  native_stream *s = ctx;
  unsigned char *p = out;
  size_t at = 0, take, n = capacity;
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
  (void)bytes;
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
  cpkt_lua_c_function opener;
  binding_init_fn binding_init;
  binding_create_fn binding_create;
  c89cbor_lua binding;
  c89cbor_lua *heap_binding;
  c89cbor_error error;
  conversion_fixture fixture;
  lonejson_error jerror;
  cpkt_lua_state *L;
  native_stream stream;
  c89cbor_source source;
  c89cbor_sink sink;
  int rc;
  struct timespec begin, end;
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
  L = cpkt_lua_l_newstate();
  assert(L != NULL);
  cpkt_lua_l_openlibs(L);
  cpkt_lua_pushstring(L, c89cbor_version(NULL));
  cpkt_lua_setglobal(L, "expected_version");
  cpkt_lua_l_requiref(L, "cbor", opener, 1);
  cpkt_lua_pop(L, 1);
  assert(binding_init(&binding, L, NULL, &error) == 0);
  prepare_fixture(&fixture, &binding);
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
  cpkt_lua_setglobal(L, "native_source");
  assert(binding.push_sink(&binding, &sink, 0) == 0);
  cpkt_lua_setglobal(L, "native_sink");
  assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
  if (strcmp(args->script, "--native") == 0) {
    c89cbor_transfer transfer;
    assert(c89cbor_transfer_init(NULL, &transfer, &source, &sink,
                                 C89CBOR_SEQUENCE, 0) == 0);
    do {
      rc = c89cbor_transfer_step(&transfer);
    } while (rc == C89CBOR_OK);
    assert(rc == C89CBOR_DONE);
    rc = 0;
  } else {
    rc = cpkt_lua_l_dofile(L, args->script);
    if (rc != 0)
      fprintf(stderr, "lua: %s\n", cpkt_lua_tostring(L, -1));
  }
  assert(rc == 0 && stream.produced == stream.limit &&
         stream.consumed == stream.limit);
  assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  printf("{\"case\":\"%s-native-transfer\",\"bytes\":%lu,\"seconds\":%.9f}\n",
         strcmp(args->script, "--native") == 0 ? "c" : "lua",
         (unsigned long)stream.limit,
         (double)(end.tv_sec - begin.tv_sec) +
             (double)(end.tv_nsec - begin.tv_nsec) / 1e9);
  assert(binding.cleanup(&binding) == 0);
  assert(binding.cleanup(&binding) == 0 &&
         binding.check_runtime(&binding, 1) == NULL);
  cpkt_lua_close(L);
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
