#include <c89cbor/lua.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef int (*push_source_fn)(cpkt_lua_state *, c89cbor_source *, int);
typedef int (*push_sink_fn)(cpkt_lua_state *, c89cbor_sink *, int);
typedef struct native_stream {
  size_t offset;
  uint64_t produced, consumed, limit;
  unsigned char record[1027];
} native_stream;
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
  push_source_fn push_source;
  push_sink_fn push_sink;
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
  symbol = dlsym(module, "c89cbor_lua_push_source");
  assert(symbol != NULL);
  memcpy(&push_source, &symbol, sizeof(push_source));
  symbol = dlsym(module, "c89cbor_lua_push_sink");
  assert(symbol != NULL);
  memcpy(&push_sink, &symbol, sizeof(push_sink));
  L = cpkt_lua_l_newstate();
  assert(L != NULL);
  cpkt_lua_l_openlibs(L);
  cpkt_lua_pushstring(L, c89cbor_version());
  cpkt_lua_setglobal(L, "expected_version");
  cpkt_lua_l_requiref(L, "cbor", opener, 1);
  cpkt_lua_pop(L, 1);
  memset(&stream, 0, sizeof(stream));
  stream.record[0] = 0x59;
  stream.record[1] = 4;
  memset(stream.record + 3, 'x', sizeof(stream.record) - 3);
  stream.limit = UINT64_C(1027) * 65536U;
  source.context = &stream;
  source.read = produce;
  sink.context = &stream;
  sink.write = consume;
  assert(push_source(L, &source, 0) == 0);
  cpkt_lua_setglobal(L, "native_source");
  assert(push_sink(L, &sink, 0) == 0);
  cpkt_lua_setglobal(L, "native_sink");
  assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
  if (strcmp(args->script, "--native") == 0) {
    c89cbor_transfer transfer;
    assert(c89cbor_transfer_init(&transfer, &source, &sink, C89CBOR_SEQUENCE,
                                 0) == 0);
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
  cpkt_lua_close(L);
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
