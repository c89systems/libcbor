#include <c89cbor/lua.h>
#include "measure.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef C89_COSE_LUA
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <dlfcn.h>
#endif

typedef struct cose_bench {
  c89cbor root;
  c89cbor_cose_key content, wrapping, private_key, public_key;
  c89cbor_cose_key signing, verification;
  c89cbor_cwt token;
  lonejson_jwt_claim_policy policy;
  int auth;
  c89cbor_cose_operation seal, open;
  c89cbor_source producer, wire_source;
  c89cbor_sink wire_sink, consumer;
  c89cbor_cose_options options;
  c89cbor_cose_key *keys[8];
  size_t key_count;
  bench_counts counts;
  unsigned char ring[4096], object[4096];
  size_t offset, length, wire_length;
  uint64_t generated, consumed, payload, wire_bytes;
  int early;
} cose_bench;
static int generate(void *context, void *bytes, size_t capacity,
                    size_t *count) {
  cose_bench *b = context;
  size_t take = capacity;
  if ((uint64_t)take > b->payload - b->generated)
    take = (size_t)(b->payload - b->generated);
  memset(bytes, 'x', take);
  b->generated += take;
  ++b->counts.reads;
  b->counts.copies += take;
  *count = take;
  return 0;
}
static int consume(void *context, const void *bytes, size_t length,
                   size_t *count) {
  cose_bench *b = context;
  const unsigned char *in = bytes;
  size_t i;
  for (i = 0; i < length; ++i)
    assert(in[i] == 'x');
  assert((uint64_t)length <= b->payload - b->consumed);
  b->consumed += length;
  b->early |= b->generated < b->payload;
  ++b->counts.writes;
  *count = length;
  return 0;
}
static int ring_write(void *context, const void *bytes, size_t length,
                      size_t *count) {
  cose_bench *b = context;
  const unsigned char *in = bytes;
  size_t i, take = sizeof(b->ring) - b->length;
  if (take > length)
    take = length;
  for (i = 0; i < take; ++i)
    b->ring[(b->offset + b->length + i) % sizeof(b->ring)] = in[i];
  b->length += take;
  b->wire_bytes += take;
  b->counts.copies += take;
  ++b->counts.writes;
  *count = take;
  return take < length ? C89CBOR_OUTPUT : 0;
}
static int ring_read(void *context, void *bytes, size_t capacity,
                     size_t *count) {
  cose_bench *b = context;
  unsigned char *out = bytes;
  size_t i, take = b->length;
  if (take > capacity)
    take = capacity;
  for (i = 0; i < take; ++i)
    out[i] = b->ring[(b->offset + i) % sizeof(b->ring)];
  b->offset = (b->offset + take) % sizeof(b->ring);
  b->length -= take;
  b->counts.copies += take;
  ++b->counts.reads;
  *count = take;
  return take == 0 ? C89CBOR_INPUT : 0;
}
static int object_write(void *context, const void *bytes, size_t length,
                        size_t *count) {
  cose_bench *b = context;
  assert(length <= sizeof(b->object) - b->wire_length);
  memcpy(b->object + b->wire_length, bytes, length);
  b->wire_length += length;
  b->wire_bytes += length;
  b->counts.copies += length;
  ++b->counts.writes;
  *count = length;
  return 0;
}
static int object_read(void *context, void *bytes, size_t capacity,
                       size_t *count) {
  cose_bench *b = context;
  size_t take = b->wire_length - b->offset;
  if (take > capacity)
    take = capacity;
  memcpy(bytes, b->object + b->offset, take);
  b->offset += take;
  b->counts.copies += take;
  ++b->counts.reads;
  *count = take;
  return 0;
}
static void stream_native(cose_bench *b, c89cbor_cose_key *recipient) {
  c89cbor_error error;
  int sealed = 0, opened = 0;
  size_t calls = 0;
  if (b->auth) {
    assert((b->auth == 3 ? b->root.cose_mac0_stream_init
                         : b->root.cose_sign1_stream_init)(
               &b->root, &b->seal, &b->producer, &b->wire_sink, &b->signing,
               &b->options, &error) == 0);
    assert((b->auth == 3 ? b->root.cose_verify_mac0_stream_init
                         : b->root.cose_verify1_stream_init)(
               &b->root, &b->open, &b->wire_source, &b->consumer, recipient,
               &b->options, &error) == 0);
  } else {
    assert(b->root.cose_encrypt_stream_init(
               &b->root, &b->seal, &b->producer, &b->wire_sink, b->keys,
               b->key_count, &b->options, &error) == 0);
    assert(b->root.cose_decrypt_stream_init(&b->root, &b->open, &b->wire_source,
                                            &b->consumer, recipient,
                                            &b->options, &error) == 0);
  }
  while (sealed != C89CBOR_DONE || opened != C89CBOR_DONE) {
    if (sealed != C89CBOR_DONE)
      do {
        sealed = b->seal.step(&b->seal, &error);
      } while (sealed == 0);
    if (opened != C89CBOR_DONE)
      do {
        opened = b->open.step(&b->open, &error);
      } while (opened == 0);
    assert(sealed >= 0 && opened >= 0 && ++calls < 10000000u);
  }
  assert(b->seal.cleanup(&b->seal) == 0 && b->open.cleanup(&b->open) == 0);
}
#ifdef C89_COSE_LUA
static lua_State *open_lua(const char *path, void **module,
                           c89cbor_lua *binding) {
  lua_State *L;
  lua_CFunction opener;
  int (*initialize)(c89cbor_lua *, lua_State *, const c89cbor_allocator *,
                    c89cbor_error *);
  void *symbol;
  c89cbor_error error;
  *module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  assert(*module != NULL);
  symbol = dlsym(*module, "luaopen_cbor");
  assert(symbol != NULL && sizeof(symbol) == sizeof(opener));
  memcpy(&opener, &symbol, sizeof(opener));
  symbol = dlsym(*module, "c89cbor_lua_init");
  assert(symbol != NULL && sizeof(symbol) == sizeof(initialize));
  memcpy(&initialize, &symbol, sizeof(initialize));
  L = luaL_newstate();
  assert(L != NULL);
  luaL_openlibs(L);
  luaL_requiref(L, "cbor", opener, 1);
  lua_pop(L, 1);
  assert(initialize(binding, L, NULL, &error) == 0);
  return L;
}
static void stream_lua(cose_bench *b, c89cbor_cose_key *recipient,
                       c89cbor_lua *binding) {
  lua_State *L = binding->state;
  size_t i;
  static const char script[] =
      "local "
      "seal=assert(root[seal_method](root,producer,wire_sink,seal_keys,"
      "options)) "
      "local "
      "open=assert(root[open_method](root,wire_source,consumer,key,"
      "options)) "
      "local a,b=0,0 repeat "
      "if a~=cbor.DONE then a=seal:run() end "
      "if b~=cbor.DONE then b=open:run() end "
      "assert(a>=0 and b>=0) until a==cbor.DONE and b==cbor.DONE "
      "assert(seal:close()==0 and open:close()==0)";
#define PUSH(name, value, global)                                              \
  assert(binding->push_##name(binding, value, 0) == 0);                        \
  lua_setglobal(L, global)
  PUSH(runtime, &b->root, "root");
  PUSH(source, &b->producer, "producer");
  PUSH(source, &b->wire_source, "wire_source");
  PUSH(sink, &b->wire_sink, "wire_sink");
  PUSH(sink, &b->consumer, "consumer");
  PUSH(cose_key, recipient, "key");
  PUSH(cose_options, &b->options, "options");
#undef PUSH
  lua_newtable(L);
  for (i = 0; i < b->key_count; ++i) {
    assert(binding->push_cose_key(binding, b->keys[i], 0) == 0);
    lua_rawseti(L, -2, (lua_Integer)i + 1);
  }
  lua_setglobal(L, "keys");
  lua_getglobal(L, "keys");
  if (b->auth) {
    lua_pop(L, 1);
    assert(binding->push_cose_key(binding, &b->signing, 0) == 0);
  }
  lua_setglobal(L, "seal_keys");
  lua_pushstring(L, b->auth == 3 ? "cose_mac0_stream_init"
                    : b->auth    ? "cose_sign1_stream_init"
                                 : "cose_encrypt_stream_init");
  lua_setglobal(L, "seal_method");
  lua_pushstring(L, b->auth == 3 ? "cose_verify_mac0_stream_init"
                    : b->auth    ? "cose_verify1_stream_init"
                                 : "cose_decrypt_stream_init");
  lua_setglobal(L, "open_method");
  if (luaL_dostring(L, script) != 0) {
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    abort();
  }
}
#endif
int main(int argc, char **argv) {
  cose_bench *b = calloc(1, sizeof(*b));
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  c89cbor_cose_key *recipient;
  bench_samples samples;
  unsigned char raw[32], public_bytes[65];
  size_t length, i, repetitions = 1000u;
  int round, decrypt, stream, family, cwt;
  double setup, start, cpu, seconds, cpu_seconds;
  const char *profile, *implementation = "native";
#ifdef C89_COSE_LUA
  c89cbor_lua binding;
  void *module = NULL;
  lua_State *L = NULL;
#endif
  assert(argc >= 3 && b != NULL);
  profile = argv[1];
  stream = strcmp(argv[2], "stream") == 0;
  cwt = strcmp(argv[2], "cwt") == 0;
  family = strcmp(profile, "gcm") == 0       ? 0
           : strcmp(profile, "kw") == 0      ? 1
           : strcmp(profile, "x25519") == 0  ? 2
           : strcmp(profile, "multi") == 0   ? 3
           : strcmp(profile, "ed25519") == 0 ? 4
           : strcmp(profile, "p256") == 0    ? 5
           : strcmp(profile, "hmac") == 0    ? 6
                                             : -1;
  assert(family >= 0 && (!cwt || family >= 4));
  b->auth = family >= 4 ? family - 3 : 0;
  if (argc > 3)
    repetitions = (size_t)strtoul(argv[3], NULL, 10);
  assert(repetitions > 0 && repetitions <= 1000000u);
  setup = bench_wall();
  config.allocator.context = &b->counts;
  config.allocator.alloc = bench_allocate;
  config.allocator.free = bench_free;
  assert(c89cbor_init(&b->root, &config, &error) == 0);
  memset(raw, 0x31, sizeof(raw));
  assert(b->root.cose_key_init(&b->root, &b->content, C89CBOR_COSE_A256GCM, raw,
                               32u, NULL, 0, &error) == 0);
  raw[0] = 0x32;
  assert(b->root.cose_key_init(&b->root, &b->wrapping, C89CBOR_COSE_A256KW, raw,
                               32u, NULL, 0, &error) == 0);
  assert(b->root.cose_key_init(&b->root, &b->private_key,
                               C89CBOR_COSE_X25519_PRIVATE, raw, 32u, NULL, 0,
                               &error) == 0);
  assert(b->private_key.public_key(&b->private_key, public_bytes, 32u,
                                   &length) == 0);
  assert(b->root.cose_key_init(&b->root, &b->public_key,
                               C89CBOR_COSE_X25519_PUBLIC, public_bytes, 32u,
                               NULL, 0, &error) == 0);
  b->options = c89cbor_default_cose_options();
  b->options.encrypt = family != 0;
  b->key_count = family == 3 ? 8u : 1u;
  for (i = 0; i < b->key_count; ++i)
    b->keys[i] = family == 0   ? &b->content
                 : family == 1 ? &b->wrapping
                               : &b->public_key;
  recipient = family == 0   ? &b->content
              : family == 1 ? &b->wrapping
                            : &b->private_key;
  if (b->auth) {
    assert(b->root.cose_key_init(&b->root, &b->signing,
                                 b->auth == 1   ? C89CBOR_COSE_ED25519_PRIVATE
                                 : b->auth == 2 ? C89CBOR_COSE_P256_PRIVATE
                                                : C89CBOR_COSE_HMAC256,
                                 raw, 32u, NULL, 0, &error) == 0);
    if (b->auth != 3) {
      assert(b->signing.public_key(&b->signing, public_bytes,
                                   sizeof(public_bytes), &length) == 0);
      assert(b->root.cose_key_init(&b->root, &b->verification,
                                   b->auth == 1 ? C89CBOR_COSE_ED25519_PUBLIC
                                                : C89CBOR_COSE_P256_PUBLIC,
                                   public_bytes, length, NULL, 0, &error) == 0);
      recipient = &b->verification;
    } else
      recipient = &b->signing;
    b->options.encrypt = 0;
  }
  if (cwt) {
    static char issuer[] = "issuer", audience[] = "service";
    static const char *const algorithms[] = {"Ed25519", "ES256", "HS256"};
    static const char *const issuers[] = {"issuer"}, *const audiences[] = {
                                                         "service"};
    lonejson_jwt_claims claims;
    c89cbor_cwt_view view;
    memset(&claims, 0, sizeof(claims));
    claims.iss = issuer;
    claims.aud = audience;
    claims.exp = 1000;
    claims.has_exp = 1;
    b->policy.accepted_algs = algorithms;
    b->policy.accepted_alg_count = 3u;
    b->policy.accepted_issuers = issuers;
    b->policy.accepted_issuer_count = 1u;
    b->policy.accepted_audiences = audiences;
    b->policy.accepted_audience_count = 1u;
    b->policy.now = 100;
    assert(b->root.cwt_init(&b->root, &b->token, NULL, &error) == 0);
    assert(b->token.set_lonejson(&b->token, &claims, NULL, 0, &error) == 0);
    assert(b->token.view_get(&b->token, &view) == 0);
    b->payload = (uint64_t)view.encoded_length;
  }
  b->producer.context = b->wire_source.context = b->wire_sink.context =
      b->consumer.context = b;
  b->producer.read = generate;
  b->wire_source.read = stream ? ring_read : object_read;
  b->wire_sink.write = stream ? ring_write : object_write;
  b->consumer.write = consume;
#ifdef C89_COSE_LUA
  if (argc > 4) {
    L = open_lua(argv[4], &module, &binding);
    implementation = "lua";
    if (cwt) {
      assert(binding.push_cwt(&binding, &b->token, 0) == 0);
      lua_setglobal(L, "token");
      assert(binding.push_cose_key(&binding, &b->signing, 0) == 0);
      lua_setglobal(L, "signing");
      assert(binding.push_cose_key(&binding, recipient, 0) == 0);
      lua_setglobal(L, "verification");
      assert(binding.push_jwt_policy(&binding, &b->policy, 0) == 0);
      lua_setglobal(L, "policy");
      assert(luaL_dostring(
                 L,
                 "function seal_token() local status,s=token:seal(signing); "
                 "assert(status==0); wire=s end "
                 "function verify_token() "
                 "assert(token:verify(wire,verification,nil,policy)==0) end") ==
             0);
    }
  }
#endif
  setup = bench_wall() - setup;
  for (decrypt = 0; decrypt < (stream ? 1 : 2); ++decrypt) {
    for (round = -1; round < 5; ++round) {
      bench_counts_reset(&b->counts);
      memset(&samples, 0, sizeof(samples));
      samples.batch = stream ? repetitions : 1u;
      b->wire_bytes = 0;
      start = bench_wall();
      cpu = bench_cpu();
      if (stream) {
        b->offset = b->length = 0;
        b->generated = b->consumed = 0;
        b->payload = (uint64_t)repetitions * 1024u;
        b->early = 0;
#ifdef C89_COSE_LUA
        if (L != NULL)
          stream_lua(b, recipient, &binding);
        else
#endif
          stream_native(b, recipient);
        assert(b->generated == b->payload && b->consumed == b->payload);
        assert(b->early || b->payload <= 8192u);
        samples.values[samples.count++] =
            (bench_wall() - start) * 1e9 / (double)repetitions;
      } else {
        for (i = 0; i < repetitions; ++i) {
          double latency = bench_wall();
          if (!cwt)
            b->payload = 1024u;
          b->generated = b->consumed = b->offset = 0;
          if (cwt) {
#ifdef C89_COSE_LUA
            if (L != NULL) {
              lua_getglobal(L, decrypt ? "verify_token" : "seal_token");
              assert(lua_pcall(L, 0, 0, 0) == 0);
              if (!decrypt) {
                const void *wire;
                lua_getglobal(L, "wire");
                assert(binding.check_span(&binding, -1, &wire,
                                          &b->wire_length) == 0);
                lua_pop(L, 1);
              }
            } else
#endif
                if (!decrypt)
              assert(b->token.seal(&b->token, &b->signing, NULL, 0, b->object,
                                   sizeof(b->object), &b->wire_length,
                                   &error) == 0);
            else
              assert(b->token.verify(&b->token, b->object, b->wire_length,
                                     recipient, NULL, &b->policy, &error) == 0);
          } else if (b->auth) {
            if (!decrypt) {
              b->wire_length = 0;
              assert((b->auth == 3 ? b->root.cose_mac0 : b->root.cose_sign1)(
                         &b->root, &b->producer, &b->wire_sink, &b->signing,
                         NULL, &error) == 0);
            } else
              assert((b->auth == 3 ? b->root.cose_verify_mac0
                                   : b->root.cose_verify1)(
                         &b->root, &b->wire_source, &b->consumer, recipient,
                         NULL, &error) == 0);
          } else if (!decrypt) {
            b->wire_length = 0;
            assert((family == 0
                        ? b->root.cose_encrypt0(&b->root, &b->producer,
                                                &b->wire_sink, &b->content,
                                                NULL, &error)
                        : b->root.cose_encrypt(
                              &b->root, &b->producer, &b->wire_sink, b->keys,
                              b->key_count, NULL, &error)) == 0);
          } else {
            assert(b->root.cose_decrypt(&b->root, &b->wire_source, &b->consumer,
                                        recipient, NULL, &error) == 0);
            assert(b->consumed == b->payload);
          }
          if (samples.count < 256u)
            samples.values[samples.count++] = (bench_wall() - latency) * 1e9;
        }
      }
      seconds = bench_wall() - start;
      cpu_seconds = bench_cpu() - cpu;
      if (round >= 0)
        bench_report(implementation,
                     cwt       ? (decrypt ? "cwt-verify" : "cwt-seal")
                     : stream  ? "cose-stream-roundtrip"
                     : decrypt ? "cose-object-open"
                               : "cose-object-seal",
                     profile, round, repetitions,
                     stream ? (size_t)(b->wire_bytes / repetitions)
                            : b->wire_length,
                     seconds, cpu_seconds, setup, &b->counts, &samples);
    }
  }
#ifdef C89_COSE_LUA
  if (L != NULL) {
    assert(binding.cleanup(&binding) == 0);
    lua_close(L);
    assert(dlclose(module) == 0);
  }
#endif
  if (cwt)
    assert(b->token.cleanup(&b->token) == 0);
  if (b->auth) {
    if (b->auth != 3)
      assert(b->verification.cleanup(&b->verification) == 0);
    assert(b->signing.cleanup(&b->signing) == 0);
  }
  assert(b->public_key.cleanup(&b->public_key) == 0 &&
         b->private_key.cleanup(&b->private_key) == 0);
  assert(b->wrapping.cleanup(&b->wrapping) == 0 &&
         b->content.cleanup(&b->content) == 0);
  assert(b->root.cleanup(&b->root) == 0 && b->counts.bytes == 0);
  free(b);
  return 0;
}
