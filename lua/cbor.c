#include <c89cbor/lua.h>
#include <limits.h>
#include <string.h>

#define DEC "c89cbor.decoder"
#define ENC "c89cbor.encoder"
#define READER "c89cbor.reader"
#define SOURCE "c89cbor.source"
#define SINK "c89cbor.sink"
#define TRANSFER "c89cbor.transfer"
#define ALLOC "c89cbor.allocator"
#define TOKEN "c89cbor.token"
#define SPAN "c89cbor.span"
#define FRAMES "c89cbor.frames"
#define FD "c89cbor.fd"

typedef struct handle {
  void *ptr;
  struct handle *parent[2];
  size_t count;
  size_t borrowers;
  int heap_kind;
  int active;
  const c89cbor_allocator *allocator;
} handle;
typedef struct span {
  const void *bytes;
  size_t length;
} span;
typedef struct endpoint {
  c89cbor_fd fd;
  c89cbor_source source;
  c89cbor_sink sink;
} endpoint;

static uint64_t integer(cpkt_lua_state *L, int index) {
  cpkt_lua_integer n = cpkt_lua_l_checkinteger(L, index);
  return ((uint64_t)n.high << 32U) | n.low;
}
static void push_integer(cpkt_lua_state *L, uint64_t n) {
  cpkt_lua_pushinteger(L,
                       cpkt_lua_integer_make((unsigned int)(n >> 32U),
                                             (unsigned int)(n & UINT32_MAX)));
}
static uint64_t optional(cpkt_lua_state *L, int index, uint64_t fallback) {
  return cpkt_lua_isnoneornil(L, index) ? fallback : integer(L, index);
}
static size_t size_arg(cpkt_lua_state *L, int index, size_t fallback) {
  uint64_t n = optional(L, index, (uint64_t)fallback);
  if (n > (uint64_t)(size_t)-1)
    cpkt_lua_l_argerror(L, index, "size exceeds size_t");
  return (size_t)n;
}
static uint32_t limit_arg(cpkt_lua_state *L, int index) {
  uint64_t n = optional(L, index, 0);
  if (n > UINT32_MAX)
    cpkt_lua_l_argerror(L, index, "limit exceeds uint32_t");
  return (uint32_t)n;
}
static handle *checked(cpkt_lua_state *L, int index, const char *kind) {
  handle *h = cpkt_lua_l_checkudata(L, index, kind);
  if (h->ptr == NULL)
    cpkt_lua_l_argerror(L, index, "handle is closed");
  return h;
}
static handle *new_handle(cpkt_lua_state *L, const char *kind, size_t bytes) {
  handle *h = cpkt_lua_newuserdatauv(L, sizeof(*h) + bytes, 2);
  memset(h, 0, sizeof(*h) + bytes);
  h->ptr = bytes ? h + 1 : NULL;
  cpkt_lua_l_setmetatable(L, kind);
  return h;
}
static handle *any_handle(cpkt_lua_state *L, int index) {
  static const char *const kinds[] = {
      DEC, ENC, READER, SOURCE, SINK, TRANSFER, ALLOC, TOKEN, SPAN, FRAMES, FD};
  size_t i;
  for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
    handle *h = cpkt_lua_l_testudata(L, index, kinds[i]);
    if (h != NULL)
      return h;
  }
  return NULL;
}
static void pin(cpkt_lua_state *L, handle *h, int index, int slot) {
  handle *parent;
  if (index == 0 || cpkt_lua_isnoneornil(L, index))
    return;
  index = cpkt_lua_absindex(L, index);
  parent = any_handle(L, index);
  if (parent != NULL) {
    ++parent->borrowers;
    h->parent[slot - 1] = parent;
  }
  cpkt_lua_pushvalue(L, index);
  cpkt_lua_setiuservalue(L, -2, slot);
}
static void unpin(handle *h) {
  int i;
  for (i = 0; i < 2; ++i) {
    if (h->parent[i] != NULL) {
      --h->parent[i]->borrowers;
      h->parent[i] = NULL;
    }
  }
}
static int result(cpkt_lua_state *L, int status) {
  push_integer(L, (uint64_t)(int64_t)status);
  return 1;
}
static void release_handle(handle *h) {
  if (h->ptr != NULL) {
    if (h->heap_kind == 1)
      c89cbor_decoder_destroy(h->ptr);
    if (h->heap_kind == 2)
      c89cbor_encoder_destroy(h->ptr);
    h->ptr = NULL;
  }
  unpin(h);
}
static int close_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  if (h == NULL || h->borrowers || h->active)
    return result(L, C89CBOR_INVALID);
  release_handle(h);
  return result(L, 0);
}
static int gc_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  /* Unreachable borrowers may finalize in either order. Their pins keep
   * reachable owners alive; a dead owner's borrow count cannot block GC. */
  if (h != NULL)
    release_handle(h);
  return 0;
}
#define BRIDGE(name, ctype, kind)                                              \
  int c89cbor_lua_push_##name(cpkt_lua_state *L, ctype *value, int owner) {    \
    handle *h;                                                                 \
    if (L == NULL || value == NULL)                                            \
      return C89CBOR_INVALID;                                                  \
    if (owner)                                                                 \
      owner = cpkt_lua_absindex(L, owner);                                     \
    h = new_handle(L, kind, 0);                                                \
    h->ptr = value;                                                            \
    pin(L, h, owner, 1);                                                       \
    return 0;                                                                  \
  }                                                                            \
  ctype *c89cbor_lua_check_##name(cpkt_lua_state *L, int index) {              \
    handle *h = cpkt_lua_l_testudata(L, index, kind);                          \
    return h == NULL ? NULL : h->ptr;                                          \
  }
BRIDGE(decoder, c89cbor_decoder, DEC)
BRIDGE(encoder, c89cbor_encoder, ENC)
BRIDGE(reader, c89cbor_reader, READER)
BRIDGE(source, c89cbor_source, SOURCE)
BRIDGE(sink, c89cbor_sink, SINK)
BRIDGE(transfer, c89cbor_transfer, TRANSFER)
BRIDGE(allocator, c89cbor_allocator, ALLOC)
int c89cbor_lua_push_span(cpkt_lua_state *L, const void *bytes, size_t n,
                          int owner) {
  handle *h;
  span *s;
  if (L == NULL || (bytes == NULL && n))
    return C89CBOR_INVALID;
  if (owner)
    owner = cpkt_lua_absindex(L, owner);
  h = new_handle(L, SPAN, sizeof(*s));
  s = h->ptr;
  s->bytes = bytes;
  s->length = n;
  pin(L, h, owner, 1);
  return 0;
}
int c89cbor_lua_check_span(cpkt_lua_state *L, int index, const void **bytes,
                           size_t *n) {
  handle *h = cpkt_lua_l_testudata(L, index, SPAN);
  span *s;
  if (h == NULL || h->ptr == NULL || bytes == NULL || n == NULL)
    return C89CBOR_INVALID;
  s = h->ptr;
  *bytes = s->bytes;
  *n = s->length;
  return 0;
}
static const void *input(cpkt_lua_state *L, int index, size_t *n) {
  const void *bytes;
  if (cpkt_lua_isnoneornil(L, index)) {
    *n = 0;
    return NULL;
  }
  if (c89cbor_lua_check_span(L, index, &bytes, n) == 0)
    return bytes;
  return cpkt_lua_l_checklstring(L, index, n);
}
static int new_frames(cpkt_lua_state *L) {
  size_t n = size_arg(L, 1, C89CBOR_DEPTH);
  handle *h;
  if (!n || n > ((size_t)-1 - sizeof(handle)) / sizeof(c89cbor_frame))
    return cpkt_lua_l_argerror(L, 1, "invalid frame capacity");
  h = new_handle(L, FRAMES, n * sizeof(c89cbor_frame));
  h->count = n;
  return 1;
}
static int codec_init(cpkt_lua_state *L, int encoder, int create) {
  handle *frames = NULL, *a = NULL, *h;
  c89cbor_allocator *allocator = NULL;
  size_t chunk = size_arg(L, 2, 0);
  int rc;
  if (!cpkt_lua_isnoneornil(L, 1)) {
    if (create) {
      a = checked(L, 1, ALLOC);
      allocator = a->ptr;
    } else {
      frames = checked(L, 1, FRAMES);
      if (frames->borrowers)
        return cpkt_lua_l_argerror(L, 1, "frames already in use");
    }
  }
  h = new_handle(L, encoder ? ENC : DEC,
                 create    ? 0
                 : encoder ? sizeof(c89cbor_encoder)
                           : sizeof(c89cbor_decoder));
  if (create) {
    if (encoder) {
      c89cbor_encoder *e = NULL;
      rc = c89cbor_encoder_create(NULL, allocator, &e);
      h->ptr = e;
    } else {
      c89cbor_decoder *d = NULL;
      rc = c89cbor_decoder_create(NULL, allocator, &d);
      h->ptr = d;
    }
    h->heap_kind = encoder ? 2 : 1;
    h->allocator = allocator;
  } else if (encoder)
    rc = c89cbor_encoder_init(NULL, h->ptr, frames == NULL ? NULL : frames->ptr,
                              frames == NULL ? 0 : frames->count, chunk);
  else
    rc = c89cbor_decoder_init(NULL, h->ptr, frames == NULL ? NULL : frames->ptr,
                              frames == NULL ? 0 : frames->count, chunk);
  if (frames != NULL || a != NULL)
    pin(L, h, 1, 1);
  if (rc < 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, rc);
    return 2;
  }
  return 1;
}
static int new_decoder(cpkt_lua_state *L) { return codec_init(L, 0, 0); }
static int new_encoder(cpkt_lua_state *L) { return codec_init(L, 1, 0); }
static int create_decoder(cpkt_lua_state *L) { return codec_init(L, 0, 1); }
static int create_encoder(cpkt_lua_state *L) { return codec_init(L, 1, 1); }
static int next_decoder(cpkt_lua_state *L) {
  c89cbor_decoder *d = checked(L, 1, DEC)->ptr;
  c89cbor_token t;
  size_t n, used;
  const void *bytes = input(L, 2, &n);
  int rc = c89cbor_decoder_next(d, bytes, n, &used, &t);
  result(L, rc);
  push_integer(L, used);
  if (rc == C89CBOR_TOKEN) {
    handle *h = new_handle(L, TOKEN, sizeof(t));
    memcpy(h->ptr, &t, sizeof(t));
    pin(L, h, 2, 1);
  } else
    cpkt_lua_pushnil(L);
  return 3;
}
static int finish_decoder(cpkt_lua_state *L) {
  return result(L, c89cbor_decoder_finish(checked(L, 1, DEC)->ptr));
}
static int reset_decoder(cpkt_lua_state *L) {
  return result(L, c89cbor_decoder_reset(checked(L, 1, DEC)->ptr));
}
static int finish_encoder(cpkt_lua_state *L) {
  return result(L, c89cbor_encoder_finish(checked(L, 1, ENC)->ptr));
}
static int reset_encoder(cpkt_lua_state *L) {
  return result(L, c89cbor_encoder_reset(checked(L, 1, ENC)->ptr));
}
static int new_token(cpkt_lua_state *L) {
  uint64_t kind = integer(L, 1), argument = optional(L, 2, 0);
  size_t n = 0;
  const void *bytes = NULL;
  handle *h;
  c89cbor_token *t;
  int indefinite = cpkt_lua_toboolean(L, 4);
  if (kind > C89CBOR_END)
    return cpkt_lua_l_argerror(L, 1, "unknown token kind");
  if (!cpkt_lua_isnoneornil(L, 3))
    bytes = input(L, 3, &n);
  h = new_handle(L, TOKEN, sizeof(*t));
  t = h->ptr;
  t->type = (c89cbor_type)kind;
  t->argument = argument;
  t->data = bytes;
  t->length = n;
  t->indefinite = indefinite;
  pin(L, h, 3, 1);
  return 1;
}
static void unpin_data(cpkt_lua_state *L, handle *h) {
  if (h->parent[1] != NULL) {
    --h->parent[1]->borrowers;
    h->parent[1] = NULL;
  }
  cpkt_lua_pushnil(L);
  cpkt_lua_setiuservalue(L, 1, 2);
}
static int put_encoder(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  c89cbor_encoder *e = h->ptr;
  c89cbor_token *t = checked(L, 2, TOKEN)->ptr;
  int rc = c89cbor_encoder_put(e, t);
  if (rc == 0)
    unpin_data(L, h);
  if (rc == 0 && t->type == C89CBOR_DATA && t->length) {
    /* Pin DATA until drained, including when its token is collected by Lua. */
    h->parent[1] = checked(L, 2, TOKEN);
    ++h->parent[1]->borrowers;
    cpkt_lua_pushvalue(L, 2);
    cpkt_lua_setiuservalue(L, 1, 2);
  }
  return result(L, rc);
}
static int read_encoder(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  c89cbor_encoder *e = h->ptr;
  unsigned char bytes[C89CBOR_CHUNK];
  size_t n, capacity = size_arg(L, 2, sizeof(bytes));
  int rc;
  if (capacity > sizeof(bytes))
    capacity = sizeof(bytes);
  rc = c89cbor_encoder_read(e, bytes, capacity, &n);
  result(L, rc);
  cpkt_lua_pushlstring(L, (const char *)bytes, n);
  if (rc != C89CBOR_OUTPUT)
    unpin_data(L, h);
  return 2;
}
static int token_kind(cpkt_lua_state *L) {
  return result(L, ((c89cbor_token *)checked(L, 1, TOKEN)->ptr)->type);
}
static int token_argument(cpkt_lua_state *L) {
  push_integer(L, ((c89cbor_token *)checked(L, 1, TOKEN)->ptr)->argument);
  return 1;
}
static int token_indefinite(cpkt_lua_state *L) {
  cpkt_lua_pushboolean(
      L, ((c89cbor_token *)checked(L, 1, TOKEN)->ptr)->indefinite);
  return 1;
}
static int token_span(cpkt_lua_state *L) {
  c89cbor_token *t = checked(L, 1, TOKEN)->ptr;
  c89cbor_lua_push_span(L, t->data, t->length, 1);
  return 1;
}
static int span_string(cpkt_lua_state *L) {
  span *s = checked(L, 1, SPAN)->ptr;
  cpkt_lua_pushlstring(L, s->bytes == NULL ? "" : s->bytes, s->length);
  return 1;
}
static int span_length(cpkt_lua_state *L) {
  span *s = checked(L, 1, SPAN)->ptr;
  push_integer(L, s->length);
  return 1;
}
static int new_span(cpkt_lua_state *L) {
  size_t n;
  const void *bytes = input(L, 1, &n);
  c89cbor_lua_push_span(L, bytes, n, 1);
  return 1;
}
static int float_set(cpkt_lua_state *L) {
  c89cbor_token *t = checked(L, 1, TOKEN)->ptr;
  return result(L, c89cbor_float64_set(NULL, t, cpkt_lua_l_checknumber(L, 2)));
}
static int float_get(cpkt_lua_state *L) {
  double value = 0;
  int rc = c89cbor_float64_get(NULL, checked(L, 1, TOKEN)->ptr, &value);
  result(L, rc);
  if (rc == 0)
    cpkt_lua_pushnumber(L, value);
  else
    cpkt_lua_pushnil(L);
  return 2;
}
static int new_reader(cpkt_lua_state *L) {
  uint64_t mode = optional(L, 1, 0);
  uint32_t limit = limit_arg(L, 2);
  handle *h;
  if (mode > 2)
    return cpkt_lua_l_argerror(L, 1, "invalid framing mode");
  h = new_handle(L, READER, sizeof(c89cbor_reader));
  c89cbor_reader_init(NULL, h->ptr, (c89cbor_framing)mode, limit);
  return 1;
}
static int next_reader(cpkt_lua_state *L) {
  c89cbor_reader *r = checked(L, 1, READER)->ptr;
  size_t n, used;
  const void *bytes = input(L, 2, &n);
  c89cbor_event event;
  int rc = c89cbor_reader_next(r, bytes, n, &used, &event);
  result(L, rc);
  push_integer(L, used);
  if (rc == C89CBOR_TOKEN) {
    handle *h;
    cpkt_lua_newtable(L);
    result(L, event.type);
    cpkt_lua_setfield(L, -2, "type");
    push_integer(L, event.length);
    cpkt_lua_setfield(L, -2, "length");
    if (event.type == C89CBOR_RECORD_TOKEN) {
      h = new_handle(L, TOKEN, sizeof(event.token));
      memcpy(h->ptr, &event.token, sizeof(event.token));
      pin(L, h, 2, 1);
      cpkt_lua_setfield(L, -2, "token");
    }
  } else
    cpkt_lua_pushnil(L);
  return 3;
}
static int finish_reader(cpkt_lua_state *L) {
  return result(L, c89cbor_reader_finish(checked(L, 1, READER)->ptr));
}
static int length32(cpkt_lua_state *L) {
  unsigned char bytes[4];
  uint64_t n = integer(L, 1);
  int rc = n > UINT32_MAX
               ? C89CBOR_LIMIT
               : c89cbor_length32(NULL, (uint32_t)n, limit_arg(L, 2), bytes);
  result(L, rc);
  if (!rc)
    cpkt_lua_pushlstring(L, (const char *)bytes, 4);
  else
    cpkt_lua_pushnil(L);
  return 2;
}
static int new_fd(cpkt_lua_state *L) {
  uint64_t fd = integer(L, 1);
  handle *h;
  endpoint *e;
  if (fd > INT_MAX)
    return cpkt_lua_l_argerror(L, 1, "invalid descriptor");
  h = new_handle(L, FD, sizeof(*e));
  e = h->ptr;
  c89cbor_fd_init(NULL, &e->fd, (int)fd, &e->source, &e->sink);
  return 1;
}
static int fd_source(cpkt_lua_state *L) {
  endpoint *e = checked(L, 1, FD)->ptr;
  c89cbor_lua_push_source(L, &e->source, 1);
  return 1;
}
static int fd_sink(cpkt_lua_state *L) {
  endpoint *e = checked(L, 1, FD)->ptr;
  c89cbor_lua_push_sink(L, &e->sink, 1);
  return 1;
}
static int new_transfer(cpkt_lua_state *L) {
  c89cbor_source *source = checked(L, 1, SOURCE)->ptr;
  c89cbor_sink *sink = checked(L, 2, SINK)->ptr;
  uint64_t mode = optional(L, 3, 0);
  uint32_t limit = limit_arg(L, 4);
  handle *h;
  int rc;
  if (mode > 2)
    return cpkt_lua_l_argerror(L, 3, "invalid framing mode");
  h = new_handle(L, TRANSFER, sizeof(c89cbor_transfer));
  rc = c89cbor_transfer_init(NULL, h->ptr, source, sink, (c89cbor_framing)mode,
                             limit);
  pin(L, h, 1, 1);
  pin(L, h, 2, 2);
  if (rc < 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, rc);
    return 2;
  }
  return 1;
}
static int transfer_step(cpkt_lua_state *L) {
  handle *h = checked(L, 1, TRANSFER);
  int rc;
  if (h->active)
    return result(L, C89CBOR_INVALID);
  h->active = 1;
  rc = c89cbor_transfer_step(h->ptr);
  h->active = 0;
  return result(L, rc);
}
static int transfer_run(cpkt_lua_state *L) {
  handle *h = checked(L, 1, TRANSFER);
  int rc;
  if (h->active)
    return result(L, C89CBOR_INVALID);
  h->active = 1;
  do {
    rc = c89cbor_transfer_step(h->ptr);
  } while (rc == 0);
  h->active = 0;
  return result(L, rc);
}
static int transfer_counts(cpkt_lua_state *L) {
  c89cbor_transfer *t = checked(L, 1, TRANSFER)->ptr;
  push_integer(L, t->read_bytes);
  push_integer(L, t->written_bytes);
  return 2;
}
static int version(cpkt_lua_state *L) {
  cpkt_lua_pushstring(L, c89cbor_version(NULL));
  return 1;
}
static int status_string(cpkt_lua_state *L) {
  return cpkt_lua_pushstring(
             L, c89cbor_status_string(NULL, (int)(int64_t)integer(L, 1))),
         1;
}
static void metatable(cpkt_lua_state *L, const char *name,
                      const cpkt_lua_reg *methods) {
  cpkt_lua_l_newmetatable(L, name);
  cpkt_lua_pushvalue(L, -1);
  cpkt_lua_setfield(L, -2, "__index");
  cpkt_lua_pushcfunction(L, gc_handle);
  cpkt_lua_setfield(L, -2, "__gc");
  cpkt_lua_pushcfunction(L, close_handle);
  cpkt_lua_setfield(L, -2, "close");
  cpkt_lua_pushstring(L, name);
  cpkt_lua_setfield(L, -2, "__metatable");
  if (methods != NULL)
    cpkt_lua_l_setfuncs(L, methods, 0);
  cpkt_lua_pop(L, 1);
}
int luaopen_cbor(cpkt_lua_state *L) {
  static const cpkt_lua_reg dec[] = {{"next", next_decoder},
                                     {"finish", finish_decoder},
                                     {"reset", reset_decoder},
                                     {NULL, NULL}};
  static const cpkt_lua_reg enc[] = {{"put", put_encoder},
                                     {"read", read_encoder},
                                     {"finish", finish_encoder},
                                     {"reset", reset_encoder},
                                     {NULL, NULL}};
  static const cpkt_lua_reg tok[] = {{"kind", token_kind},
                                     {"argument", token_argument},
                                     {"indefinite", token_indefinite},
                                     {"span", token_span},
                                     {"float64_set", float_set},
                                     {"float64_get", float_get},
                                     {NULL, NULL}};
  static const cpkt_lua_reg sp[] = {
      {"string", span_string}, {"length", span_length}, {NULL, NULL}};
  static const cpkt_lua_reg rd[] = {
      {"next", next_reader}, {"finish", finish_reader}, {NULL, NULL}};
  static const cpkt_lua_reg fd[] = {
      {"source", fd_source}, {"sink", fd_sink}, {NULL, NULL}};
  static const cpkt_lua_reg tr[] = {{"step", transfer_step},
                                    {"run", transfer_run},
                                    {"counts", transfer_counts},
                                    {NULL, NULL}};
  static const cpkt_lua_reg module[] = {{"version", version},
                                        {"status_string", status_string},
                                        {"decoder", new_decoder},
                                        {"encoder", new_encoder},
                                        {"decoder_create", create_decoder},
                                        {"encoder_create", create_encoder},
                                        {"frames", new_frames},
                                        {"token", new_token},
                                        {"span", new_span},
                                        {"reader", new_reader},
                                        {"length32", length32},
                                        {"fd", new_fd},
                                        {"transfer", new_transfer},
                                        {NULL, NULL}};
  static const char *const types[] = {
      "UINT",    "NEGATIVE", "BYTES", "TEXT",      "ARRAY",  "MAP",
      "TAG",     "BOOL",     "NULL",  "UNDEFINED", "SIMPLE", "FLOAT16",
      "FLOAT32", "FLOAT64",  "DATA",  "END"};
  size_t i;
  metatable(L, DEC, dec);
  metatable(L, ENC, enc);
  metatable(L, TOKEN, tok);
  metatable(L, SPAN, sp);
  metatable(L, READER, rd);
  metatable(L, FD, fd);
  metatable(L, TRANSFER, tr);
  metatable(L, SOURCE, NULL);
  metatable(L, SINK, NULL);
  metatable(L, ALLOC, NULL);
  metatable(L, FRAMES, NULL);
  cpkt_lua_newtable(L);
  cpkt_lua_l_setfuncs(L, module, 0);
  for (i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
    push_integer(L, i);
    cpkt_lua_setfield(L, -2, types[i]);
  }
#define CONSTANT(name)                                                         \
  result(L, C89CBOR_##name);                                                   \
  cpkt_lua_setfield(L, -2, #name)
  CONSTANT(OK);
  CONSTANT(TOKEN);
  CONSTANT(INPUT);
  CONSTANT(OUTPUT);
  CONSTANT(DONE);
  CONSTANT(INVALID);
  CONSTANT(MALFORMED);
  CONSTANT(LIMIT);
  CONSTANT(NOMEM);
  CONSTANT(IO);
  CONSTANT(SINGLE);
  CONSTANT(SEQUENCE);
  CONSTANT(LENGTH32);
  CONSTANT(RECORD_BEGIN);
  CONSTANT(RECORD_TOKEN);
  CONSTANT(RECORD_END);
#undef CONSTANT
  return 1;
}
