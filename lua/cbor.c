#include <c89cbor/lua.h>
#include <limits.h>
#include <string.h>
#define ROOT "c89cbor.runtime"
#define CONVERSION "c89cbor.conversion"
#define VIEW "c89cbor.record_view"
#define OPTIONS "c89cbor.options"
#define CONFIG "c89cbor.config"

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
  struct handle *parent[5];
  size_t count;
  size_t borrowers;
  int heap_kind;
  int active;
  int gc_pending;
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
  handle *h = cpkt_lua_newuserdatauv(L, sizeof(*h) + bytes, 5);
  memset(h, 0, sizeof(*h) + bytes);
  h->ptr = bytes ? h + 1 : NULL;
  if (bytes != 0) {
    h->heap_kind = strcmp(kind, DEC) == 0          ? -1
                   : strcmp(kind, ENC) == 0        ? -2
                   : strcmp(kind, READER) == 0     ? -3
                   : strcmp(kind, TRANSFER) == 0   ? -4
                   : strcmp(kind, FD) == 0         ? -5
                   : strcmp(kind, ROOT) == 0       ? -6
                   : strcmp(kind, CONVERSION) == 0 ? -7
                                                   : 0;
  }
  cpkt_lua_l_setmetatable(L, kind);
  return h;
}
static handle *any_handle(cpkt_lua_state *L, int index) {
  static const char *const kinds[] = {
      DEC,  ENC,    READER, SOURCE, SINK,       TRANSFER, ALLOC,   TOKEN,
      SPAN, FRAMES, FD,     ROOT,   CONVERSION, VIEW,     OPTIONS, CONFIG};
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
  if (parent == h)
    return;
  if (parent != NULL) {
    ++parent->borrowers;
    h->parent[slot - 1] = parent;
  }
  cpkt_lua_pushvalue(L, index);
  cpkt_lua_setiuservalue(L, -2, slot);
}
static int release_handle(handle *h);
static void drop_parent(handle *parent) {
  --parent->borrowers;
  if (parent->borrowers == 0 && parent->gc_pending && !parent->active)
    (void)release_handle(parent);
}
static void unpin(handle *h) {
  int i;
  for (i = 0; i < 5; ++i) {
    if (h->parent[i] != NULL) {
      drop_parent(h->parent[i]);
      h->parent[i] = NULL;
    }
  }
}
static int result(cpkt_lua_state *L, int status) {
  push_integer(L, (uint64_t)(int64_t)status);
  return 1;
}
static int release_handle(handle *h) {
  int status = 0;
  if (h->ptr != NULL) {
    switch (h->heap_kind) {
    case 1:
      status = c89cbor_decoder_destroy(h->ptr);
      break;
    case -1:
      status = c89cbor_decoder_cleanup(h->ptr);
      break;
    case 2:
      status = c89cbor_encoder_destroy(h->ptr);
      break;
    case -2:
      status = c89cbor_encoder_cleanup(h->ptr);
      break;
    case 3:
      status = c89cbor_reader_destroy(h->ptr);
      break;
    case -3:
      status = c89cbor_reader_cleanup(h->ptr);
      break;
    case 4:
      status = c89cbor_transfer_destroy(h->ptr);
      break;
    case -4:
      status = c89cbor_transfer_cleanup(h->ptr);
      break;
    case 5:
      status = c89cbor_fd_destroy(h->ptr);
      break;
    case -5:
      status = c89cbor_fd_cleanup(h->ptr);
      break;
    case 6:
      status = c89cbor_destroy(h->ptr);
      break;
    case -6:
      status = c89cbor_cleanup(h->ptr);
      break;
    case 7:
      status = c89cbor_conversion_destroy(h->ptr);
      break;
    case -7:
      status = c89cbor_conversion_cleanup(h->ptr);
      break;
    default:
      break;
    }
    if (status != 0)
      return status;
    h->ptr = NULL;
  }
  unpin(h);
  return C89CBOR_OK;
}
static int close_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  if (h == NULL || h->borrowers || h->active)
    return result(L, C89CBOR_INVALID);
  return result(L, release_handle(h));
}
static int gc_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  if (h != NULL) {
    h->gc_pending = 1;
    if (h->borrowers == 0 && !h->active)
      (void)release_handle(h);
  }
  return 0;
}
#define BRIDGE(name, ctype, kind)                                              \
  static int push_##name(cpkt_lua_state *L, ctype *value, int owner) {         \
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
  static ctype *check_##name(cpkt_lua_state *L, int index) {                   \
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
BRIDGE(runtime, c89cbor, ROOT)
BRIDGE(conversion, c89cbor_conversion, CONVERSION)
BRIDGE(fd, c89cbor_fd, FD)
BRIDGE(options, c89cbor_options, OPTIONS)
BRIDGE(config, c89cbor_config, CONFIG)
static int valid_record_view(const lonejson_record_view *view) {
  return view != NULL && view->size >= sizeof(*view) &&
         view->abi_version == LONEJSON_VIEW_ABI_VERSION && view->flags == 0 &&
         view->schema.size >= sizeof(view->schema) &&
         view->schema.abi_version == LONEJSON_VIEW_ABI_VERSION &&
         view->schema.flags == 0 && view->schema.runtime != NULL &&
         view->schema.map != NULL && view->record != NULL &&
         view->schema.record_size >= view->schema.map->struct_size;
}
static int push_record_view(cpkt_lua_state *L, lonejson_record_view *view,
                            int owner) {
  handle *h;
  if (L == NULL || !valid_record_view(view))
    return C89CBOR_INVALID;
  if (owner != 0)
    owner = cpkt_lua_absindex(L, owner);
  h = new_handle(L, VIEW, sizeof(*view));
  memcpy(h->ptr, view, sizeof(*view));
  pin(L, h, owner, 1);
  return C89CBOR_OK;
}
static lonejson_record_view *check_record_view(cpkt_lua_state *L, int index) {
  handle *h = cpkt_lua_l_testudata(L, index, VIEW);
  return h != NULL && valid_record_view(h->ptr) ? h->ptr : NULL;
}
static int push_span(cpkt_lua_state *L, const void *bytes, size_t n,
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
static int check_span(cpkt_lua_state *L, int index, const void **bytes,
                      size_t *n) {
  handle *h = cpkt_lua_l_testudata(L, index, SPAN);
  span *s;
  if (bytes != NULL)
    *bytes = NULL;
  if (n != NULL)
    *n = 0;
  if (h == NULL || h->ptr == NULL || bytes == NULL || n == NULL)
    return C89CBOR_INVALID;
  s = h->ptr;
  *bytes = s->bytes;
  *n = s->length;
  return 0;
}

/* The binding itself owns no Lua references. Each pushed handle owns its pins.
 */
int c89cbor_lua_init(c89cbor_lua *binding, cpkt_lua_state *state,
                     const c89cbor_allocator *allocator, c89cbor_error *error) {
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (binding == NULL)
    return C89CBOR_INVALID;
  memset(binding, 0, sizeof(*binding));
  binding->push_runtime = c89cbor_lua_push_runtime;
  binding->check_runtime = c89cbor_lua_check_runtime;
  binding->push_conversion = c89cbor_lua_push_conversion;
  binding->check_conversion = c89cbor_lua_check_conversion;
  binding->push_record_view = c89cbor_lua_push_record_view;
  binding->check_record_view = c89cbor_lua_check_record_view;
  binding->push_decoder = c89cbor_lua_push_decoder;
  binding->check_decoder = c89cbor_lua_check_decoder;
  binding->push_encoder = c89cbor_lua_push_encoder;
  binding->check_encoder = c89cbor_lua_check_encoder;
  binding->push_reader = c89cbor_lua_push_reader;
  binding->check_reader = c89cbor_lua_check_reader;
  binding->push_source = c89cbor_lua_push_source;
  binding->check_source = c89cbor_lua_check_source;
  binding->push_sink = c89cbor_lua_push_sink;
  binding->check_sink = c89cbor_lua_check_sink;
  binding->push_transfer = c89cbor_lua_push_transfer;
  binding->check_transfer = c89cbor_lua_check_transfer;
  binding->push_fd = c89cbor_lua_push_fd;
  binding->check_fd = c89cbor_lua_check_fd;
  binding->push_allocator = c89cbor_lua_push_allocator;
  binding->check_allocator = c89cbor_lua_check_allocator;
  binding->push_span = c89cbor_lua_push_span;
  binding->push_options = c89cbor_lua_push_options;
  binding->check_options = c89cbor_lua_check_options;
  binding->push_config = c89cbor_lua_push_config;
  binding->check_config = c89cbor_lua_check_config;
  binding->check_span = c89cbor_lua_check_span;
  binding->cleanup = c89cbor_lua_cleanup;
  binding->destroy = c89cbor_lua_destroy;
  binding->diagnostic = c89cbor_lua_diagnostic;
  binding->allocator =
      allocator == NULL ? c89cbor_default_allocator() : *allocator;
  if (state == NULL || binding->allocator.alloc == NULL ||
      binding->allocator.free == NULL) {
    binding->error.status = C89CBOR_INVALID;
    if (error != NULL)
      *error = binding->error;
    return C89CBOR_INVALID;
  }
  binding->state = state;
  binding->active = 1;
  return C89CBOR_OK;
}
int c89cbor_lua_create(cpkt_lua_state *state,
                       const c89cbor_allocator *allocator, c89cbor_lua **out,
                       c89cbor_error *error) {
  c89cbor_lua *binding;
  c89cbor_allocator selected =
      allocator == NULL ? c89cbor_default_allocator() : *allocator;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  if (state == NULL || selected.alloc == NULL || selected.free == NULL) {
    if (error != NULL)
      error->status = C89CBOR_INVALID;
    return C89CBOR_INVALID;
  }
  binding = selected.alloc(selected.context, sizeof(*binding));
  if (binding == NULL) {
    if (error != NULL)
      error->status = C89CBOR_NOMEM;
    return C89CBOR_NOMEM;
  }
  status = c89cbor_lua_init(binding, state, &selected, error);
  if (status != 0) {
    selected.free(selected.context, binding);
    return status;
  }
  binding->owned = 1;
  *out = binding;
  return C89CBOR_OK;
}
int c89cbor_lua_cleanup(c89cbor_lua *binding) {
  if (binding == NULL)
    return C89CBOR_INVALID;
  binding->state = NULL;
  binding->active = 0;
  return C89CBOR_OK;
}
int c89cbor_lua_destroy(c89cbor_lua *binding) {
  c89cbor_allocator allocator;
  if (binding == NULL)
    return C89CBOR_OK;
  if (!binding->owned)
    return C89CBOR_INVALID;
  allocator = binding->allocator;
  (void)c89cbor_lua_cleanup(binding);
  allocator.free(allocator.context, binding);
  return C89CBOR_OK;
}
int c89cbor_lua_diagnostic(const c89cbor_lua *binding, c89cbor_error *error) {
  if (error == NULL)
    return C89CBOR_INVALID;
  memset(error, 0, sizeof(*error));
  if (binding == NULL)
    return C89CBOR_INVALID;
  *error = binding->error;
  return C89CBOR_OK;
}
static int binding_valid(const c89cbor_lua *binding) {
  return binding != NULL && binding->active && binding->state != NULL;
}
static int owner_valid(cpkt_lua_state *L, int owner) {
  handle *h;
  if (owner == 0)
    return 1;
  if (cpkt_lua_isnoneornil(L, owner))
    return 0;
  h = any_handle(L, owner);
  return h == NULL || h->ptr != NULL;
}
#define BINDING_BRIDGE(name, type)                                             \
  int c89cbor_lua_push_##name(c89cbor_lua *binding, type *value, int owner) {  \
    if (!binding_valid(binding) || !owner_valid(binding->state, owner))        \
      return C89CBOR_INVALID;                                                  \
    return push_##name(binding->state, value, owner);                          \
  }                                                                            \
  type *c89cbor_lua_check_##name(c89cbor_lua *binding, int index) {            \
    return binding_valid(binding) ? check_##name(binding->state, index)        \
                                  : NULL;                                      \
  }
BINDING_BRIDGE(runtime, c89cbor)
BINDING_BRIDGE(conversion, c89cbor_conversion)
BINDING_BRIDGE(record_view, lonejson_record_view)
BINDING_BRIDGE(decoder, c89cbor_decoder)
BINDING_BRIDGE(encoder, c89cbor_encoder)
BINDING_BRIDGE(reader, c89cbor_reader)
BINDING_BRIDGE(source, c89cbor_source)
BINDING_BRIDGE(sink, c89cbor_sink)
BINDING_BRIDGE(transfer, c89cbor_transfer)
BINDING_BRIDGE(fd, c89cbor_fd)
BINDING_BRIDGE(allocator, c89cbor_allocator)
BINDING_BRIDGE(options, c89cbor_options)
BINDING_BRIDGE(config, c89cbor_config)
#undef BINDING_BRIDGE
int c89cbor_lua_push_span(c89cbor_lua *binding, const void *bytes,
                          size_t length, int owner) {
  if (!binding_valid(binding) || !owner_valid(binding->state, owner))
    return C89CBOR_INVALID;
  return push_span(binding->state, bytes, length, owner);
}
int c89cbor_lua_check_span(c89cbor_lua *binding, int index, const void **bytes,
                           size_t *length) {
  if (bytes != NULL)
    *bytes = NULL;
  if (length != NULL)
    *length = 0;
  return binding_valid(binding)
             ? check_span(binding->state, index, bytes, length)
             : C89CBOR_INVALID;
}
static const void *input(cpkt_lua_state *L, int index, size_t *n) {
  const void *bytes;
  if (cpkt_lua_isnoneornil(L, index)) {
    *n = 0;
    return NULL;
  }
  if (check_span(L, index, &bytes, n) == 0)
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
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  handle *frames = NULL, *a = NULL, *h;
  c89cbor_allocator *allocator = NULL;
  size_t chunk = size_arg(L, 2 + base, 0);
  int rc;
  if (base && checked(L, 1, ROOT)->active) {
    cpkt_lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  if (!cpkt_lua_isnoneornil(L, 1 + base)) {
    if (create) {
      a = checked(L, 1 + base, ALLOC);
      allocator = a->ptr;
    } else {
      frames = checked(L, 1 + base, FRAMES);
      if (frames->borrowers)
        return cpkt_lua_l_argerror(L, 1, "frames already in use");
    }
  }
  h = new_handle(L, encoder ? ENC : DEC,
                 create    ? 0
                 : encoder ? sizeof(c89cbor_encoder)
                           : sizeof(c89cbor_decoder));
  if (base)
    checked(L, 1, ROOT)->active = 1;
  if (create) {
    if (encoder) {
      c89cbor_encoder *e = NULL;
      rc = c89cbor_encoder_create(runtime, allocator, &e);
      h->ptr = e;
    } else {
      c89cbor_decoder *d = NULL;
      rc = c89cbor_decoder_create(runtime, allocator, &d);
      h->ptr = d;
    }
    h->heap_kind = encoder ? 2 : 1;
    h->allocator = allocator;
  } else if (encoder)
    rc = c89cbor_encoder_init(runtime, h->ptr,
                              frames == NULL ? NULL : frames->ptr,
                              frames == NULL ? 0 : frames->count, chunk);
  else
    rc = c89cbor_decoder_init(runtime, h->ptr,
                              frames == NULL ? NULL : frames->ptr,
                              frames == NULL ? 0 : frames->count, chunk);
  if (base)
    checked(L, 1, ROOT)->active = 0;
  if (frames != NULL || a != NULL)
    pin(L, h, 1 + base, 1);
  if (base)
    pin(L, h, 1, 3);
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
static int next_tag(cpkt_lua_state *L) {
  c89cbor_decoder *decoder = checked(L, 1, DEC)->ptr;
  uint64_t number;
  size_t length, consumed;
  const void *bytes = input(L, 2, &length);
  int status =
      c89cbor_decoder_next_tag(decoder, bytes, length, &consumed, &number);
  result(L, status);
  push_integer(L, consumed);
  if (status == C89CBOR_TOKEN)
    push_integer(L, number);
  else
    cpkt_lua_pushnil(L);
  return 3;
}
static int reset_decoder(cpkt_lua_state *L) {
  return result(L, c89cbor_decoder_reset(checked(L, 1, DEC)->ptr));
}
static int finish_encoder(cpkt_lua_state *L) {
  return result(L, c89cbor_encoder_finish(checked(L, 1, ENC)->ptr));
}
static void unpin_data(cpkt_lua_state *L, handle *h);
static int reset_encoder(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  int status;
  if (h->borrowers)
    return result(L, C89CBOR_BUSY);
  status = c89cbor_encoder_reset(h->ptr);
  if (status == 0)
    unpin_data(L, h);
  return result(L, status);
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
    drop_parent(h->parent[1]);
    h->parent[1] = NULL;
  }
  cpkt_lua_pushnil(L);
  cpkt_lua_setiuservalue(L, 1, 2);
}
static int encoder_tag(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  int status;
  if (h->borrowers)
    return result(L, C89CBOR_BUSY);
  status = c89cbor_encoder_tag(h->ptr, integer(L, 2));
  if (status == 0)
    unpin_data(L, h);
  return result(L, status);
}
static int encoder_end_tag(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  int status;
  if (h->borrowers)
    return result(L, C89CBOR_BUSY);
  status = c89cbor_encoder_end_tag(h->ptr);
  if (status == 0)
    unpin_data(L, h);
  return result(L, status);
}
static int put_encoder(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  c89cbor_encoder *e = h->ptr;
  c89cbor_token *t = checked(L, 2, TOKEN)->ptr;
  int rc;
  if (h->borrowers)
    return result(L, C89CBOR_BUSY);
  rc = c89cbor_encoder_put(e, t);
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
  push_span(L, t->data, t->length, 1);
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
  push_span(L, bytes, n, 1);
  return 1;
}
static int float_set(cpkt_lua_state *L) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  c89cbor_token *t = checked(L, 1 + base, TOKEN)->ptr;
  return result(
      L, c89cbor_float64_set(runtime, t, cpkt_lua_l_checknumber(L, 2 + base)));
}
static int float_get(cpkt_lua_state *L) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  double value = 0;
  int rc =
      c89cbor_float64_get(runtime, checked(L, 1 + base, TOKEN)->ptr, &value);
  result(L, rc);
  if (rc == 0)
    cpkt_lua_pushnumber(L, value);
  else
    cpkt_lua_pushnil(L);
  return 2;
}
static int reader_factory(cpkt_lua_state *L, int create) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  uint64_t mode = optional(L, 1 + base, 0);
  uint32_t limit = limit_arg(L, 2 + base);
  handle *h;
  c89cbor_reader *reader = NULL;
  int status;
  if (mode > 2)
    return cpkt_lua_l_argerror(L, 1, "invalid framing mode");
  if (base && checked(L, 1, ROOT)->active) {
    cpkt_lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  h = new_handle(L, READER, create ? 0 : sizeof(c89cbor_reader));
  if (base)
    checked(L, 1, ROOT)->active = 1;
  if (create) {
    status =
        c89cbor_reader_create(runtime, (c89cbor_framing)mode, limit, &reader);
    h->ptr = reader;
    h->heap_kind = 3;
  } else
    status = c89cbor_reader_init(runtime, h->ptr, (c89cbor_framing)mode, limit);
  if (base)
    checked(L, 1, ROOT)->active = 0;
  if (status != 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, status);
    return 2;
  }
  if (base)
    pin(L, h, 1, 3);
  return 1;
}
static int new_reader(cpkt_lua_state *L) { return reader_factory(L, 0); }
static int create_reader(cpkt_lua_state *L) { return reader_factory(L, 1); }
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
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  unsigned char bytes[4];
  uint64_t n = integer(L, 1 + base);
  int rc = n > UINT32_MAX ? C89CBOR_LIMIT
                          : c89cbor_length32(runtime, (uint32_t)n,
                                             limit_arg(L, 2 + base), bytes);
  result(L, rc);
  if (!rc)
    cpkt_lua_pushlstring(L, (const char *)bytes, 4);
  else
    cpkt_lua_pushnil(L);
  return 2;
}
static int fd_factory(cpkt_lua_state *L, int create) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  uint64_t fd = integer(L, 1 + base);
  handle *h;
  endpoint *e;
  c89cbor_fd *descriptor = NULL;
  int status;
  if (fd > INT_MAX)
    return cpkt_lua_l_argerror(L, 1, "invalid descriptor");
  if (base && checked(L, 1, ROOT)->active) {
    cpkt_lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  h = new_handle(L, FD, create ? 0 : sizeof(*e));
  if (base)
    checked(L, 1, ROOT)->active = 1;
  if (create) {
    status = c89cbor_fd_create(runtime, (int)fd, &descriptor);
    h->ptr = descriptor;
    h->heap_kind = 5;
  } else {
    e = h->ptr;
    status = c89cbor_fd_init(runtime, &e->fd, (int)fd, &e->source, &e->sink);
  }
  if (base)
    checked(L, 1, ROOT)->active = 0;
  if (status != 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, status);
    return 2;
  }
  if (base)
    pin(L, h, 1, 3);
  return 1;
}
static int new_fd(cpkt_lua_state *L) { return fd_factory(L, 0); }
static int create_fd(cpkt_lua_state *L) { return fd_factory(L, 1); }
static int fd_source(cpkt_lua_state *L) {
  c89cbor_fd *fd = checked(L, 1, FD)->ptr;
  handle *h = new_handle(L, SOURCE, sizeof(c89cbor_source));
  (void)c89cbor_fd_source(fd, h->ptr);
  pin(L, h, 1, 1);
  return 1;
}
static int fd_sink(cpkt_lua_state *L) {
  c89cbor_fd *fd = checked(L, 1, FD)->ptr;
  handle *h = new_handle(L, SINK, sizeof(c89cbor_sink));
  (void)c89cbor_fd_sink(fd, h->ptr);
  pin(L, h, 1, 1);
  return 1;
}
static int transfer_factory(cpkt_lua_state *L, int create) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL ? 1 : 0;
  c89cbor_source *source = checked(L, 1 + base, SOURCE)->ptr;
  c89cbor_sink *sink = checked(L, 2 + base, SINK)->ptr;
  uint64_t mode = optional(L, 3 + base, 0);
  uint32_t limit = limit_arg(L, 4 + base);
  handle *h;
  c89cbor_transfer *transfer = NULL;
  int rc;
  if (mode > 2)
    return cpkt_lua_l_argerror(L, 3, "invalid framing mode");
  if (base && checked(L, 1, ROOT)->active) {
    cpkt_lua_pushnil(L);
    result(L, C89CBOR_BUSY);
    return 2;
  }
  h = new_handle(L, TRANSFER, create ? 0 : sizeof(c89cbor_transfer));
  if (base)
    checked(L, 1, ROOT)->active = 1;
  if (create) {
    rc = c89cbor_transfer_create(runtime, source, sink, (c89cbor_framing)mode,
                                 limit, &transfer);
    h->ptr = transfer;
    h->heap_kind = 4;
  } else
    rc = c89cbor_transfer_init(runtime, h->ptr, source, sink,
                               (c89cbor_framing)mode, limit);
  if (base)
    checked(L, 1, ROOT)->active = 0;
  pin(L, h, 1 + base, 1);
  pin(L, h, 2 + base, 2);
  if (base)
    pin(L, h, 1, 3);
  if (rc < 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, rc);
    return 2;
  }
  return 1;
}
static int new_transfer(cpkt_lua_state *L) { return transfer_factory(L, 0); }
static int create_transfer(cpkt_lua_state *L) { return transfer_factory(L, 1); }
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
  int base = check_runtime(L, 1) != NULL ? 1 : 0;
  return cpkt_lua_pushstring(L, c89cbor_status_string(
                                    NULL, (int)(int64_t)integer(L, 1 + base))),
         1;
}

static void diagnostic_table(cpkt_lua_state *L, const c89cbor_error *error) {
  cpkt_lua_newtable(L);
#define ERROR_INTEGER(field)                                                   \
  push_integer(L, (uint64_t)(int64_t)error->field);                            \
  cpkt_lua_setfield(L, -2, #field)
#define ERROR_STRING(field)                                                    \
  cpkt_lua_pushstring(L, error->field);                                        \
  cpkt_lua_setfield(L, -2, #field)
  ERROR_INTEGER(status);
  ERROR_INTEGER(cause);
  ERROR_INTEGER(system_errno);
  ERROR_INTEGER(offset);
  ERROR_INTEGER(shortened);
  ERROR_INTEGER(truncated);
  ERROR_STRING(layer);
  ERROR_STRING(message);
  ERROR_STRING(path);
#undef ERROR_INTEGER
#undef ERROR_STRING
}
static int diagnostic_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  c89cbor_error error;
  int status = C89CBOR_INVALID;
  memset(&error, 0, sizeof(error));
  if (h != NULL && h->ptr != NULL) {
#define DIAGNOSTIC(kind, type, function)                                       \
  if (cpkt_lua_l_testudata(L, 1, kind) != NULL)                                \
  status = function((type *)h->ptr, &error)
    DIAGNOSTIC(ROOT, c89cbor, c89cbor_diagnostic);
    DIAGNOSTIC(CONVERSION, c89cbor_conversion, c89cbor_conversion_diagnostic);
    DIAGNOSTIC(DEC, c89cbor_decoder, c89cbor_decoder_diagnostic);
    DIAGNOSTIC(ENC, c89cbor_encoder, c89cbor_encoder_diagnostic);
    DIAGNOSTIC(READER, c89cbor_reader, c89cbor_reader_diagnostic);
    DIAGNOSTIC(TRANSFER, c89cbor_transfer, c89cbor_transfer_diagnostic);
    DIAGNOSTIC(FD, c89cbor_fd, c89cbor_fd_diagnostic);
#undef DIAGNOSTIC
  }
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static size_t table_size(cpkt_lua_state *L, int index, const char *key,
                         size_t fallback) {
  size_t value;
  cpkt_lua_getfield(L, index, key);
  value = size_arg(L, -1, fallback);
  cpkt_lua_pop(L, 1);
  return value;
}
static void options_from_lua(cpkt_lua_state *L, int index,
                             c89cbor_options *options) {
  c89cbor_options *native = check_options(L, index);
  *options = c89cbor_default_options();
  if (native != NULL) {
    *options = *native;
    return;
  }
  if (cpkt_lua_isnoneornil(L, index))
    return;
  cpkt_lua_l_checktype(L, index, CPKT_LUA_TTABLE);
  options->depth = table_size(L, index, "depth", options->depth);
  options->chunk = table_size(L, index, "chunk", options->chunk);
  options->key_bytes = table_size(L, index, "key_bytes", options->key_bytes);
  options->active_keys =
      table_size(L, index, "active_keys", options->active_keys);
  options->active_key_bytes =
      table_size(L, index, "active_key_bytes", options->active_key_bytes);
  options->number_bytes =
      table_size(L, index, "number_bytes", options->number_bytes);
  options->field_bytes =
      table_size(L, index, "field_bytes", options->field_bytes);
  options->array_elements =
      table_size(L, index, "array_elements", options->array_elements);
  options->record_bytes =
      table_size(L, index, "record_bytes", options->record_bytes);
  options->step_input = table_size(L, index, "step_input", options->step_input);
  options->step_output =
      table_size(L, index, "step_output", options->step_output);
  options->step_events =
      table_size(L, index, "step_events", options->step_events);
  cpkt_lua_getfield(L, index, "allow_unknown_fields");
  options->allow_unknown_fields = cpkt_lua_toboolean(L, -1);
  cpkt_lua_pop(L, 1);
  cpkt_lua_getfield(L, index, "field_sinks");
  if (!cpkt_lua_isnil(L, -1))
    cpkt_lua_l_argerror(L, index,
                        "native field sinks require typed options from C");
  cpkt_lua_pop(L, 1);
}
static int default_options(cpkt_lua_state *L) {
  c89cbor_options options = c89cbor_default_options();
  cpkt_lua_newtable(L);
  push_integer(L, options.depth);
  cpkt_lua_setfield(L, -2, "depth");
  push_integer(L, options.chunk);
  cpkt_lua_setfield(L, -2, "chunk");
  push_integer(L, options.key_bytes);
  cpkt_lua_setfield(L, -2, "key_bytes");
  push_integer(L, options.active_keys);
  cpkt_lua_setfield(L, -2, "active_keys");
  push_integer(L, options.active_key_bytes);
  cpkt_lua_setfield(L, -2, "active_key_bytes");
  push_integer(L, options.number_bytes);
  cpkt_lua_setfield(L, -2, "number_bytes");
  push_integer(L, options.field_bytes);
  cpkt_lua_setfield(L, -2, "field_bytes");
  push_integer(L, options.array_elements);
  cpkt_lua_setfield(L, -2, "array_elements");
  push_integer(L, options.record_bytes);
  cpkt_lua_setfield(L, -2, "record_bytes");
  push_integer(L, options.step_input);
  cpkt_lua_setfield(L, -2, "step_input");
  push_integer(L, options.step_output);
  cpkt_lua_setfield(L, -2, "step_output");
  push_integer(L, options.step_events);
  cpkt_lua_setfield(L, -2, "step_events");
  cpkt_lua_pushboolean(L, 0);
  cpkt_lua_setfield(L, -2, "allow_unknown_fields");
  return 1;
}
static int default_allocator(cpkt_lua_state *L) {
  handle *h = new_handle(L, ALLOC, sizeof(c89cbor_allocator));
  c89cbor_allocator allocator = c89cbor_default_allocator();
  memcpy(h->ptr, &allocator, sizeof(allocator));
  return 1;
}
static void config_from_lua(cpkt_lua_state *L, int index,
                            c89cbor_config *config) {
  c89cbor_config *native = check_config(L, index);
  c89cbor_allocator *allocator;
  int child;
  *config = c89cbor_default_config();
  if (native != NULL) {
    *config = *native;
    return;
  }
  if (cpkt_lua_isnoneornil(L, index))
    return;
  cpkt_lua_l_checktype(L, index, CPKT_LUA_TTABLE);
  config->step_input = table_size(L, index, "step_input", 0);
  config->step_output = table_size(L, index, "step_output", 0);
  config->step_events = table_size(L, index, "step_events", 0);
  cpkt_lua_getfield(L, index, "allocator");
  if (!cpkt_lua_isnil(L, -1)) {
    allocator = check_allocator(L, -1);
    if (allocator == NULL)
      cpkt_lua_l_argerror(L, index,
                          "allocator must be a live native allocator");
    config->allocator = *allocator;
  }
  cpkt_lua_pop(L, 1);
  cpkt_lua_getfield(L, index, "json_config");
  if (!cpkt_lua_isnil(L, -1)) {
    cpkt_lua_l_checktype(L, -1, CPKT_LUA_TTABLE);
    child = cpkt_lua_absindex(L, -1);
    config->json_config.max_depth =
        table_size(L, child, "max_depth", config->json_config.max_depth);
    config->json_config.max_dynamic_string_bytes =
        table_size(L, child, "max_dynamic_string_bytes",
                   config->json_config.max_dynamic_string_bytes);
    config->json_config.max_alloc_bytes = table_size(
        L, child, "max_alloc_bytes", config->json_config.max_alloc_bytes);
    config->json_config.json_value_max_depth =
        table_size(L, child, "json_value_max_depth",
                   config->json_config.json_value_max_depth);
    config->json_config.json_value_max_string_bytes =
        table_size(L, child, "json_value_max_string_bytes",
                   config->json_config.json_value_max_string_bytes);
    config->json_config.json_value_max_key_bytes =
        table_size(L, child, "json_value_max_key_bytes",
                   config->json_config.json_value_max_key_bytes);
    config->json_config.json_value_max_number_bytes =
        table_size(L, child, "json_value_max_number_bytes",
                   config->json_config.json_value_max_number_bytes);
    config->json_config.write_max_output_bytes =
        table_size(L, child, "write_max_output_bytes",
                   config->json_config.write_max_output_bytes);
  }
  cpkt_lua_pop(L, 1);
}
static int default_config(cpkt_lua_state *L) {
  cpkt_lua_newtable(L);
  push_integer(L, 0);
  cpkt_lua_setfield(L, -2, "step_input");
  push_integer(L, 0);
  cpkt_lua_setfield(L, -2, "step_output");
  push_integer(L, 0);
  cpkt_lua_setfield(L, -2, "step_events");
  return 1;
}
static int runtime_factory(cpkt_lua_state *L, int create) {
  c89cbor_config config;
  c89cbor_error error;
  c89cbor *runtime = NULL;
  handle *h;
  int status;
  config_from_lua(L, 1, &config);
  h = new_handle(L, ROOT, create ? 0 : sizeof(c89cbor));
  if (create)
    status = c89cbor_create(&config, &runtime, &error);
  else {
    runtime = h->ptr;
    status = c89cbor_init(runtime, &config, &error);
  }
  h->ptr = runtime;
  h->heap_kind = create ? 6 : -6;
  if (status != 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, status);
    diagnostic_table(L, &error);
    return 3;
  }
  pin(L, h, 1, 1);
  if (cpkt_lua_type(L, 1) == CPKT_LUA_TTABLE) {
    cpkt_lua_getfield(L, 1, "allocator");
    if (!cpkt_lua_isnil(L, -1)) {
      cpkt_lua_pushvalue(L, -1);
      cpkt_lua_setiuservalue(L, -3, 2);
      if (any_handle(L, -1) != NULL) {
        h->parent[1] = any_handle(L, -1);
        ++h->parent[1]->borrowers;
      }
    }
    cpkt_lua_pop(L, 1);
  }
  return 1;
}
static int new_runtime(cpkt_lua_state *L) { return runtime_factory(L, 1); }
static int init_runtime(cpkt_lua_state *L) { return runtime_factory(L, 0); }
static int peek_encoder(cpkt_lua_state *L) {
  c89cbor_encoder *encoder = checked(L, 1, ENC)->ptr;
  const void *bytes;
  size_t length;
  int status = c89cbor_encoder_peek(encoder, &bytes, &length);
  result(L, status);
  if (status == C89CBOR_OUTPUT)
    (void)push_span(L, bytes, length, 1);
  else
    cpkt_lua_pushnil(L);
  return 2;
}
static int advance_encoder(cpkt_lua_state *L) {
  handle *h = checked(L, 1, ENC);
  c89cbor_encoder *encoder = h->ptr;
  const void *bytes;
  size_t length;
  int status = c89cbor_encoder_advance(encoder, size_arg(L, 2, 0));
  if (status == 0 &&
      c89cbor_encoder_peek(encoder, &bytes, &length) != C89CBOR_OUTPUT)
    unpin_data(L, h);
  return result(L, status);
}
static int reset_reader(cpkt_lua_state *L) {
  return result(L, c89cbor_reader_reset(checked(L, 1, READER)->ptr));
}
static int conversion_step(cpkt_lua_state *L) {
  handle *h = checked(L, 1, CONVERSION);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_conversion_step(h->ptr, &error);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int conversion_run(cpkt_lua_state *L) {
  handle *h = checked(L, 1, CONVERSION);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  do {
    status = c89cbor_conversion_step(h->ptr, &error);
  } while (status == C89CBOR_OK);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int progress_handle(cpkt_lua_state *L) {
  handle *h = any_handle(L, 1);
  c89cbor_progress progress;
  int status = C89CBOR_INVALID;
  memset(&progress, 0, sizeof(progress));
  if (h != NULL && h->ptr != NULL) {
    if (cpkt_lua_l_testudata(L, 1, CONVERSION) != NULL)
      status = c89cbor_conversion_progress(h->ptr, &progress);
    if (cpkt_lua_l_testudata(L, 1, TRANSFER) != NULL)
      status = c89cbor_transfer_progress(h->ptr, &progress);
  }
  result(L, status);
  cpkt_lua_newtable(L);
#define PROGRESS(field)                                                        \
  push_integer(L, progress.field);                                             \
  cpkt_lua_setfield(L, -2, #field)
  PROGRESS(input);
  PROGRESS(output);
  PROGRESS(records);
#undef PROGRESS
  return 2;
}
enum conversion_kind { JSON_CBOR, CBOR_JSON, ENCODE_MAP, DECODE_MAP };
static int runtime_conversion(cpkt_lua_state *L, enum conversion_kind kind,
                              int synchronous) {
  handle *root = checked(L, 1, ROOT), *h;
  c89cbor *runtime = root->ptr;
  c89cbor_source *source = NULL;
  c89cbor_sink *sink = NULL;
  lonejson_record_view *view = NULL;
  c89cbor_conversion *operation = NULL;
  c89cbor_options options;
  c89cbor_error error;
  int status, source_index = 0, sink_index = 0, view_index = 0;
  if (root->active)
    return result(L, C89CBOR_BUSY);
  if (kind == JSON_CBOR || kind == CBOR_JSON) {
    source_index = 2;
    sink_index = 3;
  } else if (kind == ENCODE_MAP) {
    view_index = 2;
    sink_index = 3;
  } else {
    source_index = 2;
    view_index = 3;
  }
  if (source_index)
    source = checked(L, source_index, SOURCE)->ptr;
  if (sink_index)
    sink = checked(L, sink_index, SINK)->ptr;
  if (view_index)
    view = checked(L, view_index, VIEW)->ptr;
  options_from_lua(L, 4, &options);
  root->active = 1;
  if (synchronous == 1) {
    if (kind == JSON_CBOR)
      status = runtime->json_to_cbor(runtime, source, sink, &options, &error);
    else if (kind == CBOR_JSON)
      status = runtime->cbor_to_json(runtime, source, sink, &options, &error);
    else if (kind == ENCODE_MAP)
      status = runtime->encode_map_view(runtime, view, sink, &options, &error);
    else
      status =
          runtime->decode_map_view(runtime, source, view, &options, &error);
    root->active = 0;
    result(L, status);
    diagnostic_table(L, &error);
    return 2;
  }
  root->active = 0;
  /* Allocate Lua storage before creating native children: Lua OOM must not
   * strand an unreferenced native operation. */
  h = new_handle(L, CONVERSION,
                 synchronous == 2 ? sizeof(c89cbor_conversion) : 0);
  root->active = 1;
  if (synchronous == 2) {
    operation = h->ptr;
    if (kind == JSON_CBOR)
      status = runtime->json_to_cbor_init(runtime, operation, source, sink,
                                          &options, &error);
    else if (kind == CBOR_JSON)
      status = runtime->cbor_to_json_init(runtime, operation, source, sink,
                                          &options, &error);
    else if (kind == ENCODE_MAP)
      status = runtime->encode_map_view_init(runtime, operation, view, sink,
                                             &options, &error);
    else
      status = runtime->decode_map_view_init(runtime, operation, source, view,
                                             &options, &error);
  } else if (kind == JSON_CBOR)
    status = runtime->json_to_cbor_open(runtime, source, sink, &options,
                                        &operation, &error);
  else if (kind == CBOR_JSON)
    status = runtime->cbor_to_json_open(runtime, source, sink, &options,
                                        &operation, &error);
  else if (kind == ENCODE_MAP)
    status = runtime->encode_map_view_open(runtime, view, sink, &options,
                                           &operation, &error);
  else
    status = runtime->decode_map_view_open(runtime, source, view, &options,
                                           &operation, &error);
  h->ptr = operation;
  h->heap_kind = synchronous == 2 ? -7 : 7;
  root->active = 0;
  if (status != 0) {
    cpkt_lua_pop(L, 1);
    cpkt_lua_pushnil(L);
    result(L, status);
    diagnostic_table(L, &error);
    return 3;
  }
  pin(L, h, 1, 1);
  pin(L, h, source_index ? source_index : view_index, 2);
  pin(L, h, sink_index ? sink_index : view_index, 3);
  pin(L, h, 4, 4);
  return 1;
}
static int json_to_cbor(cpkt_lua_state *L) {
  return runtime_conversion(L, JSON_CBOR, 1);
}
static int json_to_cbor_open(cpkt_lua_state *L) {
  return runtime_conversion(L, JSON_CBOR, 0);
}
static int cbor_to_json(cpkt_lua_state *L) {
  return runtime_conversion(L, CBOR_JSON, 1);
}
static int cbor_to_json_open(cpkt_lua_state *L) {
  return runtime_conversion(L, CBOR_JSON, 0);
}
static int encode_map(cpkt_lua_state *L) {
  return runtime_conversion(L, ENCODE_MAP, 1);
}
static int encode_map_open(cpkt_lua_state *L) {
  return runtime_conversion(L, ENCODE_MAP, 0);
}
static int decode_map(cpkt_lua_state *L) {
  return runtime_conversion(L, DECODE_MAP, 1);
}
static int decode_map_open(cpkt_lua_state *L) {
  return runtime_conversion(L, DECODE_MAP, 0);
}
static int json_to_cbor_init(cpkt_lua_state *L) {
  return runtime_conversion(L, JSON_CBOR, 2);
}
static int cbor_to_json_init(cpkt_lua_state *L) {
  return runtime_conversion(L, CBOR_JSON, 2);
}
static int encode_map_init(cpkt_lua_state *L) {
  return runtime_conversion(L, ENCODE_MAP, 2);
}
static int decode_map_init(cpkt_lua_state *L) {
  return runtime_conversion(L, DECODE_MAP, 2);
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
  cpkt_lua_pushcfunction(L, close_handle);
  cpkt_lua_setfield(L, -2, "cleanup");
  cpkt_lua_pushcfunction(L, close_handle);
  cpkt_lua_setfield(L, -2, "destroy");
  cpkt_lua_pushcfunction(L, diagnostic_handle);
  cpkt_lua_setfield(L, -2, "diagnostic");
  cpkt_lua_pushstring(L, name);
  cpkt_lua_setfield(L, -2, "__metatable");
  if (methods != NULL)
    cpkt_lua_l_setfuncs(L, methods, 0);
  cpkt_lua_pop(L, 1);
}
int luaopen_cbor(cpkt_lua_state *L) {
  static const cpkt_lua_reg dec[] = {{"next", next_decoder},
                                     {"next_tag", next_tag},
                                     {"finish", finish_decoder},
                                     {"reset", reset_decoder},
                                     {NULL, NULL}};
  static const cpkt_lua_reg enc[] = {{"put", put_encoder},
                                     {"tag", encoder_tag},
                                     {"end_tag", encoder_end_tag},
                                     {"peek", peek_encoder},
                                     {"advance", advance_encoder},
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
  static const cpkt_lua_reg rd[] = {{"next", next_reader},
                                    {"finish", finish_reader},
                                    {"reset", reset_reader},
                                    {NULL, NULL}};
  static const cpkt_lua_reg fd[] = {
      {"source", fd_source}, {"sink", fd_sink}, {NULL, NULL}};
  static const cpkt_lua_reg tr[] = {{"step", transfer_step},
                                    {"run", transfer_run},
                                    {"counts", transfer_counts},
                                    {"progress", progress_handle},
                                    {NULL, NULL}};
  static const cpkt_lua_reg cv[] = {{"step", conversion_step},
                                    {"run", conversion_run},
                                    {"progress", progress_handle},
                                    {NULL, NULL}};
  static const cpkt_lua_reg root[] = {{"encoder", new_encoder},
                                      {"decoder", new_decoder},
                                      {"encoder_init", new_encoder},
                                      {"decoder_init", new_decoder},
                                      {"encoder_create", create_encoder},
                                      {"decoder_create", create_decoder},
                                      {"reader", new_reader},
                                      {"reader_init", new_reader},
                                      {"reader_create", create_reader},
                                      {"fd", new_fd},
                                      {"fd_init", new_fd},
                                      {"fd_create", create_fd},
                                      {"transfer", new_transfer},
                                      {"transfer_init", new_transfer},
                                      {"transfer_create", create_transfer},
                                      {"json_to_cbor", json_to_cbor},
                                      {"json_to_cbor_open", json_to_cbor_open},
                                      {"json_to_cbor_init", json_to_cbor_init},
                                      {"cbor_to_json", cbor_to_json},
                                      {"cbor_to_json_open", cbor_to_json_open},
                                      {"cbor_to_json_init", cbor_to_json_init},
                                      {"encode_map", encode_map},
                                      {"encode_map_open", encode_map_open},
                                      {"encode_map_init", encode_map_init},
                                      {"encode_map_view", encode_map},
                                      {"encode_map_view_open", encode_map_open},
                                      {"encode_map_view_init", encode_map_init},
                                      {"decode_map", decode_map},
                                      {"decode_map_open", decode_map_open},
                                      {"decode_map_init", decode_map_init},
                                      {"decode_map_view", decode_map},
                                      {"decode_map_view_open", decode_map_open},
                                      {"decode_map_view_init", decode_map_init},
                                      {"default_options", default_options},
                                      {"default_config", default_config},
                                      {"default_allocator", default_allocator},
                                      {"version", version},
                                      {"status_string", status_string},
                                      {"float64_set", float_set},
                                      {"float64_get", float_get},
                                      {"length32", length32},
                                      {NULL, NULL}};
  static const cpkt_lua_reg module[] = {
      {"version", version},
      {"create", new_runtime},
      {"init", init_runtime},
      {"default_options", default_options},
      {"default_config", default_config},
      {"default_allocator", default_allocator},
      {"status_string", status_string},
      {"decoder", new_decoder},
      {"encoder", new_encoder},
      {"decoder_create", create_decoder},
      {"encoder_create", create_encoder},
      {"frames", new_frames},
      {"token", new_token},
      {"span", new_span},
      {"reader", new_reader},
      {"reader_create", create_reader},
      {"length32", length32},
      {"fd", new_fd},
      {"fd_create", create_fd},
      {"transfer", new_transfer},
      {"transfer_create", create_transfer},
      {NULL, NULL}};
  static const char *const types[] = {
      "UINT",    "NEGATIVE", "BYTES", "TEXT",      "ARRAY",  "MAP",
      "TAG",     "BOOL",     "NULL",  "UNDEFINED", "SIMPLE", "FLOAT16",
      "FLOAT32", "FLOAT64",  "DATA",  "END"};
  size_t i;
  metatable(L, DEC, dec);
  metatable(L, ROOT, root);
  metatable(L, CONVERSION, cv);
  metatable(L, VIEW, NULL);
  metatable(L, OPTIONS, NULL);
  metatable(L, CONFIG, NULL);
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
  CONSTANT(UNSUPPORTED);
  CONSTANT(SCHEMA);
  CONSTANT(BUSY);
  CONSTANT(SINGLE);
  CONSTANT(SEQUENCE);
  CONSTANT(LENGTH32);
  CONSTANT(RECORD_BEGIN);
  CONSTANT(RECORD_TOKEN);
  CONSTANT(RECORD_END);
#undef CONSTANT
  return 1;
}
