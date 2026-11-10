/* Grammar and bounded UTF-8 technique derived from cai/src/cai_cbor.c,
 * c89.systems, MIT; see docs/provenance.md. Pull I/O and full RFC types are
 * new. */
#include <c89cbor/cbor.h>
#include <float.h>
#include <stdlib.h>
#include <string.h>

static int fail(c89cbor_state *s, int code) {
  s->failed = code;
  return code;
}
static c89cbor_frame *top(c89cbor_state *s) {
  return s->depth == 0 ? NULL : &s->frames[s->depth - 1];
}
static void done(c89cbor_state *s) {
  c89cbor_frame *f = top(s);
  if (f == NULL)
    s->complete = 1;
  else if (f->type == C89CBOR_ARRAY || f->type == C89CBOR_MAP ||
           f->type == C89CBOR_TAG) {
    f->odd ^= 1U;
    if (!f->indefinite && (f->type != C89CBOR_MAP || !f->odd))
      --f->remaining;
  }
}
static int begin(c89cbor_state *s, const c89cbor_token *t) {
  c89cbor_frame *p = top(s), *f;
  if (s->complete || t->type < C89CBOR_UINT || t->type > C89CBOR_FLOAT64 ||
      t->length != 0 || t->data != NULL ||
      (t->indefinite && (t->type < C89CBOR_BYTES || t->type > C89CBOR_MAP)))
    return fail(s, C89CBOR_MALFORMED);
  if (p != NULL) {
    if (p->type == C89CBOR_BYTES || p->type == C89CBOR_TEXT) {
      if (!p->indefinite || t->type != p->type || t->indefinite)
        return fail(s, C89CBOR_MALFORMED);
    } else if (!p->indefinite && p->remaining == 0)
      return fail(s, C89CBOR_MALFORMED);
  }
  if (t->type >= C89CBOR_BYTES && t->type <= C89CBOR_TAG) {
    if (s->depth == s->capacity)
      return fail(s, C89CBOR_LIMIT);
    f = &s->frames[s->depth++];
    memset(f, 0, sizeof(*f));
    f->remaining = t->type == C89CBOR_TAG ? 1 : t->argument;
    f->type = t->type;
    f->indefinite = t->indefinite;
  } else {
    if ((t->type == C89CBOR_BOOL && t->argument > 1) ||
        ((t->type == C89CBOR_NULL || t->type == C89CBOR_UNDEFINED) &&
         t->argument != 0) ||
        (t->type == C89CBOR_SIMPLE &&
         (t->argument > 255 || (t->argument >= 20 && t->argument < 32))) ||
        (t->type == C89CBOR_FLOAT16 && t->argument > 65535U) ||
        (t->type == C89CBOR_FLOAT32 && t->argument > UINT32_MAX))
      return fail(s, C89CBOR_MALFORMED);
    done(s);
  }
  return C89CBOR_OK;
}
static int utf8(c89cbor_frame *f, const unsigned char *data, size_t count) {
  size_t i = 0;
  unsigned int pending = f->utf8, byte;
  uint32_t scalar = f->scalar, minimum = f->minimum;
  while (i < count) {
    byte = data[i];
    if (!pending && byte < 128U) {
      while (count - i >= sizeof(uint64_t)) {
        uint64_t word;
        memcpy(&word, data + i, sizeof(word));
        if (word & UINT64_C(0x8080808080808080))
          break;
        i += sizeof(word);
      }
      while (i < count && data[i] < 128U)
        ++i;
      continue;
    }
    ++i;
    if (pending) {
      if ((byte & 0xc0U) != 0x80U)
        return 0;
      scalar = (scalar << 6U) | (byte & 0x3fU);
      if (--pending == 0 && (scalar < minimum || scalar > 0x10ffffU ||
                             (scalar >= 0xd800U && scalar <= 0xdfffU)))
        return 0;
    } else if (byte >= 0xc2U && byte <= 0xdfU) {
      pending = 1;
      scalar = byte & 0x1fU;
      minimum = 0x80U;
    } else if (byte >= 0xe0U && byte <= 0xefU) {
      pending = 2;
      scalar = byte & 0x0fU;
      minimum = 0x800U;
    } else if (byte >= 0xf0U && byte <= 0xf4U) {
      pending = 3;
      scalar = byte & 7U;
      minimum = 0x10000U;
    } else
      return 0;
  }
  f->utf8 = pending;
  f->scalar = scalar;
  f->minimum = minimum;
  return 1;
}
static int data_room(c89cbor_state *s, const void *data, size_t n) {
  c89cbor_frame *f = top(s);
  if (f == NULL || (f->type != C89CBOR_BYTES && f->type != C89CBOR_TEXT) ||
      f->indefinite || (n != 0 && data == NULL) || (uint64_t)n > f->remaining)
    return fail(s, C89CBOR_MALFORMED);
  return C89CBOR_OK;
}
static int data_take(c89cbor_state *s, const void *data, size_t n) {
  c89cbor_frame *f;
  if (data_room(s, data, n) < 0)
    return s->failed;
  f = top(s);
  if (f->type == C89CBOR_TEXT &&
      (!utf8(f, data, n) || ((uint64_t)n == f->remaining && f->utf8)))
    return fail(s, C89CBOR_MALFORMED);
  f->remaining -= (uint64_t)n;
  return C89CBOR_OK;
}
static int end(c89cbor_state *s, uint64_t type) {
  c89cbor_frame *f = top(s);
  if (f == NULL || type != (uint64_t)f->type ||
      (!f->indefinite && f->remaining != 0) || f->utf8 ||
      (f->type == C89CBOR_MAP && f->odd))
    return fail(s, C89CBOR_MALFORMED);
  --s->depth;
  done(s);
  return C89CBOR_OK;
}
static int state_init(c89cbor_state *s, c89cbor_frame *frames, size_t capacity,
                      size_t chunk) {
  if ((frames == NULL) != (capacity == 0))
    return C89CBOR_INVALID;
  s->frames = frames == NULL ? s->local_frames : frames;
  s->capacity = frames == NULL ? C89CBOR_DEPTH : capacity;
  s->chunk = chunk == 0 ? C89CBOR_CHUNK : chunk;
  return C89CBOR_OK;
}
int c89cbor_decoder_init(c89cbor_decoder *d, c89cbor_frame *f, size_t capacity,
                         size_t chunk) {
  if (d == NULL)
    return C89CBOR_INVALID;
  memset(d, 0, sizeof(*d));
  return state_init(&d->state, f, capacity, chunk);
}
int c89cbor_encoder_init(c89cbor_encoder *e, c89cbor_frame *f, size_t capacity,
                         size_t chunk) {
  if (e == NULL)
    return C89CBOR_INVALID;
  memset(e, 0, sizeof(*e));
  return state_init(&e->state, f, capacity, chunk);
}
static int parse_header(c89cbor_decoder *d, c89cbor_token *t) {
  unsigned int major = d->header[0] >> 5U, extra = d->header[0] & 31U;
  size_t i;
  c89cbor_frame *f;
  for (i = 1; i < d->have; ++i)
    t->argument = (t->argument << 8U) | d->header[i];
  if (extra < 24)
    t->argument = extra;
  if (d->header[0] == 255U) {
    f = top(&d->state);
    if (f == NULL || !f->indefinite)
      return fail(&d->state, C89CBOR_MALFORMED);
    t->type = C89CBOR_END;
    t->argument = (uint64_t)f->type;
    return end(&d->state, t->argument);
  }
  if (extra >= 28 && extra != 31)
    return fail(&d->state, C89CBOR_MALFORMED);
  if (extra == 31 && (major < 2 || major > 5))
    return fail(&d->state, C89CBOR_MALFORMED);
  t->indefinite = extra == 31;
  if (t->indefinite)
    t->argument = 0;
  if (major < 7)
    t->type = (c89cbor_type)major;
  else if (extra == 25)
    t->type = C89CBOR_FLOAT16;
  else if (extra == 26)
    t->type = C89CBOR_FLOAT32;
  else if (extra == 27)
    t->type = C89CBOR_FLOAT64;
  else {
    if (extra == 24 && t->argument < 32)
      return fail(&d->state, C89CBOR_MALFORMED);
    if (t->argument == 20 || t->argument == 21) {
      t->type = C89CBOR_BOOL;
      t->argument -= 20;
    } else if (t->argument == 22 || t->argument == 23) {
      t->type = t->argument == 22 ? C89CBOR_NULL : C89CBOR_UNDEFINED;
      t->argument = 0;
    } else
      t->type = C89CBOR_SIMPLE;
  }
  return begin(&d->state, t);
}
int c89cbor_decoder_next(c89cbor_decoder *d, const void *input, size_t n,
                         size_t *consumed, c89cbor_token *t) {
  const unsigned char *p = input;
  c89cbor_frame *f;
  size_t take;
  unsigned int extra;
  int rc;
  if (consumed != NULL)
    *consumed = 0;
  if (d == NULL || consumed == NULL || t == NULL || (n && input == NULL) ||
      d->state.frames == NULL)
    return C89CBOR_INVALID;
  if (d->state.failed)
    return d->state.failed;
  memset(t, 0, sizeof(*t));
  f = top(&d->state);
  if (f != NULL && !f->indefinite && f->remaining == 0) {
    t->type = C89CBOR_END;
    t->argument = (uint64_t)f->type;
    rc = end(&d->state, t->argument);
    return rc < 0 ? rc : C89CBOR_TOKEN;
  }
  if (d->state.complete)
    return C89CBOR_DONE;
  if (f != NULL && !f->indefinite &&
      (f->type == C89CBOR_BYTES || f->type == C89CBOR_TEXT)) {
    if (!n)
      return C89CBOR_INPUT;
    take = n < d->state.chunk ? n : d->state.chunk;
    if ((uint64_t)take > f->remaining)
      take = (size_t)f->remaining;
    rc = data_take(&d->state, p, take);
    *consumed = take;
    if (rc < 0)
      return rc;
    t->type = C89CBOR_DATA;
    t->data = p;
    t->length = take;
    return C89CBOR_TOKEN;
  }
  if (!d->have) {
    if (!n)
      return C89CBOR_INPUT;
    d->header[0] = *p++;
    --n;
    ++*consumed;
    d->have = 1;
    extra = d->header[0] & 31U;
    d->need =
        extra < 24 || extra >= 28 ? 1 : (size_t)1 + ((size_t)1 << (extra - 24));
  }
  take = d->need - d->have;
  if (take > n)
    take = n;
  if (take)
    memcpy(d->header + d->have, p, take);
  d->have += take;
  *consumed += take;
  if (d->have != d->need)
    return C89CBOR_INPUT;
  rc = parse_header(d, t);
  d->have = d->need = 0;
  return rc < 0 ? rc : C89CBOR_TOKEN;
}
int c89cbor_decoder_finish(c89cbor_decoder *d) {
  if (d == NULL || d->state.frames == NULL)
    return C89CBOR_INVALID;
  if (d->state.failed)
    return d->state.failed;
  if (!d->state.complete || d->state.depth || d->have)
    return fail(&d->state, C89CBOR_MALFORMED);
  return C89CBOR_OK;
}
int c89cbor_decoder_reset(c89cbor_decoder *d) {
  if (d == NULL || d->state.failed || !d->state.complete || d->state.depth)
    return C89CBOR_INVALID;
  d->state.complete = 0;
  return C89CBOR_OK;
}
int c89cbor_encoder_put(c89cbor_encoder *e, const c89cbor_token *t) {
  c89cbor_frame *f;
  uint64_t value;
  size_t bytes = 0, i;
  unsigned int major;
  int rc, indefinite;
  if (e == NULL || t == NULL || e->state.frames == NULL)
    return C89CBOR_INVALID;
  if (e->state.failed)
    return e->state.failed;
  if (e->offset < e->size || e->remaining)
    return C89CBOR_OUTPUT;
  e->offset = e->size = 0;
  if (t->type == C89CBOR_DATA) {
    if (t->argument || t->indefinite)
      return fail(&e->state, C89CBOR_MALFORMED);
    rc = data_room(&e->state, t->data, t->length);
    if (rc < 0)
      return rc;
    e->data = t->data;
    e->remaining = t->length;
    return C89CBOR_OK;
  }
  if (t->type == C89CBOR_END) {
    if (t->data != NULL || t->length || t->indefinite)
      return fail(&e->state, C89CBOR_MALFORMED);
    f = top(&e->state);
    indefinite = f != NULL && f->indefinite;
    rc = end(&e->state, t->argument);
    if (rc < 0)
      return rc;
    if (indefinite) {
      e->header[0] = 255U;
      e->size = 1;
    }
    return C89CBOR_OK;
  }
  rc = begin(&e->state, t);
  if (rc < 0)
    return rc;
  value = t->argument;
  major = (unsigned int)t->type;
  if (t->type == C89CBOR_BOOL) {
    major = 7;
    value += 20;
  } else if (t->type == C89CBOR_NULL) {
    major = 7;
    value = 22;
  } else if (t->type == C89CBOR_UNDEFINED) {
    major = 7;
    value = 23;
  } else if (t->type == C89CBOR_SIMPLE)
    major = 7;
  else if (t->type >= C89CBOR_FLOAT16) {
    bytes = (size_t)2 << (t->type - C89CBOR_FLOAT16);
    e->header[0] = (unsigned char)(249 + t->type - C89CBOR_FLOAT16);
  }
  if (!bytes) {
    if (t->indefinite)
      e->header[0] = (unsigned char)((major << 5U) | 31U);
    else if (value < 24)
      e->header[0] = (unsigned char)((major << 5U) | (unsigned int)value);
    else {
      bytes = value <= 255          ? 1
              : value <= 65535      ? 2
              : value <= UINT32_MAX ? 4
                                    : 8;
      e->header[0] = (unsigned char)((major << 5U) | (bytes == 1   ? 24U
                                                      : bytes == 2 ? 25U
                                                      : bytes == 4 ? 26U
                                                                   : 27U));
    }
  }
  for (i = 0; i < bytes; ++i)
    e->header[bytes - i] = (unsigned char)(value >> (8U * i));
  e->size = bytes + 1;
  return C89CBOR_OK;
}
int c89cbor_encoder_read(c89cbor_encoder *e, void *out, size_t capacity,
                         size_t *written) {
  size_t take;
  int rc;
  if (written != NULL)
    *written = 0;
  if (e == NULL || written == NULL || (capacity && out == NULL) ||
      e->state.frames == NULL)
    return C89CBOR_INVALID;
  if (e->state.failed)
    return e->state.failed;
  if (capacity > e->state.chunk)
    capacity = e->state.chunk;
  if (e->offset < e->size) {
    take = e->size - e->offset;
    if (take > capacity)
      take = capacity;
    if (take)
      memcpy(out, e->header + e->offset, take);
    e->offset += take;
    *written = take;
  } else if (e->remaining) {
    take = e->remaining < capacity ? e->remaining : capacity;
    if (take) {
      rc = data_take(&e->state, e->data, take);
      if (rc < 0)
        return rc;
      memcpy(out, e->data, take);
      e->data += take;
      e->remaining -= take;
      *written = take;
    }
  }
  return e->offset < e->size || e->remaining ? C89CBOR_OUTPUT : C89CBOR_OK;
}
int c89cbor_encoder_finish(c89cbor_encoder *e) {
  if (e == NULL || e->state.frames == NULL)
    return C89CBOR_INVALID;
  if (e->state.failed)
    return e->state.failed;
  if (e->remaining || e->offset < e->size)
    return C89CBOR_OUTPUT;
  if (!e->state.complete || e->state.depth)
    return fail(&e->state, C89CBOR_MALFORMED);
  return C89CBOR_OK;
}
int c89cbor_encoder_reset(c89cbor_encoder *e) {
  if (e == NULL || e->state.failed || !e->state.complete || e->state.depth ||
      e->remaining || e->offset < e->size)
    return C89CBOR_INVALID;
  e->state.complete = 0;
  return C89CBOR_OK;
}
static int allocator_valid(const c89cbor_allocator *a) {
  return a == NULL || (a->alloc != NULL && a->free != NULL);
}
int c89cbor_decoder_create(const c89cbor_allocator *a, c89cbor_decoder **out) {
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  if (!allocator_valid(a))
    return C89CBOR_INVALID;
  *out =
      a == NULL ? malloc(sizeof(**out)) : a->alloc(a->context, sizeof(**out));
  if (*out == NULL)
    return C89CBOR_NOMEM;
  return c89cbor_decoder_init(*out, NULL, 0, 0);
}
int c89cbor_encoder_create(const c89cbor_allocator *a, c89cbor_encoder **out) {
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  if (!allocator_valid(a))
    return C89CBOR_INVALID;
  *out =
      a == NULL ? malloc(sizeof(**out)) : a->alloc(a->context, sizeof(**out));
  if (*out == NULL)
    return C89CBOR_NOMEM;
  return c89cbor_encoder_init(*out, NULL, 0, 0);
}
void c89cbor_decoder_destroy(c89cbor_decoder *d, const c89cbor_allocator *a) {
  if (d == NULL || !allocator_valid(a))
    return;
  if (a == NULL)
    free(d);
  else
    a->free(a->context, d);
}
void c89cbor_encoder_destroy(c89cbor_encoder *e, const c89cbor_allocator *a) {
  if (e == NULL || !allocator_valid(a))
    return;
  if (a == NULL)
    free(e);
  else
    a->free(a->context, e);
}
int c89cbor_float64_set(c89cbor_token *t, double value) {
  if (t == NULL || sizeof(value) != sizeof(uint64_t) || DBL_MANT_DIG != 53 ||
      DBL_MAX_EXP != 1024)
    return C89CBOR_INVALID;
  memset(t, 0, sizeof(*t));
  t->type = C89CBOR_FLOAT64;
  memcpy(&t->argument, &value, sizeof(value));
  return C89CBOR_OK;
}
int c89cbor_float64_get(const c89cbor_token *t, double *value) {
  if (t == NULL || value == NULL || t->type != C89CBOR_FLOAT64 ||
      t->indefinite || sizeof(*value) != sizeof(uint64_t) ||
      DBL_MANT_DIG != 53 || DBL_MAX_EXP != 1024)
    return C89CBOR_INVALID;
  memcpy(value, &t->argument, sizeof(*value));
  return C89CBOR_OK;
}
const char *c89cbor_version(void) { return C89CBOR_VERSION; }
const char *c89cbor_status_string(int status) {
  switch (status) {
  case C89CBOR_OK:
    return "success";
  case C89CBOR_TOKEN:
    return "token available";
  case C89CBOR_INPUT:
    return "more input required";
  case C89CBOR_OUTPUT:
    return "drain output";
  case C89CBOR_DONE:
    return "item complete";
  case C89CBOR_INVALID:
    return "invalid argument or operation order";
  case C89CBOR_MALFORMED:
    return "malformed or truncated CBOR";
  case C89CBOR_LIMIT:
    return "configured resource limit exceeded";
  case C89CBOR_NOMEM:
    return "allocation failed";
  case C89CBOR_IO:
    return "I/O failed";
  default:
    return "unknown status";
  }
}
