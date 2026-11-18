/* Grammar and bounded UTF-8 technique derived from cai/src/cai_cbor.c,
 * c89.systems, MIT; see docs/provenance.md. Pull I/O and full RFC types are
 * new. */
#include "internal.h"
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
static int value_room(c89cbor_state *s, c89cbor_type type, int indefinite) {
  c89cbor_frame *p = top(s);
  if (s->complete)
    return fail(s, C89CBOR_MALFORMED);
  if (p != NULL) {
    if (p->type == C89CBOR_BYTES || p->type == C89CBOR_TEXT) {
      if (!p->indefinite || type != p->type || indefinite)
        return fail(s, C89CBOR_MALFORMED);
    } else if (!p->indefinite && p->remaining == 0)
      return fail(s, C89CBOR_MALFORMED);
  }
  return C89CBOR_OK;
}
/* Parsed headers and mapped producers construct valid token fields. Share
 * their container checks with public put, whose caller-owned fields need
 * separate representation validation. */
static int accept_value(c89cbor_state *s, const c89cbor_token *t) {
  c89cbor_frame *f;
  if (value_room(s, t->type, t->indefinite) != 0)
    return s->failed;
  if (t->type >= C89CBOR_BYTES && t->type <= C89CBOR_TAG) {
    if (s->depth == s->capacity)
      return fail(s, C89CBOR_LIMIT);
    f = &s->frames[s->depth++];
    memset(f, 0, sizeof(*f));
    f->remaining = t->type == C89CBOR_TAG ? 1 : t->argument;
    f->type = t->type;
    f->indefinite = t->indefinite;
  } else {
    done(s);
  }
  return C89CBOR_OK;
}
static int begin(c89cbor_state *s, const c89cbor_token *t) {
  if (t->type < C89CBOR_UINT || t->type > C89CBOR_FLOAT64 || t->length != 0 ||
      t->data != NULL ||
      (t->indefinite && (t->type < C89CBOR_BYTES || t->type > C89CBOR_MAP)) ||
      (t->type == C89CBOR_BOOL && t->argument > 1) ||
      ((t->type == C89CBOR_NULL || t->type == C89CBOR_UNDEFINED) &&
       t->argument != 0) ||
      (t->type == C89CBOR_SIMPLE &&
       (t->argument > 255 || (t->argument >= 20 && t->argument < 32))) ||
      (t->type == C89CBOR_FLOAT16 && t->argument > 65535U) ||
      (t->type == C89CBOR_FLOAT32 && t->argument > UINT32_MAX))
    return fail(s, C89CBOR_MALFORMED);
  return accept_value(s, t);
}
/* Bounded unaligned loads; stop before the first non-ASCII byte. */
static size_t ascii_prefix(const unsigned char *data, size_t count) {
  size_t i = 0;
  while (count - i >= 4 * sizeof(uint64_t)) {
    uint64_t a, b, c, d;
    memcpy(&a, data + i, sizeof(a));
    memcpy(&b, data + i + sizeof(a), sizeof(b));
    memcpy(&c, data + i + 2 * sizeof(a), sizeof(c));
    memcpy(&d, data + i + 3 * sizeof(a), sizeof(d));
    if ((a | b | c | d) & UINT64_C(0x8080808080808080))
      break;
    i += 4 * sizeof(uint64_t);
  }
  while (count - i >= sizeof(uint64_t)) {
    uint64_t word;
    memcpy(&word, data + i, sizeof(word));
    if (word & UINT64_C(0x8080808080808080))
      break;
    i += sizeof(word);
  }
  while (i < count && data[i] < 128U)
    ++i;
  return i;
}
int c89_utf8(c89cbor_frame *f, const unsigned char *data, size_t count) {
  size_t i = 0;
  unsigned int pending = f->utf8, byte;
  uint32_t scalar, minimum;
  if (!pending && count != 0 && data[0] < 128U) {
    i = ascii_prefix(data, count);
    if (i == count)
      return 1;
  }
  scalar = f->scalar;
  minimum = f->minimum;
  while (i < count) {
    byte = data[i];
    if (!pending && byte < 128U) {
      i += ascii_prefix(data + i, count - i);
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
/* Consume a span already bounded to a live definite string frame. */
static int data_consume(c89cbor_state *s, c89cbor_frame *f, const void *data,
                        size_t n) {
  if (f->type == C89CBOR_TEXT &&
      (!c89_utf8(f, data, n) || ((uint64_t)n == f->remaining && f->utf8)))
    return fail(s, C89CBOR_MALFORMED);
  f->remaining -= (uint64_t)n;
  return C89CBOR_OK;
}
static int data_take(c89cbor_state *s, const void *data, size_t n) {
  if (data_room(s, data, n) < 0)
    return s->failed;
  return data_consume(s, top(s), data, n);
}
static void end_frame(c89cbor_state *s) {
  --s->depth;
  done(s);
}
static int end(c89cbor_state *s, uint64_t type) {
  c89cbor_frame *f = top(s);
  if (f == NULL || type != (uint64_t)f->type ||
      (!f->indefinite && f->remaining != 0) || f->utf8 ||
      (f->type == C89CBOR_MAP && f->odd))
    return fail(s, C89CBOR_MALFORMED);
  end_frame(s);
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
int c89cbor_decoder_init(c89cbor *runtime, c89cbor_decoder *d, c89cbor_frame *f,
                         size_t capacity, size_t chunk) {
  if (d == NULL)
    return C89CBOR_INVALID;
  /* Grammar frames initialize on begin, including caller-supplied frames.
   * Clearing unused embedded frames on every short operation is redundant. */
  memset(&d->state, 0, offsetof(c89cbor_state, local_frames));
  d->have = d->need = 0;
  d->next = c89cbor_decoder_next;
  d->next_tag = c89cbor_decoder_next_tag;
  d->finish = c89cbor_decoder_finish;
  d->reset = c89cbor_decoder_reset;
  d->cleanup = c89cbor_decoder_cleanup;
  d->destroy = c89cbor_decoder_destroy;
  d->diagnostic = c89cbor_decoder_diagnostic;
  {
    int status = c89_lifetime_init(&d->lifetime, runtime, NULL);
    if (status == 0)
      status = state_init(&d->state, f, capacity, chunk);
    if (status != 0) {
      d->state.frames = NULL;
      (void)c89_lifetime_cleanup(&d->lifetime);
    }
    return status;
  }
}
int c89cbor_encoder_init(c89cbor *runtime, c89cbor_encoder *e, c89cbor_frame *f,
                         size_t capacity, size_t chunk) {
  if (e == NULL)
    return C89CBOR_INVALID;
  memset(&e->state, 0, offsetof(c89cbor_state, local_frames));
  e->offset = e->size = e->remaining = e->validated = 0;
  e->data = NULL;
  e->put = c89cbor_encoder_put;
  e->tag = c89cbor_encoder_tag;
  e->end_tag = c89cbor_encoder_end_tag;
  e->read = c89cbor_encoder_read;
  e->peek = c89cbor_encoder_peek;
  e->advance = c89cbor_encoder_advance;
  e->finish = c89cbor_encoder_finish;
  e->reset = c89cbor_encoder_reset;
  e->cleanup = c89cbor_encoder_cleanup;
  e->destroy = c89cbor_encoder_destroy;
  e->diagnostic = c89cbor_encoder_diagnostic;
  {
    int status = c89_lifetime_init(&e->lifetime, runtime, NULL);
    if (status == 0)
      status = state_init(&e->state, f, capacity, chunk);
    if (status != 0) {
      e->state.frames = NULL;
      (void)c89_lifetime_cleanup(&e->lifetime);
    }
    return status;
  }
}
static uint64_t argument_bytes(const unsigned char *bytes, unsigned int extra) {
  if (extra == 24u)
    return bytes[0];
  if (extra == 25u)
    return ((uint64_t)bytes[0] << 8u) | bytes[1];
  if (extra == 26u)
    return ((uint64_t)bytes[0] << 24u) | ((uint64_t)bytes[1] << 16u) |
           ((uint64_t)bytes[2] << 8u) | bytes[3];
  if (extra == 27u)
    return ((uint64_t)bytes[0] << 56u) | ((uint64_t)bytes[1] << 48u) |
           ((uint64_t)bytes[2] << 40u) | ((uint64_t)bytes[3] << 32u) |
           ((uint64_t)bytes[4] << 24u) | ((uint64_t)bytes[5] << 16u) |
           ((uint64_t)bytes[6] << 8u) | bytes[7];
  return 0;
}
static int parse_header(c89cbor_decoder *d, const unsigned char *header,
                        c89cbor_token *t) {
  unsigned int major = header[0] >> 5U, extra = header[0] & 31U;
  c89cbor_frame *f;
  t->argument = extra < 24u ? extra : argument_bytes(header + 1, extra);
  if (header[0] == 255U) {
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
  return accept_value(&d->state, t);
}
static int decoder_next_work(c89cbor_decoder *d, const void *input, size_t n,
                             size_t *consumed, c89cbor_token *t) {
  const unsigned char *p = input;
  c89cbor_frame *f;
  size_t take, need;
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
    /* Reaching zero proves the frame's final DATA/child was accepted. UTF-8
     * completion and map parity were checked before decrementing remaining. */
    end_frame(&d->state);
    return C89CBOR_TOKEN;
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
    rc = data_consume(&d->state, f, p, take);
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
    extra = p[0] & 31u;
    need = extra < 24u || extra >= 28u
               ? 1u
               : (size_t)1u + ((size_t)1u << (extra - 24u));
    if (n >= need) {
      *consumed = need;
      rc = parse_header(d, p, t);
      return rc < 0 ? rc : C89CBOR_TOKEN;
    }
    d->header[0] = *p++;
    --n;
    ++*consumed;
    d->have = 1;
    d->need = need;
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
  rc = parse_header(d, d->header, t);
  d->have = d->need = 0;
  return rc < 0 ? rc : C89CBOR_TOKEN;
}

int c89cbor_decoder_next(c89cbor_decoder *d, const void *input, size_t length,
                         size_t *consumed, c89cbor_token *token) {
  int status = decoder_next_work(d, input, length, consumed, token);
  if (d != NULL && d->lifetime.magic == C89_LIFETIME_MAGIC) {
    if (consumed != NULL)
      d->lifetime.progress.input += (uint64_t)*consumed;
    if (status < 0)
      c89_error(&d->lifetime, status, "decoder");
  }
  return status;
}

/* The caller has a complete one-byte TEXT header and its bounded payload.
 * An exact match to a validated immutable schema key already proves UTF-8.
 * Unknown keys still receive full UTF-8 validation. INPUT consumes nothing. */
int c89_decoder_text(c89cbor_decoder *d, const unsigned char *text,
                     size_t length, size_t *consumed, int matched) {
  c89cbor_frame *parent = top(&d->state);
  c89cbor_frame frame;
  int status;
  *consumed = 0;
  if (d->have != 0 || d->state.failed ||
      (parent != NULL && !parent->indefinite && parent->remaining == 0))
    return C89CBOR_INPUT;
  status = value_room(&d->state, C89CBOR_TEXT, 0);
  if (status == 0 && d->state.depth == d->state.capacity)
    status = fail(&d->state, C89CBOR_LIMIT);
  *consumed = 1;
  if (status == 0) {
    *consumed += length;
    if (!matched) {
      memset(&frame, 0, sizeof(frame));
      if (!c89_utf8(&frame, text, length) || frame.utf8 != 0)
        status = fail(&d->state, C89CBOR_MALFORMED);
    }
  }
  if (status == 0)
    done(&d->state);
  d->lifetime.progress.input += (uint64_t)*consumed;
  return status == 0 ? C89CBOR_TOKEN
                     : c89_error(&d->lifetime, status, "decoder");
}
/* Drain a complete, already opened string from the caller's bounded input
 * chunk. Reuse the ordinary DATA and END grammar/UTF-8 checks. */
int c89_decoder_span(c89cbor_decoder *d, const void *input, size_t length) {
  c89cbor_frame *frame = top(&d->state);
  int status;
  if (frame == NULL || frame->remaining != (uint64_t)length)
    return C89CBOR_INVALID;
  status = data_take(&d->state, input, length);
  d->lifetime.progress.input += (uint64_t)length;
  if (status == 0)
    status = end(&d->state, frame->type);
  return status < 0 ? c89_error(&d->lifetime, status, "decoder") : status;
}
static int decoder_finish_work(c89cbor_decoder *d) {
  if (d == NULL || d->state.frames == NULL)
    return C89CBOR_INVALID;
  if (d->state.failed)
    return d->state.failed;
  if (!d->state.complete || d->state.depth || d->have)
    return fail(&d->state, C89CBOR_MALFORMED);
  return C89CBOR_OK;
}
int c89cbor_decoder_next_tag(c89cbor_decoder *d, const void *input,
                             size_t length, size_t *consumed,
                             uint64_t *number) {
  c89cbor_token token;
  int status;
  if (consumed != NULL)
    *consumed = 0;
  if (number != NULL)
    *number = 0;
  if (consumed == NULL || number == NULL)
    return C89CBOR_INVALID;
  status = c89cbor_decoder_next(d, input, length, consumed, &token);
  if (status != C89CBOR_TOKEN)
    return status;
  if (token.type != C89CBOR_TAG) {
    (void)fail(&d->state, C89CBOR_SCHEMA);
    return c89_error(&d->lifetime, C89CBOR_SCHEMA, "tag");
  }
  *number = token.argument;
  return C89CBOR_TOKEN;
}
int c89cbor_decoder_reset(c89cbor_decoder *d) {
  if (d == NULL || d->state.failed || !d->state.complete || d->state.depth)
    return C89CBOR_INVALID;
  d->state.complete = 0;
  return C89CBOR_OK;
}
static size_t encode_header(const c89cbor_token *t, unsigned char header[9]) {
  uint64_t value;
  size_t bytes = 0, i;
  unsigned int major;
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
    header[0] = (unsigned char)(249 + t->type - C89CBOR_FLOAT16);
  }
  if (!bytes) {
    if (t->indefinite)
      header[0] = (unsigned char)((major << 5U) | 31U);
    else if (value < 24)
      header[0] = (unsigned char)((major << 5U) | (unsigned int)value);
    else {
      bytes = value <= 255          ? 1
              : value <= 65535      ? 2
              : value <= UINT32_MAX ? 4
                                    : 8;
      header[0] = (unsigned char)((major << 5U) | (bytes == 1   ? 24U
                                                   : bytes == 2 ? 25U
                                                   : bytes == 4 ? 26U
                                                                : 27U));
    }
  }
#if defined(__GNUC__) && defined(__BYTE_ORDER__) &&                            \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  if (bytes == 8u) {
    uint64_t wire = __builtin_bswap64(value);
    memcpy(header + 1, &wire, sizeof(wire));
    return 9;
  }
#endif
  for (i = 0; i < bytes; ++i)
    header[bytes - i] = (unsigned char)(value >> (8U * i));
  return bytes + 1;
}
static int encoder_put_work(c89cbor_encoder *e, const c89cbor_token *t) {
  c89cbor_frame *f;
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
  e->size = encode_header(t, e->header);
  return C89CBOR_OK;
}
int c89cbor_encoder_peek(c89cbor_encoder *e, const void **bytes,
                         size_t *length) {
  size_t take;
  int status;
  if (bytes != NULL)
    *bytes = NULL;
  if (length != NULL)
    *length = 0;
  if (e == NULL || bytes == NULL || length == NULL || e->state.frames == NULL)
    return C89CBOR_INVALID;
  if (e->state.failed)
    return c89_error(&e->lifetime, e->state.failed, "encoder");
  if (e->offset < e->size) {
    take = e->size - e->offset;
    if (take > e->state.chunk)
      take = e->state.chunk;
    *bytes = e->header + e->offset;
    *length = take;
    return C89CBOR_OUTPUT;
  }
  if (e->remaining == 0)
    return C89CBOR_OK;
  if (e->validated == 0) {
    take = e->remaining < e->state.chunk ? e->remaining : e->state.chunk;
    /* put checked the complete DATA extent; remaining bounds each chunk. */
    status = data_consume(&e->state, top(&e->state), e->data, take);
    if (status != 0)
      return c89_error(&e->lifetime, status, "encoder");
    e->validated = take;
  }
  *bytes = e->data;
  *length = e->validated;
  return C89CBOR_OUTPUT;
}
int c89cbor_encoder_advance(c89cbor_encoder *e, size_t count) {
  size_t available;
  if (e == NULL || e->state.frames == NULL)
    return C89CBOR_INVALID;
  if (e->state.failed)
    return c89_error(&e->lifetime, e->state.failed, "encoder");
  if (e->offset < e->size) {
    available = e->size - e->offset;
    if (available > e->state.chunk)
      available = e->state.chunk;
    if (count > available)
      return C89CBOR_INVALID;
    e->offset += count;
  } else {
    if (count > e->validated)
      return C89CBOR_INVALID;
    if (count != 0)
      e->data += count;
    e->remaining -= count;
    e->validated -= count;
  }
  e->lifetime.progress.output += (uint64_t)count;
  return e->offset < e->size || e->remaining ? C89CBOR_OUTPUT : C89CBOR_OK;
}
int c89cbor_encoder_read(c89cbor_encoder *e, void *out, size_t capacity,
                         size_t *written) {
  const void *bytes;
  size_t length;
  int status;
  if (written != NULL)
    *written = 0;
  if (written == NULL || (capacity != 0 && out == NULL))
    return C89CBOR_INVALID;
  status = c89cbor_encoder_peek(e, &bytes, &length);
  if (status != C89CBOR_OUTPUT)
    return status;
  if (length > capacity)
    length = capacity;
  if (length != 0)
    memcpy(out, bytes, length);
  *written = length;
  return c89cbor_encoder_advance(e, length);
}
/* Mapped traversal already owns a bounded output chunk. Accept and drain
 * small tokens in one call; large DATA remains borrowed through peek/advance.
 */
int c89_encoder_buffer(c89cbor_encoder *e, const c89cbor_token *token,
                       unsigned char *output, size_t capacity,
                       size_t *written) {
  size_t length;
  int status;
  *written = 0;
  if (capacity >= 9u && token->type != C89CBOR_DATA &&
      token->type != C89CBOR_END) {
    if (e->state.failed)
      return e->state.failed;
    if (e->offset < e->size || e->remaining)
      return C89CBOR_OUTPUT;
    status = accept_value(&e->state, token);
    if (status != 0)
      return c89_error(&e->lifetime, status, "encoder");
    e->size = e->offset = 0;
    *written = encode_header(token, output);
    e->lifetime.progress.output += (uint64_t)*written;
    return C89CBOR_OK;
  }
  status = encoder_put_work(e, token);
  if (status != 0)
    return c89_error(&e->lifetime, status, "encoder");
  if (e->size != 0) {
    if (e->size > capacity)
      return C89CBOR_OK;
    memcpy(output, e->header, e->size);
    *written = e->offset = e->size;
  } else if (e->remaining != 0) {
    length = e->remaining < e->state.chunk ? e->remaining : e->state.chunk;
    if (length > capacity ||
        (length >= e->state.chunk / 2u && capacity == e->state.chunk))
      return C89CBOR_OK;
    status = data_take(&e->state, e->data, length);
    if (status != 0)
      return c89_error(&e->lifetime, status, "encoder");
    memcpy(output, e->data, length);
    e->data += length;
    e->remaining -= length;
    *written = length;
  }
  e->lifetime.progress.output += (uint64_t)*written;
  return C89CBOR_OK;
}
/* Fuse a complete small text span, preserving the same grammar and UTF-8
 * validation as TEXT/DATA/END. The caller reserves the maximum header size. */
static int buffer_text(c89cbor_encoder *e, const void *text, size_t length,
                       unsigned char *output, size_t capacity, size_t *written,
                       int validate) {
  c89cbor_token token;
  c89cbor_frame frame;
  int status;
  *written = 0;
  if (capacity < 9u || length > capacity - 9u)
    return C89CBOR_OUTPUT;
  if (e->state.failed)
    return e->state.failed;
  if (e->offset < e->size || e->remaining)
    return C89CBOR_OUTPUT;
  status = value_room(&e->state, C89CBOR_TEXT, 0);
  if (status == 0 && e->state.depth == e->state.capacity)
    status = fail(&e->state, C89CBOR_LIMIT);
  if (status == 0 && validate) {
    memset(&frame, 0, sizeof(frame));
    if ((length != 0 && text == NULL) || !c89_utf8(&frame, text, length) ||
        frame.utf8 != 0)
      status = fail(&e->state, C89CBOR_MALFORMED);
  }
  if (status != 0)
    return c89_error(&e->lifetime, status, "encoder");
  e->size = e->offset = 0;
  if (length < 24u) {
    output[0] = (unsigned char)(0x60u | (unsigned int)length);
    *written = 1;
  } else {
    memset(&token, 0, sizeof(token));
    token.type = C89CBOR_TEXT;
    token.argument = (uint64_t)length;
    *written = encode_header(&token, output);
  }
  if (length != 0)
    memcpy(output + *written, text, length);
  *written += length;
  done(&e->state);
  e->lifetime.progress.output += (uint64_t)*written;
  return C89CBOR_OK;
}
int c89_encoder_buffer_text(c89cbor_encoder *e, const void *text, size_t length,
                            unsigned char *output, size_t capacity,
                            size_t *written) {
  return buffer_text(e, text, length, output, capacity, written, 1);
}
int c89_encoder_buffer_key(c89cbor_encoder *e, const lonejson_field *field,
                           unsigned char *output, size_t capacity,
                           size_t *written) {
  /* Schema keys have already passed validation and remain immutable for the
   * operation. Text values continue through per-value UTF-8 validation. */
  return buffer_text(e, field->json_key, field->json_key_len, output, capacity,
                     written, 0);
}
/* A validated schema key and one native scalar fit in the current bounded
 * chunk. Check the map slot once and accept the complete pair atomically.
 * Caller-owned tokens still enter through public put's full validation. */
int c89_encoder_buffer_pair(c89cbor_encoder *e, const lonejson_field *field,
                            const c89cbor_token *value, unsigned char *output,
                            size_t capacity, size_t *written) {
  c89cbor_frame *parent = top(&e->state);
  c89cbor_token key;
  size_t used;
  *written = 0;
  if (capacity < 18u || field->json_key_len > capacity - 18u ||
      e->offset < e->size || e->remaining != 0)
    return C89CBOR_OUTPUT;
  if (e->state.failed)
    return e->state.failed;
  if (parent == NULL || parent->type != C89CBOR_MAP || parent->odd ||
      (!parent->indefinite && parent->remaining == 0))
    return fail(&e->state, C89CBOR_MALFORMED);
  if (e->state.depth == e->state.capacity)
    return fail(&e->state, C89CBOR_LIMIT);
  if (field->json_key_len < 24u) {
    output[0] = (unsigned char)(0x60u | (unsigned int)field->json_key_len);
    used = 1;
  } else {
    memset(&key, 0, sizeof(key));
    key.type = C89CBOR_TEXT;
    key.argument = (uint64_t)field->json_key_len;
    used = encode_header(&key, output);
  }
  if (field->json_key_len != 0)
    memcpy(output + used, field->json_key, field->json_key_len);
  used += field->json_key_len;
  used += encode_header(value, output + used);
  if (!parent->indefinite)
    --parent->remaining;
  e->size = e->offset = 0;
  e->lifetime.progress.output += (uint64_t)used;
  *written = used;
  return C89CBOR_OK;
}
static int encoder_finish_work(c89cbor_encoder *e) {
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
int c89cbor_decoder_create(c89cbor *runtime, const c89cbor_allocator *allocator,
                           c89cbor_decoder **out) {
  c89cbor_allocator selected;
  void *storage;
  int status;
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, allocator, sizeof(**out), &storage, &selected);
  if (status != 0)
    return status;
  status = c89cbor_decoder_init(runtime, storage, NULL, 0, 0);
  if (status != 0) {
    selected.free(selected.context, storage);
    return status;
  }
  *out = storage;
  (*out)->lifetime.allocator = selected;
  (*out)->lifetime.owned = 1;
  return C89CBOR_OK;
}
int c89cbor_decoder_cleanup(c89cbor_decoder *value) {
  int status;
  if (value == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&value->lifetime);
  if (status == 0) {
    value->state.frames = NULL;
  }
  return status;
}
int c89cbor_decoder_destroy(c89cbor_decoder *value) {
  return value == NULL ? C89CBOR_OK
                       : c89_lifetime_destroy(&value->lifetime, value);
}
int c89cbor_decoder_diagnostic(const c89cbor_decoder *value,
                               c89cbor_error *error) {
  return c89_lifetime_diagnostic(value == NULL ? NULL : &value->lifetime,
                                 error);
}
int c89cbor_encoder_create(c89cbor *runtime, const c89cbor_allocator *allocator,
                           c89cbor_encoder **out) {
  c89cbor_allocator selected;
  void *storage;
  int status;
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, allocator, sizeof(**out), &storage, &selected);
  if (status != 0)
    return status;
  status = c89cbor_encoder_init(runtime, storage, NULL, 0, 0);
  if (status != 0) {
    selected.free(selected.context, storage);
    return status;
  }
  *out = storage;
  (*out)->lifetime.allocator = selected;
  (*out)->lifetime.owned = 1;
  return C89CBOR_OK;
}
int c89cbor_encoder_cleanup(c89cbor_encoder *value) {
  int status;
  if (value == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&value->lifetime);
  if (status == 0) {
    value->state.frames = NULL;
    value->data = NULL;
    value->remaining = value->validated = 0;
  }
  return status;
}
int c89cbor_encoder_destroy(c89cbor_encoder *value) {
  return value == NULL ? C89CBOR_OK
                       : c89_lifetime_destroy(&value->lifetime, value);
}
int c89cbor_encoder_diagnostic(const c89cbor_encoder *value,
                               c89cbor_error *error) {
  return c89_lifetime_diagnostic(value == NULL ? NULL : &value->lifetime,
                                 error);
}
int c89cbor_float64_set(c89cbor *runtime, c89cbor_token *t, double value) {
  (void)runtime;
  if (t == NULL || sizeof(value) != sizeof(uint64_t) || DBL_MANT_DIG != 53 ||
      DBL_MAX_EXP != 1024)
    return C89CBOR_INVALID;
  memset(t, 0, sizeof(*t));
  t->type = C89CBOR_FLOAT64;
  memcpy(&t->argument, &value, sizeof(value));
  return C89CBOR_OK;
}
int c89cbor_float64_get(c89cbor *runtime, const c89cbor_token *t,
                        double *value) {
  (void)runtime;
  if (t == NULL || value == NULL || t->type != C89CBOR_FLOAT64 ||
      t->indefinite || sizeof(*value) != sizeof(uint64_t) ||
      DBL_MANT_DIG != 53 || DBL_MAX_EXP != 1024)
    return C89CBOR_INVALID;
  memcpy(value, &t->argument, sizeof(*value));
  return C89CBOR_OK;
}
const char *c89cbor_version(c89cbor *runtime) {
  (void)runtime;
  return C89CBOR_VERSION;
}
const char *c89cbor_status_string(c89cbor *runtime, int status) {
  (void)runtime;
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
  case C89CBOR_BUSY:
    return "receiver is busy";
  case C89CBOR_UNSUPPORTED:
    return "unsupported conversion";
  case C89CBOR_SCHEMA:
    return "mapped schema violation";
  case C89CBOR_AUTH:
    return "authentication failed";
  case C89CBOR_CRYPTO:
    return "cryptographic backend failed";
  case C89CBOR_IO:
    return "I/O failed";
  default:
    return "unknown status";
  }
}

int c89cbor_decoder_finish(c89cbor_decoder *value) {
  int status = decoder_finish_work(value);
  if (status < 0 && value != NULL &&
      value->lifetime.magic == C89_LIFETIME_MAGIC) {
    c89_error(&value->lifetime, status, "decoder");
  }
  return status;
}

int c89cbor_encoder_put(c89cbor_encoder *value, const c89cbor_token *token) {
  int status = encoder_put_work(value, token);
  if (status < 0 && value != NULL &&
      value->lifetime.magic == C89_LIFETIME_MAGIC) {
    c89_error(&value->lifetime, status, "encoder");
  }
  return status;
}
int c89cbor_encoder_tag(c89cbor_encoder *encoder, uint64_t number) {
  c89cbor_token token;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_TAG;
  token.argument = number;
  return c89cbor_encoder_put(encoder, &token);
}
int c89cbor_encoder_end_tag(c89cbor_encoder *encoder) {
  c89cbor_token token;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_END;
  token.argument = C89CBOR_TAG;
  return c89cbor_encoder_put(encoder, &token);
}

int c89cbor_encoder_finish(c89cbor_encoder *value) {
  int status = encoder_finish_work(value);
  if (status < 0 && value != NULL &&
      value->lifetime.magic == C89_LIFETIME_MAGIC) {
    c89_error(&value->lifetime, status, "encoder");
  }
  return status;
}
