#include <c89cbor/io.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int c89cbor_reader_init(c89cbor_reader *r, c89cbor_framing framing,
                        uint32_t limit) {
  if (r == NULL || framing < C89CBOR_SINGLE || framing > C89CBOR_LENGTH32)
    return C89CBOR_INVALID;
  memset(r, 0, sizeof(*r));
  r->framing = framing;
  r->limit = limit == 0 ? 128U * 1024U : limit;
  return c89cbor_decoder_init(&r->decoder, NULL, 0, 0);
}
int c89cbor_reader_next(c89cbor_reader *r, const void *input, size_t length,
                        size_t *consumed, c89cbor_event *event) {
  const unsigned char *p = input;
  size_t used = 0, take;
  int rc;
  if (consumed != NULL)
    *consumed = 0;
  if (r == NULL || consumed == NULL || event == NULL ||
      (length && input == NULL) || r->decoder.state.frames == NULL)
    return C89CBOR_INVALID;
  if (r->failed)
    return r->failed;
  memset(event, 0, sizeof(*event));
  if (r->complete && r->framing == C89CBOR_SINGLE)
    return C89CBOR_DONE;
  if (!r->active) {
    if (r->framing == C89CBOR_LENGTH32) {
      while (r->have < 4 && length) {
        r->length = (r->length << 8U) | *p++;
        ++r->have;
        --length;
        ++*consumed;
      }
      if (r->have != 4)
        return C89CBOR_INPUT;
      if (r->length == 0 || r->length > r->limit) {
        r->failed = C89CBOR_LIMIT;
        return r->failed;
      }
      r->remaining = r->length;
    } else if (!length)
      return C89CBOR_INPUT;
    r->active = 1;
    event->type = C89CBOR_RECORD_BEGIN;
    event->length = r->length;
    return C89CBOR_TOKEN;
  }
  take = length;
  if (r->framing == C89CBOR_LENGTH32 && take > r->remaining)
    take = r->remaining;
  rc = c89cbor_decoder_next(&r->decoder, input, take, &used, &event->token);
  *consumed = used;
  if (r->framing == C89CBOR_LENGTH32)
    r->remaining -= (uint32_t)used;
  event->length = r->length;
  if (rc == C89CBOR_DONE) {
    if (r->framing == C89CBOR_LENGTH32 && r->remaining != 0)
      rc = C89CBOR_MALFORMED;
    else {
      event->type = C89CBOR_RECORD_END;
      r->active = 0;
      r->complete = 1;
      r->have = 0;
      r->length = 0;
      rc = c89cbor_decoder_reset(&r->decoder);
      return rc == 0 ? C89CBOR_TOKEN : rc;
    }
  } else if (rc == C89CBOR_TOKEN)
    event->type = C89CBOR_RECORD_TOKEN;
  else if (rc == C89CBOR_INPUT && r->framing == C89CBOR_LENGTH32 &&
           r->remaining == 0)
    rc = C89CBOR_MALFORMED;
  if (rc < 0)
    r->failed = rc;
  return rc;
}
int c89cbor_reader_finish(c89cbor_reader *r) {
  if (r == NULL || r->decoder.state.frames == NULL)
    return C89CBOR_INVALID;
  if (r->failed)
    return r->failed;
  if (r->active || r->have || (r->framing == C89CBOR_SINGLE && !r->complete)) {
    r->failed = C89CBOR_MALFORMED;
    return r->failed;
  }
  return C89CBOR_OK;
}
int c89cbor_length32(uint32_t length, uint32_t limit, unsigned char out[4]) {
  if (out == NULL)
    return C89CBOR_INVALID;
  if (limit == 0)
    limit = 128U * 1024U;
  if (length == 0 || length > limit)
    return C89CBOR_LIMIT;
  out[0] = (unsigned char)(length >> 24U);
  out[1] = (unsigned char)(length >> 16U);
  out[2] = (unsigned char)(length >> 8U);
  out[3] = (unsigned char)length;
  return C89CBOR_OK;
}
int c89cbor_transfer_init(c89cbor_transfer *t, const c89cbor_source *source,
                          const c89cbor_sink *sink, c89cbor_framing framing,
                          uint32_t limit) {
  if (t == NULL || source == NULL || sink == NULL || source->read == NULL ||
      sink->write == NULL)
    return C89CBOR_INVALID;
  memset(t, 0, sizeof(*t));
  t->source = *source;
  t->sink = *sink;
  return c89cbor_reader_init(&t->reader, framing, limit);
}
static int transfer_work(c89cbor_transfer *t) {
  size_t n = 0, at, used;
  c89cbor_event event;
  int rc;
  if (t->finished)
    return C89CBOR_DONE;
  if (t->offset == t->length) {
    rc = t->source.read(t->source.context, t->buffer, sizeof(t->buffer), &n);
    if (t->failed)
      return t->failed;
    if (n > sizeof(t->buffer) || (rc != 0 && n))
      return C89CBOR_INVALID;
    if (rc == C89CBOR_INPUT || rc < 0)
      return rc;
    if (rc != 0)
      return C89CBOR_INVALID;
    if (n == 0) {
      rc = c89cbor_reader_finish(&t->reader);
      if (rc < 0)
        return rc;
      t->finished = 1;
      return C89CBOR_DONE;
    }
    t->read_bytes += (uint64_t)n;
    at = 0;
    do {
      rc = c89cbor_reader_next(&t->reader, t->buffer + at, n - at, &used,
                               &event);
      at += used;
      if (rc < 0)
        return rc;
      if (rc == C89CBOR_DONE && at != n)
        return C89CBOR_MALFORMED;
    } while (rc == C89CBOR_TOKEN);
    if (at != n)
      return C89CBOR_MALFORMED;
    t->offset = 0;
    t->length = n;
  }
  n = 0;
  rc = t->sink.write(t->sink.context, t->buffer + t->offset,
                     t->length - t->offset, &n);
  if (t->failed)
    return t->failed;
  if (n > t->length - t->offset || (rc != 0 && rc != C89CBOR_OUTPUT))
    return rc < 0 ? rc : C89CBOR_INVALID;
  t->offset += n;
  t->written_bytes += (uint64_t)n;
  if (rc == C89CBOR_OUTPUT)
    return rc;
  return n == 0 ? C89CBOR_IO : C89CBOR_OK;
}
int c89cbor_transfer_step(c89cbor_transfer *t) {
  int rc;
  if (t == NULL || t->source.read == NULL || t->sink.write == NULL)
    return C89CBOR_INVALID;
  if (t->failed)
    return t->failed;
  if (t->busy) {
    t->failed = C89CBOR_INVALID;
    return t->failed;
  }
  t->busy = 1;
  rc = transfer_work(t);
  t->busy = 0;
  if (rc < 0)
    t->failed = rc;
  return rc;
}
static int fd_read(void *context, void *buffer, size_t capacity,
                   size_t *count) {
  c89cbor_fd *fd = context;
  ssize_t n;
  *count = 0;
  do {
    n = read(fd->descriptor, buffer, capacity);
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? C89CBOR_INPUT : C89CBOR_IO;
  *count = (size_t)n;
  return C89CBOR_OK;
}
static int fd_write(void *context, const void *bytes, size_t length,
                    size_t *count) {
  c89cbor_fd *fd = context;
  ssize_t n;
  *count = 0;
  do {
#ifdef MSG_NOSIGNAL
    n = send(fd->descriptor, bytes, length, MSG_NOSIGNAL);
    if (n < 0 && errno == ENOTSOCK)
      n = write(fd->descriptor, bytes, length);
#else
    n = write(fd->descriptor, bytes, length);
#endif
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? C89CBOR_OUTPUT
                                                   : C89CBOR_IO;
  *count = (size_t)n;
  return C89CBOR_OK;
}
int c89cbor_fd_init(c89cbor_fd *fd, int descriptor, c89cbor_source *source,
                    c89cbor_sink *sink) {
  if (fd == NULL || descriptor < 0 || (source == NULL && sink == NULL))
    return C89CBOR_INVALID;
  fd->descriptor = descriptor;
  if (source != NULL) {
    source->context = fd;
    source->read = fd_read;
  }
  if (sink != NULL) {
    sink->context = fd;
    sink->write = fd_write;
  }
  return C89CBOR_OK;
}
