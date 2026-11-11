#include "internal.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int c89cbor_reader_init(c89cbor *runtime, c89cbor_reader *r,
                        c89cbor_framing framing, uint32_t limit) {
  if (r == NULL)
    return C89CBOR_INVALID;
  memset(r, 0, sizeof(*r));
  r->next = c89cbor_reader_next;
  r->finish = c89cbor_reader_finish;
  r->reset = c89cbor_reader_reset;
  r->cleanup = c89cbor_reader_cleanup;
  r->destroy = c89cbor_reader_destroy;
  r->diagnostic = c89cbor_reader_diagnostic;
  {
    int status = c89_lifetime_init(&r->lifetime, runtime, NULL);
    if (status != 0)
      return status;
  }
  if (framing < C89CBOR_SINGLE || framing > C89CBOR_LENGTH32) {
    (void)c89_lifetime_cleanup(&r->lifetime);
    return C89CBOR_INVALID;
  }
  r->framing = framing;
  r->limit = limit == 0 ? 128U * 1024U : limit;
  return c89cbor_decoder_init(NULL, &r->decoder, NULL, 0, 0);
}
static int reader_next_work(c89cbor_reader *r, const void *input, size_t length,
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
static int reader_finish_work(c89cbor_reader *r) {
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
int c89cbor_length32(c89cbor *runtime, uint32_t length, uint32_t limit,
                     unsigned char out[4]) {
  (void)runtime;
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
int c89cbor_transfer_init(c89cbor *runtime, c89cbor_transfer *t,
                          const c89cbor_source *source,
                          const c89cbor_sink *sink, c89cbor_framing framing,
                          uint32_t limit) {
  if (t == NULL)
    return C89CBOR_INVALID;
  memset(t, 0, sizeof(*t));
  t->step = c89cbor_transfer_step;
  t->progress = c89cbor_transfer_progress;
  t->cleanup = c89cbor_transfer_cleanup;
  t->destroy = c89cbor_transfer_destroy;
  t->diagnostic = c89cbor_transfer_diagnostic;
  {
    int status = c89_lifetime_init(&t->lifetime, runtime, NULL);
    if (status != 0)
      return status;
  }
  if (source == NULL || sink == NULL || source->read == NULL ||
      sink->write == NULL || framing < C89CBOR_SINGLE ||
      framing > C89CBOR_LENGTH32) {
    (void)c89_lifetime_cleanup(&t->lifetime);
    return C89CBOR_INVALID;
  }
  t->source = *source;
  t->sink = *sink;
  t->input_budget = runtime == NULL ? C89CBOR_CHUNK : runtime->step_input;
  t->output_budget = runtime == NULL ? C89CBOR_CHUNK : runtime->step_output;
  t->event_budget = runtime == NULL ? 256 : runtime->step_events;
  return c89cbor_reader_init(NULL, &t->reader, framing, limit);
}
static int transfer_work(c89cbor_transfer *t) {
  size_t n = 0, used, offered, events = 0;
  c89cbor_event event;
  int rc;
  if (t->finished)
    return C89CBOR_DONE;
  if (t->offset == t->length) {
    offered = sizeof(t->buffer);
    if (offered > t->input_budget)
      offered = t->input_budget;
    rc = t->source.read(t->source.context, t->buffer, offered, &n);
    if (n > offered || ((rc == C89CBOR_INPUT || rc > C89CBOR_INPUT) && n))
      return C89CBOR_IO;
    t->read_bytes += (uint64_t)n;
    if (rc == C89CBOR_INPUT || rc < 0)
      return rc;
    if (rc != 0)
      return C89CBOR_IO;
    if (n == 0) {
      rc = c89cbor_reader_finish(&t->reader);
      if (rc < 0)
        return rc;
      t->finished = 1;
      return C89CBOR_DONE;
    }
    t->offset = 0;
    t->length = n;
    t->validation_offset = 0;
    t->validated = 0;
  }
  while (!t->validated && events < t->event_budget) {
    rc = c89cbor_reader_next(&t->reader, t->buffer + t->validation_offset,
                             t->length - t->validation_offset, &used, &event);
    t->validation_offset += used;
    ++events;
    if (rc < 0)
      return rc;
    if (rc != C89CBOR_TOKEN) {
      if (t->validation_offset != t->length)
        return C89CBOR_MALFORMED;
      t->validated = 1;
    }
  }
  if (!t->validated)
    return C89CBOR_OK;
  offered = t->length - t->offset;
  if (offered > t->output_budget)
    offered = t->output_budget;
  rc = t->sink.write(t->sink.context, t->buffer + t->offset, offered, &n);
  if (n > offered)
    return C89CBOR_IO;
  t->offset += n;
  t->written_bytes += (uint64_t)n;
  if (rc == C89CBOR_OUTPUT || rc < 0)
    return rc;
  if (rc != 0 || n == 0)
    return C89CBOR_IO;
  return C89CBOR_OK;
}
int c89cbor_transfer_step(c89cbor_transfer *t) {
  int rc;
  if (t == NULL || t->source.read == NULL || t->sink.write == NULL)
    return C89CBOR_INVALID;
  if (t->failed)
    return t->failed;
  if (t->busy)
    return C89CBOR_BUSY;
  t->busy = 1;
  t->lifetime.busy = 1;
  rc = transfer_work(t);
  t->busy = 0;
  t->lifetime.busy = 0;
  t->lifetime.progress.input = t->read_bytes;
  t->lifetime.progress.output = t->written_bytes;
  t->lifetime.progress.records = t->reader.lifetime.progress.records;
  if (rc < 0)
    t->failed = rc;
  return c89_error(&t->lifetime, rc, "transfer");
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
int c89cbor_fd_init(c89cbor *runtime, c89cbor_fd *fd, int descriptor,
                    c89cbor_source *source, c89cbor_sink *sink) {
  if (fd == NULL)
    return C89CBOR_INVALID;
  memset(fd, 0, sizeof(*fd));
  fd->source = c89cbor_fd_source;
  fd->sink = c89cbor_fd_sink;
  fd->cleanup = c89cbor_fd_cleanup;
  fd->destroy = c89cbor_fd_destroy;
  fd->diagnostic = c89cbor_fd_diagnostic;
  {
    int status = c89_lifetime_init(&fd->lifetime, runtime, NULL);
    if (status != 0)
      return status;
  }
  if (descriptor < 0 || (source == NULL && sink == NULL)) {
    (void)c89_lifetime_cleanup(&fd->lifetime);
    fd->descriptor = -1;
    return C89CBOR_INVALID;
  }
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

int c89cbor_reader_reset(c89cbor_reader *reader) {
  int status = c89cbor_reader_finish(reader);
  if (status != 0)
    return C89CBOR_INVALID;
  reader->complete = 0;
  reader->lifetime.progress.records = 0;
  return C89CBOR_OK;
}
int c89cbor_transfer_progress(const c89cbor_transfer *value,
                              c89cbor_progress *out) {
  if (out != NULL)
    memset(out, 0, sizeof(*out));
  if (value == NULL || out == NULL ||
      value->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  *out = value->lifetime.progress;
  return C89CBOR_OK;
}
int c89cbor_fd_source(c89cbor_fd *fd, c89cbor_source *source) {
  if (source != NULL)
    memset(source, 0, sizeof(*source));
  if (fd == NULL || source == NULL || !fd->lifetime.live)
    return C89CBOR_INVALID;
  source->context = fd;
  source->read = fd_read;
  return C89CBOR_OK;
}
int c89cbor_fd_sink(c89cbor_fd *fd, c89cbor_sink *sink) {
  if (sink != NULL)
    memset(sink, 0, sizeof(*sink));
  if (fd == NULL || sink == NULL || !fd->lifetime.live)
    return C89CBOR_INVALID;
  sink->context = fd;
  sink->write = fd_write;
  return C89CBOR_OK;
}

int c89cbor_reader_cleanup(c89cbor_reader *value) {
  int status;
  if (value == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&value->lifetime);
  if (status == 0) {
    value->decoder.state.frames = NULL;
  }
  return status;
}
int c89cbor_reader_destroy(c89cbor_reader *value) {
  return value == NULL ? C89CBOR_OK
                       : c89_lifetime_destroy(&value->lifetime, value);
}
int c89cbor_reader_diagnostic(const c89cbor_reader *value,
                              c89cbor_error *error) {
  return c89_lifetime_diagnostic(value == NULL ? NULL : &value->lifetime,
                                 error);
}

int c89cbor_transfer_cleanup(c89cbor_transfer *value) {
  int status;
  if (value == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&value->lifetime);
  if (status == 0) {
    value->source.read = NULL;
    value->sink.write = NULL;
  }
  return status;
}
int c89cbor_transfer_destroy(c89cbor_transfer *value) {
  return value == NULL ? C89CBOR_OK
                       : c89_lifetime_destroy(&value->lifetime, value);
}
int c89cbor_transfer_diagnostic(const c89cbor_transfer *value,
                                c89cbor_error *error) {
  return c89_lifetime_diagnostic(value == NULL ? NULL : &value->lifetime,
                                 error);
}

int c89cbor_fd_cleanup(c89cbor_fd *value) {
  int status;
  if (value == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&value->lifetime);
  if (status == 0) {
    value->descriptor = -1;
  }
  return status;
}
int c89cbor_fd_destroy(c89cbor_fd *value) {
  return value == NULL ? C89CBOR_OK
                       : c89_lifetime_destroy(&value->lifetime, value);
}
int c89cbor_fd_diagnostic(const c89cbor_fd *value, c89cbor_error *error) {
  return c89_lifetime_diagnostic(value == NULL ? NULL : &value->lifetime,
                                 error);
}

int c89cbor_reader_create(c89cbor *runtime, c89cbor_framing framing,
                          uint32_t limit, c89cbor_reader **out) {
  c89cbor_allocator allocator;
  void *storage;
  int status;
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(**out), &storage, &allocator);
  if (status != 0)
    return status;
  status = c89cbor_reader_init(runtime, storage, framing, limit);
  if (status != 0) {
    (void)c89cbor_reader_cleanup(storage);
    allocator.free(allocator.context, storage);
    return status;
  }
  *out = storage;
  (*out)->lifetime.owned = 1;
  return C89CBOR_OK;
}

int c89cbor_transfer_create(c89cbor *runtime, const c89cbor_source *source,
                            const c89cbor_sink *sink, c89cbor_framing framing,
                            uint32_t limit, c89cbor_transfer **out) {
  c89cbor_allocator allocator;
  void *storage;
  int status;
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(**out), &storage, &allocator);
  if (status != 0)
    return status;
  status =
      c89cbor_transfer_init(runtime, storage, source, sink, framing, limit);
  if (status != 0) {
    (void)c89cbor_transfer_cleanup(storage);
    allocator.free(allocator.context, storage);
    return status;
  }
  *out = storage;
  (*out)->lifetime.owned = 1;
  return C89CBOR_OK;
}

int c89cbor_fd_create(c89cbor *runtime, int descriptor, c89cbor_fd **out) {
  c89cbor_allocator allocator;
  c89cbor_source source;
  void *storage;
  int status;
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(runtime, NULL, sizeof(**out), &storage, &allocator);
  if (status != 0)
    return status;
  status = c89cbor_fd_init(runtime, storage, descriptor, &source, NULL);
  if (status != 0) {
    (void)c89cbor_fd_cleanup(storage);
    allocator.free(allocator.context, storage);
    return status;
  }
  *out = storage;
  (*out)->lifetime.owned = 1;
  return C89CBOR_OK;
}

int c89cbor_reader_next(c89cbor_reader *value, const void *input, size_t length,
                        size_t *consumed, c89cbor_event *event) {
  int status = reader_next_work(value, input, length, consumed, event);
  if (value != NULL && value->lifetime.magic == C89_LIFETIME_MAGIC) {
    if (consumed != NULL)
      value->lifetime.progress.input += (uint64_t)*consumed;
    if (status == C89CBOR_TOKEN && event->type == C89CBOR_RECORD_END)
      ++value->lifetime.progress.records;
    c89_error(&value->lifetime, status, "reader");
  }
  return status;
}

int c89cbor_reader_finish(c89cbor_reader *value) {
  int status = reader_finish_work(value);
  if (value != NULL && value->lifetime.magic == C89_LIFETIME_MAGIC) {
    c89_error(&value->lifetime, status, "reader");
  }
  return status;
}
