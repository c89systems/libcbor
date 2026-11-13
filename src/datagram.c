#include "internal.h"
#include <c89cbor/datagram.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

typedef struct datagram_state {
  int descriptor, have_input, pending, failed;
  size_t capacity, input_length, input_offset, output_length;
  unsigned char *input, *output;
  struct sockaddr_storage peer, destination;
  socklen_t peer_length, destination_length;
  c89cbor_decoder decoder;
  c89cbor_datagram_counts counts;
} datagram_state;
static int live(const c89cbor_datagram *self) {
  return self != NULL && self->lifetime.magic == C89_LIFETIME_MAGIC &&
         self->lifetime.live && self->state != NULL;
}
static int begin(c89cbor_datagram *self) {
  if (!live(self))
    return C89CBOR_INVALID;
  if (self->lifetime.busy)
    return C89CBOR_BUSY;
  self->lifetime.busy = 1;
  memset(&self->lifetime.error, 0, sizeof(self->lifetime.error));
  return C89CBOR_OK;
}
static int finish(c89cbor_datagram *self, int status, int system_error,
                  c89cbor_error *error) {
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (live(self) && self->lifetime.busy) {
    if (status < 0) {
      self->lifetime.error.status = status;
      self->lifetime.error.system_errno = system_error;
      strcpy(self->lifetime.error.layer, "datagram");
      strncpy(self->lifetime.error.message, c89cbor_status_string(NULL, status),
              sizeof(self->lifetime.error.message) - 1u);
    }
    if (error != NULL)
      *error = self->lifetime.error;
    self->lifetime.busy = 0;
  } else if (error != NULL)
    error->status = status;
  if (system_error != 0)
    errno = system_error;
  return status;
}
static int validate(const void *bytes, size_t length) {
  c89cbor_decoder decoder;
  c89cbor_token token;
  size_t offset = 0, used;
  int status;
  if (length == 0)
    return C89CBOR_MALFORMED;
  status = c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0);
  if (status != 0)
    return status;
  do {
    status = decoder.next(&decoder, (const unsigned char *)bytes + offset,
                          length - offset, &used, &token);
    offset += used;
  } while (status == C89CBOR_TOKEN);
  if (status == C89CBOR_DONE && offset == length)
    status = decoder.finish(&decoder);
  else if (status >= 0)
    status = C89CBOR_MALFORMED;
  (void)decoder.cleanup(&decoder);
  return status;
}
static int receive_work(c89cbor_datagram *self) {
  datagram_state *state = self->state;
  struct msghdr message;
  struct iovec vector;
  ssize_t received;
  int status;
  state->have_input = 0;
  state->input_length = state->input_offset = 0;
  memset(&message, 0, sizeof(message));
  memset(&state->peer, 0, sizeof(state->peer));
  vector.iov_base = state->input;
  vector.iov_len = state->capacity;
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_name = &state->peer;
  message.msg_namelen = sizeof(state->peer);
  received = recvmsg(state->descriptor, &message, 0);
  if (received < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
               ? C89CBOR_INPUT
               : C89CBOR_IO;
  state->peer_length = message.msg_namelen;
  if ((message.msg_flags & MSG_TRUNC) != 0 ||
      (size_t)received > state->capacity)
    status = C89CBOR_LIMIT;
  else if (message.msg_namelen > sizeof(state->peer))
    status = C89CBOR_LIMIT;
  else
    status = validate(state->input, (size_t)received);
  if (status != 0) {
    if (state->counts.rejected != UINT64_MAX)
      ++state->counts.rejected;
    errno = status == C89CBOR_LIMIT ? EMSGSIZE : EBADMSG;
    return status;
  }
  if (state->counts.received == UINT64_MAX ||
      (uint64_t)received > UINT64_MAX - state->counts.input) {
    errno = EOVERFLOW;
    return C89CBOR_LIMIT;
  }
  ++state->counts.received;
  state->counts.input += (uint64_t)received;
  state->input_length = (size_t)received;
  state->have_input = 1;
  return C89CBOR_OK;
}
int c89cbor_datagram_receive(c89cbor_datagram *self,
                             c89cbor_datagram_message *out,
                             c89cbor_error *error) {
  datagram_state *state;
  int status, saved;
  if (out != NULL)
    memset(out, 0, sizeof(*out));
  status = begin(self);
  if (status != 0) {
    if (error != NULL) {
      memset(error, 0, sizeof(*error));
      error->status = status;
    }
    return status;
  }
  if (out == NULL)
    return finish(self, C89CBOR_INVALID, 0, error);
  status = receive_work(self);
  saved = status < 0 ? errno : 0;
  state = self->state;
  if (status == 0) {
    out->bytes = state->input;
    out->length = state->input_length;
    out->peer = state->peer_length ? &state->peer : NULL;
    out->peer_length = state->peer_length;
  }
  return finish(self, status, saved, error);
}
static int send_work(c89cbor_datagram *self, const void *bytes, size_t length,
                     const void *peer, size_t peer_length) {
  datagram_state *state = self->state;
  struct sockaddr_storage address;
  struct msghdr message;
  struct iovec vector;
  ssize_t sent;
  int flags = 0;
  if (state->counts.sent == UINT64_MAX ||
      length > UINT64_MAX - state->counts.output) {
    errno = EOVERFLOW;
    return C89CBOR_LIMIT;
  }
  memset(&message, 0, sizeof(message));
  if (peer != NULL) {
    if (peer_length == 0 || peer_length > sizeof(address)) {
      errno = EINVAL;
      return C89CBOR_INVALID;
    }
    memset(&address, 0, sizeof(address));
    memcpy(&address, peer, peer_length);
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)peer_length;
  } else {
    if (peer_length != 0) {
      errno = EINVAL;
      return C89CBOR_INVALID;
    }
    if (state->destination_length != 0) {
      message.msg_name = &state->destination;
      message.msg_namelen = state->destination_length;
    }
  }
  /* POSIX iovec predates const payloads; a local pointer copy removes the
   * qualifier without writing through it or casting away const. */
  memcpy(&vector.iov_base, &bytes, sizeof(bytes));
  vector.iov_len = length;
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif
  sent = sendmsg(state->descriptor, &message, flags);
  if (sent < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
               ? C89CBOR_OUTPUT
               : C89CBOR_IO;
  if ((size_t)sent != length) {
    errno = EIO;
    return C89CBOR_IO;
  }
  ++state->counts.sent;
  state->counts.output += (uint64_t)length;
  return C89CBOR_OK;
}
int c89cbor_datagram_send(c89cbor_datagram *self, const void *bytes,
                          size_t length, const void *peer, size_t peer_length,
                          c89cbor_error *error) {
  datagram_state *state;
  int status = begin(self), saved = 0;
  if (status != 0) {
    if (error != NULL) {
      memset(error, 0, sizeof(*error));
      error->status = status;
    }
    return status;
  }
  state = self->state;
  if (state->output_length != 0)
    status = C89CBOR_BUSY;
  else if (bytes == NULL)
    status = C89CBOR_INVALID;
  else if (length > state->capacity) {
    status = C89CBOR_LIMIT;
    saved = EMSGSIZE;
  } else {
    status = validate(bytes, length);
    if (status == 0) {
      status = send_work(self, bytes, length, peer, peer_length);
      saved = status < 0 ? errno : 0;
    } else
      saved = EBADMSG;
  }
  return finish(self, status, saved, error);
}
int c89cbor_datagram_set_peer(c89cbor_datagram *self, const void *peer,
                              size_t length) {
  datagram_state *state;
  int status = begin(self);
  if (status != 0)
    return status;
  state = self->state;
  if ((peer == NULL && length != 0) || (peer != NULL && length == 0) ||
      length > sizeof(state->destination))
    status = C89CBOR_INVALID;
  else if (state->output_length != 0)
    status = C89CBOR_BUSY;
  else {
    memset(&state->destination, 0, sizeof(state->destination));
    if (length != 0)
      memcpy(&state->destination, peer, length);
    state->destination_length = (socklen_t)length;
  }
  return finish(self, status, 0, NULL);
}
static int source_read(c89cbor_datagram *self, void *bytes, size_t capacity,
                       size_t *count, int stream) {
  datagram_state *state;
  size_t take;
  int status = begin(self), saved = 0;
  *count = 0;
  if (status != 0)
    return status;
  state = self->state;
  if (stream && state->input_offset == state->input_length) {
    status = receive_work(self);
    saved = status < 0 ? errno : 0;
  } else if (!state->have_input)
    status = C89CBOR_INPUT;
  if (status == 0) {
    take = state->input_length - state->input_offset;
    if (take > capacity)
      take = capacity;
    if (take != 0)
      memcpy(bytes, state->input + state->input_offset, take);
    state->input_offset += take;
    *count = take;
  }
  return finish(self, status, saved, NULL);
}
static int scoped_read(void *self, void *bytes, size_t capacity,
                       size_t *count) {
  return source_read(self, bytes, capacity, count, 0);
}
static int stream_read(void *self, void *bytes, size_t capacity,
                       size_t *count) {
  return source_read(self, bytes, capacity, count, 1);
}
static int sink_write(void *context, const void *bytes, size_t length,
                      size_t *count) {
  c89cbor_datagram *self = context;
  datagram_state *state;
  const unsigned char *input = bytes;
  c89cbor_token token;
  size_t offset = 0, used;
  int status = begin(self), saved = 0;
  *count = 0;
  if (status != 0)
    return status;
  state = self->state;
  if (state->failed)
    return finish(self, state->failed, EBADMSG, NULL);
  if (state->pending) {
    if (length == 0 || input[0] != state->output[state->output_length - 1u])
      return finish(self, C89CBOR_INVALID, 0, NULL);
    status = send_work(self, state->output, state->output_length, NULL, 0);
    saved = status < 0 ? errno : 0;
    if (status == 0) {
      state->pending = 0;
      state->output_length = 0;
      *count = 1u;
      status = state->decoder.reset(&state->decoder);
    }
    if (status < 0)
      state->failed = status;
    return finish(self, status, saved, NULL);
  }
  do {
    status = state->decoder.next(&state->decoder, input + offset,
                                 length - offset, &used, &token);
    if (used > state->capacity - state->output_length) {
      status = C89CBOR_LIMIT;
      saved = EMSGSIZE;
      break;
    }
    if (used != 0)
      memcpy(state->output + state->output_length, input + offset, used);
    state->output_length += used;
    offset += used;
  } while (status == C89CBOR_TOKEN);
  if (status == C89CBOR_DONE) {
    status = send_work(self, state->output, state->output_length, NULL, 0);
    saved = status < 0 ? errno : 0;
    if (status == 0) {
      state->output_length = 0;
      status = state->decoder.reset(&state->decoder);
    } else {
      /* Retrying the final unaccepted byte drives the pending atomic send. */
      if (offset == 0) {
        status = C89CBOR_IO;
        saved = EIO;
      } else {
        --offset;
        state->pending = 1;
      }
    }
  } else if (status == C89CBOR_INPUT)
    status = C89CBOR_OK;
  else if (status < 0 && saved == 0)
    saved = EBADMSG;
  *count = offset;
  if (status < 0)
    state->failed = status;
  return finish(self, status, saved, NULL);
}
int c89cbor_datagram_source(c89cbor_datagram *self, c89cbor_source *out) {
  if (out != NULL)
    memset(out, 0, sizeof(*out));
  if (!live(self) || out == NULL)
    return C89CBOR_INVALID;
  out->context = self;
  out->read = scoped_read;
  return C89CBOR_OK;
}
int c89cbor_datagram_stream_source(c89cbor_datagram *self,
                                   c89cbor_source *out) {
  int status = c89cbor_datagram_source(self, out);
  if (status == 0)
    out->read = stream_read;
  return status;
}
int c89cbor_datagram_sink(c89cbor_datagram *self, c89cbor_sink *out) {
  if (out != NULL)
    memset(out, 0, sizeof(*out));
  if (!live(self) || out == NULL)
    return C89CBOR_INVALID;
  out->context = self;
  out->write = sink_write;
  return C89CBOR_OK;
}
int c89cbor_datagram_reset(c89cbor_datagram *self) {
  datagram_state *state;
  int status = begin(self);
  if (status != 0)
    return status;
  state = self->state;
  memset(state->input, 0, state->capacity);
  memset(state->output, 0, state->capacity);
  state->have_input = state->pending = state->failed = 0;
  state->input_length = state->input_offset = state->output_length = 0;
  (void)c89cbor_decoder_cleanup(&state->decoder);
  status = c89cbor_decoder_init(NULL, &state->decoder, NULL, 0, 0);
  return finish(self, status, 0, NULL);
}
int c89cbor_datagram_progress(const c89cbor_datagram *self,
                              c89cbor_datagram_counts *out) {
  if (out != NULL)
    memset(out, 0, sizeof(*out));
  if (!live(self) || out == NULL)
    return C89CBOR_INVALID;
  *out = ((const datagram_state *)self->state)->counts;
  return C89CBOR_OK;
}
int c89cbor_datagram_diagnostic(const c89cbor_datagram *self,
                                c89cbor_error *error) {
  return c89_lifetime_diagnostic(self == NULL ? NULL : &self->lifetime, error);
}
int c89cbor_datagram_cleanup(c89cbor_datagram *self) {
  datagram_state *state;
  c89cbor_allocator allocator;
  if (self == NULL)
    return C89CBOR_OK;
  if (self->lifetime.magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (self->lifetime.busy || self->lifetime.dependents)
    return C89CBOR_BUSY;
  self->lifetime.busy = 1;
  state = self->state;
  self->state = NULL;
  allocator = self->lifetime.allocator;
  if (state != NULL) {
    (void)c89cbor_decoder_cleanup(&state->decoder);
    if (state->input != NULL) {
      memset(state->input, 0, state->capacity);
      allocator.free(allocator.context, state->input);
    }
    if (state->output != NULL) {
      memset(state->output, 0, state->capacity);
      allocator.free(allocator.context, state->output);
    }
    allocator.free(allocator.context, state);
  }
  self->lifetime.busy = 0;
  return c89_lifetime_cleanup(&self->lifetime);
}
int c89cbor_datagram_destroy(c89cbor_datagram *self) {
  int status;
  if (self == NULL)
    return C89CBOR_OK;
  if (self->lifetime.magic != C89_LIFETIME_MAGIC || !self->lifetime.owned)
    return C89CBOR_INVALID;
  status = c89cbor_datagram_cleanup(self);
  return status == 0 ? c89_lifetime_destroy(&self->lifetime, self) : status;
}
int c89cbor_datagram_init(c89cbor *runtime, c89cbor_datagram *self,
                          int descriptor, size_t capacity,
                          c89cbor_error *error) {
  datagram_state *state;
  c89cbor_allocator selected;
  int status, type;
  socklen_t length = sizeof(type);
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (self == NULL)
    return C89CBOR_INVALID;
  memset(self, 0, sizeof(*self));
  self->receive = c89cbor_datagram_receive;
  self->send = c89cbor_datagram_send;
  self->set_peer = c89cbor_datagram_set_peer;
  self->source = c89cbor_datagram_source;
  self->stream_source = c89cbor_datagram_stream_source;
  self->sink = c89cbor_datagram_sink;
  self->reset = c89cbor_datagram_reset;
  self->progress = c89cbor_datagram_progress;
  self->diagnostic = c89cbor_datagram_diagnostic;
  self->cleanup = c89cbor_datagram_cleanup;
  self->destroy = c89cbor_datagram_destroy;
  status = c89_lifetime_init(&self->lifetime, runtime, NULL);
  if (status != 0) {
    if (error != NULL)
      error->status = status;
    return status;
  }
  self->lifetime.busy = 1;
  if (capacity == 0)
    capacity = C89CBOR_CHUNK;
  if (descriptor < 0 || capacity > (size_t)INT_MAX ||
      getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
      type != SOCK_DGRAM) {
    status = capacity > (size_t)INT_MAX ? C89CBOR_LIMIT : C89CBOR_INVALID;
    goto failed;
  }
  status =
      c89_allocate(runtime, NULL, sizeof(*state), (void **)&state, &selected);
  if (status != 0)
    goto failed;
  memset(state, 0, sizeof(*state));
  self->state = state;
  state->descriptor = descriptor;
  state->capacity = capacity;
  status =
      c89_allocate(runtime, NULL, capacity, (void **)&state->input, &selected);
  if (status == 0)
    status = c89_allocate(runtime, NULL, capacity, (void **)&state->output,
                          &selected);
  if (status == 0)
    status = c89cbor_decoder_init(NULL, &state->decoder, NULL, 0, 0);
  if (status == 0) {
    self->lifetime.busy = 0;
    return C89CBOR_OK;
  }
failed:
  self->lifetime.error.status = status;
  strcpy(self->lifetime.error.layer, "datagram-init");
  if (error != NULL)
    *error = self->lifetime.error;
  self->lifetime.busy = 0;
  (void)c89cbor_datagram_cleanup(self);
  return status;
}
int c89cbor_datagram_create(c89cbor *runtime, int descriptor, size_t capacity,
                            c89cbor_datagram **out, c89cbor_error *error) {
  c89cbor_allocator allocator;
  c89cbor_datagram *self;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status =
      c89_allocate(runtime, NULL, sizeof(*self), (void **)&self, &allocator);
  if (status == 0) {
    status = c89cbor_datagram_init(runtime, self, descriptor, capacity, error);
    if (status == 0) {
      self->lifetime.owned = 1;
      *out = self;
    } else
      allocator.free(allocator.context, self);
  } else if (error != NULL)
    error->status = status;
  return status;
}
