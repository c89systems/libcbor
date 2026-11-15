#include <errno.h>
#include <sys/uio.h>

/* Application datagram source fixture: recvmsg boundaries are validated before
 * any prefix is given to the byte-stream API. Silence is INPUT, never EOF. */
typedef struct cose_datagram {
  c89cbor_datagram receiver;
  c89cbor_source source;
  int fd, deadline, injected_errno;
  unsigned char bytes[2048];
  size_t capacity, length, offset, calls, queued;
} cose_datagram;
static int cose_datagram_receive(int fd, void *bytes, size_t capacity,
                                 size_t *length) {
  struct msghdr message;
  struct iovec vector;
  c89cbor_decoder decoder;
  c89cbor_token token;
  ssize_t received;
  size_t used, offset = 0;
  int status;
  *length = 0;
  memset(&message, 0, sizeof(message));
  vector.iov_base = bytes;
  vector.iov_len = capacity;
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  received = recvmsg(fd, &message, 0);
  if (received < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? C89CBOR_INPUT : C89CBOR_IO;
  if ((message.msg_flags & MSG_TRUNC) != 0) {
    errno = EMSGSIZE;
    return C89CBOR_IO;
  }
  if (received == 0) {
    errno = EBADMSG;
    return C89CBOR_IO;
  }
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  do {
    status = decoder.next(&decoder, (const unsigned char *)bytes + offset,
                          (size_t)received - offset, &used, &token);
    offset += used;
  } while (status == C89CBOR_TOKEN);
  if (status == C89CBOR_DONE && offset == (size_t)received &&
      decoder.finish(&decoder) == 0) {
    *length = (size_t)received;
    status = C89CBOR_OK;
  } else {
    errno = EBADMSG;
    status = C89CBOR_IO;
  }
  assert(decoder.cleanup(&decoder) == 0);
  return status;
}
static int cose_datagram_source(void *context, void *bytes, size_t capacity,
                                size_t *count) {
  cose_datagram *datagram = context;
  int status;
  ++datagram->calls;
  *count = 0;
  if (datagram->injected_errno != 0) {
    errno = datagram->injected_errno;
    return C89CBOR_IO;
  }
  status =
      datagram->source.read(datagram->source.context, bytes, capacity, count);
  if (status == C89CBOR_INPUT && datagram->deadline) {
    errno = ETIMEDOUT;
    return C89CBOR_IO;
  }
  return status;
}
static int cose_datagram_drive(c89cbor_cose_operation *operation,
                               cose_datagram *datagram) {
  c89cbor_error error;
  c89cbor_datagram_counts counts;
  int status;
  size_t steps = 0;
  do {
    status = operation->step(operation, &error);
    if (status == C89CBOR_INPUT && datagram->queued != 0) {
      assert(datagram->receiver.progress(&datagram->receiver, &counts) == 0);
      if (counts.received < datagram->queued) {
        cose_socket_ready(datagram->fd, POLLIN);
        status = C89CBOR_OK;
      }
    }
    assert(++steps < 10000u);
  } while (status == C89CBOR_OK || status == C89CBOR_OUTPUT);
  return status;
}
static int cose_datagram_open(fixture *f, c89cbor_cose_operation *operation,
                              c89cbor_cose_key *key, int mode,
                              const c89cbor_cose_options *options,
                              c89cbor_error *error) {
  if (mode == 2 || mode == 3)
    return f->runtime.cose_verify1_stream_init(
        &f->runtime, operation, &f->source, &f->sink, key, options, error);
  if (mode == 4)
    return f->runtime.cose_verify_mac0_stream_init(
        &f->runtime, operation, &f->source, &f->sink, key, options, error);
  return f->runtime.cose_decrypt_stream_init(&f->runtime, operation, &f->source,
                                             &f->sink, key, options, error);
}
static void cose_udp_failures(fixture *f) {
  static const int packets[][3] = {{0, 1, 2}, {0, 2, -1}, {1, 0, 2},
                                   {0, 0, 1}, {0, 1, -1}, {-1, -1, -1},
                                   {0, 1, 2}};
  static const int expected_status[] = {
      C89CBOR_DONE,  C89CBOR_AUTH,  C89CBOR_AUTH, C89CBOR_AUTH,
      C89CBOR_INPUT, C89CBOR_INPUT, C89CBOR_AUTH};
  static const size_t expected_bytes[] = {65u, 32u, 0, 32u, 64u, 0, 32u};
  cose_datagram *datagram = calloc(1, sizeof(*datagram));
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_key imported, *key, *keys[1];
  c89cbor_cose_operation sender, receiver;
  c89cbor_source source;
  c89cbor_error error;
  unsigned char raw[32];
  size_t offsets[4], lengths[3], i, j, calls, n;
  int pair[2], mode, scenario, status, domain;
  assert(datagram != NULL);
  options.record_bytes = 32u;
  options.step_input = 11u;
  options.step_output = 7u;
  options.step_events = 3u;
  for (mode = 0; mode < 5; ++mode) {
    if (mode >= 2) {
      memset(raw, 0, sizeof(raw));
      raw[31] = 1;
      assert(f->runtime.cose_key_init(&f->runtime, &imported,
                                      mode == 2   ? C89CBOR_COSE_ED25519_PRIVATE
                                      : mode == 3 ? C89CBOR_COSE_P256_PRIVATE
                                                  : C89CBOR_COSE_HMAC256,
                                      raw, sizeof(raw), NULL, 0, &error) == 0);
    }
    options.encrypt = mode == 1;
    endpoints(f, &f->input, &f->wire);
    f->input.length = 65u;
    memset(f->input.bytes, 'v', f->input.length);
    key = mode >= 2 ? &imported : mode == 1 ? &f->public_key : &f->content;
    keys[0] = key;
    if (mode == 2 || mode == 3)
      status = f->runtime.cose_sign1_stream_init(
          &f->runtime, &sender, &f->source, &f->sink, key, &options, &error);
    else if (mode == 4)
      status = f->runtime.cose_mac0_stream_init(
          &f->runtime, &sender, &f->source, &f->sink, key, &options, &error);
    else
      status = f->runtime.cose_encrypt_stream_init(&f->runtime, &sender,
                                                   &f->source, &f->sink, keys,
                                                   1u, &options, &error);
    assert(status == 0 && drive(&sender) == C89CBOR_DONE &&
           sender.cleanup(&sender) == 0);
    offsets[0] = 0;
    for (i = 0; i < 3u; ++i) {
      offsets[i + 1u] =
          cose_item_end(f->wire.bytes, f->wire.length, offsets[i]);
      lengths[i] = offsets[i + 1u] - offsets[i];
    }
    assert(offsets[3] == f->wire.length);
    key = mode >= 2 ? &imported : mode == 1 ? &f->private_key : &f->content;
    for (domain = 0; domain < 2; ++domain)
      for (scenario = 0; scenario < 7; ++scenario) {
        cose_socket_pair(domain ? AF_UNIX : AF_INET, SOCK_DGRAM, pair);
        memset(datagram, 0, sizeof(*datagram));
        datagram->fd = pair[1];
        datagram->capacity = sizeof(datagram->bytes);
        assert(f->runtime.datagram_init(&f->runtime, &datagram->receiver,
                                        pair[1], datagram->capacity,
                                        &error) == 0);
        assert(datagram->receiver.stream_source(&datagram->receiver,
                                                &datagram->source) == 0);
        for (i = 0; i < 3u && packets[scenario][i] >= 0; ++i) {
          j = (size_t)packets[scenario][i];
          memcpy(f->output.bytes, f->wire.bytes + offsets[j], lengths[j]);
          if (scenario == 6 && j == 1u) {
            f->output.length = lengths[j];
            cwt_corrupt_payload(&f->output);
          }
          assert(send(pair[0], f->output.bytes, lengths[j], 0) ==
                 (ssize_t)lengths[j]);
          ++datagram->queued;
        }
        source.context = datagram;
        source.read = cose_datagram_source;
        endpoints(f, &f->input, &f->output);
        f->source = source;
        f->output.pause = scenario == 0;
        assert(cose_datagram_open(f, &receiver, key, mode, &options, &error) ==
               0);
        status = cose_datagram_drive(&receiver, datagram);
        assert(status == expected_status[scenario] &&
               f->output.length == expected_bytes[scenario]);
        for (i = 0; i < f->output.length; ++i)
          assert(f->output.bytes[i] == 'v');
        if (status == C89CBOR_INPUT) {
          calls = datagram->calls;
          assert(receiver.step(&receiver, &error) == C89CBOR_INPUT &&
                 datagram->calls == calls + 1u);
          datagram->deadline = 1;
          assert(cose_datagram_drive(&receiver, datagram) == C89CBOR_IO);
          assert(receiver.diagnostic(&receiver, &error) == 0 &&
                 error.system_errno == ETIMEDOUT);
        }
        assert(receiver.cleanup(&receiver) == 0);
        assert(datagram->receiver.cleanup(&datagram->receiver) == 0);
        assert(close(pair[0]) == 0 && close(pair[1]) == 0);
        f->output.pause = 0;
      }
    memset(datagram, 0, sizeof(*datagram));
    datagram->injected_errno = EHOSTUNREACH;
    endpoints(f, &f->input, &f->output);
    f->source.context = datagram;
    f->source.read = cose_datagram_source;
    assert(cose_datagram_open(f, &receiver, key, mode, &options, &error) == 0);
    assert(cose_datagram_drive(&receiver, datagram) == C89CBOR_IO &&
           f->output.length == 0);
    assert(receiver.diagnostic(&receiver, &error) == 0 &&
           error.system_errno == EHOSTUNREACH);
    calls = datagram->calls;
    assert(receiver.step(&receiver, &error) == C89CBOR_IO &&
           datagram->calls == calls);
    assert(receiver.cleanup(&receiver) == 0);
    if (mode >= 2)
      assert(imported.cleanup(&imported) == 0);
  }
  /* Truncation cannot admit a valid prefix, nor may datagram boundaries be
   * used to concatenate partial CBOR values or two independent messages. */
  cose_socket_pair(AF_INET, SOCK_DGRAM, pair);
  memcpy(f->output.bytes, f->wire.bytes, lengths[0]);
  f->output.bytes[lengths[0]] = 0;
  assert(send(pair[0], f->output.bytes, lengths[0] + 1u, 0) ==
         (ssize_t)(lengths[0] + 1u));
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes, lengths[0], &n) ==
             C89CBOR_IO &&
         n == 0 && errno == EMSGSIZE);
  assert(send(pair[0], f->wire.bytes, lengths[0], 0) == (ssize_t)lengths[0]);
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == 0 &&
         n == lengths[0]);
  assert(send(pair[0], "", 0, 0) == 0);
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == C89CBOR_IO &&
         errno == EBADMSG);
  memcpy(f->output.bytes, f->wire.bytes, lengths[0]);
  memcpy(f->output.bytes + lengths[0], f->wire.bytes, lengths[0]);
  assert(send(pair[0], f->output.bytes, lengths[0] * 2u, 0) ==
         (ssize_t)(lengths[0] * 2u));
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == C89CBOR_IO &&
         n == 0);
  assert(send(pair[0], f->wire.bytes, 1u, 0) == 1);
  assert(send(pair[0], f->wire.bytes + 1u, lengths[0] - 1u, 0) ==
         (ssize_t)(lengths[0] - 1u));
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == C89CBOR_IO);
  cose_socket_ready(pair[1], POLLIN);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == C89CBOR_IO);
  assert(cose_datagram_receive(pair[1], datagram->bytes,
                               sizeof(datagram->bytes), &n) == C89CBOR_INPUT &&
         n == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
  free(datagram);
}
