#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct cose_cbor_flow {
  uint64_t generated, received, length, values;
  c89cbor_decoder decoder;
  int early;
} cose_cbor_flow;
static unsigned char cose_cbor_byte(uint64_t offset) {
  size_t part = (size_t)(offset % 1027u);
  return part == 0 ? 0x59 : part == 1 ? 4 : part == 2 ? 0 : 'v';
}
static int cose_cbor_source(void *context, void *bytes, size_t capacity,
                            size_t *count) {
  cose_cbor_flow *flow = context;
  unsigned char *out = bytes;
  size_t i, take = capacity;
  if ((uint64_t)take > flow->length - flow->generated)
    take = (size_t)(flow->length - flow->generated);
  for (i = 0; i < take; ++i)
    out[i] = cose_cbor_byte(flow->generated + i);
  flow->generated += take;
  *count = take;
  return 0;
}
static int cose_cbor_sink(void *context, const void *bytes, size_t length,
                          size_t *count) {
  cose_cbor_flow *flow = context;
  const unsigned char *in = bytes;
  c89cbor_token token;
  size_t i, used, offset = 0;
  int status;
  assert((uint64_t)length <= flow->length - flow->received);
  for (i = 0; i < length; ++i)
    assert(in[i] == cose_cbor_byte(flow->received + i));
  if (flow->generated < flow->length)
    flow->early = 1;
  for (;;) {
    status = flow->decoder.next(&flow->decoder, in + offset, length - offset,
                                &used, &token);
    offset += used;
    assert(status == C89CBOR_TOKEN || status == C89CBOR_DONE ||
           status == C89CBOR_INPUT);
    if (status == C89CBOR_DONE) {
      ++flow->values;
      assert(flow->decoder.reset(&flow->decoder) == 0);
    }
    if (status == C89CBOR_INPUT) {
      assert(offset == length);
      break;
    }
  }
  flow->received += length;
  *count = length;
  return 0;
}
static void cose_socket_pair(int domain, int type, int pair[2]) {
  struct sockaddr_in address;
  socklen_t length = sizeof(address);
  int listener, i, flags;
  if (domain == 0) {
    int temporary;
    assert(pipe(pair) == 0);
    temporary = pair[0];
    pair[0] = pair[1];
    pair[1] = temporary;
  } else if (domain == AF_UNIX)
    assert(socketpair(domain, type, 0, pair) == 0);
  else {
    listener = socket(AF_INET, type, 0);
    assert(listener >= 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
    pair[0] = socket(AF_INET, type, 0);
    assert(pair[0] >= 0);
    if (type == SOCK_STREAM) {
      assert(listen(listener, 1) == 0);
      assert(connect(pair[0], (struct sockaddr *)&address, length) == 0);
      pair[1] = accept(listener, NULL, NULL);
      assert(pair[1] >= 0 && close(listener) == 0);
    } else {
      pair[1] = listener;
      assert(connect(pair[0], (struct sockaddr *)&address, length) == 0);
    }
  }
  for (i = 0; i < 2; ++i) {
    flags = fcntl(pair[i], F_GETFL, 0);
    assert(flags >= 0 && fcntl(pair[i], F_SETFL, flags | O_NONBLOCK) == 0);
  }
}
static void cose_stream_transport(fixture *f, int domain, int encrypt) {
  cose_cbor_flow *flow = calloc(1, sizeof(*flow));
  c89cbor_cose_operation sender, receiver;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_key *keys[1];
  c89cbor_error error;
  c89cbor_fd outgoing, incoming;
  c89cbor_source source;
  c89cbor_sink sink;
  int pair[2], sent = 0, received = 0;
  size_t steps = 0;
  assert(flow != NULL);
  flow->length = 1027u * 128u;
  assert(c89cbor_decoder_init(NULL, &flow->decoder, NULL, 0, 0) == 0);
  cose_socket_pair(domain, SOCK_STREAM, pair);
  assert(f->runtime.fd_init(&f->runtime, &outgoing, pair[0], NULL, &sink) == 0);
  source.context = flow;
  source.read = cose_cbor_source;
  keys[0] = encrypt ? &f->public_key : &f->content;
  options.encrypt = encrypt;
  options.step_input = options.step_output = 256u;
  options.step_events = 32u;
  assert(f->runtime.cose_encrypt_stream_init(&f->runtime, &sender, &source,
                                             &sink, keys, 1u, &options,
                                             &error) == 0);
  assert(f->runtime.fd_init(&f->runtime, &incoming, pair[1], &source, NULL) ==
         0);
  sink.context = flow;
  sink.write = cose_cbor_sink;
  assert(f->runtime.cose_decrypt_stream_init(
             &f->runtime, &receiver, &source, &sink,
             encrypt ? &f->private_key : &f->content, &options, &error) == 0);
  while (sent != C89CBOR_DONE || received != C89CBOR_DONE) {
    if (sent != C89CBOR_DONE) {
      sent = sender.step(&sender, &error);
      assert(sent >= 0);
    }
    if (received != C89CBOR_DONE) {
      received = receiver.step(&receiver, &error);
      assert(received >= 0);
    }
    assert(++steps < 100000u);
  }
  assert(flow->received == flow->length && flow->values == 128u && flow->early);
  assert(sender.cleanup(&sender) == 0 && receiver.cleanup(&receiver) == 0);
  assert(outgoing.cleanup(&outgoing) == 0 && incoming.cleanup(&incoming) == 0);
  assert(flow->decoder.cleanup(&flow->decoder) == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
  free(flow);
}
/* UDP and Unix datagrams carry complete bounded independent objects. No
 * fragmentation, ordering or retransmission protocol is smuggled underneath. */
static void cose_datagram_transport(fixture *f, int domain, int encrypt) {
  int pair[2];
  c89cbor_error error;
  c89cbor_cose_key *keys[1];
  ssize_t count;
  size_t length;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  f->input.length = 4u;
  memcpy(f->input.bytes, "\203\001\002\003", 4u);
  endpoints(f, &f->input, &f->wire);
  keys[0] = &f->public_key;
  assert((encrypt ? f->runtime.cose_encrypt(&f->runtime, &f->source, &f->sink,
                                            keys, 1u, NULL, &error)
                  : f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                             &f->content, NULL, &error)) == 0);
  length = f->wire.length;
  assert(length < 512u);
  cose_socket_pair(domain, SOCK_DGRAM, pair);
  assert(send(pair[0], f->wire.bytes, length, 0) == (ssize_t)length);
  count = recv(pair[1], f->wire.bytes, sizeof(f->wire.bytes), 0);
  assert(count == (ssize_t)length);
  assert(cose_open_to_buffer(f, encrypt ? &f->private_key : &f->content, NULL,
                             0) == 0);
  assert(f->output.length == f->input.length &&
         memcmp(f->input.bytes, f->output.bytes, f->input.length) == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
}
static void cose_transports(fixture *f) {
  int encrypt;
  for (encrypt = 0; encrypt < 2; ++encrypt) {
    cose_stream_transport(f, AF_UNIX, encrypt);
    cose_stream_transport(f, AF_INET, encrypt);
    cose_stream_transport(f, 0, encrypt);
    cose_datagram_transport(f, AF_UNIX, encrypt);
    cose_datagram_transport(f, AF_INET, encrypt);
  }
}
