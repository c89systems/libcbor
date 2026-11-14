#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#include <c89cbor/lonejson.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>

typedef struct fixture {
  c89cbor root;
  c89cbor_datagram sender, receiver;
  unsigned char bytes[8192];
} fixture;
static void nonblock(int descriptor) {
  int flags = fcntl(descriptor, F_GETFL, 0);
  assert(flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0);
}
static void pair_open(int family, int pair[2]) {
  struct sockaddr_storage storage;
  struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
  socklen_t length;
  if (family == AF_UNIX)
    assert(socketpair(family, SOCK_DGRAM, 0, pair) == 0);
  else {
    memset(&storage, 0, sizeof(storage));
    if (family == AF_INET) {
      length = sizeof(*v4);
      v4->sin_family = AF_INET;
      assert(inet_pton(AF_INET, "127.0.0.1", &v4->sin_addr) == 1);
    } else {
      length = sizeof(*v6);
      v6->sin6_family = AF_INET6;
      assert(inet_pton(AF_INET6, "::1", &v6->sin6_addr) == 1);
    }
    pair[1] = socket(family, SOCK_DGRAM, 0);
    pair[0] = socket(family, SOCK_DGRAM, 0);
    assert(pair[0] >= 0 && pair[1] >= 0);
    assert(bind(pair[1], (struct sockaddr *)&storage, length) == 0);
    assert(getsockname(pair[1], (struct sockaddr *)&storage, &length) == 0);
    assert(connect(pair[0], (struct sockaddr *)&storage, length) == 0);
  }
  nonblock(pair[0]);
  nonblock(pair[1]);
}
static int receive_ready(c89cbor_datagram *self, int descriptor,
                         c89cbor_datagram_message *packet,
                         c89cbor_error *error) {
  struct pollfd ready;
  int status;
  ready.fd = descriptor;
  ready.events = POLLIN;
  ready.revents = 0;
  do {
    status = poll(&ready, 1, 5000);
  } while (status < 0 && errno == EINTR);
  assert(status == 1 && (ready.revents & POLLIN) != 0);
  status = self->receive(self, packet, error);
  if (status == C89CBOR_INPUT || status == C89CBOR_IO)
    fprintf(stderr, "ready datagram receive: status=%d errno=%d\n", status,
            error->system_errno);
  return status;
}
static void packets(fixture *f, int family) {
  static const unsigned char item[] = {0x83, 1, 2, 3};
  c89cbor_datagram_message packet;
  c89cbor_datagram_counts counts;
  c89cbor_error error;
  c89cbor_source source;
  size_t count, total;
  int pair[2];
  fprintf(stderr, "datagram family=%d\n", family);
  pair_open(family, pair);
  assert(f->root.datagram_init(&f->root, &f->sender, pair[0], 32u, &error) ==
         0);
  assert(f->root.datagram_init(&f->root, &f->receiver, pair[1], 32u, &error) ==
         0);
  assert(f->root.cleanup(&f->root) == C89CBOR_BUSY);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == C89CBOR_INPUT &&
         packet.bytes == NULL);
  assert(f->sender.send(&f->sender, item, sizeof(item), NULL, 0, &error) == 0);
  errno = EBADMSG;
  assert(f->sender.send(&f->sender, item, sizeof(item), NULL, 1u, &error) ==
         C89CBOR_INVALID);
  assert(error.system_errno == EINVAL);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) == 0);
  assert(packet.length == sizeof(item) &&
         memcmp(packet.bytes, item, sizeof(item)) == 0);
  if (family == AF_UNIX)
    assert(packet.peer == NULL && packet.peer_length == 0);
  assert(f->receiver.set_peer(&f->receiver, packet.peer, packet.peer_length) ==
         0);
  assert(f->receiver.send(&f->receiver, packet.bytes, packet.length, NULL, 0,
                          &error) == 0);
  assert(receive_ready(&f->sender, pair[0], &packet, &error) == 0 &&
         packet.length == sizeof(item));
  assert(f->sender.source(&f->sender, &source) == 0);
  total = 0;
  do {
    assert(source.read(source.context, f->bytes + total, 1u, &count) == 0);
    total += count;
  } while (count != 0);
  assert(total == sizeof(item) && memcmp(f->bytes, item, total) == 0);
  assert(f->sender.stream_source(&f->sender, &source) == 0);
  assert(source.read(source.context, f->bytes, sizeof(f->bytes), &count) ==
             C89CBOR_INPUT &&
         count == 0);
  /* Oversize input contains a valid one-byte prefix; no prefix is admitted. */
  memset(f->bytes, 1, 33u);
  assert(send(pair[0], f->bytes, 33u, 0) == 33);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) ==
         C89CBOR_LIMIT);
  assert(packet.bytes == NULL && packet.length == 0 &&
         error.system_errno == EMSGSIZE);
  assert(send(pair[0], "", 0, 0) == 0);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) ==
             C89CBOR_MALFORMED &&
         packet.bytes == NULL);
  assert(send(pair[0], "\1\2", 2u, 0) == 2);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) ==
         C89CBOR_MALFORMED);
  assert(send(pair[0], "\x82\1", 2u, 0) == 2);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) ==
         C89CBOR_MALFORMED);
  assert(f->sender.send(&f->sender, "\1\2", 2u, NULL, 0, &error) ==
         C89CBOR_MALFORMED);
  assert(f->sender.send(&f->sender, f->bytes, 33u, NULL, 0, &error) ==
         C89CBOR_LIMIT);
  assert(f->sender.send(&f->sender, item, sizeof(item), NULL, 0, &error) == 0);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) == 0);
  assert(f->receiver.progress(&f->receiver, &counts) == 0 &&
         counts.received == 2u && counts.rejected == 4u);
  assert(f->receiver.reset(&f->receiver) == 0);
  assert(f->receiver.progress(&f->receiver, &counts) == 0 &&
         counts.rejected == 4u);
  assert(f->receiver.cleanup(&f->receiver) == 0 &&
         f->sender.cleanup(&f->sender) == 0);
  assert(fcntl(pair[0], F_GETFD) >= 0 && fcntl(pair[1], F_GETFD) >= 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
}
static void named_peers(fixture *f) {
  struct sockaddr_un address[2];
  c89cbor_datagram_message packet;
  c89cbor_error error;
  char directory[] = "c89cbor-datagram-XXXXXX";
  int pair[2], i;
  assert(mkdtemp(directory) != NULL);
  memset(address, 0, sizeof(address));
  for (i = 0; i < 2; ++i) {
    address[i].sun_family = AF_UNIX;
    assert(snprintf(address[i].sun_path, sizeof(address[i].sun_path), "%s/%d",
                    directory, i) > 0);
    pair[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
    assert(pair[i] >= 0);
    assert(bind(pair[i], (struct sockaddr *)&address[i], sizeof(address[i])) ==
           0);
    nonblock(pair[i]);
  }
  assert(f->root.datagram_init(&f->root, &f->sender, pair[0], 32u, &error) ==
         0);
  assert(f->root.datagram_init(&f->root, &f->receiver, pair[1], 32u, &error) ==
         0);
  assert(f->sender.send(&f->sender, "\1", 1u, &address[1], sizeof(address[1]),
                        &error) == 0);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) == 0);
  assert(packet.peer != NULL &&
         packet.peer_length > offsetof(struct sockaddr_un, sun_path));
  assert(f->receiver.set_peer(&f->receiver, packet.peer, packet.peer_length) ==
         0);
  assert(f->receiver.send(&f->receiver, "\2", 1u, NULL, 0, &error) == 0);
  assert(receive_ready(&f->sender, pair[0], &packet, &error) == 0 &&
         packet.length == 1u && ((const unsigned char *)packet.bytes)[0] == 2);
  assert(f->sender.send(&f->sender, "\3", 1u, packet.peer, packet.peer_length,
                        &error) == 0);
  assert(receive_ready(&f->receiver, pair[1], &packet, &error) == 0 &&
         packet.length == 1u && ((const unsigned char *)packet.bytes)[0] == 3);
  assert(f->receiver.cleanup(&f->receiver) == 0 &&
         f->sender.cleanup(&f->sender) == 0);
  for (i = 0; i < 2; ++i)
    assert(close(pair[i]) == 0 && unlink(address[i].sun_path) == 0);
  assert(rmdir(directory) == 0);
}
static void backpressure(fixture *f) {
  static const unsigned char item[] = {0x48, 1, 2, 3, 4, 5, 6, 7, 8};
  c89cbor_datagram_message packet;
  c89cbor_datagram_counts counts;
  c89cbor_error error;
  c89cbor_sink sink;
  int pair[2], buffer_size = 1024, status;
  size_t count, i, packets = 0;
  pair_open(AF_UNIX, pair);
  assert(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &buffer_size,
                    sizeof(buffer_size)) == 0);
  assert(f->root.datagram_init(&f->root, &f->sender, pair[0], 32u, &error) ==
         0);
  assert(f->root.datagram_init(&f->root, &f->receiver, pair[1], 32u, &error) ==
         0);
  while (send(pair[0], "\1", 1u, 0) == 1)
    assert(++packets < 10000u);
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
  assert(f->sender.sink(&f->sender, &sink) == 0);
  for (i = 0; i < sizeof(item) - 1u; ++i)
    assert(sink.write(sink.context, item + i, 1u, &count) == 0 && count == 1u);
  assert(sink.write(sink.context, item + i, 1u, &count) == C89CBOR_OUTPUT &&
         count == 0);
  assert(sink.write(sink.context, item + i, 1u, &count) == C89CBOR_OUTPUT &&
         count == 0);
  assert(f->sender.send(&f->sender, "\1", 1u, NULL, 0, &error) == C89CBOR_BUSY);
  assert(f->sender.set_peer(&f->sender, NULL, 0) == C89CBOR_BUSY);
  assert(f->sender.progress(&f->sender, &counts) == 0 && counts.sent == 0);
  while ((status = f->receiver.receive(&f->receiver, &packet, &error)) == 0)
    --packets;
  assert(status == C89CBOR_INPUT && packets == 0);
  assert(sink.write(sink.context, item + i, 1u, &count) == 0 && count == 1u);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == 0 &&
         packet.length == sizeof(item));
  assert(memcmp(packet.bytes, item, sizeof(item)) == 0);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == C89CBOR_INPUT);
  assert(sink.write(sink.context, "\1\2", 2u, &count) == 0 && count == 1u);
  assert(sink.write(sink.context, "\2", 1u, &count) == 0 && count == 1u);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == 0 &&
         packet.length == 1u);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == 0 &&
         packet.length == 1u);
  memset(f->bytes, 'a', 40u);
  f->bytes[0] = 0x58;
  f->bytes[1] = 38;
  assert(sink.write(sink.context, f->bytes, 40u, &count) == C89CBOR_LIMIT);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == C89CBOR_INPUT);
  assert(f->sender.reset(&f->sender) == 0);
  assert(sink.write(sink.context, "\1", 1u, &count) == 0 && count == 1u);
  assert(f->receiver.receive(&f->receiver, &packet, &error) == 0);
  assert(f->sender.cleanup(&f->sender) == 0 &&
         f->receiver.cleanup(&f->receiver) == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
}
typedef struct probe {
  size_t calls, fail, live;
  c89cbor_datagram *self;
} probe;
static void *allocate(void *context, size_t length) {
  probe *p = context;
  void *bytes;
  if (++p->calls == p->fail)
    return NULL;
  bytes = malloc(length);
  if (bytes != NULL)
    ++p->live;
  return bytes;
}
static void release(void *context, void *bytes) {
  probe *p = context;
  if (p->self != NULL)
    assert(p->self->cleanup(p->self) == C89CBOR_BUSY);
  assert(p->live != 0);
  --p->live;
  free(bytes);
}
static void ownership(void) {
  c89cbor root;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_datagram *self, caller;
  c89cbor_error error;
  probe p;
  size_t at;
  int pair[2];
  memset(&p, 0, sizeof(p));
  config.allocator.context = &p;
  config.allocator.alloc = allocate;
  config.allocator.free = release;
  assert(c89cbor_init(&root, &config, &error) == 0);
  pair_open(AF_UNIX, pair);
  for (at = 1; at <= 5u; ++at) {
    p.calls = 0;
    p.fail = at;
    self = NULL;
    if (at <= 4u)
      assert(root.datagram_create(&root, pair[0], 0, &self, &error) ==
                 C89CBOR_NOMEM &&
             self == NULL);
    else {
      assert(root.datagram_create(&root, pair[0], 0, &self, &error) == 0);
      p.self = self;
      assert(self->destroy(self) == 0);
      p.self = NULL;
    }
    assert(p.live == 0 && root.lifetime.dependents == 0);
  }
  p.fail = 0;
  assert(root.datagram_init(&root, &caller, -1, 0, &error) == C89CBOR_INVALID);
  assert(caller.cleanup(&caller) == 0);
  assert(root.datagram_init(&root, &caller, pair[0], (size_t)-1, &error) ==
         C89CBOR_LIMIT);
  assert(caller.cleanup(&caller) == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  assert(root.datagram_init(&root, &caller, pair[0], 0, &error) ==
         C89CBOR_INVALID);
  assert(caller.cleanup(&caller) == 0);
  assert(close(pair[0]) == 0 && close(pair[1]) == 0 &&
         root.cleanup(&root) == 0);
}
static void *run(void *unused) {
  fixture *f = calloc(1, sizeof(*f));
  c89cbor_error error;
  (void)unused;
  assert(f != NULL && c89cbor_init(&f->root, NULL, &error) == 0);
  packets(f, AF_UNIX);
  packets(f, AF_INET);
  packets(f, AF_INET6);
  named_peers(f);
  backpressure(f);
  ownership();
  assert(f->root.cleanup(&f->root) == 0);
  free(f);
  return NULL;
}
int main(void) {
  pthread_t worker;
  assert(pthread_create(&worker, NULL, run, NULL) == 0 &&
         pthread_join(worker, NULL) == 0);
  return 0;
}
