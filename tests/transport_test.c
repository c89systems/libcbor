#include <c89cbor/io.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void ready(int fd, short events) {
  struct pollfd p;
  int rc;
  p.fd = fd;
  p.events = events;
  p.revents = 0;
  do {
    rc = poll(&p, 1, 5000);
  } while (rc < 0 && errno == EINTR);
  assert(rc > 0 && !(p.revents & (POLLERR | POLLNVAL)));
}
static void nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL);
  assert(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}
static void pair(const char *kind, int fd[2], int *datagram) {
  int listen_fd, small = 1024;
  struct sockaddr_in address;
  socklen_t n = sizeof(address);
  *datagram = strcmp(kind, "udp") == 0          ? 1
              : strcmp(kind, "unix-dgram") == 0 ? 2
                                                : 0;
  if (strcmp(kind, "pipe") == 0) {
    assert(pipe(fd) == 0);
    return;
  }
  if (strncmp(kind, "unix", 4) == 0) {
    assert(socketpair(AF_UNIX, *datagram ? SOCK_DGRAM : SOCK_STREAM, 0, fd) ==
           0);
  } else {
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    listen_fd = socket(AF_INET, *datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    assert(listen_fd >= 0);
    assert(bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(getsockname(listen_fd, (struct sockaddr *)&address, &n) == 0);
    fd[1] = socket(AF_INET, *datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    assert(fd[1] >= 0);
    if (!*datagram)
      assert(listen(listen_fd, 1) == 0);
    assert(connect(fd[1], (struct sockaddr *)&address, sizeof(address)) == 0);
    if (*datagram)
      fd[0] = listen_fd;
    else {
      fd[0] = accept(listen_fd, NULL, NULL);
      assert(fd[0] >= 0);
      close(listen_fd);
    }
  }
  assert(setsockopt(fd[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
}
static void send_all(int fd, const void *bytes, size_t length) {
  const unsigned char *p = bytes;
  ssize_t n;
  while (length) {
    n = write(fd, p, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ready(fd, POLLOUT);
      continue;
    }
    assert(n > 0);
    p += n;
    length -= (size_t)n;
  }
}
static uint64_t decode(c89cbor_reader *r, const void *bytes, size_t length) {
  const unsigned char *p = bytes;
  c89cbor_event event;
  size_t used, at = 0, i;
  uint64_t count = 0;
  int rc;
  do {
    rc = c89cbor_reader_next(r, p + at, length - at, &used, &event);
    assert(rc >= 0);
    at += used;
    if (rc == C89CBOR_TOKEN && event.type == C89CBOR_RECORD_TOKEN &&
        event.token.type == C89CBOR_DATA) {
      const unsigned char *data = event.token.data;
      for (i = 0; i < event.token.length; ++i)
        assert(data[i] == 'x');
      count += event.token.length;
    }
  } while (rc == C89CBOR_TOKEN);
  assert(at == length);
  return count;
}
static void receive_stream(int fd, uint64_t total, int datagram, size_t message,
                           size_t fragment) {
  c89cbor_reader reader;
  unsigned char bytes[2048];
  uint64_t count = 0;
  ssize_t n;
  struct sockaddr_storage peer;
  socklen_t peer_length;
  unsigned char ack = 0;
  assert(c89cbor_reader_init(&reader, C89CBOR_SINGLE, 0) == 0);
  while (count < total) {
    peer_length = sizeof(peer);
    n = datagram == 1 ? recvfrom(fd, bytes, sizeof(bytes), 0,
                                 (struct sockaddr *)&peer, &peer_length)
                      : read(fd, bytes, datagram ? sizeof(bytes) : fragment);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ready(fd, POLLIN);
      continue;
    }
    assert(n > 0);
    if (datagram)
      assert(c89cbor_reader_init(&reader, C89CBOR_SINGLE, 0) == 0);
    count += decode(&reader, bytes, (size_t)n);
    if (datagram) {
      assert(c89cbor_reader_finish(&reader) == 0);
      assert(count % message == 0);
      if (datagram == 1)
        assert(sendto(fd, &ack, 1, 0, (struct sockaddr *)&peer, peer_length) ==
               1);
      else
        send_all(fd, &ack, 1);
    }
  }
  assert(count == total && c89cbor_reader_finish(&reader) == 0);
}
static void stream(int fd, uint64_t total, size_t message, int datagram) {
  c89cbor_encoder e;
  c89cbor_token t;
  unsigned char payload[1024], bytes[2048];
  uint64_t sent = 0;
  size_t written, length = 0;
  int rc;
  unsigned char ack;
  ssize_t received;
  memset(payload, 'x', sizeof(payload));
  if (datagram) {
    assert(c89cbor_encoder_init(&e, NULL, 0, 0) == 0);
    memset(&t, 0, sizeof(t));
    t.type = C89CBOR_BYTES;
    t.argument = message;
    assert(c89cbor_encoder_put(&e, &t) == 0);
    assert(c89cbor_encoder_read(&e, bytes, sizeof(bytes), &length) == 0);
    memset(bytes + length, 'x', message);
    length += message;
    while (sent < total) {
      send_all(fd, bytes, length);
      sent += message;
      ready(fd, POLLIN);
      do {
        received = read(fd, &ack, 1);
      } while (received < 0 && errno == EINTR);
      assert(received == 1);
    }
    return;
  }
  assert(c89cbor_encoder_init(&e, NULL, 0, 0) == 0);
  memset(&t, 0, sizeof(t));
  t.type = C89CBOR_BYTES;
  t.argument = total;
  for (;;) {
    assert(c89cbor_encoder_put(&e, &t) == 0);
    do {
      rc = c89cbor_encoder_read(&e, bytes, sizeof(bytes), &written);
      assert(rc >= 0);
      send_all(fd, bytes, written);
    } while (rc == C89CBOR_OUTPUT);
    if (t.type == C89CBOR_END)
      break;
    memset(&t, 0, sizeof(t));
    if (sent < total) {
      t.type = C89CBOR_DATA;
      t.data = payload;
      t.length = total - sent < sizeof(payload) ? (size_t)(total - sent)
                                                : sizeof(payload);
      sent += t.length;
    } else {
      t.type = C89CBOR_END;
      t.argument = C89CBOR_BYTES;
    }
  }
  assert(c89cbor_encoder_finish(&e) == 0);
}
int main(int argc, char **argv) {
  int fd[2], datagram, status;
  pid_t child;
  uint64_t total;
  struct timespec begin, end;
  const char *kind = argc > 1 ? argv[1] : "unix";
  size_t message = 512;
  total = argc > 2 ? (uint64_t)strtoul(argv[2], NULL, 10) : 1024U * 1024U;
  assert(total > 0 && total % message == 0);
  signal(SIGPIPE, SIG_IGN);
  pair(kind, fd, &datagram);
  nonblock(fd[0]);
  nonblock(fd[1]);
  /* Datagram fixtures acknowledge each independently decoded item. This is a
   * benchmark fixture's pacing, not a product reliability protocol. */
  child = fork();
  assert(child >= 0);
  if (child == 0) {
    close(fd[1]);
    receive_stream(fd[0], total, datagram, message, argc > 2 ? 2048U : 37U);
    close(fd[0]);
    _exit(0);
  }
  assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
  close(fd[0]);
  stream(fd[1], total, message, datagram);
  close(fd[1]);
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  printf("{\"transport\":\"%s\",\"payload_bytes\":%lu,\"seconds\":%.9f,"
         "\"verified\":true}\n",
         kind, (unsigned long)total,
         (double)(end.tv_sec - begin.tv_sec) +
             (double)(end.tv_nsec - begin.tv_nsec) / 1e9);
  return 0;
}
