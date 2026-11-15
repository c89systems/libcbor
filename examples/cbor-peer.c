/* A bounded authenticated request/reply application. See docs/standalone.md.
 * This deliberately blocking example is independent of cai and uses public API.
 */
#include <c89cbor/lonejson.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define WIRE_BOUND 1200u

typedef struct peer {
  c89cbor root;
  c89cbor_cose_key signing, verification, decryption, recipient;
  c89cbor_cwt token;
  c89cbor_datagram datagram;
  unsigned char input[WIRE_BOUND], output[WIRE_BOUND], claims[256], id[16],
      last[16];
  int have_last, server;
} peer;
static int fail(const char *what) {
  fprintf(stderr, "cbor-peer: %s\n", what);
  return 1;
}
static void erase(void *bytes, size_t length) {
  volatile unsigned char *p = bytes;
  while (length-- != 0)
    *p++ = 0;
}
static int entropy(void *bytes, size_t size) {
  int fd = open("/dev/urandom", O_RDONLY);
  size_t at = 0;
  ssize_t n;
  if (fd < 0)
    return -1;
  while (at < size) {
    n = read(fd, (unsigned char *)bytes + at, size - at);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      (void)close(fd);
      return -1;
    }
    at += (size_t)n;
  }
  return close(fd);
}
static int key_file(const char *path, unsigned char *bytes) {
  int fd = open(path, O_RDONLY);
  size_t at = 0;
  ssize_t n;
  unsigned char extra;
  if (fd < 0)
    return -1;
  while (at < 32u) {
    n = read(fd, bytes + at, 32u - at);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    at += (size_t)n;
  }
  do {
    n = read(fd, &extra, 1u);
  } while (n < 0 && errno == EINTR);
  (void)close(fd);
  return at == 32u && n == 0 ? 0 : -1;
}
static int generate(const char *directory) {
  static const char *const names[] = {"sign.key", "sign.pub", "encrypt.key",
                                      "encrypt.pub"};
  c89cbor root;
  c89cbor_cose_key key;
  c89cbor_error error;
  unsigned char secret[32], public_bytes[32];
  char path[512];
  size_t length, i, j;
  int fd, status = c89cbor_init(&root, NULL, &error);
  if (status != 0)
    return fail("cannot initialize libcbor");
  for (i = 0; i < 2u && status == 0; ++i) {
    if (entropy(secret, sizeof(secret)) != 0) {
      erase(secret, sizeof(secret));
      status = -1;
      break;
    }
    status = root.cose_key_init(&root, &key,
                                i == 0 ? C89CBOR_COSE_ED25519_PRIVATE
                                       : C89CBOR_COSE_X25519_PRIVATE,
                                secret, 32u, NULL, 0, &error);
    if (status != 0) {
      erase(secret, sizeof(secret));
      break;
    }
    status = key.public_key(&key, public_bytes, sizeof(public_bytes), &length);
    for (j = 0; j < 2u && status == 0; ++j) {
      fd = snprintf(path, sizeof(path), "%s/%s", directory, names[i * 2u + j]);
      if (fd < 0 || (size_t)fd >= sizeof(path)) {
        status = -1;
        break;
      }
      fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) {
        status = -1;
        break;
      }
      if (write(fd, j ? public_bytes : secret, 32u) != 32)
        status = -1;
      if (close(fd) != 0)
        status = -1;
    }
    erase(secret, sizeof(secret));
    (void)key.cleanup(&key);
  }
  (void)root.cleanup(&root);
  return status == 0 ? 0
                     : fail("key generation failed; files are never "
                            "overwritten; inspect partial output");
}
static int admit(void *context, const c89cbor_cwt_view *view) {
  peer *p = context;
  if (view->cti_length != sizeof(p->id))
    return C89CBOR_AUTH;
  if (!p->server && memcmp(view->cti, p->id, sizeof(p->id)) != 0)
    return C89CBOR_AUTH;
  if (p->server && p->have_last &&
      memcmp(view->cti, p->last, sizeof(p->last)) == 0)
    return C89CBOR_AUTH;
  if (p->server) {
    memcpy(p->last, view->cti, sizeof(p->last));
    memcpy(p->id, view->cti, sizeof(p->id));
    p->have_last = 1;
  }
  return 0;
}
static int prepare(peer *p, char **files) {
  static const c89cbor_cose_key_kind kinds[] = {
      C89CBOR_COSE_ED25519_PRIVATE, C89CBOR_COSE_ED25519_PUBLIC,
      C89CBOR_COSE_X25519_PRIVATE, C89CBOR_COSE_X25519_PUBLIC};
  c89cbor_cose_key *keys[4], *recipients[1];
  c89cbor_error error;
  c89cbor_cwt_options options;
  unsigned char raw[32];
  size_t i;
  int status;
  status = c89cbor_init(&p->root, NULL, &error);
  if (status != 0)
    return status;
  keys[0] = &p->signing;
  keys[1] = &p->verification;
  keys[2] = &p->decryption;
  keys[3] = &p->recipient;
  for (i = 0; i < 4u; ++i) {
    if (key_file(files[i], raw) != 0) {
      erase(raw, sizeof(raw));
      return C89CBOR_IO;
    }
    status = p->root.cose_key_init(&p->root, keys[i], kinds[i], raw, 32u, NULL,
                                   0, &error);
    erase(raw, sizeof(raw));
    if (status != 0)
      return status;
  }
  options = p->root.default_cwt_options(&p->root);
  options.cose.record_bytes = 256;
  options.cose.header_bytes = 256;
  options.cose.encrypt = 1;
  options.cose.aad = "libcbor-peer";
  options.cose.aad_length = 12;
  options.require_encryption = options.require_cti = 1;
  options.admit = admit;
  options.context = p;
  status = p->root.cwt_init(&p->root, &p->token, &options, &error);
  recipients[0] = &p->recipient;
  if (status == 0)
    status =
        p->token.set_seal_keys(&p->token, &p->signing, recipients, 1u, &error);
  if (status == 0)
    status = p->token.set_verify_keys(&p->token, &p->verification,
                                      &p->decryption, &error);
  return status;
}
static int emit(c89cbor_encoder *e, unsigned char *bytes, size_t *length,
                c89cbor_type type, uint64_t argument, const void *data,
                size_t count) {
  c89cbor_token token;
  size_t used;
  int status;
  memset(&token, 0, sizeof(token));
  token.type = type;
  token.argument = argument;
  token.data = data;
  token.length = count;
  status = e->put(e, &token);
  if (status == 0)
    status = e->read(e, bytes + *length, 256u - *length, &used);
  else
    used = 0;
  *length += used;
  return status == C89CBOR_OK ? 0 : status;
}
static int seal(peer *p, const char *message, size_t *written) {
  c89cbor_encoder encoder;
  c89cbor_error error;
  size_t length = 0;
  int status;
  time_t now = time(NULL);
  const char *issuer = p->server ? "server" : "client";
  const char *audience = p->server ? "client" : "server";
  if (now < 0 || strlen(message) > 64u)
    return C89CBOR_LIMIT;
  status = c89cbor_encoder_init(NULL, &encoder, NULL, 0, 0);
#define EMIT(t, a, d, n)                                                       \
  do {                                                                         \
    if (status == 0)                                                           \
      status = emit(&encoder, p->claims, &length, t, a, d, n);                 \
  } while (0)
#define TEXT(s)                                                                \
  do {                                                                         \
    EMIT(C89CBOR_TEXT, strlen(s), NULL, 0);                                    \
    EMIT(C89CBOR_DATA, 0, s, strlen(s));                                       \
    EMIT(C89CBOR_END, C89CBOR_TEXT, NULL, 0);                                  \
  } while (0)
  EMIT(C89CBOR_MAP, 5, NULL, 0);
  EMIT(C89CBOR_UINT, 1, NULL, 0);
  TEXT(issuer);
  EMIT(C89CBOR_UINT, 3, NULL, 0);
  TEXT(audience);
  EMIT(C89CBOR_UINT, 4, NULL, 0);
  EMIT(C89CBOR_UINT, (uint64_t)now + 60u, NULL, 0);
  EMIT(C89CBOR_UINT, 7, NULL, 0);
  EMIT(C89CBOR_BYTES, 16, NULL, 0);
  EMIT(C89CBOR_DATA, 0, p->id, 16);
  EMIT(C89CBOR_END, C89CBOR_BYTES, NULL, 0);
  TEXT("msg");
  TEXT(message);
  EMIT(C89CBOR_END, C89CBOR_MAP, NULL, 0);
#undef TEXT
#undef EMIT
  (void)encoder.cleanup(&encoder);
  if (status == 0)
    status = p->token.set_claims(&p->token, p->claims, length, &error);
  return status == 0 ? p->token.seal(&p->token, p->output, sizeof(p->output),
                                     written, &error)
                     : status;
}
static int verify(peer *p, const void *bytes, size_t length) {
  static const char *const algorithms[] = {"Ed25519"},
                           *const server[] = {"server"},
                           *const client[] = {"client"},
                           *const required[] = {"exp"};
  lonejson_jwt_claim_policy policy;
  c89cbor_error error;
  memset(&policy, 0, sizeof(policy));
  policy.now = (int64_t)time(NULL);
  policy.accepted_algs = algorithms;
  policy.accepted_alg_count = 1;
  policy.accepted_issuers = p->server ? client : server;
  policy.accepted_issuer_count = 1;
  policy.accepted_audiences = p->server ? server : client;
  policy.accepted_audience_count = 1;
  policy.required_claims = required;
  policy.required_claim_count = 1;
  return p->token.verify(&p->token, bytes, length, &policy, &error);
}
static int exact(int fd, void *bytes, size_t length, int writing) {
  unsigned char *p = bytes;
  ssize_t n;
  while (length != 0) {
    n = writing ? write(fd, p, length) : read(fd, p, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return C89CBOR_IO;
    p += n;
    length -= (size_t)n;
  }
  return 0;
}
static int frame(peer *p, int fd, int writing, size_t *length) {
  uint32_t n;
  int status;
  if (writing)
    n = htonl((uint32_t)*length);
  status = exact(fd, &n, sizeof(n), writing);
  if (status != 0)
    return status;
  if (!writing)
    *length = (size_t)ntohl(n);
  if (*length == 0 || *length > WIRE_BOUND)
    return C89CBOR_LIMIT;
  return exact(fd, writing ? p->output : p->input, *length, writing);
}
static int sockets(const char *transport, const char *address, int server,
                   int *datagram, char *local, size_t local_size) {
  struct sockaddr_un un;
  struct sockaddr_in ip;
  struct sockaddr *socket_address;
  struct timeval timeout;
  struct pollfd ready;
  socklen_t address_length;
  int fd, accepted, domain, bound = 0;
  unsigned long port;
  *datagram =
      strcmp(transport, "udp") == 0 || strcmp(transport, "unixgram") == 0;
  domain = strcmp(transport, "unix") == 0 || strcmp(transport, "unixgram") == 0
               ? AF_UNIX
               : AF_INET;
  if (domain == AF_UNIX) {
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    if (strlen(address) >= sizeof(un.sun_path))
      return -1;
    strcpy(un.sun_path, address);
    socket_address = (struct sockaddr *)&un;
    address_length = sizeof(un);
  } else {
    char *end;
    port = strtoul(address, &end, 10);
    if (*address == 0 || *end != 0 || port > 65535u)
      return -1;
    memset(&ip, 0, sizeof(ip));
    ip.sin_family = AF_INET;
    ip.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, "127.0.0.1", &ip.sin_addr) != 1)
      return -1;
    socket_address = (struct sockaddr *)&ip;
    address_length = sizeof(ip);
  }
  fd = socket(domain, *datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
    goto failed;
  if (server) {
    if (bind(fd, socket_address, address_length) != 0)
      goto failed;
    bound = 1;
    if (domain == AF_UNIX) {
      strcpy(local, address);
    }
    if (!*datagram && listen(fd, 1) != 0)
      goto failed;
    if (domain == AF_INET) {
      address_length = sizeof(ip);
      if (getsockname(fd, (struct sockaddr *)&ip, &address_length) != 0)
        goto failed;
      printf("READY %u\n", (unsigned)ntohs(ip.sin_port));
    } else
      printf("READY %s\n", address);
    fflush(stdout);
    if (!*datagram) {
      ready.fd = fd;
      ready.events = POLLIN;
      if (poll(&ready, 1, 3000) != 1)
        goto failed;
      accepted = accept(fd, NULL, NULL);
      if (accepted < 0)
        goto failed;
      (void)close(fd);
      fd = accepted;
      if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) !=
              0 ||
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) !=
              0)
        goto failed;
    }
  } else {
    if (*datagram && domain == AF_UNIX) {
      struct sockaddr_un client_address;
      memset(&client_address, 0, sizeof(client_address));
      client_address.sun_family = AF_UNIX;
      accepted =
          snprintf(client_address.sun_path, sizeof(client_address.sun_path),
                   "%s.client.%lu", address, (unsigned long)getpid());
      if (accepted < 0 || (size_t)accepted >= sizeof(client_address.sun_path) ||
          (size_t)accepted >= local_size)
        goto failed;
      if (bind(fd, (struct sockaddr *)&client_address,
               sizeof(client_address)) != 0) {
        goto failed;
      }
      strcpy(local, client_address.sun_path);
      bound = 1;
    }
    if (connect(fd, socket_address, address_length) != 0)
      goto failed;
  }
  return fd;
failed:
  (void)close(fd);
  if (bound && local[0]) {
    (void)unlink(local);
    local[0] = 0;
  }
  return -1;
}
int main(int argc, char **argv) {
  peer *p;
  c89cbor_datagram_message message;
  c89cbor_error error;
  char local[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
  int fd = -1, datagram = 0, status = 0, count = 1, i;
  size_t length = 0;
  if (argc == 3 && strcmp(argv[1], "keygen") == 0)
    return generate(argv[2]);
  if ((argc != 8 && argc != 9) ||
      (strcmp(argv[1], "server") != 0 && strcmp(argv[1], "client") != 0) ||
      (strcmp(argv[2], "tcp") != 0 && strcmp(argv[2], "udp") != 0 &&
       strcmp(argv[2], "unix") != 0 && strcmp(argv[2], "unixgram") != 0))
    return fail("usage: cbor-peer keygen EXISTING_DIRECTORY | {server|client} "
                "{tcp|udp|unix|unixgram} PORT_OR_PATH SIGN_KEY PEER_SIGN_PUB "
                "ENCRYPT_KEY PEER_ENCRYPT_PUB [COUNT|MESSAGE]");
  p = calloc(1, sizeof(*p));
  if (p == NULL)
    return fail("out of memory");
  p->server = strcmp(argv[1], "server") == 0;
  if (p->server && argc == 9) {
    count = atoi(argv[8]);
    if (count < 1 || count > 1000)
      status = C89CBOR_INVALID;
  }
  if (status == 0)
    status = prepare(p, argv + 4);
  (void)signal(SIGPIPE, SIG_IGN);
  if (status == 0) {
    fd = sockets(argv[2], argv[3], p->server, &datagram, local, sizeof(local));
    if (fd < 0)
      status = C89CBOR_IO;
  }
  if (status == 0 && datagram)
    status =
        p->root.datagram_init(&p->root, &p->datagram, fd, WIRE_BOUND, &error);
  if (status == 0 && !p->server && entropy(p->id, sizeof(p->id)) != 0)
    status = C89CBOR_IO;
  for (i = 0; i < count && status == 0; ++i) {
    if (!p->server) {
      status = seal(p, argc == 9 ? argv[8] : "hello", &length);
      if (status == 0)
        status = datagram ? p->datagram.send(&p->datagram, p->output, length,
                                             NULL, 0, &error)
                          : frame(p, fd, 1, &length);
    }
    if (status == 0) {
      if (datagram) {
        status = p->datagram.receive(&p->datagram, &message, &error);
        if (status == 0)
          status = verify(p, message.bytes, message.length);
        if (status == 0 && p->server)
          status = p->datagram.set_peer(&p->datagram, message.peer,
                                        message.peer_length);
      } else {
        status = frame(p, fd, 0, &length);
        if (status == 0)
          status = verify(p, p->input, length);
      }
    }
    if (status == 0 && p->server) {
      status = seal(p, "acknowledged", &length);
      if (status == 0)
        status = datagram ? p->datagram.send(&p->datagram, p->output, length,
                                             NULL, 0, &error)
                          : frame(p, fd, 1, &length);
    }
  }
  if (status == 0)
    puts(p->server ? "request authenticated; response sent"
                   : "response authenticated and correlated");
  else
    fprintf(stderr, "cbor-peer: %s (errno=%d)\n",
            c89cbor_status_string(&p->root, status), errno);
  if (p->datagram.state != NULL)
    (void)p->datagram.cleanup(&p->datagram);
  if (p->token.state != NULL)
    (void)p->token.cleanup(&p->token);
  if (p->recipient.state != NULL)
    (void)p->recipient.cleanup(&p->recipient);
  if (p->decryption.state != NULL)
    (void)p->decryption.cleanup(&p->decryption);
  if (p->verification.state != NULL)
    (void)p->verification.cleanup(&p->verification);
  if (p->signing.state != NULL)
    (void)p->signing.cleanup(&p->signing);
  (void)p->root.cleanup(&p->root);
  if (fd >= 0)
    (void)close(fd);
  if (local[0])
    (void)unlink(local);
  free(p);
  return status == 0 ? 0 : 1;
}
