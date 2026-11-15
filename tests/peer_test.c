/* Exercise the shipped application as separate processes, including rejection.
 * This is the controller; the example itself contains no test-only switches. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#include <c89cbor/lonejson.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static const char *application;
static char directory[] = "peer-test-XXXXXX";
static char files[2][4][256];
static void waited(pid_t pid, int success) {
  int status;
  assert(waitpid(pid, &status, 0) == pid);
  assert(WIFEXITED(status));
  assert((WEXITSTATUS(status) == 0) == success);
}
static pid_t start(const char *role, const char *transport, const char *address,
                   const char *extra, int output, int wrong_key) {
  pid_t pid = fork();
  size_t which = strcmp(role, "client") == 0 ? 0u : 1u;
  assert(pid >= 0);
  if (pid == 0) {
    if (output >= 0) {
      assert(dup2(output, STDOUT_FILENO) == STDOUT_FILENO);
      (void)close(output);
    }
    execl(application, application, role, transport, address, files[which][0],
          files[wrong_key ? which : 1u - which][1], files[which][2],
          files[1u - which][3], extra, (char *)NULL);
    _exit(127);
  }
  return pid;
}
static pid_t server(const char *transport, int count, char *address) {
  int descriptors[2];
  pid_t pid;
  char line[256], extra[16];
  size_t at = 0;
  struct pollfd p;
  ssize_t n;
  assert(pipe(descriptors) == 0);
  assert(fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) == 0);
  assert(snprintf(address, 256, "%s/socket", directory) > 0);
  if (strcmp(transport, "tcp") == 0 || strcmp(transport, "udp") == 0)
    strcpy(address, "0");
  assert(snprintf(extra, sizeof(extra), "%d", count) > 0);
  pid = start("server", transport, address, extra, descriptors[1], 0);
  assert(close(descriptors[1]) == 0);
  p.fd = descriptors[0];
  p.events = POLLIN;
  while (at < sizeof(line) - 1u) {
    assert(poll(&p, 1, 5000) == 1);
    n = read(descriptors[0], line + at, 1u);
    assert(n == 1);
    if (line[at++] == '\n')
      break;
  }
  line[at] = 0;
  assert(strncmp(line, "READY ", 6u) == 0 && at > 7u);
  line[at - 1u] = 0;
  strcpy(address, line + 6u);
  /* READY has been consumed. The application ignores SIGPIPE for closed peers.
   */
  assert(close(descriptors[0]) == 0);
  return pid;
}
static int connect_socket(const char *address, int type) {
  struct sockaddr_in a;
  struct timeval timeout;
  int fd = socket(AF_INET, type, 0);
  assert(fd >= 0);
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((unsigned short)atoi(address));
  assert(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
  assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
         0);
  return fd;
}
static void import_key(c89cbor *root, c89cbor_cose_key *key,
                       c89cbor_cose_key_kind kind, const char *path) {
  unsigned char raw[32];
  c89cbor_error error;
  FILE *file = fopen(path, "rb");
  assert(file != NULL && fread(raw, 1u, 32u, file) == 32u && fclose(file) == 0);
  assert(root->cose_key_init(root, key, kind, raw, 32u, NULL, 0, &error) == 0);
  memset(raw, 0, sizeof(raw));
}
static size_t token(unsigned char *wire, int bad_aad, int omit_exp,
                    int response, const void *id) {
  c89cbor root;
  c89cbor_cose_key sign, recipient, *keys[1];
  c89cbor_cwt cwt;
  c89cbor_cwt_options options;
  c89cbor_error error;
  lonejson_jwt_claims claims;
  size_t length;
  char issuer[] = "client", audience[] = "server";
  assert(c89cbor_init(&root, NULL, &error) == 0);
  import_key(&root, &sign, C89CBOR_COSE_ED25519_PRIVATE,
             files[response ? 1 : 0][0]);
  import_key(&root, &recipient, C89CBOR_COSE_X25519_PUBLIC,
             files[response ? 0 : 1][3]);
  options = root.default_cwt_options(&root);
  options.cose.encrypt = 1;
  options.cose.record_bytes = options.cose.header_bytes = 256;
  options.cose.aad = bad_aad ? "incorrect-aa" : "libcbor-peer";
  options.cose.aad_length = 12;
  assert(root.cwt_init(&root, &cwt, &options, &error) == 0);
  keys[0] = &recipient;
  assert(cwt.set_seal_keys(&cwt, &sign, keys, 1u, &error) == 0);
  memset(&claims, 0, sizeof(claims));
  claims.iss = response ? audience : issuer;
  claims.aud = response ? issuer : audience;
  claims.exp = (int64_t)time(NULL) + 60;
  claims.has_exp = !omit_exp;
  assert(cwt.set_lonejson(&cwt, &claims, id, 16u, &error) == 0);
  assert(cwt.seal(&cwt, wire, 1200u, &length, &error) == 0);
  assert(cwt.cleanup(&cwt) == 0 && recipient.cleanup(&recipient) == 0 &&
         sign.cleanup(&sign) == 0 && root.cleanup(&root) == 0);
  return length;
}
/* Authenticate a real request before correlating the test reply, so its keys,
 * AAD and ID are valid and missing exp is the only admission failure. */
static void request_id(const void *bytes, size_t length, unsigned char *id) {
  static const char *const algorithms[] = {"Ed25519"},
                           *const issuers[] = {"client"},
                           *const audiences[] = {"server"};
  c89cbor root;
  c89cbor_cwt cwt;
  c89cbor_cose_key verify, decrypt;
  c89cbor_cwt_options options;
  c89cbor_cwt_view view;
  c89cbor_error error;
  lonejson_jwt_claim_policy policy;
  assert(c89cbor_init(&root, NULL, &error) == 0);
  import_key(&root, &verify, C89CBOR_COSE_ED25519_PUBLIC, files[0][1]);
  import_key(&root, &decrypt, C89CBOR_COSE_X25519_PRIVATE, files[1][2]);
  options = root.default_cwt_options(&root);
  options.cose.record_bytes = options.cose.header_bytes = 256;
  options.cose.aad = "libcbor-peer";
  options.cose.aad_length = 12;
  options.require_cti = options.require_encryption = 1;
  assert(root.cwt_init(&root, &cwt, &options, &error) == 0);
  assert(cwt.set_verify_keys(&cwt, &verify, &decrypt, &error) == 0);
  memset(&policy, 0, sizeof(policy));
  policy.now = (int64_t)time(NULL);
  policy.accepted_algs = algorithms;
  policy.accepted_alg_count = 1;
  policy.accepted_issuers = issuers;
  policy.accepted_issuer_count = 1;
  policy.accepted_audiences = audiences;
  policy.accepted_audience_count = 1;
  assert(cwt.verify(&cwt, bytes, length, &policy, &error) == 0);
  assert(cwt.view_get(&cwt, &view) == 0 && view.claims->has_exp &&
         view.cti_length == 16u);
  memcpy(id, view.cti, 16u);
  assert(cwt.cleanup(&cwt) == 0 && verify.cleanup(&verify) == 0 &&
         decrypt.cleanup(&decrypt) == 0 && root.cleanup(&root) == 0);
}
static void missing_response_expiration(void) {
  struct sockaddr_in address, remote;
  struct timeval timeout;
  socklen_t size = sizeof(address), remote_size = sizeof(remote);
  unsigned char request[1200], reply[1200], id[16];
  char port[16];
  pid_t child;
  size_t length;
  ssize_t received;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(fd >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
  assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
  assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
         0);
  assert(snprintf(port, sizeof(port), "%u", (unsigned)ntohs(address.sin_port)) >
         0);
  child = start("client", "udp", port, NULL, -1, 0);
  received = recvfrom(fd, request, sizeof(request), 0,
                      (struct sockaddr *)&remote, &remote_size);
  assert(received > 0);
  request_id(request, (size_t)received, id);
  length = token(reply, 0, 1, 1, id);
  assert(sendto(fd, reply, length, 0, (struct sockaddr *)&remote,
                remote_size) == (ssize_t)length);
  waited(child, 0);
  assert(close(fd) == 0);
}
int main(int argc, char **argv) {
  static const char *const transports[] = {"tcp", "udp", "unix", "unixgram"};
  static const char *const names[] = {"sign.key", "sign.pub", "encrypt.key",
                                      "encrypt.pub"};
  char path[256], address[256];
  unsigned char wire[1201], reply[1200];
  uint32_t frame;
  pid_t pid, client;
  size_t i, j, length;
  int fd;
  assert(argc == 2);
  application = argv[1];
  assert(mkdtemp(directory) != NULL);
  for (i = 0; i < 2u; ++i) {
    assert(snprintf(path, sizeof(path), "%s/%s", directory,
                    i ? "server" : "client") > 0);
    assert(mkdir(path, 0700) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
      execl(application, application, "keygen", path, (char *)NULL);
      _exit(127);
    }
    waited(pid, 1);
    for (j = 0; j < 4u; ++j)
      assert(snprintf(files[i][j], sizeof(files[i][j]), "%s/%s", path,
                      names[j]) > 0);
  }
  for (i = 0; i < 4u; ++i) {
    pid = server(transports[i], 1, address);
    client = start("client", transports[i], address, "test message", -1, 0);
    waited(client, 1);
    waited(pid, 1);
    pid = server(transports[i], 1, address);
    client = start("client", transports[i], address, "wrong peer", -1, 1);
    waited(client, 0);
    waited(pid, 1); /* server succeeded; client distrusted reply */
  }
  missing_response_expiration();
  /* UDP failure modes use actual application sockets and crypto. */
  for (i = 0; i < 7u; ++i) {
    pid = server("udp", i == 3u ? 2 : 1, address);
    fd = connect_socket(address, SOCK_DGRAM);
    length = token(wire, i == 1u, i == 6u, 0, "0123456789abcdef");
    if (i == 0) {
      wire[0] = 0;
      length = 2;
    }
    if (i == 2)
      wire[length - 1u] ^= 1u;
    if (i == 4) {
      memset(wire, 0, sizeof(wire));
      length = sizeof(wire);
    }
    if (i == 5)
      length = 0;
    assert(send(fd, wire, length, 0) == (ssize_t)length);
    if (i == 3) {
      assert(recv(fd, reply, sizeof(reply), 0) > 0);
      assert(send(fd, wire, length, 0) == (ssize_t)length); /* replay */
    }
    waited(pid, 0);
    assert(close(fd) == 0);
  }
  for (i = 0; i < 3u; ++i) {
    pid = server("tcp", 1, address);
    fd = connect_socket(address, SOCK_STREAM);
    frame = htonl(i == 0 ? 1201u : i == 1 ? 100u : 0u);
    assert(write(fd, &frame, sizeof(frame)) == sizeof(frame));
    if (i == 1)
      assert(write(fd, "abc", 3u) == 3);
    assert(close(fd) == 0);
    waited(pid, 0);
  }
  pid = server("udp", 1, address);
  waited(pid, 0); /* no datagram: deadline */
  pid = server("tcp", 1, address);
  waited(pid, 0); /* no connection: deadline */
  client = start("client", "tcp", "0", NULL, -1, 0);
  waited(client, 0);
  /* Rejected client address must never become an owned cleanup path. The old
   * truncation path unlinked this pre-existing ordinary file before any bind.
   */
  length = strlen(directory);
  memcpy(address, directory, length);
  address[length++] = '/';
  memset(address + length, 'x', 107u - length);
  address[107] = 0;
  fd = open(address, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(fd >= 0);
  assert(write(fd, "keep", 4u) == 4 && close(fd) == 0);
  client = start("client", "unixgram", address, NULL, -1, 0);
  waited(client, 0);
  fd = open(address, O_RDONLY);
  assert(fd >= 0);
  assert(read(fd, reply, 4u) == 4 && memcmp(reply, "keep", 4u) == 0 &&
         close(fd) == 0);
  assert(unlink(address) == 0);
  for (i = 0; i < 2u; ++i) {
    for (j = 0; j < 4u; ++j)
      assert(unlink(files[i][j]) == 0);
    assert(snprintf(path, sizeof(path), "%s/%s", directory,
                    i ? "server" : "client") > 0);
    assert(rmdir(path) == 0);
  }
  assert(rmdir(directory) == 0);
  return 0;
}
