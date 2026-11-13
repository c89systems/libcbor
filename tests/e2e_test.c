#include <c89cbor/lonejson.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct buffer {
  unsigned char bytes[16384];
  size_t length, offset;
} buffer;
typedef struct fixture {
  buffer input, output, wire, http;
  c89cbor root;
} fixture;
static int read_buffer(void *context, void *bytes, size_t capacity,
                       size_t *count) {
  buffer *b = context;
  size_t n = b->length - b->offset;
  if (n > capacity)
    n = capacity;
  memcpy(bytes, b->bytes + b->offset, n);
  b->offset += n;
  *count = n;
  return 0;
}
static int write_buffer(void *context, const void *bytes, size_t length,
                        size_t *count) {
  buffer *b = context;
  *count = 0;
  if (length > sizeof(b->bytes) - b->length)
    return C89CBOR_LIMIT;
  memcpy(b->bytes + b->length, bytes, length);
  b->length += length;
  *count = length;
  return 0;
}
static void send_bytes(int fd, const void *bytes, size_t length) {
  const unsigned char *p = bytes;
  ssize_t count;
  while (length) {
    count = send(fd, p, length, 0);
    assert(count > 0);
    p += count;
    length -= (size_t)count;
  }
}
static int peer(fixture *f, int port, const char *action, const char *family,
                const buffer *input, buffer *output, int wrong_aad) {
  struct sockaddr_in address;
  struct timeval timeout;
  char header[512], *end;
  size_t used = 0, body;
  ssize_t count;
  int fd, status;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons((unsigned short)port);
  assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
  fd = socket(AF_INET, SOCK_STREAM, 0);
  assert(fd >= 0);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
         0);
  assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
         0);
  assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
  status = snprintf(header, sizeof(header),
                    "POST /%s/%s HTTP/1.0\r\nHost: "
                    "localhost\r\nContent-Length: %lu\r\nX-AAD: %s\r\n\r\n",
                    action, family, (unsigned long)input->length,
                    wrong_aad ? "00" : "6c696263626f722d653265");
  assert(status > 0 && (size_t)status < sizeof(header));
  send_bytes(fd, header, (size_t)status);
  send_bytes(fd, input->bytes, input->length);
  while ((count = read(fd, f->http.bytes + used,
                       sizeof(f->http.bytes) - 1u - used)) > 0) {
    used += (size_t)count;
    assert(used < sizeof(f->http.bytes) - 1u);
  }
  assert(count == 0);
  assert(close(fd) == 0);
  f->http.bytes[used] = 0;
  assert(sscanf((const char *)f->http.bytes, "HTTP/%*s %d", &status) == 1);
  end = strstr((char *)f->http.bytes, "\r\n\r\n");
  assert(end != NULL);
  body = (size_t)(end + 4 - (char *)f->http.bytes);
  output->length = used - body;
  output->offset = 0;
  memcpy(output->bytes, f->http.bytes + body, output->length);
  return status;
}
static int native(fixture *f, int family, int seal, c89cbor_cose_key *key,
                  c89cbor_cose_key *const *recipients, buffer *input,
                  buffer *output) {
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_cose_options options;
  c89cbor_error error;
  source.context = input;
  source.read = read_buffer;
  sink.context = output;
  sink.write = write_buffer;
  input->offset = 0;
  output->length = output->offset = 0;
  options = f->root.default_cose_options(&f->root);
  options.aad = "libcbor-e2e";
  options.aad_length = 11;
  if (family < 3) {
    if (!seal)
      return f->root.cose_decrypt(&f->root, &source, &sink, key, &options,
                                  &error);
    if (family == 0)
      return f->root.cose_encrypt0(&f->root, &source, &sink, key, &options,
                                   &error);
    return f->root.cose_encrypt(&f->root, &source, &sink, recipients, 2u,
                                &options, &error);
  }
  return (family == 5 ? seal ? f->root.cose_mac0 : f->root.cose_verify_mac0
          : seal      ? f->root.cose_sign1
                      : f->root.cose_verify1)(&f->root, &source, &sink, key,
                                         &options, &error);
}
static void tamper(buffer *wire) {
  c89cbor_decoder decoder;
  c89cbor_token token;
  size_t offset = 0, used, blobs = 0;
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  do {
    assert(decoder.next(&decoder, wire->bytes + offset, wire->length - offset,
                        &used, &token) == C89CBOR_TOKEN);
    offset += used;
    if (token.type == C89CBOR_DATA && ++blobs == 3u) {
      assert(token.length != 0);
      wire->bytes[(size_t)((const unsigned char *)token.data - wire->bytes)] ^=
          1u;
      break;
    }
  } while (offset < wire->length);
  assert(blobs == 3u);
  assert(decoder.cleanup(&decoder) == 0);
}
int main(void) {
  static const char *const names[] = {"gcm", "kw", "x", "ed", "p256", "hmac"};
  static const c89cbor_cose_key_kind kinds[] = {
      C89CBOR_COSE_A256GCM,        C89CBOR_COSE_A256KW,
      C89CBOR_COSE_X25519_PRIVATE, C89CBOR_COSE_ED25519_PRIVATE,
      C89CBOR_COSE_P256_PRIVATE,   C89CBOR_COSE_HMAC256};
  static const char *const algs[] = {"Ed25519", "ES256", "HS256"};
  static const char *const issuers[] = {"i"}, *const audiences[] = {"a"};
  static const unsigned char claims[] = {
      0xa3, 1, 0x61, 'i', 3, 0x61, 'a', 4, 0x1a, 0xf4, 0x86, 0x57, 0x00};
  fixture *f;
  c89cbor_cose_key keys[6], public_key, *recipients[2];
  c89cbor_cwt token;
  c89cbor_cwt_options options;
  lonejson_jwt_claim_policy policy;
  c89cbor_error error;
  c89cbor_cwt_view view;
  unsigned char raw[32], public_bytes[32];
  size_t i, j, length;
  char name[32];
  const char *port_text = getenv("C89CBOR_E2E_PORT");
  int port;
  if (port_text == NULL)
    return 77;
  port = atoi(port_text);
  assert(port > 0 && port < 65536);
  f = calloc(1, sizeof(*f));
  assert(f != NULL);
  assert(c89cbor_init(&f->root, NULL, &error) == 0);
  memset(raw, 0, sizeof(raw));
  raw[31] = 1;
  for (i = 0; i < 6u; ++i)
    assert(f->root.cose_key_init(&f->root, &keys[i], kinds[i], raw, 32u, NULL,
                                 0, &error) == 0);
  assert(keys[2].public_key(&keys[2], public_bytes, 32u, &length) == 0);
  assert(f->root.cose_key_init(&f->root, &public_key,
                               C89CBOR_COSE_X25519_PUBLIC, public_bytes, length,
                               NULL, 0, &error) == 0);
  f->input.length = sizeof(claims);
  memcpy(f->input.bytes, claims, sizeof(claims));
  for (i = 0; i < 6u; ++i) {
    recipients[0] = recipients[1] = i == 2 ? &public_key : &keys[i];
    assert(native(f, (int)i, 1, &keys[i], recipients, &f->input, &f->wire) ==
           0);
    assert(peer(f, port, "open", names[i], &f->wire, &f->output, 0) == 200);
    assert(f->output.length == f->input.length &&
           memcmp(f->input.bytes, f->output.bytes, f->input.length) == 0);
    assert(peer(f, port, "open", names[i], &f->wire, &f->output, 1) == 422);
    tamper(&f->wire);
    assert(peer(f, port, "open", names[i], &f->wire, &f->output, 0) == 422);
    assert(peer(f, port, "seal", names[i], &f->input, &f->wire, 0) == 200);
    assert(native(f, (int)i, 0, &keys[i], NULL, &f->wire, &f->output) == 0);
    assert(f->output.length == f->input.length &&
           memcmp(f->input.bytes, f->output.bytes, f->input.length) == 0);
    tamper(&f->wire);
    assert(native(f, (int)i, 0, &keys[i], NULL, &f->wire, &f->output) < 0 &&
           f->output.length == 0);
  }
  memset(&policy, 0, sizeof(policy));
  policy.now = 1700000000;
  policy.accepted_algs = algs;
  policy.accepted_alg_count = 3;
  policy.accepted_issuers = issuers;
  policy.accepted_issuer_count = 1;
  policy.accepted_audiences = audiences;
  policy.accepted_audience_count = 1;
  for (i = 3; i < 6u; ++i)
    for (j = 0; j < 3u; ++j) {
      options = f->root.default_cwt_options(&f->root);
      options.cose.encrypt = j != 0;
      options.cose.aad = "libcbor-e2e";
      options.cose.aad_length = 11;
      assert(f->root.cwt_init(&f->root, &token, &options, &error) == 0);
      recipients[0] = j == 2 ? &public_key : &keys[j];
      assert(token.set_seal_keys(&token, &keys[i], recipients, 1u, &error) ==
             0);
      assert(token.set_verify_keys(&token, &keys[i], &keys[j], &error) == 0);
      assert(token.set_claims(&token, claims, sizeof(claims), &error) == 0);
      assert(token.seal(&token, f->wire.bytes, sizeof(f->wire.bytes),
                        &f->wire.length, &error) == 0);
      assert(snprintf(name, sizeof(name), "cwt-%s-%s", names[i], names[j]) > 0);
      assert(peer(f, port, "open", name, &f->wire, &f->output, 0) == 200);
      assert(f->output.length == sizeof(claims) &&
             memcmp(f->output.bytes, claims, sizeof(claims)) == 0);
      assert(peer(f, port, "seal", name, &f->input, &f->wire, 0) == 200);
      assert(token.verify(&token, f->wire.bytes, f->wire.length, &policy,
                          &error) == 0);
      assert(token.view_get(&token, &view) == 0 && view.authenticated);
      policy.now = 4102444800LL;
      assert(token.verify(&token, f->wire.bytes, f->wire.length, &policy,
                          &error) == C89CBOR_AUTH);
      policy.now = 1700000000;
      assert(token.cleanup(&token) == 0);
    }
  assert(public_key.cleanup(&public_key) == 0);
  for (i = 0; i < 6u; ++i)
    assert(keys[i].cleanup(&keys[i]) == 0);
  assert(f->root.cleanup(&f->root) == 0);
  free(f);
  puts("COSE/CWT bidirectional peer and rejection checks passed");
  return 0;
}
