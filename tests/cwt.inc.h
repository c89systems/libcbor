#include <sys/uio.h>
typedef struct cwt_admission {
  c89cbor_cwt *receiver;
  size_t calls;
  int reject;
} cwt_admission;
static void cwt_corrupt_payload(buffer *wire) {
  c89cbor_decoder decoder;
  c89cbor_token token;
  size_t offset = 0, used;
  int status;
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  do {
    status = decoder.next(&decoder, wire->bytes + offset, wire->length - offset,
                          &used, &token);
    offset += used;
    assert(status == C89CBOR_TOKEN);
    if (token.type == C89CBOR_DATA && token.length >= 32u) {
      wire->bytes[(size_t)((const unsigned char *)token.data - wire->bytes)] ^=
          1u;
      break;
    }
  } while (1);
  assert(decoder.cleanup(&decoder) == 0);
}
static int cwt_admit(void *context, const c89cbor_cwt_view *view) {
  cwt_admission *admission = context;
  c89cbor_cwt_view hidden;
  ++admission->calls;
  assert(view->authenticated && view->cti_length == 3u);
  assert(memcmp(view->cti, "\0id", 3u) == 0);
  assert(admission->receiver->view_get(admission->receiver, &hidden) ==
         C89CBOR_BUSY);
  assert(admission->receiver->cleanup(admission->receiver) == C89CBOR_BUSY);
  return admission->reject ? C89CBOR_AUTH : C89CBOR_OK;
}
static void cwt_transport(fixture *f, c89cbor_cwt *receiver,
                          c89cbor_cose_key *verification,
                          c89cbor_cose_key *decryption,
                          const lonejson_jwt_claim_policy *policy) {
  static const int domains[] = {0, AF_UNIX, AF_INET, AF_INET};
  static const int types[] = {SOCK_STREAM, SOCK_STREAM, SOCK_STREAM,
                              SOCK_DGRAM};
  c89cbor_cwt_view view;
  c89cbor_error error;
  struct msghdr message;
  struct iovec vector;
  int pair[2];
  size_t i, sent, received, take;
  ssize_t count;
  for (i = 0; i < 4u; ++i) {
    cose_socket_pair(domains[i], types[i], pair);
    sent = 0;
    do {
      count = write(pair[0], f->wire.bytes + sent, f->wire.length - sent);
      assert(count > 0);
      sent += (size_t)count;
    } while (sent < f->wire.length);
    received = 0;
    if (types[i] == SOCK_DGRAM) {
      memset(&message, 0, sizeof(message));
      vector.iov_base = f->output.bytes;
      vector.iov_len = sizeof(f->output.bytes);
      message.msg_iov = &vector;
      message.msg_iovlen = 1;
      count = recvmsg(pair[1], &message, 0);
      assert(count > 0 && !(message.msg_flags & MSG_TRUNC));
      received = (size_t)count;
    } else
      while (received < f->wire.length) {
        take = f->wire.length - received;
        if (take > 13u)
          take = 13u;
        count = read(pair[1], f->output.bytes + received, take);
        assert(count > 0);
        received += (size_t)count;
      }
    assert(received == f->wire.length &&
           memcmp(f->wire.bytes, f->output.bytes, received) == 0);
    assert(receiver->verify(receiver, f->output.bytes, received, verification,
                            decryption, policy, &error) == 0);
    assert(receiver->view_get(receiver, &view) == 0 && view.authenticated);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
  }
}
static void cwt_tokens(fixture *f) {
  static const char *const algorithms[] = {"Ed25519", "ES256", "HS256"};
  static const char *const issuers[] = {"issuer"};
  static const char *const audiences[] = {"service"};
  static const char *const required[] = {"sub", "exp"};
  char issuer[] = "issuer", subject[] = "subject", audience[] = "service";
  char nonce[] = "challenge", scope[] = "read write", azp[] = "client";
  char alternate[] = "other", *array[2];
  lonejson_jwt_claims claims;
  lonejson_jwt_claim_policy policy;
  c89cbor_cwt_options options = c89cbor_default_cwt_options();
  c89cbor_cwt caller, *token;
  c89cbor_cwt_view view;
  c89cbor_cose_key signing, verifying, *recipients[2];
  c89cbor_cose_key_info info;
  c89cbor_error error;
  c89cbor_token label;
  cwt_admission admission;
  unsigned char raw[32], public_bytes[65];
  const void *value;
  size_t written, length, value_length, calls;
  int algorithm, encryption, allocated;
  memset(&claims, 0, sizeof(claims));
  claims.iss = issuer;
  claims.sub = subject;
  claims.aud = audience;
  claims.nonce = nonce;
  claims.scope = scope;
  claims.azp = azp;
  claims.has_exp = claims.has_nbf = claims.has_iat = 1;
  claims.exp = 101;
  claims.nbf = claims.iat = 100;
  memset(&policy, 0, sizeof(policy));
  policy.accepted_algs = algorithms;
  policy.accepted_alg_count = 3u;
  policy.accepted_issuers = issuers;
  policy.accepted_issuer_count = 1u;
  policy.accepted_audiences = audiences;
  policy.accepted_audience_count = 1u;
  policy.required_claims = required;
  policy.required_claim_count = 2u;
  policy.expected_nonce = nonce;
  policy.expected_azp = azp;
  policy.now = 100;
  options.require_cti = 1;
  options.admit = cwt_admit;
  options.context = &admission;
  memset(&admission, 0, sizeof(admission));
  for (algorithm = 0; algorithm < 3; ++algorithm) {
    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    assert(f->runtime.cose_key_init(&f->runtime, &signing,
                                    algorithm == 0
                                        ? C89CBOR_COSE_ED25519_PRIVATE
                                    : algorithm == 1 ? C89CBOR_COSE_P256_PRIVATE
                                                     : C89CBOR_COSE_HMAC256,
                                    raw, sizeof(raw), NULL, 0, &error) == 0);
    if (algorithm != 2) {
      assert(signing.public_key(&signing, public_bytes, sizeof(public_bytes),
                                &length) == 0);
      assert(
          f->runtime.cose_key_init(&f->runtime, &verifying,
                                   algorithm == 0 ? C89CBOR_COSE_ED25519_PUBLIC
                                                  : C89CBOR_COSE_P256_PUBLIC,
                                   public_bytes, length, NULL, 0, &error) == 0);
    } else
      assert(f->runtime.cose_key_init(&f->runtime, &verifying,
                                      C89CBOR_COSE_HMAC256, raw, sizeof(raw),
                                      NULL, 0, &error) == 0);
    for (encryption = 0; encryption < 4; ++encryption)
      for (allocated = 0; allocated < 2; ++allocated) {
        options.cose.encrypt = encryption >= 2;
        if (allocated)
          assert(f->runtime.cwt_create(&f->runtime, &options, &token, &error) ==
                 0);
        else {
          token = &caller;
          assert(f->runtime.cwt_init(&f->runtime, token, &options, &error) ==
                 0);
        }
        admission.receiver = token;
        admission.reject = 0;
        assert(f->runtime.cleanup(&f->runtime) == C89CBOR_BUSY);
        assert(token->view_get(token, &view) == C89CBOR_INPUT &&
               view.encoded == NULL);
        assert(token->set_lonejson(token, &claims, "\0id", 3u, &error) == 0);
        assert(token->view_get(token, &view) == 0 && !view.authenticated &&
               view.algorithm == 0);
        assert(view.claims->exp == 101 && view.claims->has_exp &&
               strcmp(view.claims->iss, issuer) == 0);
        assert(token->set_lonejson(token, view.claims, view.cti,
                                   view.cti_length, &error) == 0);
        assert(token->view_get(token, &view) == 0);
        assert(token->set_claims(token, view.encoded, view.encoded_length,
                                 &error) == 0);
        recipients[0] = encryption == 1   ? &f->content
                        : encryption == 2 ? &f->wrap
                                          : &f->public_key;
        recipients[1] = &f->wrap;
        assert(token->seal(token, &signing, encryption ? recipients : NULL,
                           encryption == 3 ? 2u
                           : encryption    ? 1u
                                           : 0u,
                           f->wire.bytes, sizeof(f->wire.bytes), &written,
                           &error) == 0);
        f->wire.length = written;
        assert(written > view.encoded_length && f->wire.bytes[0] == 0xd8 &&
               f->wire.bytes[1] == 61u);
        cwt_transport(f, token, &verifying,
                      encryption == 1   ? &f->content
                      : encryption == 2 ? &f->wrap
                      : encryption == 3 ? &f->private_key
                                        : NULL,
                      &policy);
        calls = admission.calls;
        assert(token->verify(token, f->wire.bytes, written, &verifying,
                             encryption == 1   ? &f->content
                             : encryption == 2 ? &f->wrap
                             : encryption == 3 ? &f->private_key
                                               : NULL,
                             &policy, &error) == 0);
        assert(admission.calls == calls + 1u &&
               token->view_get(token, &view) == 0);
        assert(view.authenticated && view.algorithm == (algorithm == 0   ? -19
                                                        : algorithm == 1 ? -9
                                                                         : 5));
        assert(view.cti_length == 3u && memcmp(view.cti, "\0id", 3u) == 0);
        assert(signing.metadata(&signing, &info) == 0);
        memset(&label, 0, sizeof(label));
        label.type = C89CBOR_UINT;
        label.argument = 1;
        assert(token->claim(token, &label, &value, &value_length) == 0 &&
               value_length == 7u);
        assert(memcmp(value, "\x66issuer", 7u) == 0);
        admission.reject = 1;
        assert(token->verify(token, f->wire.bytes, written, &verifying,
                             encryption == 1   ? &f->content
                             : encryption == 2 ? &f->wrap
                             : encryption == 3 ? &f->private_key
                                               : NULL,
                             &policy, &error) == C89CBOR_AUTH);
        assert(token->view_get(token, &view) == C89CBOR_INPUT &&
               view.claims == NULL);
        admission.reject = 0;
        policy.now = 101;
        calls = admission.calls;
        assert(token->verify(token, f->wire.bytes, written, &verifying,
                             encryption == 1   ? &f->content
                             : encryption == 2 ? &f->wrap
                             : encryption == 3 ? &f->private_key
                                               : NULL,
                             &policy, &error) == C89CBOR_AUTH);
        assert(error.cause != 0 && admission.calls == calls &&
               token->view_get(token, &view) == C89CBOR_INPUT);
        policy.now = 100;
        cwt_corrupt_payload(&f->wire);
        assert(token->verify(token, f->wire.bytes, written, &verifying,
                             encryption == 1   ? &f->content
                             : encryption == 2 ? &f->wrap
                             : encryption == 3 ? &f->private_key
                                               : NULL,
                             &policy, &error) == C89CBOR_AUTH);
        assert(admission.calls == calls &&
               token->view_get(token, &view) == C89CBOR_INPUT);
        assert(f->runtime.json == NULL);
        if (allocated)
          assert(token->destroy(token) == 0);
        else {
          assert(token->destroy(token) == C89CBOR_INVALID);
          assert(token->cleanup(token) == 0 && token->cleanup(token) == 0);
        }
      }
    assert(signing.cleanup(&signing) == 0 &&
           verifying.cleanup(&verifying) == 0);
  }
  /* Audience arrays retain exact strings and use lonejson's strict policy. */
  options.admit = NULL;
  assert(f->runtime.cwt_init(&f->runtime, &caller, &options, &error) == 0);
  array[0] = audience;
  array[1] = alternate;
  claims.aud = NULL;
  claims.aud_array.items = array;
  claims.aud_array.count = 2u;
  claims.scp.items = array;
  claims.scp.count = 2u;
  assert(caller.set_lonejson(&caller, &claims, "id", 2u, &error) == 0);
  assert(caller.view_get(&caller, &view) == 0 &&
         view.claims->aud_array.count == 2u && view.claims->scp.count == 2u);
  assert(strcmp(view.claims->aud_array.items[1], "other") == 0);
  assert(caller.cleanup(&caller) == 0);
}
static void cwt_policy_edges(fixture *f) {
  static const char *const algs[] = {"HS256"}, *const wrong_algs[] = {
                                                   "Ed25519"};
  static const char *const issuers[] = {"issuer"}, *const wrong_issuers[] = {
                                                       "wrong"};
  static const char *const audiences[] = {"service"}, *const wrong_audiences[] =
                                                          {"wrong"};
  static const char *const scopes[] = {"read", "extra"}, *const wrong_scopes[] =
                                                             {"write"};
  static const char *const required[] = {"exp", "sub", "iat"};
  char issuer[] = "issuer", subject[] = "subject", aud[] = "service",
       other[] = "other";
  char nonce[] = "challenge", azp[] = "client", scope[] = "read",
       extra[] = "extra", *array[2], *scope_items[1];
  lonejson_jwt_claims claims;
  lonejson_jwt_claim_policy policy;
  c89cbor_cwt_options options = c89cbor_default_cwt_options();
  c89cbor_cwt sender, receiver, required_encryption;
  c89cbor_cose_key key;
  c89cbor_cwt_view view;
  c89cbor_error error;
  unsigned char raw[32] = {0};
  size_t length;
  int which;
  memset(&claims, 0, sizeof(claims));
  memset(&policy, 0, sizeof(policy));
  claims.iss = issuer;
  claims.sub = subject;
  claims.nonce = nonce;
  claims.azp = azp;
  claims.scope = scope;
  array[0] = aud;
  array[1] = other;
  claims.aud_array.items = array;
  claims.aud_array.count = 2u;
  claims.scp.items = &array[1];
  claims.scp.count = 1u;
  claims.has_exp = claims.has_nbf = claims.has_iat = 1;
  claims.exp = 101;
  claims.nbf = claims.iat = 100;
  policy.accepted_algs = algs;
  policy.accepted_alg_count = 1u;
  policy.accepted_issuers = issuers;
  policy.accepted_issuer_count = 1u;
  policy.accepted_audiences = audiences;
  policy.accepted_audience_count = 1u;
  policy.now = 100;
  policy.expected_nonce = nonce;
  policy.expected_azp = azp;
  policy.required_claims = required;
  policy.required_claim_count = 3u;
  policy.required_scopes = scopes;
  policy.required_scope_count = 2u;
  assert(f->runtime.cwt_init(&f->runtime, &sender, NULL, &error) == 0);
  assert(f->runtime.cwt_init(&f->runtime, &receiver, NULL, &error) == 0);
  options.require_encryption = 1;
  assert(f->runtime.cwt_init(&f->runtime, &required_encryption, &options,
                             &error) == 0);
  assert(f->runtime.cose_key_init(&f->runtime, &key, C89CBOR_COSE_HMAC256, raw,
                                  sizeof(raw), NULL, 0, &error) == 0);
  /* scp is a CBOR string array; its scope participates without JSON parsing. */
  scope_items[0] = extra;
  claims.scp.items = scope_items;
  claims.scp.count = 1u;
  assert(sender.set_lonejson(&sender, &claims, NULL, 0, &error) == 0);
  assert(sender.seal(&sender, &key, NULL, 0, f->wire.bytes,
                     sizeof(f->wire.bytes), &length, &error) == 0);
  assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL, &policy,
                         &error) == 0);
  assert(required_encryption.verify(&required_encryption, f->wire.bytes, length,
                                    &key, &f->content, &policy,
                                    &error) == C89CBOR_AUTH);
  /* Omit the optional CWT tag, then both tags: attached untagged COSE is valid.
   */
  assert(receiver.verify(&receiver, f->wire.bytes + 2u, length - 2u, &key, NULL,
                         &policy, &error) == 0);
  assert(receiver.verify(&receiver, f->wire.bytes + 3u, length - 3u, &key, NULL,
                         &policy, &error) == 0);
  memmove(f->input.bytes, f->wire.bytes, length);
  memmove(f->input.bytes + 2u, f->wire.bytes + 3u, length - 3u);
  assert(receiver.verify(&receiver, f->input.bytes, length - 1u, &key, NULL,
                         &policy, &error) == C89CBOR_MALFORMED);
  for (which = 0; which < 10; ++which) {
    lonejson_jwt_claim_policy wrong = policy;
    switch (which) {
    case 0:
      wrong.accepted_algs = wrong_algs;
      break;
    case 1:
      wrong.accepted_issuers = wrong_issuers;
      break;
    case 2:
      wrong.accepted_audiences = wrong_audiences;
      break;
    case 3:
      wrong.expected_nonce = "wrong";
      break;
    case 4:
      wrong.expected_azp = "wrong";
      break;
    case 5:
      wrong.required_scopes = wrong_scopes;
      wrong.required_scope_count = 1u;
      break;
    case 6:
      wrong.require_all_audiences_accepted = 1;
      break;
    case 7:
      wrong.now = 99;
      break;
    case 8:
      wrong.now = 101;
      break;
    default:
      wrong.allowed_clock_skew = -1;
      break;
    }
    assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL, &wrong,
                           &error) == C89CBOR_AUTH);
    assert(receiver.view_get(&receiver, &view) == C89CBOR_INPUT &&
           view.encoded == NULL);
    assert(error.cause != 0);
  }
  policy.allowed_clock_skew = 1;
  policy.now = 99;
  assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL, &policy,
                         &error) == 0);
  policy.now = 101;
  assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL, &policy,
                         &error) == 0);
  policy.now = 102;
  assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL, &policy,
                         &error) == C89CBOR_AUTH);
  /* Require a nonempty binary ID independently of lonejson's string claims. */
  assert(required_encryption.cleanup(&required_encryption) == 0);
  options.require_encryption = 0;
  options.require_cti = 1;
  assert(f->runtime.cwt_init(&f->runtime, &required_encryption, &options,
                             &error) == 0);
  policy.now = 100;
  assert(required_encryption.verify(&required_encryption, f->wire.bytes, length,
                                    &key, NULL, &policy,
                                    &error) == C89CBOR_AUTH);
  assert(sender.set_lonejson(&sender, &claims, "", 0, &error) == 0);
  assert(sender.seal(&sender, &key, NULL, 0, f->wire.bytes,
                     sizeof(f->wire.bytes), &length, &error) == 0);
  assert(required_encryption.verify(&required_encryption, f->wire.bytes, length,
                                    &key, NULL, &policy,
                                    &error) == C89CBOR_AUTH);
  /* Fractional dates retain their bits and compare exactly to integer clocks.
   */
  {
    static const unsigned char fractional[] = {
        0xa3, 1,   0x66, 'i', 's', 's', 'u', 'e', 'r',  3,    0x67,
        's',  'e', 'r',  'v', 'i', 'c', 'e', 4,   0xf9, 0x56, 0x48};
    assert(sender.set_claims(&sender, fractional, sizeof(fractional), &error) ==
           0);
    assert(sender.seal(&sender, &key, NULL, 0, f->wire.bytes,
                       sizeof(f->wire.bytes), &length, &error) == 0);
    policy.expected_nonce = policy.expected_azp = NULL;
    policy.required_claim_count = policy.required_scope_count = 0;
    policy.allowed_clock_skew = 0;
    assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL,
                           &policy, &error) == 0);
    assert(receiver.view_get(&receiver, &view) == 0 && view.claims->exp == 101);
    assert(view.encoded_length == sizeof(fractional) &&
           memcmp(view.encoded, fractional, sizeof(fractional)) == 0);
    policy.now = 101;
    assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL,
                           &policy, &error) == C89CBOR_AUTH);
    memcpy(f->input.bytes, fractional, sizeof(fractional));
    f->input.bytes[0] = 0xa4;
    memcpy(f->input.bytes + sizeof(fractional), "\x05\xf9\x56\x48", 4u);
    assert(sender.set_claims(&sender, f->input.bytes, sizeof(fractional) + 4u,
                             &error) == 0);
    assert(sender.seal(&sender, &key, NULL, 0, f->wire.bytes,
                       sizeof(f->wire.bytes), &length, &error) == 0);
    policy.now = 100;
    assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL,
                           &policy, &error) == C89CBOR_AUTH);
    policy.allowed_clock_skew = 1;
    assert(receiver.verify(&receiver, f->wire.bytes, length, &key, NULL,
                           &policy, &error) == 0);
  }
  assert(key.cleanup(&key) == 0);
  assert(sender.cleanup(&sender) == 0 && receiver.cleanup(&receiver) == 0 &&
         required_encryption.cleanup(&required_encryption) == 0);
}
static void cwt_allocations(void) {
  cose_allocator_probe probe;
  c89cbor_config config = c89cbor_default_config();
  c89cbor runtime;
  c89cbor_cwt *token;
  c89cbor_error error;
  size_t at;
  c89cbor_cwt caller;
  c89cbor_cwt_options options = c89cbor_default_cwt_options();
  memset(&probe, 0, sizeof(probe));
  config.allocator.context = &probe;
  config.allocator.alloc = cose_probe_alloc;
  config.allocator.free = cose_probe_free;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  for (at = 1; at <= 6u; ++at) {
    probe.calls = 0;
    probe.fail_at = at;
    token = NULL;
    if (at <= 5u) {
      assert(runtime.cwt_create(&runtime, NULL, &token, &error) ==
             C89CBOR_NOMEM);
      assert(token == NULL && probe.live == 0 &&
             runtime.lifetime.dependents == 0);
    } else {
      assert(runtime.cwt_create(&runtime, NULL, &token, &error) == 0);
      probe.token = token;
      probe.reenter = 1;
      assert(token->destroy(token) == 0 && probe.live == 0);
      probe.token = NULL;
      probe.reenter = 0;
    }
  }
  options.cose.recipients = 33u;
  assert(runtime.cwt_init(&runtime, &caller, &options, &error) ==
         C89CBOR_LIMIT);
  assert(error.status == C89CBOR_LIMIT && caller.cleanup(&caller) == 0 &&
         probe.live == 0);
  options = c89cbor_default_cwt_options();
  options.cose.aad_length = 1u;
  assert(runtime.cwt_init(&runtime, &caller, &options, &error) ==
         C89CBOR_INVALID);
  assert(error.status == C89CBOR_INVALID && caller.cleanup(&caller) == 0 &&
         probe.live == 0);
  options = c89cbor_default_cwt_options();
  options.claims = (size_t)-1;
  assert(runtime.cwt_init(&runtime, &caller, &options, &error) ==
         C89CBOR_LIMIT);
  assert(caller.cleanup(&caller) == 0 && probe.live == 0);
  assert(c89cbor_cwt_init(NULL, &caller, NULL, &error) == C89CBOR_INVALID);
  assert(error.status == C89CBOR_INVALID && caller.cleanup(&caller) == 0);
  assert(runtime.cleanup(&runtime) == 0);
}
static void cwt_claim_edges(fixture *f) {
  static const unsigned char map[] = {
      0xa6, 1,    0x66, 'i', 's',  's',  'u', 'e', 'r',  3,    0x67,
      's',  'e',  'r',  'v', 'i',  'c',  'e', 4,   0xf9, 0x56, 0x48,
      7,    0x42, 0,    1,   0x20, 0x82, 1,   2,   0x64, 'r',  'o',
      'l',  'e',  0x65, 'a', 'd',  'm',  'i', 'n'};
  static const unsigned char duplicate[] = {0xa2, 1, 0x61, 'a',
                                            0x18, 1, 0x61, 'b'};
  static const unsigned char duplicate_text[] = {0xa2, 0x61, 'x',  1, 0x7f,
                                                 0x61, 'x',  0xff, 2};
  static const unsigned char nul[] = {0xa1, 1, 0x63, 'a', 0, 'b'};
  static const unsigned char nan_date[] = {0xa1, 4, 0xf9, 0x7e, 0};
  static const unsigned char max_date[] = {0xa1, 4, 0xfb, 0x43, 0xe0, 0,
                                           0,    0, 0,    0,    0};
  static const unsigned char too_large[] = {0xa1, 4, 0x1b, 0x80, 0, 0,
                                            0,    0, 0,    0,    0};
  static const unsigned char minimum[] = {0xa1, 4,    0x3b, 0x7f, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff};
  const unsigned char *invalid[6];
  size_t sizes[6], i, length;
  c89cbor_cwt token;
  c89cbor_cwt_view view;
  c89cbor_error error;
  c89cbor_token label;
  const void *bytes;
  invalid[0] = duplicate;
  sizes[0] = sizeof(duplicate);
  invalid[1] = duplicate_text;
  sizes[1] = sizeof(duplicate_text);
  invalid[2] = nul;
  sizes[2] = sizeof(nul);
  invalid[3] = nan_date;
  sizes[3] = sizeof(nan_date);
  invalid[4] = max_date;
  sizes[4] = sizeof(max_date);
  invalid[5] = too_large;
  sizes[5] = sizeof(too_large);
  assert(f->runtime.cwt_init(&f->runtime, &token, NULL, &error) == 0);
  assert(token.set_claims(&token, map, sizeof(map), &error) == 0);
  assert(token.view_get(&token, &view) == 0 && view.claims->exp == 101 &&
         view.claim_count == 6u);
  assert(view.encoded_length == sizeof(map) &&
         memcmp(view.encoded, map, sizeof(map)) == 0);
  memset(&label, 0, sizeof(label));
  label.type = C89CBOR_TEXT;
  label.data = (const unsigned char *)"role";
  label.length = 4u;
  assert(token.claim(&token, &label, &bytes, &length) == 0 && length == 6u &&
         memcmp(bytes,
                "\x65"
                "admin",
                6u) == 0);
  label.type = C89CBOR_NEGATIVE;
  label.argument = 0;
  assert(token.claim(&token, &label, &bytes, &length) == 0 && length == 3u &&
         memcmp(bytes, "\x82\x01\x02", 3u) == 0);
  assert(token.set_claims(&token, minimum, sizeof(minimum), &error) == 0);
  assert(token.view_get(&token, &view) == 0 && view.claims->exp == INT64_MIN);
  for (i = 0; i < 6u; ++i) {
    assert(token.set_claims(&token, invalid[i], sizes[i], &error) < 0);
    assert(token.view_get(&token, &view) == C89CBOR_INPUT &&
           view.encoded == NULL);
    assert(token.set_claims(&token, map, sizeof(map), &error) == 0);
  }
  memcpy(f->input.bytes, map, sizeof(map));
  f->input.bytes[sizeof(map)] = 0;
  assert(token.set_claims(&token, f->input.bytes, sizeof(map) + 1u, &error) ==
         C89CBOR_MALFORMED);
  assert(token.cleanup(&token) == 0);
}
