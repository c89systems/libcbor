static size_t cose_item_end(const unsigned char *bytes, size_t length,
                            size_t start) {
  c89cbor_decoder decoder;
  c89cbor_token token;
  size_t used, offset = start;
  int status;
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  do {
    status =
        decoder.next(&decoder, bytes + offset, length - offset, &used, &token);
    offset += used;
  } while (status == C89CBOR_TOKEN);
  assert(status == C89CBOR_DONE && offset > start &&
         decoder.finish(&decoder) == 0);
  assert(decoder.cleanup(&decoder) == 0);
  return offset;
}
static int cose_open_to_buffer(fixture *f, c89cbor_cose_key *key,
                               const c89cbor_cose_options *options,
                               int stream) {
  c89cbor_error error;
  endpoints(f, &f->wire, &f->output);
  return stream ? f->runtime.cose_decrypt_stream(&f->runtime, &f->source,
                                                 &f->sink, key, options, &error)
                : f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink,
                                          key, options, &error);
}
static void cose_header_failures(fixture *f) {
  static const unsigned char duplicate[] = {0xa2, 1, 3, 1, 3};
  static const unsigned char critical[] = {0xa3, 1,  3,    2,  0x81,
                                           0x18, 99, 0x18, 99, 0xf5};
  unsigned char saved[256];
  size_t length;
  c89cbor_error error;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  memset(f->input.bytes, 'x', 17u);
  f->input.length = 17u;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                  &f->content, NULL, &error) == 0);
  length = f->wire.length;
  assert(length < sizeof(saved));
  memcpy(saved, f->wire.bytes, length);
  memmove(f->wire.bytes + 3u + sizeof(duplicate), saved + 6u, length - 6u);
  f->wire.bytes[2] = (unsigned char)(0x40u + sizeof(duplicate));
  memcpy(f->wire.bytes + 3u, duplicate, sizeof(duplicate));
  f->wire.length = length + sizeof(duplicate) - 3u;
  assert(cose_open_to_buffer(f, &f->content, NULL, 0) == C89CBOR_MALFORMED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, length);
  f->wire.length = length + 2u;
  f->wire.bytes[6] = 0xa2;
  memmove(f->wire.bytes + 23u, saved + 21u, length - 21u);
  f->wire.bytes[21] = 1;
  f->wire.bytes[22] = 3;
  assert(cose_open_to_buffer(f, &f->content, NULL, 0) == C89CBOR_MALFORMED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, length);
  memmove(f->wire.bytes + 3u + sizeof(critical), saved + 6u, length - 6u);
  f->wire.bytes[2] = (unsigned char)(0x40u + sizeof(critical));
  memcpy(f->wire.bytes + 3u, critical, sizeof(critical));
  f->wire.length = length + sizeof(critical) - 3u;
  assert(cose_open_to_buffer(f, &f->content, NULL, 0) == C89CBOR_UNSUPPORTED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, length);
  f->wire.length = length;
  f->wire.bytes[0] = 0xd1;
  assert(cose_open_to_buffer(f, &f->content, NULL, 0) == C89CBOR_UNSUPPORTED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, length);
  f->wire.bytes[5] = 0xf4;
  assert(cose_open_to_buffer(f, &f->content, NULL, 0) == C89CBOR_MALFORMED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, length);
  f->wire.length = length;
  options.aad = "different";
  options.aad_length = 9u;
  assert(cose_open_to_buffer(f, &f->content, &options, 0) == C89CBOR_AUTH &&
         f->output.length == 0);
  options.aad = NULL;
  options.aad_length = 0;
  options.record_bytes = 16u;
  assert(cose_open_to_buffer(f, &f->content, &options, 0) == C89CBOR_LIMIT &&
         f->output.length == 0);
  options.record_bytes = 2048u;
  options.header_bytes = 1u;
  assert(cose_open_to_buffer(f, &f->content, &options, 0) == C89CBOR_LIMIT &&
         f->output.length == 0);
}
static void cose_stream_attacks(fixture *f) {
  unsigned char *a = malloc(sizeof(f->wire.bytes)),
                *b = malloc(sizeof(f->wire.bytes));
  unsigned char id[16];
  c89cbor_cose_key *keys[1];
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error;
  size_t alen, blen, a0, a1, b0, b1;
  assert(a != NULL && b != NULL);
  memset(id, 0x81, sizeof(id));
  options.record_bytes = 32u;
  options.encrypt = 1;
  options.stream_id = id;
  keys[0] = &f->public_key;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  f->input.length = 65u;
  memset(f->input.bytes, 'x', f->input.length);
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink, keys,
                                        1u, &options, &error) == 0);
  alen = f->wire.length;
  memcpy(a, f->wire.bytes, alen);
  memset(f->input.bytes, 'z', f->input.length);
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink, keys,
                                        1u, &options, &error) == 0);
  blen = f->wire.length;
  memcpy(b, f->wire.bytes, blen);
  a0 = cose_item_end(a, alen, 0);
  a1 = cose_item_end(a, alen, a0);
  b0 = cose_item_end(b, blen, 0);
  b1 = cose_item_end(b, blen, b0);
  /* The substituted record has matching ID/sequence/AAD and a valid tag, but
   * uses an independently established content key. Public keys allow its
   * creation; stream-key continuity must still reject it. */
  memcpy(f->wire.bytes, a, a0);
  memcpy(f->wire.bytes + a0, b + b0, b1 - b0);
  memcpy(f->wire.bytes + a0 + b1 - b0, a + a1, alen - a1);
  f->wire.length = a0 + b1 - b0 + alen - a1;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) == C89CBOR_AUTH);
  assert(f->output.length == 32u && f->output.bytes[0] == 'x');
  memcpy(f->wire.bytes, a, alen);
  f->wire.length = a1;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) ==
             C89CBOR_MALFORMED &&
         f->output.length == 64u);
  memcpy(f->wire.bytes, a + a0, a1 - a0);
  memcpy(f->wire.bytes + a1 - a0, a, a0);
  f->wire.length = a1;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) == C89CBOR_AUTH &&
         f->output.length == 0);
  memcpy(f->wire.bytes, a, a0);
  memcpy(f->wire.bytes + a0, a, a0);
  f->wire.length = a0 * 2u;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) == C89CBOR_AUTH &&
         f->output.length == 32u);
  memcpy(f->wire.bytes, a, alen);
  f->wire.length = alen;
  assert(a[19] == 0xf4);
  f->wire.bytes[19] = 0xf5;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) == C89CBOR_AUTH &&
         f->output.length == 0);
  memcpy(f->wire.bytes, a, alen);
  f->wire.length = alen;
  id[0] ^= 1u;
  assert(cose_open_to_buffer(f, &f->private_key, &options, 1) == C89CBOR_AUTH &&
         f->output.length == 0);
  free(a);
  free(b);
}
static void cose_recipient_attacks(fixture *f) {
  static const size_t positions[] = {10u, 24u, 56u, 77u, 111u};
  c89cbor_cose_key *keys[2], wrong;
  c89cbor_error error;
  unsigned char saved[512], raw[32];
  size_t i, length, first_end;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  f->input.length = 17u;
  memset(f->input.bytes, 'x', 17u);
  keys[0] = &f->public_key;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt(&f->runtime, &f->source, &f->sink, keys, 1u,
                                 NULL, &error) == 0);
  assert(f->wire.length == 151u);
  memcpy(saved, f->wire.bytes, f->wire.length);
  for (i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
    memcpy(f->wire.bytes, saved, 151u);
    f->wire.bytes[positions[i]] ^= 1u;
    assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == C89CBOR_AUTH &&
           f->output.length == 0);
  }
  memcpy(f->wire.bytes, saved, 151u);
  memset(f->wire.bytes + 77u, 0, 32u);
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == C89CBOR_AUTH &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, 151u);
  f->wire.bytes[74] =
      0x23; /* A private -4 component cannot arrive as an epk. */
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) ==
             C89CBOR_MALFORMED &&
         f->output.length == 0);
  memcpy(f->wire.bytes, saved, 151u);
  memset(raw, 0x99, sizeof(raw));
  assert(f->runtime.cose_key_init(&f->runtime, &wrong,
                                  C89CBOR_COSE_X25519_PRIVATE, raw, 32u, "x",
                                  1u, &error) == 0);
  assert(cose_open_to_buffer(f, &wrong, NULL, 0) == C89CBOR_AUTH &&
         f->output.length == 0);
  assert(wrong.cleanup(&wrong) == 0);
  keys[0] = &f->wrap;
  keys[1] = &f->public_key;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt(&f->runtime, &f->source, &f->sink, keys, 2u,
                                 NULL, &error) == 0);
  length = f->wire.length;
  assert(length < sizeof(saved) && f->wire.bytes[57] == 0x82);
  memcpy(saved, f->wire.bytes, length);
  /* Unsupported first recipient does not prevent the second from working. */
  assert(f->wire.bytes[62] == 0x24);
  f->wire.bytes[62] = 0x29;
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == 0 &&
         f->output.length == 17u);
  memcpy(f->wire.bytes, saved, length);
  first_end = cose_item_end(saved, length, 58u);
  memcpy(f->wire.bytes + 58u, saved + first_end, length - first_end);
  memcpy(f->wire.bytes + 58u + length - first_end, saved + 58u,
         first_end - 58u);
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == 0 &&
         f->output.length == 17u);
  assert(cose_open_to_buffer(f, &f->wrap, NULL, 0) == 0 &&
         f->output.length == 17u);
  /* Nested recipients are unsupported, while duplicate labels are malformed. */
  memcpy(f->wire.bytes, saved, length);
  f->wire.bytes[58] = 0x84;
  memmove(f->wire.bytes + first_end + 1u, saved + first_end,
          length - first_end);
  f->wire.bytes[first_end] = 0x80;
  f->wire.length = length + 1u;
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == 0 &&
         f->output.length == 17u);
}
static void cose_header_edges(fixture *f) {
  static const unsigned char duplicate_after_unsupported[] = {
      0x83, 0x40, 0xa3, 1,   0x61, 'x', 1,   0x24,
      4,    0x44, 'w',  'r', 'a',  'p', 0x40};
  c89cbor_cose_key *keys[2];
  c89cbor_error error;
  unsigned char saved[512];
  size_t length, end;
  keys[0] = &f->wrap;
  keys[1] = &f->public_key;
  f->input.length = 17u;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt(&f->runtime, &f->source, &f->sink, keys, 2u,
                                 NULL, &error) == 0);
  length = f->wire.length;
  assert(length < sizeof(saved));
  memcpy(saved, f->wire.bytes, length);
  /* RFC 9052 section 3: encoded empty map must also be accepted. */
  assert(f->wire.bytes[59] == 0x40);
  f->wire.bytes[59] = 0x41;
  memmove(f->wire.bytes + 61u, saved + 60u, length - 60u);
  f->wire.bytes[60] = 0xa0;
  f->wire.length = length + 1u;
  assert(cose_open_to_buffer(f, &f->wrap, NULL, 0) == 0 &&
         f->output.length == 17u);
  /* An unsupported text algorithm cannot hide duplicate labels which follow
   * it, even when the second recipient is valid for our private key. */
  end = cose_item_end(saved, length, 58u);
  memcpy(f->wire.bytes, saved, 58u);
  memcpy(f->wire.bytes + 58u, duplicate_after_unsupported,
         sizeof(duplicate_after_unsupported));
  memcpy(f->wire.bytes + 58u + sizeof(duplicate_after_unsupported), saved + end,
         length - end);
  f->wire.length = 58u + sizeof(duplicate_after_unsupported) + length - end;
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) ==
             C89CBOR_MALFORMED &&
         f->output.length == 0);
}
typedef struct cose_admission {
  c89cbor_cose_operation *operation;
  buffer *output;
  unsigned char previous[16];
  int have_previous, admitted;
} cose_admission;
static int cose_admit(void *context, const void *bytes, size_t length,
                      size_t *count) {
  cose_admission *admission = context;
  c89cbor_cose_stream_info info;
  assert(admission->operation->stream_info(admission->operation, &info) == 0 &&
         !info.complete);
  *count = 0;
  if (!admission->admitted) {
    if (admission->have_previous &&
        memcmp(info.stream_id, admission->previous, 16u) == 0)
      return C89CBOR_IO;
    memcpy(admission->previous, info.stream_id, 16u);
    admission->have_previous = admission->admitted = 1;
  }
  return write_buffer(admission->output, bytes, length, count);
}
static void cose_replay_admission(fixture *f) {
  c89cbor_cose_operation op;
  c89cbor_cose_stream_info info;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_key *keys[1];
  c89cbor_error error;
  c89cbor_sink sink;
  cose_admission admission;
  int replay;
  memset(&admission, 0, sizeof(admission));
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  f->input.length = 5u;
  keys[0] = &f->content;
  options.step_input = 11u;
  options.step_output = 7u;
  options.step_events = 3u;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink, keys,
                                        1u, NULL, &error) == 0);
  admission.operation = &op;
  admission.output = &f->output;
  sink.context = &admission;
  sink.write = cose_admit;
  for (replay = 0; replay < 2; ++replay) {
    endpoints(f, &f->wire, &f->output);
    admission.admitted = 0;
    assert(f->runtime.cose_decrypt_stream_init(&f->runtime, &op, &f->source,
                                               &sink, &f->content, &options,
                                               &error) == 0);
    memset(&info, 0xff, sizeof(info));
    assert(op.stream_info(&op, &info) == C89CBOR_INPUT &&
           info.stream_id[0] == 0 && info.complete == 0);
    assert(drive(&op) == (replay ? C89CBOR_IO : C89CBOR_DONE));
    assert(f->output.length == (replay ? 0u : 5u));
    assert(op.stream_info(&op, &info) == 0 && info.complete == !replay);
    assert(op.cleanup(&op) == 0 &&
           op.stream_info(&op, &info) == C89CBOR_INVALID);
  }
  f->input.length = 0;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink, keys,
                                        1u, NULL, &error) == 0);
  endpoints(f, &f->wire, &f->output);
  assert(f->runtime.cose_decrypt_stream_init(&f->runtime, &op, &f->source,
                                             &f->sink, &f->content, &options,
                                             &error) == 0);
  assert(drive(&op) == C89CBOR_DONE && f->output.length == 0);
  assert(op.stream_info(&op, &info) == 0 && info.complete && !info.encrypt);
  assert(op.cleanup(&op) == 0);
}
