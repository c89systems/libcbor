/* End-to-end bounded transport: generated input, fixed ring, authenticated
 * sink. */
typedef struct cose_pipe {
  unsigned char bytes[4096];
  size_t offset, length;
  int done;
} cose_pipe;
typedef struct cose_producer {
  uint64_t offset, length, consumed;
  int early;
} cose_producer;
static int cose_generate(void *context, void *bytes, size_t capacity,
                         size_t *count) {
  cose_producer *source = context;
  unsigned char *out = bytes;
  size_t i, length = capacity;
  if ((uint64_t)length > source->length - source->offset)
    length = (size_t)(source->length - source->offset);
  for (i = 0; i < length; ++i)
    out[i] = (unsigned char)((source->offset + i) % 251u);
  source->offset += length;
  *count = length;
  return C89CBOR_OK;
}
static int cose_verify(void *context, const void *bytes, size_t length,
                       size_t *count) {
  cose_producer *source = context;
  const unsigned char *input = bytes;
  size_t i;
  assert((uint64_t)length <= source->length - source->consumed);
  for (i = 0; i < length; ++i)
    assert(input[i] == (unsigned char)((source->consumed + i) % 251u));
  if (source->offset < source->length)
    source->early = 1;
  source->consumed += length;
  *count = length;
  return C89CBOR_OK;
}
static int cose_pipe_write(void *context, const void *bytes, size_t length,
                           size_t *count) {
  cose_pipe *pipe = context;
  const unsigned char *input = bytes;
  size_t i, take = sizeof(pipe->bytes) - pipe->length;
  if (take > length)
    take = length;
  for (i = 0; i < take; ++i)
    pipe->bytes[(pipe->offset + pipe->length + i) % sizeof(pipe->bytes)] =
        input[i];
  pipe->length += take;
  *count = take;
  return take < length ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static int cose_pipe_read(void *context, void *bytes, size_t capacity,
                          size_t *count) {
  cose_pipe *pipe = context;
  unsigned char *output = bytes;
  size_t i, take = pipe->length;
  if (take > capacity)
    take = capacity;
  if (take > 37u)
    take = 37u;
  for (i = 0; i < take; ++i)
    output[i] = pipe->bytes[(pipe->offset + i) % sizeof(pipe->bytes)];
  pipe->offset = (pipe->offset + take) % sizeof(pipe->bytes);
  pipe->length -= take;
  *count = take;
  return take == 0 && !pipe->done ? C89CBOR_INPUT : C89CBOR_OK;
}
static void cose_pipeline(fixture *f, int encrypt) {
  cose_pipe *pipe = calloc(1, sizeof(*pipe));
  cose_producer producer;
  c89cbor_cose_operation sender, receiver;
  c89cbor_cose_key *keys[2];
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error;
  size_t steps = 0;
  int sent = C89CBOR_OK, received = C89CBOR_OK;
  assert(pipe != NULL);
  memset(&producer, 0, sizeof(producer));
  producer.length = encrypt ? 65549u : 1048589u;
  options.encrypt = encrypt;
  options.step_input = options.step_output = 256u;
  options.step_events = 16u;
  keys[0] = encrypt ? &f->wrap : &f->content;
  keys[1] = &f->public_key;
  source.context = &producer;
  source.read = cose_generate;
  sink.context = pipe;
  sink.write = cose_pipe_write;
  assert(f->runtime.cose_encrypt_stream_init(&f->runtime, &sender, &source,
                                             &sink, keys, encrypt ? 2u : 1u,
                                             &options, &error) == 0);
  source.context = pipe;
  source.read = cose_pipe_read;
  sink.context = &producer;
  sink.write = cose_verify;
  assert(f->runtime.cose_decrypt_stream_init(
             &f->runtime, &receiver, &source, &sink,
             encrypt ? &f->private_key : &f->content, &options, &error) == 0);
  while (sent != C89CBOR_DONE || received != C89CBOR_DONE) {
    if (sent != C89CBOR_DONE) {
      sent = sender.step(&sender, &error);
      assert(sent >= 0);
      if (sent == C89CBOR_DONE)
        pipe->done = 1;
    }
    if (received != C89CBOR_DONE) {
      received = receiver.step(&receiver, &error);
      assert(received >= 0);
    }
    assert(++steps < 100000u);
  }
  assert(producer.offset == producer.length &&
         producer.consumed == producer.length && producer.early);
  assert(pipe->length == 0);
  assert(sender.cleanup(&sender) == 0 && receiver.cleanup(&receiver) == 0);
  free(pipe);
}
static void cose_coalesced(fixture *f, int stream) {
  c89cbor_cose_operation receiver;
  c89cbor_cose_key *keys[1];
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error;
  c89cbor_progress progress;
  unsigned char first[256];
  size_t first_length;
  int status;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  memcpy(f->input.bytes, "first", 5u);
  f->input.length = 5u;
  endpoints(f, &f->input, &f->wire);
  keys[0] = &f->content;
  if (stream)
    status = f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink,
                                            keys, 1u, NULL, &error);
  else
    status = f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                      &f->content, NULL, &error);
  assert(status == 0 && f->wire.length < sizeof(first));
  first_length = f->wire.length;
  memcpy(first, f->wire.bytes, first_length);
  memcpy(f->input.bytes, "second", 6u);
  f->input.length = 6u;
  endpoints(f, &f->input, &f->wire);
  if (stream)
    status = f->runtime.cose_encrypt_stream(&f->runtime, &f->source, &f->sink,
                                            keys, 1u, NULL, &error);
  else
    status = f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                      &f->content, NULL, &error);
  assert(status == 0);
  memmove(f->wire.bytes + first_length, f->wire.bytes, f->wire.length);
  memcpy(f->wire.bytes, first, first_length);
  f->wire.length += first_length;
  endpoints(f, &f->wire, &f->output);
  options.step_input = 11u;
  options.step_output = 7u;
  options.step_events = 3u;
  if (stream)
    status = f->runtime.cose_decrypt_stream_init(&f->runtime, &receiver,
                                                 &f->source, &f->sink,
                                                 &f->content, &options, &error);
  else
    status =
        f->runtime.cose_decrypt_init(&f->runtime, &receiver, &f->source,
                                     &f->sink, &f->content, &options, &error);
  assert(status == 0 && drive(&receiver) == C89CBOR_DONE);
  assert(f->output.length == 5u && memcmp(f->output.bytes, "first", 5u) == 0);
  f->output.length = 0;
  assert(receiver.next(&receiver, NULL, NULL, &error) == 0);
  assert(drive(&receiver) == C89CBOR_DONE);
  assert(f->output.length == 6u && memcmp(f->output.bytes, "second", 6u) == 0);
  assert(receiver.progress(&receiver, &progress) == 0 &&
         progress.records == 2u);
  assert(receiver.destroy(&receiver) == C89CBOR_INVALID);
  assert(receiver.cleanup(&receiver) == 0);
}
