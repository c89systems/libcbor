/* Failure injection covers every libcbor allocation in key/operation factories.
 * OpenSSL provider allocations use its own allocator, as the public API states.
 */
typedef struct cose_allocator_probe {
  size_t calls, fail_at, live;
  c89cbor_cose_operation *operation;
  c89cbor_cose_key *key;
  c89cbor_cwt *token;
  int reenter;
  int pin_on_allocate;
} cose_allocator_probe;
static void *cose_probe_alloc(void *context, size_t length) {
  cose_allocator_probe *probe = context;
  void *bytes;
  if (probe->pin_on_allocate && probe->key != NULL)
    assert(probe->key->cleanup(probe->key) == C89CBOR_BUSY);
  if (++probe->calls == probe->fail_at)
    return NULL;
  bytes = malloc(length);
  if (bytes != NULL)
    ++probe->live;
  return bytes;
}
static void cose_probe_free(void *context, void *bytes) {
  cose_allocator_probe *probe = context;
  if (probe->reenter) {
    if (probe->operation != NULL)
      assert(probe->operation->cleanup(probe->operation) == C89CBOR_BUSY);
    if (probe->key != NULL)
      assert(probe->key->cleanup(probe->key) == C89CBOR_BUSY);
    if (probe->token != NULL)
      assert(probe->token->cleanup(probe->token) == C89CBOR_BUSY);
  }
  if (bytes != NULL) {
    assert(probe->live > 0);
    --probe->live;
    free(bytes);
  }
}
static void cose_factory_reentry(fixture *f) {
  cose_allocator_probe probe;
  c89cbor_config config = c89cbor_default_config();
  c89cbor runtime;
  c89cbor_cose_operation caller, *operation;
  c89cbor_error error;
  int allocated;
  memset(&probe, 0, sizeof(probe));
  config.allocator.context = &probe;
  config.allocator.alloc = cose_probe_alloc;
  config.allocator.free = cose_probe_free;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  probe.key = &f->content;
  for (allocated = 0; allocated < 2; ++allocated) {
    endpoints(f, &f->input, &f->wire);
    probe.pin_on_allocate = 1;
    if (allocated)
      assert(runtime.cose_encrypt0_open(&runtime, &f->source, &f->sink,
                                        &f->content, NULL, &operation,
                                        &error) == 0);
    else {
      operation = &caller;
      assert(runtime.cose_encrypt0_init(&runtime, operation, &f->source,
                                        &f->sink, &f->content, NULL,
                                        &error) == 0);
    }
    probe.pin_on_allocate = 0;
    assert((allocated ? operation->destroy(operation)
                      : operation->cleanup(operation)) == 0);
    assert(probe.live == 0);
  }
  assert(runtime.cleanup(&runtime) == 0);
}
static int cose_bad_read(void *context, void *bytes, size_t capacity,
                         size_t *count) {
  int mode = *(int *)context;
  (void)bytes;
  *count = mode == 1 ? capacity + 1u : 0;
  return mode == 2 ? C89CBOR_OUTPUT : mode == 3 ? C89CBOR_INPUT : C89CBOR_IO;
}
static int cose_bad_write(void *context, const void *bytes, size_t length,
                          size_t *count) {
  int mode = *(int *)context;
  (void)bytes;
  *count = mode == 1 ? length + 1u : 0;
  return mode == 2 ? C89CBOR_INPUT : mode == 3 ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static void cose_lifetime(fixture *f) {
  cose_allocator_probe probe;
  c89cbor_config config = c89cbor_default_config();
  c89cbor runtime;
  c89cbor_cose_key *key;
  c89cbor_cose_operation *operation;
  c89cbor_cose_operation caller;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_error error, retained;
  c89cbor_progress progress;
  c89cbor_source source;
  c89cbor_sink sink;
  unsigned char raw[32] = {0}, nonce[12] = {0};
  size_t at, baseline, allocations;
  int mode, status;
  memset(&probe, 0, sizeof(probe));
  config.allocator.context = &probe;
  config.allocator.alloc = cose_probe_alloc;
  config.allocator.free = cose_probe_free;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(probe.live == 0);
  for (at = 1; at <= 3u; ++at) {
    probe.calls = 0;
    probe.fail_at = at;
    key = &f->content;
    status = runtime.cose_key_create(&runtime, C89CBOR_COSE_A256GCM, raw, 32u,
                                     NULL, 0, &key, &error);
    if (at <= 2u)
      assert(status == C89CBOR_NOMEM && key == NULL && error.status == status &&
             probe.live == 0);
    else {
      assert(status == 0 && key != NULL);
      probe.key = key;
      probe.reenter = 1;
      assert(key->destroy(key) == 0 && probe.live == 0);
      probe.key = NULL;
      probe.reenter = 0;
    }
  }
  probe.fail_at = 0;
  assert(runtime.cose_key_create(&runtime, C89CBOR_COSE_A256GCM, raw, 32u, NULL,
                                 0, &key, &error) == 0);
  baseline = probe.live;
  f->input.length = 17u;
  f->input.pause = f->wire.pause = 0;
  f->input.fragment = f->wire.fragment = 0;
  for (at = 1; at <= 5u; ++at) {
    endpoints(f, &f->input, &f->wire);
    probe.calls = 0;
    probe.fail_at = at;
    operation = &caller;
    status = runtime.cose_encrypt0_open(&runtime, &f->source, &f->sink, key,
                                        NULL, &operation, &error);
    if (at <= 4u) {
      assert(status == C89CBOR_NOMEM && operation == NULL &&
             error.status == status);
      assert(f->input.offset == 0 && f->wire.length == 0 &&
             probe.live == baseline);
    } else {
      assert(status == 0 && operation != NULL && f->input.offset == 0);
      allocations = probe.calls;
      do {
        status = operation->step(operation, &error);
      } while (status == 0);
      assert(status == C89CBOR_DONE && probe.calls == allocations);
      assert(operation->progress(operation, &progress) == 0 &&
             progress.records == 1u);
      probe.operation = operation;
      probe.reenter = 1;
      assert(operation->destroy(operation) == 0 && probe.live == baseline);
      probe.operation = NULL;
      probe.reenter = 0;
    }
  }
  probe.fail_at = 0;
  options.record_bytes = (size_t)-1;
  assert(runtime.cose_encrypt0_init(&runtime, &caller, &f->source, &f->sink,
                                    key, &options, &error) == C89CBOR_LIMIT);
  assert(caller.cleanup(&caller) == 0 && caller.cleanup(&caller) == 0);
  options = c89cbor_default_cose_options();
  options.nonce = nonce;
  assert(runtime.cose_encrypt_stream_init(&runtime, &caller, &f->source,
                                          &f->sink, &key, 1u, &options,
                                          &error) == C89CBOR_INVALID);
  assert(caller.cleanup(&caller) == 0 && probe.live == baseline);
  options.nonce = NULL;
  for (mode = 0; mode < 4; ++mode) {
    endpoints(f, &f->input, &f->wire);
    source = f->source;
    source.context = &mode;
    source.read = cose_bad_read;
    assert(runtime.cose_encrypt0(&runtime, &source, &f->sink, key, NULL,
                                 &error) == C89CBOR_IO);
    assert(f->wire.length == 0);
    sink = f->sink;
    sink.context = &mode;
    sink.write = cose_bad_write;
    assert(runtime.cose_encrypt0(&runtime, &f->source, &sink, key, NULL,
                                 &error) == C89CBOR_IO);
  }
  endpoints(f, &f->input, &f->wire);
  source.context = &mode;
  source.read = cose_bad_read;
  mode = 0;
  assert(runtime.cose_encrypt0_init(&runtime, &caller, &source, &f->sink, key,
                                    NULL, &error) == 0);
  assert(caller.destroy(&caller) == C89CBOR_INVALID);
  assert(caller.step(&caller, &error) == C89CBOR_IO);
  retained = error;
  assert(caller.step(&caller, &error) == C89CBOR_IO &&
         memcmp(&retained, &error, sizeof(error)) == 0);
  assert(caller.next(&caller, NULL, NULL, &error) == C89CBOR_INVALID);
  assert(caller.cleanup(&caller) == 0 && probe.live == baseline);
  assert(key->destroy(key) == 0 && probe.live == 0);
  assert(runtime.cleanup(&runtime) == 0);
}
