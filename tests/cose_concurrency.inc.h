typedef struct cose_worker {
  c89cbor_cose_operation operation;
  c89cbor_source source;
  c89cbor_sink sink;
  buffer input, wire;
  int status;
} cose_worker;
static void *cose_worker_run(void *context) {
  cose_worker *worker = context;
  c89cbor_error error;
  do {
    worker->status = worker->operation.step(&worker->operation, &error);
  } while (worker->status == 0 || worker->status == C89CBOR_INPUT ||
           worker->status == C89CBOR_OUTPUT);
  return NULL;
}
static void cose_concurrency(fixture *f) {
  cose_worker *workers = calloc(4u, sizeof(*workers));
  pthread_t threads[4];
  c89cbor_cose_key *keys[1];
  c89cbor_error error;
  size_t i;
  int encrypt;
  assert(workers != NULL);
  for (encrypt = 0; encrypt < 2; ++encrypt) {
    keys[0] = encrypt ? &f->public_key : &f->content;
    /* Factories and cleanup are serialized. Only prepared operations run
     * concurrently, sharing immutable key material and the usage counter. */
    for (i = 0; i < 4u; ++i) {
      memset(&workers[i], 0, sizeof(workers[i]));
      workers[i].input.length = 1024u;
      memset(workers[i].input.bytes, (int)('a' + i), 1024u);
      workers[i].source.context = &workers[i].input;
      workers[i].source.read = read_buffer;
      workers[i].sink.context = &workers[i].wire;
      workers[i].sink.write = write_buffer;
      assert((encrypt
                  ? f->runtime.cose_encrypt_init(
                        &f->runtime, &workers[i].operation, &workers[i].source,
                        &workers[i].sink, keys, 1u, NULL, &error)
                  : f->runtime.cose_encrypt0_init(
                        &f->runtime, &workers[i].operation, &workers[i].source,
                        &workers[i].sink, keys[0], NULL, &error)) == 0);
    }
    for (i = 0; i < 4u; ++i)
      assert(pthread_create(&threads[i], NULL, cose_worker_run, &workers[i]) ==
             0);
    for (i = 0; i < 4u; ++i)
      assert(pthread_join(threads[i], NULL) == 0);
    for (i = 0; i < 4u; ++i) {
      assert(workers[i].status == C89CBOR_DONE);
      assert(workers[i].operation.cleanup(&workers[i].operation) == 0);
      f->wire = workers[i].wire;
      assert(cose_open_to_buffer(f, encrypt ? &f->private_key : &f->content,
                                 NULL, 0) == 0);
      assert(f->output.length == 1024u &&
             memcmp(f->output.bytes, workers[i].input.bytes, 1024u) == 0);
    }
  }
  free(workers);
}
