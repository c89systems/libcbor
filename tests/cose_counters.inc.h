#include "../src/cose_internal.h"
/* Arrange unreachably large counters privately, then assert only public
 * outcomes. These checks cannot require 16 million crypto operations. */
static void cose_counters(fixture *f) {
  c89cbor_cose_operation op;
  c89_cose_state *state;
  c89_cose_key_state *key = f->content.state;
  c89cbor_error error;
  c89cbor_cose_key *keys[1];
  uint64_t uses = key->uses;
  int status, mode;
  f->input.length = 1u;
  f->input.pause = f->wire.pause = 0;
  f->input.fragment = f->wire.fragment = 0;
  key->uses = UINT64_C(1) << 24u;
  endpoints(f, &f->input, &f->wire);
  assert(f->runtime.cose_encrypt0(&f->runtime, &f->source, &f->sink,
                                  &f->content, NULL, &error) == C89CBOR_LIMIT);
  assert(f->wire.length == 0);
  key->uses = uses;
  for (mode = 0; mode < 4; ++mode) {
    endpoints(f, &f->input, &f->wire);
    keys[0] = &f->content;
    assert(f->runtime.cose_encrypt_stream_init(&f->runtime, &op, &f->source,
                                               &f->sink, keys, 1u, NULL,
                                               &error) == 0);
    state = op.conversion.state;
    if (mode == 0)
      state->sequence = UINT64_C(1) << 24u;
    else if (mode == 1)
      op.conversion.lifetime.progress.input = UINT64_MAX;
    else if (mode == 2)
      op.conversion.lifetime.progress.output = UINT64_MAX;
    else
      op.conversion.lifetime.progress.records = UINT64_MAX;
    do {
      status = op.step(&op, &error);
    } while (status == 0);
    assert(status == C89CBOR_LIMIT && f->wire.length == 0);
    assert(op.step(&op, &error) == C89CBOR_LIMIT && op.cleanup(&op) == 0);
  }
}
