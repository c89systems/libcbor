#ifndef C89CBOR_CWT_INTERNAL_H
#define C89CBOR_CWT_INTERNAL_H
#include "cose_internal.h"
#include <c89cbor/cwt.h>
typedef struct c89_cwt_entry {
  c89cbor_token label;
  size_t offset, length;
} c89_cwt_entry;
typedef struct c89_cwt_state {
  c89cbor *runtime;
  c89cbor_cwt_options options;
  c89cbor_cwt_view view;
  lonejson_jwt_claims native;
  unsigned char *workspace, *raw, *inner, *outer;
  size_t workspace_size, token_capacity;
  c89_cose_arena arena;
  c89_cwt_entry *entries;
  char **strings;
  c89cbor_encoder encoder;
  c89_cose_state crypto;
  c89cbor_cose_key *seal_keys[C89_COSE_MAX_RECIPIENTS + 1u];
  size_t seal_count;
  c89cbor_cose_key *verify_keys[2];
  size_t verify_count;
} c89_cwt_state;
void c89_cwt_clear(c89_cwt_state *);
int c89_cwt_parse(c89_cwt_state *, size_t);
int c89_cwt_encode(c89_cwt_state *, const lonejson_jwt_claims *, const void *,
                   size_t, size_t *);
void c89_cwt_runtime_methods(c89cbor *);
#endif
