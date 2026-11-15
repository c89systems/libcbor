/* Test setup conveniences. Prepared-receiver tests and benchmarks bind once. */
static int test_cwt_seal(c89cbor_cwt *token, c89cbor_cose_key *signing,
                         c89cbor_cose_key *const *keys, size_t count,
                         void *bytes, size_t capacity, size_t *written,
                         c89cbor_error *error) {
  int status = token->set_seal_keys(token, signing, keys, count, error);
  if (written != NULL)
    *written = 0;
  return status == 0 ? token->seal(token, bytes, capacity, written, error)
                     : status;
}
static int test_cwt_verify(c89cbor_cwt *token, const void *bytes, size_t length,
                           c89cbor_cose_key *key, c89cbor_cose_key *decrypt,
                           const lonejson_jwt_claim_policy *policy,
                           c89cbor_error *error) {
  int status = token->set_verify_keys(token, key, decrypt, error);
  return status == 0 ? token->verify(token, bytes, length, policy, error)
                     : status;
}
