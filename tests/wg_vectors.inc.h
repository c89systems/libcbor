/* COSE WG Examples, public domain (tests/vectors/LICENSE).
 * https://github.com/cose-wg/Examples/tree/53c9d634333bb4f529d78f5980fffa2667ee2c12
 * aes-gcm-examples/aes-gcm-enc-03.json and hmac-examples/HMac-enc-01.json.
 * Exact original wire bytes; no algorithm/header rewriting.
 */
static void cose_wg_vectors(fixture *f) {
  static const char *const key_hex[] = {
      "0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100",
      "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"};
  static const char *const wire_hex[] = {
      "d08343a10103a1054c02d1f7e6f26c43d4868d87ce58249d64a5a59a3b04867dccf6b8ef"
      "82f7d1a3b25ef84eca2bc5d7593a96e943859a9cc24ad3",
      "d18443a10105a054546869732069732074686520636f6e74656e742e5820a1a848d3471f"
      "9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58"};
  c89cbor_cose_key key;
  c89cbor_cose_options options;
  c89cbor_error error;
  unsigned char raw[32], nonce[12];
  size_t i;
  for (i = 0; i < 2u; ++i) {
    cose_hex(key_hex[i], raw, sizeof(raw));
    assert(f->runtime.cose_key_init(&f->runtime, &key,
                                    i ? C89CBOR_COSE_HMAC256
                                      : C89CBOR_COSE_A256GCM,
                                    raw, 32u, NULL, 0, &error) == 0);
    f->wire.length = strlen(wire_hex[i]) / 2u;
    cose_hex(wire_hex[i], f->wire.bytes, f->wire.length);
    endpoints(f, &f->wire, &f->output);
    assert((i ? f->runtime.cose_verify_mac0 : f->runtime.cose_decrypt)(
               &f->runtime, &f->source, &f->sink, &key, NULL, &error) == 0);
    assert(f->output.length == 20u &&
           memcmp(f->output.bytes, "This is the content.", 20u) == 0);
    memcpy(f->input.bytes, f->output.bytes, 20u);
    f->input.length = 20u;
    options = f->runtime.default_cose_options(&f->runtime);
    if (!i) {
      cose_hex("02d1f7e6f26c43d4868d87ce", nonce, 12u);
      options.nonce = nonce;
    }
    endpoints(f, &f->input, &f->output);
    assert((i ? f->runtime.cose_mac0 : f->runtime.cose_encrypt0)(
               &f->runtime, &f->source, &f->sink, &key, &options, &error) == 0);
    assert(f->output.length == f->wire.length &&
           memcmp(f->output.bytes, f->wire.bytes, f->wire.length) == 0);
    assert(key.cleanup(&key) == 0);
  }
}
