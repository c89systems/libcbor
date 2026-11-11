static void reference_hkdf(unsigned char *key, size_t key_length,
                           unsigned char *info, size_t info_length,
                           unsigned char *salt, size_t salt_length,
                           unsigned char *output, size_t output_length) {
  EVP_KDF *algorithm = EVP_KDF_fetch(NULL, "HKDF", NULL);
  EVP_KDF_CTX *context;
  OSSL_PARAM parameters[5];
  char digest[] = "SHA256";
  assert(algorithm != NULL);
  context = EVP_KDF_CTX_new(algorithm);
  assert(context != NULL);
  parameters[0] =
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  parameters[1] =
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, key_length);
  parameters[2] =
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_length);
  parameters[3] =
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_length);
  parameters[4] = OSSL_PARAM_construct_end();
  assert(EVP_KDF_derive(context, output, output_length, parameters) == 1);
  EVP_KDF_CTX_free(context);
  EVP_KDF_free(algorithm);
}
static void cose_context_reference(fixture *f) {
  /* RFC 5869 appendix A.1, then an independently encoded COSE KDF context
   * with salt, PartyU identity/integer nonce and PartyV byte-string context. */
  unsigned char ikm[22], salt_vector[13], info_vector[10], okm[42],
      expected[42];
  unsigned char protected_bytes[] = {
      0xa6, 1,    0x38, 0x1e, 0x34, 0x41, 0x55, 0x35, 1, 0x38, 0x18, 0x42,
      0x56, 0x56, 0x38, 0x19, 0x41, 0x77, 0x33, 0x43, 0, 1,    2};
  unsigned char info[64] = {0x84, 0x24, 0x83, 0x41, 0x55, 1,    0xf6,
                            0x83, 0xf6, 0x42, 0x56, 0x56, 0x41, 0x77,
                            0x82, 0x19, 1,    0,    0x57};
  static const unsigned char prefix[] = {0xd8, 0x60, 0x84, 0x43, 0xa1,
                                         1,    3,    0xa1, 5,    0x4c};
  static const unsigned char unprotected[] = {
      0xa2, 4, 0x41, 'x', 0x20, 0xa3, 1, 1, 0x20, 4, 0x21, 0x58, 0x20};
  unsigned char private_bytes[32], alice_public[32], shared[32], kek[32],
      key[32], nonce[12] = {0}, plain[17], encrypted[33], wrapped[40],
               salt[3] = {0, 1, 2};
  size_t i, at;
  memset(ikm, 0x0b, sizeof(ikm));
  for (i = 0; i < sizeof(salt_vector); ++i)
    salt_vector[i] = (unsigned char)i;
  for (i = 0; i < sizeof(info_vector); ++i)
    info_vector[i] = (unsigned char)(0xf0u + i);
  cose_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf340"
           "07208d5b887185865",
           expected, 42u);
  reference_hkdf(ikm, sizeof(ikm), info_vector, sizeof(info_vector),
                 salt_vector, sizeof(salt_vector), okm, sizeof(okm));
  assert(memcmp(okm, expected, sizeof(okm)) == 0);
  memset(private_bytes, 0x37, sizeof(private_bytes));
  cose_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
           alice_public, 32u);
  reference_shared(private_bytes, alice_public, shared);
  memcpy(info + 19u, protected_bytes, sizeof(protected_bytes));
  reference_hkdf(shared, 32u, info, 19u + sizeof(protected_bytes), salt,
                 sizeof(salt), kek, 32u);
  memset(key, 0x31, sizeof(key));
  memset(plain, 'x', sizeof(plain));
  reference_wrap(1, kek, key, wrapped);
  reference_gcm(1, key, nonce, plain, encrypted);
  memcpy(f->wire.bytes, prefix, sizeof(prefix));
  memcpy(f->wire.bytes + 10u, nonce, 12u);
  f->wire.bytes[22] = 0x58;
  f->wire.bytes[23] = 33;
  memcpy(f->wire.bytes + 24u, encrypted, 33u);
  at = 57u;
  f->wire.bytes[at++] = 0x81;
  f->wire.bytes[at++] = 0x83;
  f->wire.bytes[at++] = 0x57;
  memcpy(f->wire.bytes + at, protected_bytes, sizeof(protected_bytes));
  at += sizeof(protected_bytes);
  memcpy(f->wire.bytes + at, unprotected, sizeof(unprotected));
  at += sizeof(unprotected);
  memcpy(f->wire.bytes + at, alice_public, 32u);
  at += 32u;
  f->wire.bytes[at++] = 0x58;
  f->wire.bytes[at++] = 40;
  memcpy(f->wire.bytes + at, wrapped, 40u);
  at += 40u;
  f->wire.length = at;
  assert(cose_open_to_buffer(f, &f->private_key, NULL, 0) == 0);
  assert(f->output.length == sizeof(plain) &&
         memcmp(f->output.bytes, plain, sizeof(plain)) == 0);
}
