/* Independent COSE_Encrypt fixtures and reference consumption. Literal CBOR
 * headers/KDF context deliberately bypass every libcbor encoding helper. */
static void cose_hex(const char *text, unsigned char *bytes, size_t length) {
  size_t i;
  unsigned int value;
  assert(strlen(text) == length * 2u);
  for (i = 0; i < length; ++i) {
    assert(sscanf(text + i * 2u, "%2x", &value) == 1);
    bytes[i] = (unsigned char)value;
  }
}
static void reference_wrap(int encrypt, const unsigned char *key,
                           const unsigned char *input, unsigned char *output) {
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int first, last;
  assert(context != NULL);
  EVP_CIPHER_CTX_set_flags(context, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  if (encrypt) {
    assert(EVP_EncryptInit_ex2(context, EVP_aes_256_wrap(), key, NULL, NULL) ==
           1);
    assert(EVP_EncryptUpdate(context, output, &first, input, 32) == 1);
    assert(EVP_EncryptFinal_ex(context, output + first, &last) == 1 &&
           first + last == 40);
  } else {
    assert(EVP_DecryptInit_ex2(context, EVP_aes_256_wrap(), key, NULL, NULL) ==
           1);
    assert(EVP_DecryptUpdate(context, output, &first, input, 40) == 1);
    assert(EVP_DecryptFinal_ex(context, output + first, &last) == 1 &&
           first + last == 32);
  }
  EVP_CIPHER_CTX_free(context);
}
static void reference_gcm(int encrypt, const unsigned char *key,
                          const unsigned char *nonce,
                          const unsigned char *input, unsigned char *output) {
  static const unsigned char aad[] = {0x83, 0x67, 'E',  'n',  'c', 'r', 'y',
                                      'p',  't',  0x43, 0xa1, 1,   3,   0x40};
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  OSSL_PARAM parameters[2];
  unsigned char tag[16];
  int first, last;
  assert(context != NULL);
  if (encrypt) {
    assert(EVP_EncryptInit_ex2(context, EVP_aes_256_gcm(), key, nonce, NULL) ==
           1);
    assert(EVP_EncryptUpdate(context, NULL, &first, aad, sizeof(aad)) == 1);
    assert(EVP_EncryptUpdate(context, output, &first, input, 17) == 1 &&
           first == 17);
    assert(EVP_EncryptFinal_ex(context, output + first, &last) == 1 &&
           last == 0);
    parameters[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, output + 17u, 16u);
    parameters[1] = OSSL_PARAM_construct_end();
    assert(EVP_CIPHER_CTX_get_params(context, parameters) == 1);
  } else {
    memcpy(tag, input + 17u, sizeof(tag));
    assert(EVP_DecryptInit_ex2(context, EVP_aes_256_gcm(), key, nonce, NULL) ==
           1);
    parameters[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
    parameters[1] = OSSL_PARAM_construct_end();
    assert(EVP_CIPHER_CTX_set_params(context, parameters) == 1);
    assert(EVP_DecryptUpdate(context, NULL, &first, aad, sizeof(aad)) == 1);
    assert(EVP_DecryptUpdate(context, output, &first, input, 17) == 1 &&
           first == 17);
    assert(EVP_DecryptFinal_ex(context, output + first, &last) == 1 &&
           last == 0);
  }
  EVP_CIPHER_CTX_free(context);
}
static void reference_shared(const unsigned char *private_bytes,
                             const unsigned char *public_bytes,
                             unsigned char *output) {
  EVP_PKEY *private_key =
      EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, private_bytes, 32u);
  EVP_PKEY *public_key =
      EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, public_bytes, 32u);
  EVP_PKEY_CTX *context;
  size_t length = 32u;
  assert(private_key != NULL && public_key != NULL);
  context = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
  assert(context != NULL && EVP_PKEY_derive_init(context) == 1);
  assert(EVP_PKEY_derive_set_peer(context, public_key) == 1);
  assert(EVP_PKEY_derive(context, output, &length) == 1 && length == 32u);
  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(private_key);
  EVP_PKEY_free(public_key);
}
static void reference_kdf(unsigned char *shared, unsigned char *output) {
  /* RFC 9053 KDF context: [-5,[nil,nil,nil],[nil,nil,nil],[256,h'a101381e']].
   */
  unsigned char info[] = {0x84, 0x24, 0x83, 0xf6, 0xf6, 0xf6, 0x83,
                          0xf6, 0xf6, 0xf6, 0x82, 0x19, 1,    0,
                          0x44, 0xa1, 1,    0x38, 0x1e};
  char digest[] = "SHA256";
  EVP_KDF *algorithm = EVP_KDF_fetch(NULL, "HKDF", NULL);
  EVP_KDF_CTX *context;
  OSSL_PARAM parameters[4];
  assert(algorithm != NULL);
  context = EVP_KDF_CTX_new(algorithm);
  assert(context != NULL);
  parameters[0] =
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  parameters[1] =
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared, 32u);
  parameters[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info,
                                                    sizeof(info));
  parameters[3] = OSSL_PARAM_construct_end();
  assert(EVP_KDF_derive(context, output, 32u, parameters) == 1);
  EVP_KDF_CTX_free(context);
  EVP_KDF_free(algorithm);
}
static void cose_reference(fixture *f) {
  static const unsigned char prefix[] = {0xd8, 0x60, 0x84, 0x43, 0xa1,
                                         1,    3,    0xa1, 5,    0x4c};
  static const unsigned char recipient_x[] = {
      0x81, 0x83, 0x44, 0xa1, 1, 0x38, 0x1e, 0xa2, 4,    0x41,
      'x',  0x20, 0xa3, 1,    1, 0x20, 4,    0x21, 0x58, 0x20};
  static const unsigned char recipient_wrap[] = {
      0x81, 0x83, 0x40, 0xa2, 1, 0x24, 4, 0x44, 'w', 'r', 'a', 'p', 0x58, 0x28};
  unsigned char alice_public[32], bob_private[32], bob_public[32], shared[32],
      known_shared[32];
  unsigned char key[32], wrapping_key[32], wrapped[40], known_wrap[40],
      nonce[12], plain[17], encrypted[33], public_bytes[32];
  c89cbor_cose_key bob, bob_recipient, symmetric;
  c89cbor_cose_key *keys[1];
  c89cbor_error error;
  size_t length, i;
  f->input.pause = f->wire.pause = f->output.pause = 0;
  f->input.fragment = f->wire.fragment = f->output.fragment = 0;
  cose_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
           alice_public, 32u);
  cose_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
           bob_private, 32u);
  cose_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
           bob_public, 32u);
  cose_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
           known_shared, 32u);
  reference_shared(bob_private, alice_public, shared);
  assert(memcmp(shared, known_shared, 32u) == 0);
  reference_kdf(shared, wrapping_key);
  cose_hex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
           key, 32u);
  memset(nonce, 0, sizeof(nonce));
  memset(plain, 'x', sizeof(plain));
  reference_wrap(1, wrapping_key, key, wrapped);
  reference_gcm(1, key, nonce, plain, encrypted);
  assert(f->runtime.cose_key_init(&f->runtime, &bob,
                                  C89CBOR_COSE_X25519_PRIVATE, bob_private, 32u,
                                  "x", 1u, &error) == 0);
  assert(bob.public_key(&bob, public_bytes, 32u, &length) == 0 &&
         length == 32u);
  assert(memcmp(public_bytes, bob_public, 32u) == 0);
  memcpy(f->wire.bytes, prefix, sizeof(prefix));
  memcpy(f->wire.bytes + 10u, nonce, 12u);
  f->wire.bytes[22] = 0x58;
  f->wire.bytes[23] = 33;
  memcpy(f->wire.bytes + 24u, encrypted, 33u);
  memcpy(f->wire.bytes + 57u, recipient_x, sizeof(recipient_x));
  memcpy(f->wire.bytes + 77u, alice_public, 32u);
  f->wire.bytes[109] = 0x58;
  f->wire.bytes[110] = 40;
  memcpy(f->wire.bytes + 111u, wrapped, 40u);
  f->wire.length = 151u;
  endpoints(f, &f->wire, &f->output);
  assert(f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink, &bob, NULL,
                                 &error) == 0);
  assert(f->output.length == 17u && memcmp(f->output.bytes, plain, 17u) == 0);
  assert(f->runtime.cose_key_init(&f->runtime, &bob_recipient,
                                  C89CBOR_COSE_X25519_PUBLIC, bob_public, 32u,
                                  "x", 1u, &error) == 0);
  memcpy(f->input.bytes, plain, 17u);
  f->input.length = 17u;
  endpoints(f, &f->input, &f->wire);
  keys[0] = &bob_recipient;
  assert(f->runtime.cose_encrypt(&f->runtime, &f->source, &f->sink, keys, 1u,
                                 NULL, &error) == 0);
  assert(f->wire.length == 151u &&
         memcmp(f->wire.bytes, prefix, sizeof(prefix)) == 0);
  assert(f->wire.bytes[22] == 0x58 && f->wire.bytes[23] == 33);
  assert(memcmp(f->wire.bytes + 57u, recipient_x, sizeof(recipient_x)) == 0);
  assert(f->wire.bytes[109] == 0x58 && f->wire.bytes[110] == 40);
  reference_shared(bob_private, f->wire.bytes + 77u, shared);
  reference_kdf(shared, wrapping_key);
  reference_wrap(0, wrapping_key, f->wire.bytes + 111u, key);
  reference_gcm(0, key, f->wire.bytes + 10u, f->wire.bytes + 24u, encrypted);
  assert(memcmp(encrypted, plain, 17u) == 0);
  /* RFC 3394 section 4.6: an independently wrapped AES-256 content key. */
  for (i = 0; i < 32u; ++i)
    wrapping_key[i] = (unsigned char)i;
  cose_hex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
           key, 32u);
  cose_hex("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb9"
           "88b9b7a02dd21",
           known_wrap, 40u);
  reference_wrap(1, wrapping_key, key, wrapped);
  assert(memcmp(wrapped, known_wrap, 40u) == 0);
  reference_gcm(1, key, nonce, plain, encrypted);
  assert(f->runtime.cose_key_init(&f->runtime, &symmetric, C89CBOR_COSE_A256KW,
                                  wrapping_key, 32u, "wrap", 4u, &error) == 0);
  memcpy(f->wire.bytes, prefix, sizeof(prefix));
  memcpy(f->wire.bytes + 10u, nonce, 12u);
  f->wire.bytes[22] = 0x58;
  f->wire.bytes[23] = 33;
  memcpy(f->wire.bytes + 24u, encrypted, 33u);
  memcpy(f->wire.bytes + 57u, recipient_wrap, sizeof(recipient_wrap));
  memcpy(f->wire.bytes + 57u + sizeof(recipient_wrap), known_wrap, 40u);
  f->wire.length = 57u + sizeof(recipient_wrap) + 40u;
  endpoints(f, &f->wire, &f->output);
  assert(f->runtime.cose_decrypt(&f->runtime, &f->source, &f->sink, &symmetric,
                                 NULL, &error) == 0);
  assert(f->output.length == 17u && memcmp(f->output.bytes, plain, 17u) == 0);
  assert(symmetric.cleanup(&symmetric) == 0 &&
         bob_recipient.cleanup(&bob_recipient) == 0 && bob.cleanup(&bob) == 0);
}
