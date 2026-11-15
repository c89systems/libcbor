/* The reference inputs below are literal RFC 9052 structures, independent of
 * libcbor's encoder, parser and Sig_structure builder. */
#include <openssl/ecdsa.h>
static void cose_authentication(fixture *f) {
  static const unsigned char sig_structure[] = {
      0x84, 0x6a, 'S',  'i', 'g',  'n',  'a',  't', 'u', 'r', 'e',
      '1',  0x43, 0xa1, 1,   0x32, 0x40, 0x43, 'a', 'b', 'c'};
  static const unsigned char mac_structure[] = {0x84, 0x64, 'M',  'A', 'C',
                                                '0',  0x43, 0xa1, 1,   5,
                                                0x40, 0x43, 'a',  'b', 'c'};
  c89cbor_cose_key signing, verifying;
  c89cbor_cose_options options = c89cbor_default_cose_options();
  c89cbor_cose_operation operation;
  c89cbor_error error;
  c89cbor_cose_key_kind kind;
  EVP_MD_CTX *md;
  EVP_PKEY *reference;
  ECDSA_SIG *ec_signature;
  BIGNUM *r, *s;
  unsigned char raw[32], public_bytes[65], expected[80],
      input[sizeof(sig_structure)];
  unsigned char *der_at;
  size_t length, expected_length;
  int algorithm, stream, status, tamper_case;
  options.step_input = 11u;
  options.step_output = 7u;
  options.step_events = 3u;
  for (algorithm = 0; algorithm < 3; ++algorithm) {
    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    if (algorithm == 0)
      cose_hex(
          "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
          raw, sizeof(raw));
    kind = algorithm == 0   ? C89CBOR_COSE_ED25519_PRIVATE
           : algorithm == 1 ? C89CBOR_COSE_P256_PRIVATE
                            : C89CBOR_COSE_HMAC256;
    assert(f->runtime.cose_key_init(&f->runtime, &signing, kind, raw,
                                    sizeof(raw), NULL, 0, &error) == 0);
    if (algorithm != 2) {
      assert(signing.public_key(&signing, public_bytes, sizeof(public_bytes),
                                &length) == 0);
      assert(length == (algorithm == 0 ? 32u : 65u));
      /* RFC 8032 test 1 public key, and the SEC2 P-256 generator (d=1). */
      if (algorithm == 0)
        cose_hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            expected, 32u);
      else
        cose_hex(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            expected, 65u);
      assert(memcmp(public_bytes, expected, length) == 0);
      assert(
          f->runtime.cose_key_init(&f->runtime, &verifying,
                                   algorithm == 0 ? C89CBOR_COSE_ED25519_PUBLIC
                                                  : C89CBOR_COSE_P256_PUBLIC,
                                   public_bytes, length, NULL, 0, &error) == 0);
    } else
      assert(f->runtime.cose_key_init(&f->runtime, &verifying, kind, raw,
                                      sizeof(raw), NULL, 0, &error) == 0);
    for (stream = 0; stream < 2; ++stream) {
      endpoints(f, &f->input, &f->wire);
      memcpy(f->input.bytes, "abc", 3u);
      f->input.length = 3u;
      f->input.pause = f->wire.pause = 1;
      status = algorithm == 2 ? (stream ? f->runtime.cose_mac0_stream_init
                                        : f->runtime.cose_mac0_init)(
                                    &f->runtime, &operation, &f->source,
                                    &f->sink, &signing, &options, &error)
                              : (stream ? f->runtime.cose_sign1_stream_init
                                        : f->runtime.cose_sign1_init)(
                                    &f->runtime, &operation, &f->source,
                                    &f->sink, &signing, &options, &error);
      assert(status == 0 && signing.cleanup(&signing) == C89CBOR_BUSY);
      assert(drive(&operation) == C89CBOR_DONE);
      assert(operation.cleanup(&operation) == 0);
      if (!stream) {
        assert(f->wire.bytes[0] == (algorithm == 2 ? 0xd1 : 0xd2));
        assert(f->wire.length == (algorithm == 2 ? 45u : 77u));
        if (algorithm == 2) {
          expected_length = 0;
          assert(EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, raw, sizeof(raw),
                           mac_structure, sizeof(mac_structure), expected,
                           sizeof(expected), &expected_length) != NULL);
          assert(expected_length == 32u &&
                 memcmp(expected, f->wire.bytes + 13u, 32u) == 0);
        } else {
          memcpy(input, sig_structure, sizeof(input));
          input[15] = algorithm == 0 ? 0x32 : 0x28;
          md = EVP_MD_CTX_new();
          assert(md != NULL);
          if (algorithm == 0) {
            reference = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL,
                                                        raw, sizeof(raw));
            assert(reference != NULL);
            assert(EVP_DigestSignInit_ex(md, NULL, NULL, NULL, NULL, reference,
                                         NULL) == 1);
            expected_length = sizeof(expected);
            assert(EVP_DigestSign(md, expected, &expected_length, input,
                                  sizeof(input)) == 1);
            assert(expected_length == 64u &&
                   memcmp(expected, f->wire.bytes + 13u, 64u) == 0);
          } else {
            /* Import the SEC1 public point through independent DER SPKI. */
            static const unsigned char prefix[] = {
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
            unsigned char spki[91];
            const unsigned char *spki_at = spki;
            memcpy(spki, prefix, sizeof(prefix));
            memcpy(spki + sizeof(prefix), public_bytes, 65u);
            reference = d2i_PUBKEY(NULL, &spki_at, sizeof(spki));
            assert(reference != NULL);
            ec_signature = ECDSA_SIG_new();
            r = BN_bin2bn(f->wire.bytes + 13u, 32, NULL);
            s = BN_bin2bn(f->wire.bytes + 45u, 32, NULL);
            assert(ec_signature != NULL && r != NULL && s != NULL &&
                   ECDSA_SIG_set0(ec_signature, r, s) == 1);
            der_at = expected;
            expected_length = (size_t)i2d_ECDSA_SIG(ec_signature, &der_at);
            assert(EVP_DigestVerifyInit_ex(md, NULL, "SHA256", NULL, NULL,
                                           reference, NULL) == 1);
            assert(EVP_DigestVerify(md, expected, expected_length, input,
                                    sizeof(input)) == 1);
            ECDSA_SIG_free(ec_signature);
          }
          EVP_PKEY_free(reference);
          EVP_MD_CTX_free(md);
        }
      }
      endpoints(f, &f->wire, &f->output);
      f->output.pause = 1;
      status = algorithm == 2
                   ? (stream ? f->runtime.cose_verify_mac0_stream_init
                             : f->runtime.cose_verify_mac0_init)(
                         &f->runtime, &operation, &f->source, &f->sink,
                         &verifying, &options, &error)
                   : (stream ? f->runtime.cose_verify1_stream_init
                             : f->runtime.cose_verify1_init)(
                         &f->runtime, &operation, &f->source, &f->sink,
                         &verifying, &options, &error);
      assert(status == 0 && drive(&operation) == C89CBOR_DONE);
      assert(f->output.length == 3u && memcmp(f->output.bytes, "abc", 3u) == 0);
      assert(operation.cleanup(&operation) == 0);
      for (tamper_case = 0; tamper_case < 2; ++tamper_case) {
        if (tamper_case == 0) {
          options.aad = "wrong";
          options.aad_length = 5u;
        } else
          f->wire.bytes[f->wire.length - 1u] ^= 1u;
        endpoints(f, &f->wire, &f->output);
        status = algorithm == 2
                     ? (stream ? f->runtime.cose_verify_mac0_stream_init
                               : f->runtime.cose_verify_mac0_init)(
                           &f->runtime, &operation, &f->source, &f->sink,
                           &verifying, &options, &error)
                     : (stream ? f->runtime.cose_verify1_stream_init
                               : f->runtime.cose_verify1_init)(
                           &f->runtime, &operation, &f->source, &f->sink,
                           &verifying, &options, &error);
        assert(status == 0 && drive(&operation) == C89CBOR_AUTH);
        assert(f->output.length == 0 && operation.cleanup(&operation) == 0);
        options.aad = NULL;
        options.aad_length = 0;
      }
    }
    assert(signing.cleanup(&signing) == 0 &&
           verifying.cleanup(&verifying) == 0);
  }
  /* Invalid scalars and public points fail import without leaking a child. */
  memset(raw, 0, sizeof(raw));
  assert(f->runtime.cose_key_init(&f->runtime, &signing,
                                  C89CBOR_COSE_P256_PRIVATE, raw, 32u, NULL, 0,
                                  &error) < 0);
  assert(signing.cleanup(&signing) == 0);
  memset(public_bytes, 0, sizeof(public_bytes));
  public_bytes[0] = 4;
  assert(f->runtime.cose_key_init(&f->runtime, &signing,
                                  C89CBOR_COSE_P256_PUBLIC, public_bytes, 65u,
                                  NULL, 0, &error) < 0);
  assert(signing.cleanup(&signing) == 0);
  f->wire.pause = f->input.pause = f->output.pause = 0;
}
