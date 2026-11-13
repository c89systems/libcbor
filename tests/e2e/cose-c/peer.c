/* Bounded COSE-C data adapter. CTest owns assertions; upstream owns all COSE
 * encoding, KDF construction, ephemeral keys, key wrapping and authentication.
 * These published fixture keys must never become application defaults.
 */
#include <cose/cose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_BOUND 16384u

static HCOSE_KEY fixture_key(int sealing, int wrong, cose_errback *error) {
  unsigned char raw[32], public_bytes[32];
  size_t length = sizeof(public_bytes);
  EVP_PKEY *private_key;
  HCOSE_KEY key;
  memset(raw, 0, sizeof(raw));
  raw[31] = 1;
  /* Bit 3 survives X25519 clamping, unlike the three low bits. */
  raw[0] = wrong ? 8 : 0;
  private_key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, raw, 32);
  if (private_key == NULL)
    return NULL;
  if (EVP_PKEY_get_raw_public_key(private_key, public_bytes, &length) != 1 ||
      length != 32u) {
    EVP_PKEY_free(private_key);
    return NULL;
  }
  if (sealing) {
    EVP_PKEY_free(private_key);
    private_key =
        EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, public_bytes, 32);
    if (private_key == NULL)
      return NULL;
  }
  /* COSE-C's native-key constructor retains its own OpenSSL reference. */
  key = COSE_KEY_FromEVP(private_key, NULL, NULL, error);
  EVP_PKEY_free(private_key);
  return key;
}

static int transform(int sealing, int wrong, const unsigned char *input,
                     size_t length, const unsigned char *aad, size_t aad_length,
                     unsigned char *output, size_t *output_length) {
  cose_errback error;
  cn_cbor_errback cbor_error;
  HCOSE_ENVELOPED message = NULL;
  HCOSE_RECIPIENT recipient = NULL;
  HCOSE_KEY key = NULL;
  cn_cbor *algorithm;
  size_t size;
  int type = 0, result = 1;
  memset(&error, 0, sizeof(error));
  key = fixture_key(sealing, wrong, &error);
  if (key == NULL)
    goto done;
  if (sealing) {
    message = COSE_Enveloped_Init(COSE_INIT_FLAGS_NONE, NULL, &error);
    recipient = COSE_Recipient_Init(COSE_INIT_FLAGS_NONE, NULL, &error);
    if (message == NULL || recipient == NULL)
      goto done;
    algorithm =
        cn_cbor_int_create(COSE_Algorithm_AES_GCM_256, NULL, &cbor_error);
    if (algorithm == NULL)
      goto done;
    if (!COSE_Enveloped_map_put_int(message, COSE_Header_Algorithm, algorithm,
                                    COSE_PROTECT_ONLY, &error)) {
      cn_cbor_free(algorithm, NULL);
      goto done;
    }
    algorithm =
        cn_cbor_int_create(COSE_Algorithm_ECDH_ES_A256KW, NULL, &cbor_error);
    if (algorithm == NULL)
      goto done;
    if (!COSE_Recipient_map_put_int(recipient, COSE_Header_Algorithm, algorithm,
                                    COSE_PROTECT_ONLY, &error)) {
      cn_cbor_free(algorithm, NULL);
      goto done;
    }
    if (!COSE_Recipient_SetKey2(recipient, key, &error) ||
        !COSE_Enveloped_AddRecipient(message, recipient, &error) ||
        !COSE_Enveloped_SetContent(message, input, length, &error) ||
        !COSE_Enveloped_SetExternal(message, aad, aad_length, &error) ||
        !COSE_Enveloped_encrypt(message, &error))
      goto done;
    size = COSE_Encode((HCOSE)message, output, 0, FIXTURE_BOUND);
    if (size == 0 || size > FIXTURE_BOUND)
      goto done;
    *output_length = size;
  } else {
    result = 2;
    message = (HCOSE_ENVELOPED)COSE_Decode(input, length, &type,
                                           COSE_enveloped_object, NULL, &error);
    if (message == NULL || type != COSE_enveloped_object)
      goto done;
    recipient = COSE_Enveloped_GetRecipient(message, 0, &error);
    if (recipient == NULL || !COSE_Recipient_SetKey2(recipient, key, &error) ||
        !COSE_Enveloped_SetExternal(message, aad, aad_length, &error) ||
        !COSE_Enveloped_decrypt(message, recipient, &error))
      goto done;
    /* Upstream declares COSE_Enveloped_GetContent but does not define it.
     * Report authenticated decryption only; never substitute input bytes for
     * recovered plaintext or read a private upstream struct to emulate it.
     */
    *output_length = 0;
  }
  result = 0;
done:
  if (error.err == COSE_ERR_OUT_OF_MEMORY || error.err == COSE_ERR_INTERNAL)
    result = 1;
  if (recipient != NULL)
    COSE_Recipient_Free(recipient);
  if (message != NULL)
    COSE_Enveloped_Free(message);
  if (key != NULL)
    COSE_KEY_Free(key);
  if (result != 0)
    fprintf(stderr, "COSE-C rejected input (error %d)\n", (int)error.err);
  return result;
}

int main(int argc, char **argv) {
  unsigned char *input, *output, aad[128];
  size_t length, output_length = 0, i, aad_length;
  unsigned int value;
  int result, sealing;
  if (argc < 3 || argc > 4 ||
      (strcmp(argv[1], "seal") != 0 && strcmp(argv[1], "open") != 0) ||
      (argc == 4 && strcmp(argv[3], "wrong-key") != 0))
    return 1;
  sealing = strcmp(argv[1], "seal") == 0;
  aad_length = strlen(argv[2]);
  if (aad_length % 2u != 0 || aad_length > sizeof(aad) * 2u)
    return 1;
  aad_length /= 2u;
  for (i = 0; i < aad_length; ++i) {
    if (sscanf(argv[2] + i * 2u, "%2x", &value) != 1)
      return 1;
    aad[i] = (unsigned char)value;
  }
  input = malloc(FIXTURE_BOUND + 1u);
  output = malloc(FIXTURE_BOUND);
  if (input == NULL || output == NULL) {
    free(input);
    free(output);
    return 1;
  }
  length = fread(input, 1, FIXTURE_BOUND + 1u, stdin);
  if (ferror(stdin) || length > FIXTURE_BOUND)
    result = 1;
  else
    result = transform(sealing, argc == 4, input, length, aad, aad_length,
                       output, &output_length);
  if (result == 0 && fwrite(output, 1, output_length, stdout) != output_length)
    result = 1;
  free(input);
  free(output);
  return result;
}
