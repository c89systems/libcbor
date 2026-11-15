#ifndef C89CBOR_COSE_INTERNAL_H
#define C89CBOR_COSE_INTERNAL_H
#include "internal.h"
#include <c89cbor/cose.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <pthread.h>
#define C89_COSE_MAX_RECIPIENTS 32u
typedef struct c89_cose_key_state {
  c89cbor_cose_key_info info;
  unsigned char secret[32];
  EVP_PKEY *pkey;
  EVP_CIPHER *gcm, *wrap;
  EVP_KDF *hkdf;
  pthread_mutex_t mutex;
  uint64_t uses;
  int mutex_ready;
} c89_cose_key_state;
int c89_cose_key_valid(const c89cbor_cose_key *key);
int c89_cose_key_reserve(c89cbor_cose_key *key);
int c89_cose_keys_hold(c89cbor_cose_key *const *, size_t, c89cbor_cose_key **);
void c89_cose_keys_unhold(c89cbor_cose_key *const *, size_t);
EVP_PKEY *c89_cose_p256_import(const void *, int);
int c89_cose_auth_algorithm(c89cbor_cose_key_kind);
void c89_cose_runtime_methods(c89cbor *runtime);
int c89_cose_options_resolve(c89cbor *, const c89cbor_cose_options *,
                             c89cbor_cose_options *);
typedef struct c89_cose_cursor {
  c89cbor_decoder decoder;
  const unsigned char *bytes;
  size_t length, offset, start;
  c89cbor_token token;
} c89_cose_cursor;
typedef struct c89_cose_writer {
  c89cbor_encoder *encoder;
  unsigned char *bytes;
  size_t capacity, length;
  int status;
} c89_cose_writer;
typedef struct c89_cose_arena {
  unsigned char *bytes;
  size_t capacity, length;
} c89_cose_arena;
typedef struct c89_cose_party {
  c89cbor_type type;
  uint64_t argument;
  unsigned char *bytes;
  size_t length;
} c89_cose_party;
typedef struct c89_cose_header {
  unsigned char *protected_bytes, *id, *salt;
  size_t protected_length, id_length, salt_length;
  unsigned char nonce[12], ephemeral[32];
  c89_cose_party party[2][3];
  int algorithm, have_algorithm, protected_algorithm, have_nonce,
      have_ephemeral, protected_empty, unsupported;
} c89_cose_header;
typedef struct c89_cose_recipient {
  c89_cose_header header;
  unsigned char wrapped[40];
  size_t wrapped_length;
  int usable;
  const unsigned char *encoded;
  size_t encoded_length;
} c89_cose_recipient;
typedef struct c89_cose_state {
  c89_operation operation;
  c89cbor_conversion *owner;
  c89cbor *runtime;
  c89cbor_allocator allocator;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_cose_options options;
  c89cbor_cose_key *keys[C89_COSE_MAX_RECIPIENTS];
  size_t key_count;
  int seal, stream, encrypt, auth, seen_family, have_id, record_final;
  int eof, ready, after_output, finished, require_eof;
  unsigned char stream_id[16], record_id[16], input[C89CBOR_CHUNK];
  unsigned char stream_key[32];
  unsigned char recipient_fingerprint[32];
  int stream_key_ready, recipients_ready;
  uint64_t sequence, record_sequence;
  size_t input_length, input_offset, plain_length, wire_length;
  size_t output_length, output_offset;
  unsigned char *output, *workspace, *plain, *cipher, *wire, *aad, *external,
      *kdf;
  size_t workspace_size, wire_capacity, aad_capacity, external_capacity,
      kdf_capacity;
  c89_cose_arena arena;
  c89_cose_header body;
  c89_cose_recipient *recipients;
  size_t recipient_count, cipher_length;
  c89cbor_encoder encoder;
  c89cbor_decoder framer;
  EVP_CIPHER_CTX *cipher_context;
  EVP_MD_CTX *digest_context;
  EVP_MAC *mac;
  EVP_MAC_CTX *mac_context;
} c89_cose_state;
int c89_cose_workspace_init(c89_cose_state *);
void c89_cose_workspace_cleanup(c89_cose_state *);
void c89_cose_workspace_clear(c89_cose_state *);
int c89_cose_cursor_init(c89_cose_cursor *, const void *, size_t);
int c89_cose_next(c89_cose_cursor *);
int c89_cose_skip(c89_cose_cursor *);
int c89_cose_blob(c89_cose_cursor *, c89cbor_type, void *, size_t, size_t *);
int c89_cose_finish(c89_cose_cursor *);
int c89_cose_headers(c89_cose_cursor *, c89_cose_header *, c89_cose_arena *,
                     int);
void c89_cose_writer_init(c89_cose_writer *, c89cbor_encoder *, void *, size_t);
void c89_cose_emit(c89_cose_writer *, c89cbor_type, uint64_t);
void c89_cose_bytes(c89_cose_writer *, c89cbor_type, const void *, size_t);
int c89_cose_writer_finish(c89_cose_writer *);
int c89_cose_gcm(c89_cose_key_state *, EVP_CIPHER_CTX *, int,
                 const unsigned char *, const unsigned char *, const void *,
                 size_t, const void *, size_t, unsigned char *, size_t *);
int c89_cose_wrap(c89_cose_key_state *, EVP_CIPHER_CTX *, int,
                  const unsigned char *, const unsigned char *, size_t,
                  unsigned char *, size_t *);
int c89_cose_derive(c89_cose_key_state *, EVP_PKEY *, EVP_PKEY *,
                    const c89_cose_header *, c89cbor_encoder *, unsigned char *,
                    size_t, unsigned char *);
int c89_cose_seal_record(c89_cose_state *);
int c89_cose_open_record(c89_cose_state *);
int c89_cose_auth_record(c89_cose_state *);
int c89_cose_make_protected(c89_cose_state *, c89_cose_header *, int,
                            const c89cbor_cose_key_info *);
int c89_cose_make_aad(c89_cose_state *, int);
#endif
