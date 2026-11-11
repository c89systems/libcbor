#include <c89cbor/lonejson.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct allocations {
  size_t live;
  size_t calls;
  int fail;
  c89cbor *probe;
  int reentered;
} allocations;
static void *allocate(void *context, size_t size) {
  allocations *state = context;
  void *storage;
  ++state->calls;
  if (state->probe != NULL) {
    c89cbor_encoder *child = NULL;
    assert(state->probe->cleanup(state->probe) == C89CBOR_BUSY);
    assert(state->probe->encoder_create(state->probe, NULL, &child) ==
           C89CBOR_BUSY);
    assert(child == NULL);
    ++state->reentered;
  }
  if (state->fail)
    return NULL;
  storage = malloc(size);
  if (storage != NULL)
    ++state->live;
  return storage;
}
static void release(void *context, void *storage) {
  allocations *state = context;
  if (storage != NULL) {
    assert(state->live != 0);
    --state->live;
    free(storage);
  }
}
static void lifetime(void) {
  allocations storage;
  c89cbor_config config = c89cbor_default_config();
  c89cbor *runtime;
  c89cbor_encoder *encoder;
  c89cbor_error error;
  c89cbor_allocator invalid;
  memset(&storage, 0, sizeof(storage));
  config.allocator.context = &storage;
  config.allocator.alloc = allocate;
  config.allocator.free = release;
  storage.fail = 1;
  runtime = (c89cbor *)&storage;
  assert(c89cbor_create(&config, &runtime, &error) == C89CBOR_NOMEM);
  assert(runtime == NULL && error.status == C89CBOR_NOMEM && storage.live == 0);
  storage.fail = 0;
  assert(c89cbor_create(&config, &runtime, &error) == 0);
  assert(storage.live == 1 && error.status == 0);
  assert(strcmp(runtime->version(runtime), c89cbor_version(NULL)) == 0);
  assert(strcmp(runtime->status_string(runtime, C89CBOR_BUSY),
                c89cbor_status_string(NULL, C89CBOR_BUSY)) == 0);
  storage.fail = 1;
  assert(runtime->encoder_create(runtime, NULL, &encoder) == C89CBOR_NOMEM);
  assert(encoder == NULL && storage.live == 1);
  storage.fail = 0;
  storage.probe = runtime;
  assert(runtime->encoder_create(runtime, NULL, &encoder) == 0);
  assert(storage.reentered == 1);
  storage.probe = NULL;
  assert(storage.live == 2);
  assert(runtime->cleanup(runtime) == C89CBOR_BUSY);
  assert(runtime->destroy(runtime) == C89CBOR_BUSY);
  assert(encoder->cleanup(encoder) == 0);
  assert(encoder->cleanup(encoder) == 0);
  assert(encoder->destroy(encoder) == 0 && storage.live == 1);
  invalid = config.allocator;
  invalid.free = NULL;
  assert(runtime->encoder_create(runtime, &invalid, &encoder) ==
         C89CBOR_INVALID);
  assert(encoder == NULL);
  assert(runtime->cleanup(runtime) == 0);
  assert(runtime->cleanup(runtime) == 0);
  assert(runtime->destroy(runtime) == 0 && storage.live == 0);
}
static void borrowed_output(void) {
  c89cbor runtime;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_token token;
  c89cbor_error error;
  const void *bytes;
  const void *again;
  size_t length, repeated, consumed;
  const unsigned char expected[] = {0x63, 'a', 'b', 'c'};
  unsigned char output[sizeof(expected)];
  size_t offset = 0;
  int status;
  assert(c89cbor_init(&runtime, NULL, &error) == 0);
  assert(runtime.encoder_init(&runtime, &encoder, NULL, 0, 2) == 0);
  assert(runtime.decoder_init(&runtime, &decoder, NULL, 0, 2) == 0);
  assert(encoder.destroy(&encoder) == C89CBOR_INVALID);
  assert(runtime.destroy(&runtime) == C89CBOR_INVALID);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_TEXT;
  token.argument = 3;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.peek(&encoder, &bytes, &length) == C89CBOR_OUTPUT);
  assert(length == 1 && *(const unsigned char *)bytes == 0x63);
  assert(encoder.peek(&encoder, &again, &repeated) == C89CBOR_OUTPUT);
  assert(again == bytes && repeated == length);
  assert(encoder.advance(&encoder, 2) == C89CBOR_INVALID);
  output[offset++] = *(const unsigned char *)bytes;
  assert(encoder.advance(&encoder, 1) == 0);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_DATA;
  token.data = "abc";
  token.length = 3;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.put(&encoder, &token) == C89CBOR_OUTPUT);
  do {
    status = encoder.peek(&encoder, &bytes, &length);
    assert(status == C89CBOR_OUTPUT && length > 0 && length <= 2);
    output[offset++] = *(const unsigned char *)bytes;
    status = encoder.advance(&encoder, 1);
  } while (status == C89CBOR_OUTPUT);
  assert(offset == sizeof(expected) && memcmp(output, expected, offset) == 0);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_END;
  token.argument = C89CBOR_TEXT;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.finish(&encoder) == 0);
  assert(decoder.next(&decoder, output, offset, &consumed, &token) ==
         C89CBOR_TOKEN);
  assert(consumed == 1 && token.type == C89CBOR_TEXT && token.argument == 3);
  assert(encoder.reset(&encoder) == 0);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_TEXT;
  token.argument = 1;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.read(&encoder, output, sizeof(output), &length) == 0);
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_DATA;
  token.data = "\xff";
  token.length = 1;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.peek(&encoder, &bytes, &length) == C89CBOR_MALFORMED);
  assert(bytes == NULL && length == 0);
  assert(encoder.diagnostic(&encoder, &error) == 0);
  assert(error.status == C89CBOR_MALFORMED &&
         strcmp(error.layer, "encoder") == 0);
  assert(encoder.cleanup(&encoder) == 0);
  assert(decoder.cleanup(&decoder) == 0);
  assert(runtime.cleanup(&runtime) == 0);
}
static void failed_initialization(void) {
  c89cbor runtime;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_reader reader;
  c89cbor_transfer transfer;
  c89cbor_fd fd;
  c89cbor_source source;
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  assert(runtime.encoder_init(&runtime, &encoder, NULL, 1, 0) ==
         C89CBOR_INVALID);
  assert(encoder.cleanup(&encoder) == 0);
  assert(runtime.decoder_init(&runtime, &decoder, NULL, 1, 0) ==
         C89CBOR_INVALID);
  assert(decoder.cleanup(&decoder) == 0);
  assert(runtime.reader_init(&runtime, &reader, (c89cbor_framing)99, 0) ==
         C89CBOR_INVALID);
  assert(reader.cleanup(&reader) == 0);
  assert(runtime.transfer_init(&runtime, &transfer, NULL, NULL, C89CBOR_SINGLE,
                               0) == C89CBOR_INVALID);
  assert(transfer.cleanup(&transfer) == 0);
  assert(runtime.fd_init(&runtime, &fd, -1, &source, NULL) == C89CBOR_INVALID);
  assert(fd.cleanup(&fd) == 0);
  assert(runtime.cleanup(&runtime) == 0);
}
static void descriptor_ownership(void) {
  c89cbor runtime;
  c89cbor_reader *reader;
  c89cbor_fd *fd;
  c89cbor_source source;
  c89cbor_event event;
  c89cbor_error error;
  int descriptors[2];
  unsigned char byte = 1;
  size_t used;
  assert(pipe(descriptors) == 0);
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  assert(runtime.fd_create(&runtime, descriptors[0], &fd) == 0);
  assert(fd->source(fd, &source) == 0);
  assert(write(descriptors[1], &byte, 1) == 1);
  assert(source.read(source.context, &byte, 1, &used) == 0 && used == 1);
  assert(fd->destroy(fd) == 0);
  assert(write(descriptors[1], &byte, 1) == 1);
  assert(read(descriptors[0], &byte, 1) == 1);
  assert(runtime.reader_create(&runtime, C89CBOR_SINGLE, 0, &reader) == 0);
  assert(reader->next(reader, &byte, 1, &used, &event) == C89CBOR_TOKEN);
  assert(reader->next(reader, &byte, 1, &used, &event) == C89CBOR_TOKEN);
  assert(reader->next(reader, NULL, 0, &used, &event) == C89CBOR_TOKEN);
  assert(reader->finish(reader) == 0);
  assert(reader->reset(reader) == 0);
  assert(reader->finish(reader) == C89CBOR_MALFORMED);
  assert(reader->diagnostic(reader, &error) == 0 &&
         error.status == C89CBOR_MALFORMED);
  assert(reader->destroy(reader) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  assert(close(descriptors[0]) == 0 && close(descriptors[1]) == 0);
}
static void application_tags(void) {
  static const unsigned char expected[] = {0xd9, 0xd9, 0xf7, 0xc0, 0x01};
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_token token;
  c89cbor_error error;
  unsigned char bytes[sizeof(expected)];
  size_t used, total = 0, i;
  uint64_t number;
  int status;
  assert(c89cbor_encoder_init(NULL, &encoder, NULL, 0, 0) == 0);
  assert(encoder.tag(&encoder, 55799) == 0);
  assert(encoder.tag(&encoder, 0) == C89CBOR_OUTPUT);
  assert(encoder.read(&encoder, bytes, sizeof(bytes), &used) == 0);
  total += used;
  assert(c89cbor_encoder_tag(&encoder, 0) == 0);
  assert(encoder.read(&encoder, bytes + total, sizeof(bytes) - total, &used) ==
         0);
  total += used;
  memset(&token, 0, sizeof(token));
  token.type = C89CBOR_UINT;
  token.argument = 1;
  assert(encoder.put(&encoder, &token) == 0);
  assert(encoder.end_tag(&encoder) == C89CBOR_OUTPUT);
  assert(encoder.read(&encoder, bytes + total, sizeof(bytes) - total, &used) ==
         0);
  total += used;
  assert(encoder.end_tag(&encoder) == 0 &&
         c89cbor_encoder_end_tag(&encoder) == 0);
  assert(encoder.finish(&encoder) == 0 && total == sizeof(expected) &&
         memcmp(bytes, expected, total) == 0);
  assert(c89cbor_decoder_init(NULL, &decoder, NULL, 0, 0) == 0);
  for (i = 0; i < 3; ++i) {
    status = decoder.next_tag(&decoder, bytes + i, 1, &used, &number);
    assert(used == 1 && status == (i == 2 ? C89CBOR_TOKEN : C89CBOR_INPUT));
  }
  assert(number == 55799);
  assert(c89cbor_decoder_next_tag(&decoder, bytes + 3, total - 3, &used,
                                  &number) == C89CBOR_TOKEN);
  assert(used == 1 && number == 0);
  assert(decoder.next(&decoder, bytes + 4, 1, &used, &token) == C89CBOR_TOKEN &&
         token.argument == 1);
  assert(decoder.next(&decoder, NULL, 0, &used, &token) == C89CBOR_TOKEN &&
         token.type == C89CBOR_END);
  assert(decoder.next(&decoder, NULL, 0, &used, &token) == C89CBOR_TOKEN &&
         token.type == C89CBOR_END);
  assert(decoder.finish(&decoder) == 0 && decoder.reset(&decoder) == 0);
  number = 99;
  used = 99;
  assert(decoder.next_tag(&decoder, bytes + 4, 1, &used, NULL) ==
             C89CBOR_INVALID &&
         used == 0);
  assert(decoder.next_tag(&decoder, bytes + 4, 1, &used, &number) ==
             C89CBOR_SCHEMA &&
         used == 1 && number == 0);
  assert(decoder.next(&decoder, NULL, 0, &used, &token) == C89CBOR_SCHEMA);
  assert(decoder.diagnostic(&decoder, &error) == 0 &&
         error.status == C89CBOR_SCHEMA);
  assert(decoder.cleanup(&decoder) == 0 && encoder.cleanup(&encoder) == 0);
}
int main(void) {
  lifetime();
  borrowed_output();
  failed_initialization();
  descriptor_ownership();
  application_tags();
  return 0;
}
