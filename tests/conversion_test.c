#define _GNU_SOURCE
#include <c89cbor/lonejson.h>
#include <assert.h>
#include <errno.h>
#include <fenv.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct endpoint {
  const unsigned char *input;
  size_t input_length, offset, split, read_calls;
  unsigned char output[4096];
  size_t output_length, write_calls;
  int pause;
} endpoint;
static int read_bytes(void *context, void *buffer, size_t capacity,
                      size_t *count) {
  endpoint *memory = context;
  size_t take = memory->input_length - memory->offset;
  *count = 0;
  ++memory->read_calls;
  if (memory->pause && (memory->read_calls & 1u) != 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > memory->split)
    take = memory->split;
  if (take != 0)
    memcpy(buffer, memory->input + memory->offset, take);
  memory->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int write_bytes(void *context, const void *bytes, size_t length,
                       size_t *count) {
  endpoint *memory = context;
  size_t take = length;
  *count = 0;
  ++memory->write_calls;
  if (memory->pause && (memory->write_calls & 1u) != 0)
    return C89CBOR_OUTPUT;
  if (memory->pause && take > 3)
    take = 3;
  assert(take <= sizeof(memory->output) - memory->output_length);
  memcpy(memory->output + memory->output_length, bytes, take);
  memory->output_length += take;
  *count = take;
  return memory->pause ? C89CBOR_OUTPUT : C89CBOR_OK;
}
static int convert(c89cbor *runtime, endpoint *memory, int from_json,
                   const c89cbor_options *options, c89cbor_error *error) {
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_conversion *operation;
  c89cbor_progress progress;
  int status;
  size_t steps = 0, old_calls;
  source.context = memory;
  source.read = read_bytes;
  sink.context = memory;
  sink.write = write_bytes;
  status = from_json ? runtime->json_to_cbor_open(runtime, &source, &sink,
                                                  options, &operation, error)
                     : runtime->cbor_to_json_open(runtime, &source, &sink,
                                                  options, &operation, error);
  assert(status == 0);
  assert(memory->read_calls == 0 && memory->write_calls == 0);
  assert(runtime->cleanup(runtime) == C89CBOR_BUSY);
  do {
    old_calls = memory->read_calls;
    status = operation->step(operation, error);
    assert(memory->read_calls - old_calls <= 1);
    assert(++steps < 100000);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(operation->progress(operation, &progress) == 0);
  assert(progress.input == memory->offset &&
         progress.output == memory->output_length);
  old_calls = memory->write_calls;
  assert(operation->step(operation, error) == status);
  assert(memory->write_calls == old_calls);
  assert(operation->cleanup(operation) == 0);
  assert(operation->cleanup(operation) == 0);
  assert(operation->destroy(operation) == 0);
  return status;
}
static void json_fixture(const char *input, const unsigned char *expected,
                         size_t expected_length) {
  size_t split;
  c89cbor runtime;
  c89cbor_error error;
  endpoint memory;
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  for (split = 1; split <= 33; ++split) {
    memset(&memory, 0, sizeof(memory));
    memory.input = (const unsigned char *)input;
    memory.input_length = strlen(input);
    memory.split = split;
    memory.pause = 1;
    assert(convert(&runtime, &memory, 1, NULL, &error) == C89CBOR_DONE);
    if (expected != NULL) {
      assert(memory.output_length == expected_length);
      assert(memcmp(memory.output, expected, expected_length) == 0);
    }
  }
  assert(runtime.cleanup(&runtime) == 0);
}
static void cbor_fixture(const unsigned char *input, size_t length,
                         const char *expected) {
  size_t split;
  c89cbor runtime;
  c89cbor_error error;
  endpoint memory;
  c89cbor_options options = c89cbor_default_options();
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  for (split = 1; split <= 33; ++split) {
    memset(&memory, 0, sizeof(memory));
    memory.input = input;
    memory.input_length = length;
    memory.split = split;
    memory.pause = 1;
    options.step_events = split;
    assert(convert(&runtime, &memory, 0, &options, &error) == C89CBOR_DONE);
    assert(memory.output_length == strlen(expected));
    assert(memcmp(memory.output, expected, memory.output_length) == 0);
  }
  assert(runtime.cleanup(&runtime) == 0);
}
static void failure(const void *input, size_t length, int from_json,
                    int expected) {
  endpoint memory;
  c89cbor runtime;
  c89cbor_error error;
  memset(&memory, 0, sizeof(memory));
  memory.input = input;
  memory.input_length = length;
  memory.split = 1;
  memory.pause = 1;
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  assert(convert(&runtime, &memory, from_json, NULL, &error) == expected);
  assert(error.status == expected);
  assert(error.message[0] != '\0');
  assert(runtime.cleanup(&runtime) == 0);
}
static void fixtures(void) {
  static const unsigned char largest[] = {0x1b, 255, 255, 255, 255,
                                          255,  255, 255, 255};
  static const unsigned char lowest[] = {0x3b, 255, 255, 255, 255,
                                         255,  255, 255, 255};
  static const unsigned char half[] = {0xf9, 0x3e, 0};
  static const unsigned char single[] = {0xfa, 0x3f, 0xc0, 0, 0};
  static const unsigned char negative_zero[] = {0xfb, 128, 0, 0, 0, 0, 0, 0, 0};
  static const unsigned char object[] = {0xbf, 0x61, 'a', 0x9f, 1,    0xf5,
                                         0xf6, 0x62, 'h', 'i',  0xff, 0xff};
  static const unsigned char nul_key[] = {0xa1, 0x61, 0, 0};
  static const unsigned char indefinite_key[] = {0xbf, 0x7f, 0x61, 'a', 0x61,
                                                 'b',  0xff, 1,    0xff};
  static const unsigned char duplicates[] = {0xa2, 0x61, 'a', 0, 0x61, 'a', 1};
  static const unsigned char nan[] = {0xf9, 0x7e, 0};
  static const unsigned char non_text_key[] = {0xa1, 0, 0};
  static const unsigned char tagged[] = {0xc0, 0};
  static const unsigned char binary[] = {0x40};
  static const unsigned char trailing[] = {0, 1};
  json_fixture("18446744073709551615", largest, sizeof(largest));
  json_fixture("-18446744073709551616", lowest, sizeof(lowest));
  json_fixture("-0.0", negative_zero, sizeof(negative_zero));
  json_fixture("{\"a\":[1,true,null,\"hi\"]}", NULL, 0);
  json_fixture("{\"\xc2\xa2\":\"\xc3\xa9\"}", NULL, 0);
  cbor_fixture(largest, sizeof(largest), "18446744073709551615");
  cbor_fixture(lowest, sizeof(lowest), "-18446744073709551616");
  cbor_fixture(half, sizeof(half), "1.5");
  cbor_fixture(single, sizeof(single), "1.5");
  cbor_fixture(negative_zero, sizeof(negative_zero), "-0.0");
  cbor_fixture(object, sizeof(object), "{\"a\":[1,true,null,\"hi\"]}");
  cbor_fixture(nul_key, sizeof(nul_key), "{\"\\u0000\":0}");
  cbor_fixture(indefinite_key, sizeof(indefinite_key), "{\"ab\":1}");
  failure("18446744073709551616", 20, 1, C89CBOR_LIMIT);
  failure("-18446744073709551617", 21, 1, C89CBOR_LIMIT);
  failure("1e999", 5, 1, C89CBOR_LIMIT);
  failure("1e-999", 6, 1, C89CBOR_LIMIT);
  failure("{\"a\":0,\"\\u0061\":1}", sizeof("{\"a\":0,\"\\u0061\":1}") - 1u, 1,
          C89CBOR_SCHEMA);
  failure("[1,]", 4, 1, C89CBOR_MALFORMED);
  failure("1 2", 3, 1, C89CBOR_MALFORMED);
  failure(duplicates, sizeof(duplicates), 0, C89CBOR_SCHEMA);
  failure(nan, sizeof(nan), 0, C89CBOR_UNSUPPORTED);
  failure(non_text_key, sizeof(non_text_key), 0, C89CBOR_UNSUPPORTED);
  failure(tagged, sizeof(tagged), 0, C89CBOR_UNSUPPORTED);
  failure(binary, sizeof(binary), 0, C89CBOR_UNSUPPORTED);
  failure(trailing, sizeof(trailing), 0, C89CBOR_MALFORMED);
}
static void environment(void) {
  c89cbor runtime;
  endpoint memory;
  c89cbor_error error;
  fenv_t previous;
  int flags;
  static const unsigned char expected[] = {0xfb, 0x3f, 0xb9, 0x99, 0x99,
                                           0x99, 0x99, 0x99, 0x9a};
  assert(fegetenv(&previous) == 0);
  assert(fesetround(FE_DOWNWARD) == 0);
  assert(feraiseexcept(FE_DIVBYZERO) == 0);
  flags = fetestexcept(FE_ALL_EXCEPT);
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  memset(&memory, 0, sizeof(memory));
  memory.input = (const unsigned char *)"0.1";
  memory.input_length = 3;
  memory.split = 1;
  assert(convert(&runtime, &memory, 1, NULL, &error) == C89CBOR_DONE);
  assert(memory.output_length == sizeof(expected));
  assert(memcmp(memory.output, expected, sizeof(expected)) == 0);
  assert(fegetround() == FE_DOWNWARD && fetestexcept(FE_ALL_EXCEPT) == flags);
  assert(runtime.cleanup(&runtime) == 0);
  assert(fesetenv(&previous) == 0);
}
typedef struct memory_count {
  size_t live, bytes, peak, calls, fail_at;
  c89cbor_conversion *initializing;
  size_t reentries;
} memory_count;
static void construction_probe(memory_count *count) {
  if (count->initializing != NULL) {
    assert(count->initializing->cleanup(count->initializing) == C89CBOR_BUSY);
    assert(count->initializing->step(count->initializing, NULL) ==
           C89CBOR_BUSY);
    ++count->reentries;
  }
}
typedef union allocation_header {
  size_t size;
  long double alignment;
  void *pointer_alignment;
} allocation_header;
static void *count_allocate(void *context, size_t size) {
  memory_count *count = context;
  allocation_header *header;
  construction_probe(count);
  ++count->calls;
  if (count->calls == count->fail_at || size > (size_t)-1 - sizeof(*header))
    return NULL;
  header = malloc(sizeof(*header) + size);
  if (header == NULL)
    return NULL;
  header->size = size;
  ++count->live;
  count->bytes += size;
  if (count->peak < count->bytes)
    count->peak = count->bytes;
  return header + 1;
}
static void count_release(void *context, void *storage) {
  memory_count *count = context;
  allocation_header *header;
  if (storage == NULL)
    return;
  construction_probe(count);
  header = (allocation_header *)storage - 1;
  assert(count->live != 0 && count->bytes >= header->size);
  --count->live;
  count->bytes -= header->size;
  free(header);
}
static void *count_reallocate(void *context, void *storage, size_t size) {
  allocation_header *header;
  size_t take;
  void *replacement;
  if (storage == NULL)
    return count_allocate(context, size);
  header = (allocation_header *)storage - 1;
  take = header->size < size ? header->size : size;
  replacement = count_allocate(context, size);
  if (replacement != NULL) {
    memcpy(replacement, storage, take);
    count_release(context, storage);
  }
  return replacement;
}
static void counted_config(c89cbor_config *config, lonejson_allocator *json,
                           memory_count *count) {
  *config = c89cbor_default_config();
  *json = lonejson_default_allocator();
  config->allocator.context = count;
  config->allocator.alloc = count_allocate;
  config->allocator.free = count_release;
  json->ctx = count;
  json->malloc_fn = count_allocate;
  json->realloc_fn = count_reallocate;
  json->free_fn = count_release;
  config->json_config.allocator = json;
}
static void allocation_failures(void) {
  c89cbor runtime;
  c89cbor_config config;
  lonejson_allocator json;
  memory_count count;
  endpoint memory;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_conversion *operation;
  c89cbor_error error;
  size_t fail_at;
  int direction, status, finished;
  const unsigned char cbor[] = {0x81, 0x63, 'a', 'b', 'c'};
  for (direction = 0; direction <= 1; ++direction) {
    finished = 0;
    for (fail_at = 1; fail_at < 80; ++fail_at) {
      memset(&count, 0, sizeof(count));
      count.fail_at = fail_at;
      counted_config(&config, &json, &count);
      memset(&memory, 0, sizeof(memory));
      memory.input = direction ? (const unsigned char *)"[\"abc\"]" : cbor;
      memory.input_length =
          direction ? strlen((const char *)memory.input) : sizeof(cbor);
      memory.split = 2;
      source.context = &memory;
      source.read = read_bytes;
      sink.context = &memory;
      sink.write = write_bytes;
      assert(c89cbor_init(&runtime, &config, NULL) == 0);
      status = direction ? runtime.json_to_cbor_open(&runtime, &source, &sink,
                                                     NULL, &operation, &error)
                         : runtime.cbor_to_json_open(&runtime, &source, &sink,
                                                     NULL, &operation, &error);
      if (status == 0) {
        do {
          status = operation->step(operation, &error);
        } while (status == C89CBOR_OK);
        assert(status == C89CBOR_DONE || status == C89CBOR_NOMEM);
        assert(operation->destroy(operation) == 0);
      } else {
        assert(status == C89CBOR_NOMEM && operation == NULL);
        assert(memory.read_calls == 0 && memory.write_calls == 0);
      }
      if (count.calls < fail_at)
        finished = 1;
      assert(runtime.cleanup(&runtime) == 0);
      assert(count.live == 0 && count.bytes == 0);
      if (finished)
        break;
    }
    assert(finished);
  }
}
typedef struct construction_record {
  lonejson_int64 id;
} construction_record;
static const lonejson_field construction_fields[] = {
    LONEJSON_FIELD_I64_REQ(construction_record, id, "id")};
LONEJSON_MAP_DEFINE(construction_map, construction_record, construction_fields);
static void construction_reentry(void) {
  c89cbor runtime;
  c89cbor_config config;
  lonejson_allocator json;
  memory_count count;
  endpoint memory;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_conversion operation;
  c89cbor_error error;
  construction_record record;
  size_t fail_at;
  int direction, status, finished;
  source.context = sink.context = &memory;
  source.read = read_bytes;
  sink.write = write_bytes;
  record.id = 42;
  for (direction = 0; direction < 4; ++direction) {
    finished = 0;
    for (fail_at = 1; fail_at < 100; ++fail_at) {
      memset(&count, 0, sizeof(count));
      memset(&memory, 0, sizeof(memory));
      count.fail_at = fail_at;
      counted_config(&config, &json, &count);
      assert(c89cbor_init(&runtime, &config, NULL) == 0);
      count.initializing = &operation;
      if (direction == 0)
        status = runtime.json_to_cbor_init(&runtime, &operation, &source, &sink,
                                           NULL, &error);
      else if (direction == 1)
        status = runtime.cbor_to_json_init(&runtime, &operation, &source, &sink,
                                           NULL, &error);
      else if (direction == 2)
        status = runtime.encode_map_init(&runtime, &operation,
                                         &construction_map, &record,
                                         sizeof(record), &sink, NULL, &error);
      else
        status = runtime.decode_map_init(&runtime, &operation, &source,
                                         &construction_map, &record,
                                         sizeof(record), NULL, &error);
      count.initializing = NULL;
      assert(status == C89CBOR_OK || status == C89CBOR_NOMEM);
      assert(memory.read_calls == 0 && memory.write_calls == 0);
      assert(count.reentries != 0);
      finished = count.calls < fail_at;
      assert(operation.cleanup(&operation) == 0);
      assert(operation.cleanup(&operation) == 0);
      assert(runtime.cleanup(&runtime) == 0);
      assert(count.live == 0 && count.bytes == 0);
      if (finished)
        break;
    }
    assert(finished);
  }
}
typedef struct long_stream {
  size_t position, length, delivered, read_calls, write_calls;
  c89cbor_decoder decoder;
  size_t text_bytes;
  int before_eof;
} long_stream;
static int read_long(void *context, void *buffer, size_t capacity,
                     size_t *count) {
  long_stream *stream = context;
  unsigned char *bytes = buffer;
  size_t take, i;
  *count = 0;
  ++stream->read_calls;
  if ((stream->read_calls & 1u) != 0)
    return C89CBOR_INPUT;
  take = stream->length + 2u - stream->position;
  if (take > capacity)
    take = capacity;
  for (i = 0; i < take; ++i) {
    bytes[i] = stream->position == 0 || stream->position == stream->length + 1u
                   ? '"'
                   : 'x';
    ++stream->position;
  }
  *count = take;
  return C89CBOR_OK;
}
static int validate_long(void *context, const void *buffer, size_t length,
                         size_t *count) {
  long_stream *stream = context;
  const unsigned char *bytes = buffer;
  c89cbor_token token;
  size_t take = length, offset = 0, consumed, i;
  int status;
  *count = 0;
  ++stream->write_calls;
  if ((stream->write_calls & 1u) != 0)
    return C89CBOR_OUTPUT;
  if (take > 31)
    take = 31;
  if (stream->position < stream->length)
    stream->before_eof = 1;
  do {
    status = stream->decoder.next(&stream->decoder, bytes + offset,
                                  take - offset, &consumed, &token);
    offset += consumed;
    assert(status >= 0);
    if (status == C89CBOR_TOKEN && token.type == C89CBOR_DATA) {
      const unsigned char *data = token.data;
      for (i = 0; i < token.length; ++i)
        assert(data[i] == 'x');
      stream->text_bytes += token.length;
    }
  } while (status == C89CBOR_TOKEN);
  assert(offset == take);
  stream->delivered += take;
  *count = take;
  return C89CBOR_OUTPUT;
}
static void bounded_streaming(void) {
  c89cbor runtime;
  c89cbor_config config;
  lonejson_allocator json;
  memory_count count;
  long_stream stream;
  c89cbor_conversion *operation;
  c89cbor_source source;
  c89cbor_sink sink;
  size_t calls;
  int status;
  memset(&count, 0, sizeof(count));
  counted_config(&config, &json, &count);
  memset(&stream, 0, sizeof(stream));
  stream.length = 3u * 1024u * 1024u;
  assert(c89cbor_decoder_init(NULL, &stream.decoder, NULL, 0, 0) == 0);
  source.context = &stream;
  source.read = read_long;
  sink.context = &stream;
  sink.write = validate_long;
  assert(c89cbor_init(&runtime, &config, NULL) == 0);
  assert(runtime.json_to_cbor_open(&runtime, &source, &sink, NULL, &operation,
                                   NULL) == 0);
  calls = count.calls;
  do {
    status = operation->step(operation, NULL);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(status == C89CBOR_DONE && stream.before_eof);
  assert(stream.text_bytes == stream.length);
  assert(stream.decoder.finish(&stream.decoder) == 0);
  assert(count.calls == calls && count.peak < 128u * 1024u);
  assert(operation->destroy(operation) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  assert(count.live == 0 && count.bytes == 0);
}
static void limits_and_wrappers(void) {
  endpoint memory;
  c89cbor runtime;
  c89cbor_options options = c89cbor_default_options();
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_error error;
  memset(&memory, 0, sizeof(memory));
  memory.input = (const unsigned char *)"{\"aa\":0}";
  memory.input_length = strlen((const char *)memory.input);
  memory.split = 2;
  assert(c89cbor_init(&runtime, NULL, NULL) == 0);
  options.key_bytes = 1;
  assert(convert(&runtime, &memory, 1, &options, &error) == C89CBOR_LIMIT);
  memset(&memory, 0, sizeof(memory));
  memory.input = (const unsigned char *)"1234";
  memory.input_length = 4;
  memory.split = 1;
  options = c89cbor_default_options();
  options.number_bytes = 3;
  assert(convert(&runtime, &memory, 1, &options, &error) == C89CBOR_LIMIT);
  memset(&memory, 0, sizeof(memory));
  memory.input = (const unsigned char *)"null";
  memory.input_length = 4;
  memory.split = 1;
  source.context = &memory;
  source.read = read_bytes;
  sink.context = &memory;
  sink.write = write_bytes;
  assert(runtime.json_to_cbor(&runtime, &source, &sink, NULL, &error) == 0);
  assert(memory.output_length == 1 && memory.output[0] == 0xf6);
  memset(&memory, 0, sizeof(memory));
  memory.input = (const unsigned char *)"null";
  memory.input_length = 4;
  memory.split = 1;
  memory.pause = 1;
  assert(runtime.json_to_cbor(&runtime, &source, &sink, NULL, &error) ==
         C89CBOR_IO);
  assert(error.status == C89CBOR_IO);
  assert(runtime.cleanup(&runtime) == 0);
}
typedef struct reverse_stream {
  size_t length, position, read_calls, write_calls, text_bytes;
  int before_eof;
  lonejson_value_visitor_stream *validator;
} reverse_stream;
static int read_encoded(void *context, void *buffer, size_t capacity,
                        size_t *count) {
  reverse_stream *stream = context;
  static const unsigned char header[] = {0x7a, 0, 0x30, 0, 0};
  unsigned char *bytes = buffer;
  size_t take = stream->length + sizeof(header) - stream->position, i;
  *count = 0;
  ++stream->read_calls;
  if ((stream->read_calls & 1u) != 0)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  for (i = 0; i < take; ++i) {
    bytes[i] = stream->position < sizeof(header) ? header[stream->position] : 1;
    ++stream->position;
  }
  *count = take;
  return C89CBOR_OK;
}
static lonejson_status validate_decoded(void *context, const char *bytes,
                                        size_t length, lonejson_error *error) {
  reverse_stream *stream = context;
  size_t i;
  (void)error;
  for (i = 0; i < length; ++i)
    assert(bytes[i] == 1);
  stream->text_bytes += length;
  return LONEJSON_STATUS_OK;
}
static int write_json_stream(void *context, const void *bytes, size_t length,
                             size_t *count) {
  reverse_stream *stream = context;
  size_t take = length, consumed;
  lonejson_error error;
  *count = 0;
  ++stream->write_calls;
  if ((stream->write_calls & 1u) != 0)
    return C89CBOR_OUTPUT;
  if (take > 31)
    take = 31;
  if (stream->position < stream->length)
    stream->before_eof = 1;
  assert(stream->validator->push(stream->validator, bytes, take, &consumed,
                                 &error) == LONEJSON_STATUS_OK);
  assert(consumed == take);
  *count = take;
  return C89CBOR_OUTPUT;
}
static void reverse_bounded_streaming(void) {
  c89cbor runtime;
  c89cbor_config config;
  lonejson_allocator json;
  lonejson_value_visitor visitor = lonejson_default_value_visitor();
  memory_count count;
  reverse_stream stream;
  c89cbor_conversion *operation;
  c89cbor_source source;
  c89cbor_sink sink;
  size_t calls;
  int status;
  memset(&count, 0, sizeof(count));
  counted_config(&config, &json, &count);
  memset(&stream, 0, sizeof(stream));
  stream.length = 3u * 1024u * 1024u;
  source.context = &stream;
  source.read = read_encoded;
  sink.context = &stream;
  sink.write = write_json_stream;
  assert(c89cbor_init(&runtime, &config, NULL) == 0);
  assert(runtime.cbor_to_json_open(&runtime, &source, &sink, NULL, &operation,
                                   NULL) == 0);
  visitor.string_chunk = validate_decoded;
  stream.validator = runtime.json->value_visitor_stream_open(
      runtime.json, &visitor, &stream, NULL);
  assert(stream.validator != NULL);
  calls = count.calls;
  do {
    status = operation->step(operation, NULL);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(status == C89CBOR_DONE && stream.before_eof);
  assert(stream.validator->finish(stream.validator, NULL) ==
         LONEJSON_STATUS_OK);
  assert(stream.text_bytes == stream.length);
  assert(count.calls == calls && count.peak < 128u * 1024u);
  stream.validator->close(stream.validator);
  assert(operation->destroy(operation) == 0);
  assert(runtime.cleanup(&runtime) == 0);
  assert(count.live == 0 && count.bytes == 0);
}

static void *run_tests(void *unused) {
  (void)unused;
  fixtures();
  environment();
  limits_and_wrappers();
  allocation_failures();
  construction_reentry();
  bounded_streaming();
  reverse_bounded_streaming();
  return NULL;
}

int main(void) {
  pthread_t worker;
  assert(pthread_create(&worker, NULL, run_tests, NULL) == 0);
  assert(pthread_join(worker, NULL) == 0);
  return 0;
}
