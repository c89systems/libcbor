#include <c89cbor/lonejson.h>
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct record {
  char *text;
} record;
static const lonejson_field fields[] = {
    LONEJSON_FIELD_STRING_ALLOC_REQ(record, text, "text")};
LONEJSON_MAP_DEFINE(map, record, fields);
typedef struct gate {
  pthread_mutex_t mutex;
  pthread_cond_t ready;
  size_t arrived;
} gate;
typedef struct context {
  gate *start;
  c89cbor *runtime;
  c89cbor_conversion *operation;
  const unsigned char *input;
  size_t length, offset, used, reads, writes;
  unsigned char output[256];
  int entered;
  int blocking;
} context;
static void enter(context *state) {
  c89cbor_error error;
  c89cbor_progress progress;
  if (state->entered)
    return;
  state->entered = 1;
  assert(state->operation->step(state->operation, &error) == C89CBOR_BUSY);
  assert(state->operation->cleanup(state->operation) == C89CBOR_BUSY);
  assert(state->operation->destroy(state->operation) == C89CBOR_BUSY);
  assert(state->operation->diagnostic(state->operation, &error) == 0 &&
         error.status == 0);
  assert(state->operation->progress(state->operation, &progress) == 0);
  assert(state->runtime->cleanup(state->runtime) == C89CBOR_BUSY);
  assert(pthread_mutex_lock(&state->start->mutex) == 0);
  ++state->start->arrived;
  if (state->start->arrived == 4)
    assert(pthread_cond_broadcast(&state->start->ready) == 0);
  while (state->start->arrived != 4)
    assert(pthread_cond_wait(&state->start->ready, &state->start->mutex) == 0);
  assert(pthread_mutex_unlock(&state->start->mutex) == 0);
}
static int read_bytes(void *data, void *bytes, size_t capacity, size_t *count) {
  context *state = data;
  size_t take = state->length - state->offset;
  *count = 0;
  enter(state);
  if ((++state->reads % 3u) == 0 && !state->blocking)
    return C89CBOR_INPUT;
  if (take > capacity)
    take = capacity;
  if (take > 2)
    take = 2;
  if (take != 0)
    memcpy(bytes, state->input + state->offset, take);
  state->offset += take;
  *count = take;
  return C89CBOR_OK;
}
static int write_bytes(void *data, const void *bytes, size_t length,
                       size_t *count) {
  context *state = data;
  size_t take = length < 2u ? length : 2u;
  enter(state);
  ++state->writes;
  assert(take <= sizeof(state->output) - state->used);
  memcpy(state->output + state->used, bytes, take);
  state->used += take;
  *count = take;
  return state->blocking ? C89CBOR_OK : C89CBOR_OUTPUT;
}
static void *run(void *data) {
  context *state = data;
  c89cbor_error error;
  c89cbor_progress progress;
  size_t steps = 0;
  int status;
  do {
    status = state->operation->step(state->operation, &error);
    assert(++steps < 10000u);
  } while (status == C89CBOR_OK || status == C89CBOR_INPUT ||
           status == C89CBOR_OUTPUT);
  assert(status == C89CBOR_DONE && error.status == 0);
  assert(state->operation->progress(state->operation, &progress) == 0);
  assert(progress.records == 1 && progress.input == state->offset &&
         progress.output == state->used);
  return NULL;
}
int main(void) {
  static const char json_text[] = "{\"text\":\"A\"}";
  static const char json_b[] = "{\"text\":\"B\"}";
  static const unsigned char cbor_b[] = {0xa1, 0x64, 't',  'e',
                                         'x',  't',  0x61, 'B'};
  static const unsigned char cbor_c[] = {0xa1, 0x64, 't',  'e',
                                         'x',  't',  0x61, 'C'};
  static const unsigned char cbor_d[] = {0xa1, 0x64, 't',  'e',
                                         'x',  't',  0x61, 'D'};
  context states[4];
  context reverse;
  pthread_t threads[4];
  gate start;
  c89cbor runtime;
  c89cbor_config config = c89cbor_default_config();
  c89cbor_error error;
  lonejson_error json_error;
  lonejson *json = lonejson_new(NULL, &json_error);
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_options options = c89cbor_default_options();
  record input, output;
  size_t i;
  assert(json != NULL);
  config.json = json;
  assert(c89cbor_init(&runtime, &config, &error) == 0);
  assert(lonejson_init(json, &map, &input, &json_error) == LONEJSON_STATUS_OK);
  assert(lonejson_init(json, &map, &output, &json_error) == LONEJSON_STATUS_OK);
  assert(lonejson_record_assign_string(json, &map, &input, fields, "D", 1,
                                       &json_error) == LONEJSON_STATUS_OK);
  assert(pthread_mutex_init(&start.mutex, NULL) == 0 &&
         pthread_cond_init(&start.ready, NULL) == 0);
  start.arrived = 0;
  memset(states, 0, sizeof(states));
  for (i = 0; i < 4; ++i) {
    states[i].start = &start;
    states[i].runtime = &runtime;
    states[i].input = i == 0   ? (const unsigned char *)json_text
                      : i == 1 ? cbor_b
                               : cbor_c;
    states[i].length = i == 0 ? strlen(json_text) : sizeof(cbor_b);
    options.chunk = i + 1u;
    options.step_events = 2;
    source.context = &states[i];
    source.read = read_bytes;
    sink.context = &states[i];
    sink.write = write_bytes;
    if (i == 0)
      assert(runtime.json_to_cbor_open(&runtime, &source, &sink, &options,
                                       &states[i].operation, &error) == 0);
    else if (i == 1)
      assert(runtime.cbor_to_json_open(&runtime, &source, &sink, &options,
                                       &states[i].operation, &error) == 0);
    else if (i == 2)
      assert(runtime.decode_map_open(&runtime, &source, &map, &output,
                                     sizeof(output), &options,
                                     &states[i].operation, &error) == 0);
    else {
      states[i].length = 0;
      assert(runtime.encode_map_open(&runtime, &map, &input, sizeof(input),
                                     &sink, &options, &states[i].operation,
                                     &error) == 0);
    }
  }
  for (i = 0; i < 4; ++i)
    assert(pthread_create(&threads[i], NULL, run, &states[i]) == 0);
  for (i = 0; i < 4; ++i)
    assert(pthread_join(threads[i], NULL) == 0);
  assert(runtime.cleanup(&runtime) == C89CBOR_BUSY);
  assert(states[1].used == strlen(json_b) &&
         memcmp(states[1].output, json_b, strlen(json_b)) == 0);
  assert(strcmp(output.text, "C") == 0);
  assert(states[3].used == sizeof(cbor_d) &&
         memcmp(states[3].output, cbor_d, sizeof(cbor_d)) == 0);
  memset(&reverse, 0, sizeof(reverse));
  reverse.entered = reverse.blocking = 1;
  reverse.input = states[0].output;
  reverse.length = states[0].used;
  source.context = &reverse;
  sink.context = &reverse;
  assert(runtime.cbor_to_json(&runtime, &source, &sink, NULL, &error) == 0);
  assert(reverse.used == strlen(json_text) &&
         memcmp(reverse.output, json_text, strlen(json_text)) == 0);
  for (i = 0; i < 4; ++i)
    assert(states[i].entered &&
           states[i].operation->destroy(states[i].operation) == 0);
  assert(json->cleanup(json, &map, &input, &json_error) == LONEJSON_STATUS_OK);
  assert(json->cleanup(json, &map, &output, &json_error) == LONEJSON_STATUS_OK);
  assert(runtime.cleanup(&runtime) == 0);
  lonejson_free(json);
  assert(pthread_cond_destroy(&start.ready) == 0 &&
         pthread_mutex_destroy(&start.mutex) == 0);
  return 0;
}
