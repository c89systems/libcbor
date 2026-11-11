#ifndef C89CBOR_MAP_H
#define C89CBOR_MAP_H
#include "number.h"

/* Metadata traversal and wire traversal share a bounded frame budget. */
typedef enum c89_map_kind {
  C89_MAP_OBJECT,
  C89_MAP_ARRAY,
  C89_MAP_TEXT,
  C89_MAP_KEY,
  C89_MAP_CHUNK,
  C89_MAP_JSON
} c89_map_kind;
typedef enum c89_path_kind {
  C89_PATH_ROOT,
  C89_PATH_FIELD,
  C89_PATH_INDEX
} c89_path_kind;
typedef union c89_map_record {
  const void *input;
  void *output;
} c89_map_record;
typedef struct c89_map_frame {
  c89_map_kind kind;
  const lonejson_map *map;
  const lonejson_field *field;
  c89_map_record record;
  size_t parent;
  c89_path_kind path_kind;
  const lonejson_field *path_field;
  uint64_t path_index;
  size_t next_field;
  size_t count;
  uint64_t index;
  int phase;
  int needs_key;
  int indefinite;
  int key_text;
  int streaming;
  size_t target;
  unsigned char *seen;
  size_t unknown_start;
  size_t unknown_bytes;
  const unsigned char *data;
  size_t length;
  size_t offset;
  uint64_t text_seen;
  uint64_t expected;
  const void *borrowed;
  size_t materialized;
  int truncated;
  const c89cbor_field_sink *binding;
  size_t saved_bytes;
  size_t saved_elements;
} c89_map_frame;
typedef struct c89_map_key {
  size_t offset;
  size_t length;
} c89_map_key;
typedef struct c89_map_payload {
  const unsigned char *memory;
  size_t length;
  size_t offset;
  FILE *file;
  int descriptor;
  int owned_file;
  lonejson_reader_fn reader;
  void *reader_context;
  int reader_eof;
  int spool;
  lonejson_spooled cursor;
  unsigned char carry[4];
  size_t carry_length;
  size_t chunk_length;
  c89cbor_fd fd;
  c89cbor_source fd_source;
  int fd_ready;
  const char *path;
} c89_map_payload;
typedef struct c89_map_state {
  c89_operation operation;
  c89cbor_conversion *owner;
  c89cbor *runtime;
  lonejson *json;
  c89cbor bridge_runtime;
  int bridge_runtime_ready;
  c89cbor_conversion bridge;
  int bridge_ready;
  int bridge_started;
  uint64_t bridge_input;
  c89cbor_options options;
  c89cbor_allocator allocator;
  const lonejson_map *map;
  c89_map_record record;
  int encode;
  c89cbor_source source;
  c89cbor_sink sink;
  c89cbor_encoder encoder;
  c89cbor_decoder decoder;
  c89cbor_frame *wire_frames;
  c89_map_frame *frames;
  size_t depth;
  size_t max_fields;
  size_t seen_stride;
  unsigned char *seen;
  size_t *path_stack;
  const lonejson_map **schema_path;
  unsigned char *schema_inline;
  c89_map_key *unknown_keys;
  char *unknown_storage;
  size_t unknown_count;
  size_t unknown_length;
  char *key;
  size_t key_length;
  unsigned char *input;
  size_t input_capacity;
  size_t input_offset;
  size_t input_length;
  unsigned char *output;
  size_t output_offset;
  size_t output_length;
  unsigned char *scratch;
  size_t scratch_capacity;
  size_t scratch_length;
  size_t stored_bytes;
  size_t stored_elements;
  c89_map_payload payload;
  c89cbor_token pending;
  size_t pending_offset;
  int pending_valid;
  int pending_phase;
  size_t skip_depth;
  int eof;
  int complete;
  int started;
  int done;
  int read_attempted;
  int consumer_paused;
  size_t step_written;
  size_t error_frame;
  const lonejson_field *error_field;
  int error_key;
  lonejson_error json_error;
} c89_map_state;

int c89_map_fail(c89_map_state *state, int status, const char *message);
int c89_map_dependency(c89_map_state *state, lonejson_status status);
void *c89_map_allocate(c89_map_state *state, size_t count, size_t size);
int c89_map_schema(c89_map_state *state, const lonejson_map *map, size_t extent,
                   size_t depth);
size_t c89_map_field_size(const lonejson_field *field);
int c89_map_omit(c89_map_state *state, const lonejson_field *field,
                 const void *record, size_t depth, int *omit);
int c89_map_count(c89_map_state *state, const lonejson_map *map,
                  const void *record, size_t depth, size_t *count);
int c89_map_push(c89_map_state *state, c89_map_kind kind, size_t parent,
                 const lonejson_field *field, uint64_t index);
const c89cbor_field_sink *c89_map_binding(c89_map_state *state, size_t frame);
int c89_map_budget(c89_map_state *state, size_t bytes, size_t elements);
int c89_map_encode_step(void *context);
int c89_map_decode_step(void *context);
int c89_map_payload_read(void *context, void *buffer, size_t capacity,
                         size_t *count);
void c89_map_payload_close(c89_map_state *state);
int c89_map_json_runtime(c89_map_state *state);
int c89_map_bridge_status(c89_map_state *state, int status,
                          const c89cbor_error *error);
#endif
