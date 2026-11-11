#include "internal.h"
#include <stdlib.h>
#include <string.h>

#if LONEJSON_ABI_VERSION != 29
#error "libcbor requires lonejson 0.49.0 ABI 29"
#endif

static void *default_alloc(void *context, size_t size) {
  (void)context;
  return malloc(size);
}
static void default_free(void *context, void *ptr) {
  (void)context;
  free(ptr);
}
c89cbor_allocator c89cbor_default_allocator(void) {
  c89cbor_allocator allocator;
  allocator.context = NULL;
  allocator.alloc = default_alloc;
  allocator.free = default_free;
  return allocator;
}
int c89_allocator_valid(const c89cbor_allocator *allocator) {
  return allocator == NULL ||
         ((allocator->alloc == NULL) == (allocator->free == NULL));
}
int c89_allocate(c89cbor *parent, const c89cbor_allocator *override,
                 size_t size, void **out, c89cbor_allocator *selected) {
  if (out == NULL || selected == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  if (!c89_allocator_valid(override))
    return C89CBOR_INVALID;
  if (parent != NULL && (parent->lifetime.magic != C89_LIFETIME_MAGIC ||
                         !parent->lifetime.live || parent->lifetime.busy))
    return C89CBOR_INVALID;
  *selected =
      parent == NULL ? c89cbor_default_allocator() : parent->lifetime.allocator;
  if (override != NULL && override->alloc != NULL)
    *selected = *override;
  *out = selected->alloc(selected->context, size);
  return *out == NULL ? C89CBOR_NOMEM : C89CBOR_OK;
}
int c89_lifetime_init(c89cbor_lifetime *life, c89cbor *parent,
                      const c89cbor_allocator *allocator) {
  memset(life, 0, sizeof(*life));
  life->magic = C89_LIFETIME_MAGIC;
  life->allocator = c89cbor_default_allocator();
  if (!c89_allocator_valid(allocator))
    return C89CBOR_INVALID;
  if (parent != NULL) {
    if (parent->lifetime.magic != C89_LIFETIME_MAGIC || !parent->lifetime.live)
      return C89CBOR_INVALID;
    if (parent->lifetime.busy)
      return C89CBOR_BUSY;
    if (parent->lifetime.dependents == (size_t)-1)
      return C89CBOR_LIMIT;
    life->allocator = parent->lifetime.allocator;
    life->parent = parent;
    ++parent->lifetime.dependents;
  }
  if (allocator != NULL && allocator->alloc != NULL)
    life->allocator = *allocator;
  life->live = 1;
  return C89CBOR_OK;
}
int c89_lifetime_cleanup(c89cbor_lifetime *life) {
  if (life == NULL || life->magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  if (life->busy || life->dependents)
    return C89CBOR_BUSY;
  if (life->live && life->parent != NULL) {
    --life->parent->lifetime.dependents;
    life->parent = NULL;
  }
  life->live = 0;
  return C89CBOR_OK;
}
int c89_lifetime_destroy(c89cbor_lifetime *life, void *shell) {
  c89cbor_allocator allocator;
  int status;
  if (shell == NULL)
    return C89CBOR_OK;
  if (life->magic != C89_LIFETIME_MAGIC || !life->owned)
    return C89CBOR_INVALID;
  allocator = life->allocator;
  status = c89_lifetime_cleanup(life);
  if (status != C89CBOR_OK)
    return status;
  allocator.free(allocator.context, shell);
  return C89CBOR_OK;
}
int c89_lifetime_diagnostic(const c89cbor_lifetime *life,
                            c89cbor_error *error) {
  if (error == NULL)
    return C89CBOR_INVALID;
  memset(error, 0, sizeof(*error));
  if (life == NULL || life->magic != C89_LIFETIME_MAGIC)
    return C89CBOR_INVALID;
  *error = life->error;
  return C89CBOR_OK;
}
int c89_error(c89cbor_lifetime *life, int status, const char *layer) {
  if (life != NULL && life->magic == C89_LIFETIME_MAGIC &&
      life->error.status == 0 && status < 0 && status != C89CBOR_INVALID &&
      status != C89CBOR_BUSY) {
    life->error.status = status;
    life->error.offset = life->progress.input;
    strncpy(life->error.layer, layer, sizeof(life->error.layer) - 1u);
    strncpy(life->error.message, c89cbor_status_string(NULL, status),
            sizeof(life->error.message) - 1u);
  }
  return status;
}
c89cbor_config c89cbor_default_config(void) {
  c89cbor_config config;
  memset(&config, 0, sizeof(config));
  config.allocator = c89cbor_default_allocator();
  return config;
}
c89cbor_config c89cbor_runtime_default_config(c89cbor *runtime) {
  (void)runtime;
  return c89cbor_default_config();
}
c89cbor_allocator c89cbor_runtime_default_allocator(c89cbor *runtime) {
  (void)runtime;
  return c89cbor_default_allocator();
}
int c89cbor_init(c89cbor *runtime, const c89cbor_config *config,
                 c89cbor_error *error) {
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (runtime == NULL)
    return C89CBOR_INVALID;
  memset(runtime, 0, sizeof(*runtime));
  runtime->cleanup = c89cbor_cleanup;
  runtime->destroy = c89cbor_destroy;
  runtime->diagnostic = c89cbor_diagnostic;
  runtime->default_config = c89cbor_runtime_default_config;
  runtime->default_allocator = c89cbor_runtime_default_allocator;
  runtime->version = c89cbor_version;
  runtime->status_string = c89cbor_status_string;
  runtime->float64_set = c89cbor_float64_set;
  runtime->float64_get = c89cbor_float64_get;
  runtime->length32 = c89cbor_length32;
  runtime->encoder_init = c89cbor_encoder_init;
  runtime->decoder_init = c89cbor_decoder_init;
  runtime->encoder_create = c89cbor_encoder_create;
  runtime->decoder_create = c89cbor_decoder_create;
  runtime->reader_init = c89cbor_reader_init;
  runtime->reader_create = c89cbor_reader_create;
  runtime->transfer_init = c89cbor_transfer_init;
  runtime->transfer_create = c89cbor_transfer_create;
  runtime->fd_init = c89cbor_fd_init;
  runtime->fd_create = c89cbor_fd_create;
  status = c89_lifetime_init(&runtime->lifetime, NULL,
                             config == NULL ? NULL : &config->allocator);
  if (config != NULL)
    runtime->json = config->json;
  runtime->step_input = config == NULL || config->step_input == 0
                            ? C89CBOR_CHUNK
                            : config->step_input;
  runtime->step_output = config == NULL || config->step_output == 0
                             ? C89CBOR_CHUNK
                             : config->step_output;
  runtime->step_events =
      config == NULL || config->step_events == 0 ? 256 : config->step_events;
  if (error != NULL) {
    error->status = status;
    if (status != 0)
      strcpy(error->message, "invalid runtime allocator");
  }
  return status;
}
int c89cbor_create(const c89cbor_config *config, c89cbor **out,
                   c89cbor_error *error) {
  c89cbor_allocator allocator;
  void *storage;
  int status;
  if (error != NULL)
    memset(error, 0, sizeof(*error));
  if (out == NULL)
    return C89CBOR_INVALID;
  *out = NULL;
  status = c89_allocate(NULL, config == NULL ? NULL : &config->allocator,
                        sizeof(**out), &storage, &allocator);
  if (status == 0) {
    status = c89cbor_init(storage, config, error);
    if (status == 0) {
      *out = storage;
      (*out)->lifetime.owned = 1;
    } else {
      allocator.free(allocator.context, storage);
    }
  }
  if (error != NULL)
    error->status = status;
  return status;
}
int c89cbor_cleanup(c89cbor *runtime) {
  lonejson *json;
  int status;
  if (runtime == NULL)
    return C89CBOR_OK;
  status = c89_lifetime_cleanup(&runtime->lifetime);
  if (status != 0)
    return status;
  json = runtime->json_owned ? runtime->json : NULL;
  runtime->json = NULL;
  runtime->json_owned = 0;
  if (json != NULL)
    lonejson_free(json);
  return C89CBOR_OK;
}
int c89cbor_destroy(c89cbor *runtime) {
  int status;
  if (runtime == NULL)
    return C89CBOR_OK;
  if (!runtime->lifetime.owned)
    return C89CBOR_INVALID;
  status = c89cbor_cleanup(runtime);
  return status == 0 ? c89_lifetime_destroy(&runtime->lifetime, runtime)
                     : status;
}
int c89cbor_diagnostic(const c89cbor *runtime, c89cbor_error *error) {
  return c89_lifetime_diagnostic(runtime == NULL ? NULL : &runtime->lifetime,
                                 error);
}
