#ifndef C89CBOR_INTERNAL_H
#define C89CBOR_INTERNAL_H
#include <c89cbor/lonejson.h>
#define C89_LIFETIME_MAGIC 0x43424f52U
int c89_lifetime_init(c89cbor_lifetime *life, c89cbor *parent,
                      const c89cbor_allocator *allocator);
int c89_lifetime_cleanup(c89cbor_lifetime *life);
int c89_lifetime_destroy(c89cbor_lifetime *life, void *shell);
int c89_lifetime_diagnostic(const c89cbor_lifetime *life, c89cbor_error *error);
int c89_error(c89cbor_lifetime *life, int status, const char *layer);
int c89_allocator_valid(const c89cbor_allocator *allocator);
int c89_allocate(c89cbor *parent, const c89cbor_allocator *override,
                 size_t size, void **out, c89cbor_allocator *selected);
#endif
