#define _GNU_SOURCE
#include <pthread.h>
#include <assert.h>
#include <stddef.h>
/* Test processes only: all subsequently default-created workers, including Lua
 * and nested workers, receive musl's nominal 128 KiB budget. */
#if defined(__GLIBC__) && !defined(NDEBUG)
static void constrain_workers(void) __attribute__((constructor));
static void constrain_workers(void) {
  pthread_attr_t a;
  size_t guard, size;
  assert(pthread_getattr_default_np(&a) == 0);
  assert(pthread_attr_getguardsize(&a, &guard) == 0 && guard > 0);
  assert(pthread_attr_setstacksize(&a, 128U * 1024U) == 0);
  assert(pthread_setattr_default_np(&a) == 0);
  assert(pthread_attr_getstacksize(&a, &size) == 0 && size == 128U * 1024U);
  assert(pthread_attr_destroy(&a) == 0);
}
#endif
