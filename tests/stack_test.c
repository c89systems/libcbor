#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
static int sizes_only;
static void *inspect(void *context) {
  pthread_attr_t a;
  size_t size, guard;
  void *base;
  int status;
  pid_t child;
  struct rlimit core;
  assert(pthread_getattr_np(pthread_self(), &a) == 0);
  assert(pthread_attr_getstack(&a, &base, &size) == 0);
  assert(pthread_attr_getguardsize(&a, &guard) == 0 && guard != 0);
  if (context != NULL)
    assert(size >= 256U * 1024U);
  else
    assert(size >= 128U * 1024U && size < 160U * 1024U);
  assert(pthread_attr_destroy(&a) == 0);
  if (sizes_only)
    return NULL;
  child = fork();
  assert(child >= 0);
  if (child == 0) {
    volatile unsigned char byte;
    core.rlim_cur = core.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &core);
    byte = *(volatile unsigned char *)((uintptr_t)base - 1U);
    (void)byte;
    _exit(0);
  }
  assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
  assert(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
  return NULL;
}
static void *nested(void *unused) {
  pthread_t thread;
  inspect(unused);
  assert(pthread_create(&thread, NULL, inspect, NULL) == 0);
  assert(pthread_join(thread, NULL) == 0);
  return NULL;
}
int main(int argc, char **argv) {
  pthread_t thread;
  pthread_attr_t explicit_size;
  int explicit_marker = 1;
  sizes_only = argc > 1 && strcmp(argv[1], "sizes") == 0;
  assert(pthread_attr_init(&explicit_size) == 0);
  assert(pthread_attr_setstacksize(&explicit_size, 256U * 1024U) == 0);
  assert(pthread_create(&thread, &explicit_size, inspect, &explicit_marker) ==
         0);
  assert(pthread_join(thread, NULL) == 0);
  assert(pthread_attr_destroy(&explicit_size) == 0);
  assert(pthread_create(&thread, NULL, nested, NULL) == 0);
  assert(pthread_join(thread, NULL) == 0);
  puts("stack: default, nested, explicit sizes and faulting guards passed");
  return 0;
}
