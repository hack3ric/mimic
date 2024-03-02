#include <bpf/libbpf.h>
#include <stdio.h>

#include "log.h"

int log_verbosity = 2;

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  int result1;
  if (level == LIBBPF_WARN && LOG_ALLOW_WARN) {
    result1 = fprintf(stderr, _LOG_WARN_PREFIX);
  } else if (level == LIBBPF_INFO && LOG_ALLOW_INFO) {
    result1 = fprintf(stderr, _LOG_INFO_PREFIX);
  } else if (level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG) {
    result1 = fprintf(stderr, _LOG_DEBUG_PREFIX);
  } else {
    return 0;
  }
  if (result1 < 0) return result1;
  int result2 = vfprintf(stderr, format, args);
  if (result2 < 0) return result2;
  return result1 + result2;
}
