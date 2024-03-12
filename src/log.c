#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

int log_verbosity = 2;

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  int ret = 0;
  if (level == LIBBPF_WARN && LOG_ALLOW_WARN) {
    // Get rid of harmless warning when tc qdisc already exists
    // This is dirty, but there is no other way to filter it
    // See https://www.spinics.net/lists/bpf/msg44842.html
    va_list backup_args;
    va_copy(backup_args, args);
    char buf[128];
    ret = vsnprintf(buf, sizeof(buf), format, backup_args);
    if (ret < 0) return ret;
    if (strstr(buf, "Exclusivity flag on, cannot modify")) {
      return 0;
    } else {
      ret = fprintf(stderr, _LOG_WARN_PREFIX);
    }
  } else if (level == LIBBPF_INFO && LOG_ALLOW_INFO) {
    ret = fprintf(stderr, _LOG_INFO_PREFIX);
  } else if (level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG) {
    ret = fprintf(stderr, _LOG_DEBUG_PREFIX);
  } else {
    return 0;
  }
  ret = ret < 0 ? ret : vfprintf(stderr, format, args);
  return ret < 0 ? ret : 0;
}
