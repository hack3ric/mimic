#ifndef _MIMIC_LOG_H
#define _MIMIC_LOG_H

#include <bpf/libbpf.h>
#include <stdio.h>

#define _LOG_DEBUG_PREFIX " \e[1;34mdebug:\e[0m "
#define _LOG_INFO_PREFIX "  \e[1;32minfo:\e[0m "
#define _LOG_WARN_PREFIX "  \e[1;33mwarn:\e[0m "
#define _LOG_ERROR_PREFIX " \e[1;31merror:\e[0m "

static int log_verbosity = 2;

#define LOG_ALLOW_DEBUG (log_verbosity >= 3)
#define LOG_ALLOW_INFO (log_verbosity >= 2)
#define LOG_ALLOW_WARN (log_verbosity >= 1)
#define LOG_ALLOW_ERROR (1)

#define log_debug(fmt, ...) \
  if (LOG_ALLOW_DEBUG) fprintf(stderr, _LOG_DEBUG_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (LOG_ALLOW_INFO) fprintf(stderr, _LOG_INFO_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (LOG_ALLOW_WARN) fprintf(stderr, _LOG_WARN_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) \
  if (LOG_ALLOW_ERROR) fprintf(stderr, _LOG_ERROR_PREFIX fmt "\n", ##__VA_ARGS__)


static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  int result1;
  if (level == LIBBPF_WARN && LOG_ALLOW_WARN)
    result1 = fprintf(stderr, _LOG_WARN_PREFIX);
  else if (level == LIBBPF_INFO && LOG_ALLOW_INFO)
    result1 = fprintf(stderr, _LOG_INFO_PREFIX);
  else if (level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG)
    result1 = fprintf(stderr, _LOG_DEBUG_PREFIX);
  else
    return 0;
  if (result1 < 0) return result1;
  int result2 = vfprintf(stderr, format, args);
  if (result2 < 0) return result2;
  return result1 + result2;
}

#endif
