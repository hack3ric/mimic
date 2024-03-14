#ifndef _MIMIC_LOG_H
#define _MIMIC_LOG_H

#include <bpf/libbpf.h>
#include <stdio.h>

#include "shared/log.h"

extern int log_verbosity;

#define _LOG_ERROR_PREFIX "    \x1B[1;31merror:\x1B[0m "
#define _LOG_WARN_PREFIX "     \x1B[1;33mwarn:\x1B[0m "
#define _LOG_INFO_PREFIX "     \x1B[1;32minfo:\x1B[0m "
#define _LOG_DEBUG_PREFIX "    \x1B[1;34mdebug:\x1B[0m "
#define _LOG_TRACE_PREFIX "    \x1B[1;30mtrace:\x1B[0m "

static const char* _log_prefixes[] = {
  _LOG_ERROR_PREFIX, _LOG_WARN_PREFIX, _LOG_INFO_PREFIX, _LOG_DEBUG_PREFIX, _LOG_TRACE_PREFIX,
};

#define log(_l, fmt, ...)                     \
  if (log_verbosity >= (_l)) {                \
    fprintf(stderr, "%s", _log_prefixes[_l]); \
    fprintf(stderr, fmt, ##__VA_ARGS__);      \
    fprintf(stderr, "\n");                    \
  }

#define log_error(fmt, ...) log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define log_trace(fmt, ...) log(LOG_LEVEL_TRACE, fmt, ##__VA_ARGS__)

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);

#endif  // _MIMIC_LOG_H
