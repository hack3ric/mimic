#ifndef MIMIC_COMMON_LOG_H
#define MIMIC_COMMON_LOG_H

#include "defs.h"  // IWYU pragma: keep

extern const char* log_prefixes[][2];
extern int log_verbosity;

#define RED "\x1B[31m"
#define YELLOW "\x1B[33m"
#define GREEN "\x1B[32m"
#define BLUE "\x1B[34m"
#define GRAY "\x1B[90m"
#define BOLD "\x1B[1m"
#define RESET "\x1B[0m"

void log_any(int level, const char* fmt, ...);

#define log_error(fmt, ...) log_any(LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_any(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_any(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) log_any(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_trace(fmt, ...) log_any(LOG_TRACE, fmt, ##__VA_ARGS__)

#endif  // MIMIC_COMMON_LOG_H
