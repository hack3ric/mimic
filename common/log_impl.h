#ifndef MIMIC_COMMON_LOG_IMPL_H
#define MIMIC_COMMON_LOG_IMPL_H

#include <stdarg.h>
#include <stdio.h>

#include "defs.h"
#include "log.h"

const char* log_prefixes[][2] = {
  {BOLD RED, N_("Error")},  {BOLD YELLOW, N_(" Warn")}, {BOLD GREEN, N_(" Info")},
  {BOLD BLUE, N_("Debug")}, {BOLD GRAY, N_("Trace")},
};

int log_verbosity = 2;

void log_any(int level, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (log_verbosity >= level) {
    fprintf(stderr, "%s%s " RESET, log_prefixes[level][0], gettext(log_prefixes[level][1]));
    if (level >= LOG_TRACE) fprintf(stderr, GRAY);
    vfprintf(stderr, fmt, ap);
    if (level >= LOG_TRACE) fprintf(stderr, RESET);
    fprintf(stderr, "\n");
  }
  va_end(ap);
}

#endif  // MIMIC_COMMON_LOG_IMPL_H
