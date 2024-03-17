#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "shared/gettext.h"
#include "shared/log.h"

int log_verbosity = 2;

void log_any(int level, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (log_verbosity >= level) {
    fprintf(stderr, "%s %s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
  }
  va_end(ap);
}

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
    if (strstr(buf, "Exclusivity flag on, cannot modify")) return 0;
  }
  if (level == LIBBPF_WARN && LOG_ALLOW_WARN || level == LIBBPF_INFO && LOG_ALLOW_INFO ||
      level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG) {
    ret = fprintf(stderr, "%s %s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
  }
  ret = ret < 0 ? ret : vfprintf(stderr, format, args);
  return ret < 0 ? ret : 0;
}

const char* log_type_to_str(bool ingress, enum log_type type) {
  switch (type) {
    case LOG_TYPE_MATCHED:
      return ingress ? _("matched TCP packet") : _("matched UDP packet");
    case LOG_TYPE_CONN_ESTABLISH:
      return _("connection established");
    case LOG_TYPE_TCP_PKT:
      return ingress ? _("received TCP packet") : _("sending TCP packet");
    case LOG_TYPE_STATE:
      return _("current state");
    case LOG_TYPE_RST:
      return ingress ? _("received RST") : _("sending RST");
    case LOG_TYPE_CONN_DESTROY:
      return _("connection destroyed");
  }
}
