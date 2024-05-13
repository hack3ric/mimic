#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../common/defs.h"
#include "log.h"
#include "mimic.h"

static const char* _log_prefixes[][2] = {
  {BOLD RED, N_("Error")},  {BOLD YELLOW, N_(" Warn")}, {BOLD GREEN, N_(" Info")},
  {BOLD BLUE, N_("Debug")}, {BOLD GRAY, N_("Trace")},
};

int log_verbosity = 2;

void log_any(int level, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (log_verbosity >= level) {
    fprintf(stderr, "%s%s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
  }
  va_end(ap);
}

int libbpf_print_fn(enum libbpf_print_level bpf_level, const char* format, va_list args) {
  int ret = 0;
  if (bpf_level == LIBBPF_WARN && LOG_ALLOW_WARN) {
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
  if ((bpf_level == LIBBPF_WARN && LOG_ALLOW_WARN) ||
      (bpf_level == LIBBPF_INFO && LOG_ALLOW_INFO) ||
      (bpf_level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG)) {
    int level;
    switch (bpf_level) {
      case LIBBPF_WARN:
        level = LOG_LEVEL_WARN;
        break;
      case LIBBPF_INFO:
        level = LOG_LEVEL_INFO;
        break;
      case LIBBPF_DEBUG:
        level = LOG_LEVEL_DEBUG;
        break;
    }
    ret = fprintf(stderr, "%s%s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
    ret = ret < 0 ? ret : vfprintf(stderr, format, args);
  }
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
    case LOG_TYPE_QUICK_MSG:
    default:
      return "";
  }
}

int handle_log_event(struct log_event* e) {
  switch (e->type) {
    case LOG_TYPE_TCP_PKT:
      log_any(e->level, "%s: seq %08x, ack %08x", log_type_to_str(e->ingress, e->type),
              e->info.tcp.seq, e->info.tcp.ack_seq);
      break;
    case LOG_TYPE_STATE:
      log_any(e->level, "%s: %s, seq %08x, ack %08x", log_type_to_str(e->ingress, e->type),
              conn_state_to_str(e->info.tcp.state), e->info.tcp.seq, e->info.tcp.ack_seq);
      break;
    case LOG_TYPE_QUICK_MSG:
      log_any(e->level, "%s", e->info.msg);
      break;
    default: {
      char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
      struct conn_tuple* pkt = &e->info.conn;
      switch (e->type) {
        case LOG_TYPE_MATCHED:
        case LOG_TYPE_RST:
          if (e->ingress) {
            // invert again, since conn_tuple passed to it is already inverted
            ip_port_fmt(pkt->protocol, pkt->local, pkt->local_port, to);
            ip_port_fmt(pkt->protocol, pkt->remote, pkt->remote_port, from);
            break;
          }
          fallthrough;
        default:
          ip_port_fmt(pkt->protocol, pkt->local, pkt->local_port, from);
          ip_port_fmt(pkt->protocol, pkt->remote, pkt->remote_port, to);
      }
      log_any(e->level, "%s: %s => %s", log_type_to_str(e->ingress, e->type), from, to);
      break;
    }
  }
  return 0;
}

void log_conn(int level, const char* msg, struct conn_tuple* conn) {
  char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
  ip_port_fmt(conn->protocol, conn->local, conn->local_port, from);
  ip_port_fmt(conn->protocol, conn->remote, conn->remote_port, to);
  log_any(level, "%s: %s => %s", msg, from, to);
}
