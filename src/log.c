#include <bpf/libbpf.h>
#include <linux/tcp.h>
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
    if (level >= LOG_LEVEL_TRACE) fprintf(stderr, GRAY);
    vfprintf(stderr, fmt, ap);
    if (level >= LOG_LEVEL_TRACE) fprintf(stderr, RESET);
    fprintf(stderr, "\n");
  }
  va_end(ap);
}

void log_conn(int level, struct conn_tuple* conn, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (log_verbosity >= level) {
    char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
    ip_port_fmt(conn->protocol, conn->local, conn->local_port, from);
    ip_port_fmt(conn->protocol, conn->remote, conn->remote_port, to);
    fprintf(stderr, "%s%s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
    if (level >= LOG_LEVEL_TRACE) fprintf(stderr, GRAY);
    fprintf(stderr, "%s => %s :: ", from, to);
    vfprintf(stderr, fmt, ap);
    if (level >= LOG_LEVEL_TRACE) fprintf(stderr, RESET);
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
      (bpf_level == LIBBPF_DEBUG && LOG_ALLOW_TRACE)) {
    int level;
    switch (bpf_level) {
      case LIBBPF_WARN:
        level = LOG_LEVEL_WARN;
        break;
      case LIBBPF_INFO:
        level = LOG_LEVEL_INFO;
        break;
      case LIBBPF_DEBUG:
        level = LOG_LEVEL_TRACE;
        break;
    }
    ret = fprintf(stderr, "%s%s " RESET, _log_prefixes[level][0], gettext(_log_prefixes[level][1]));
    if (level >= LOG_LEVEL_TRACE) ret = ret < 0 ? ret : fprintf(stderr, GRAY);
    ret = ret < 0 ? ret : vfprintf(stderr, format, args);
    if (level >= LOG_LEVEL_TRACE) ret = ret < 0 ? ret : fprintf(stderr, RESET);
  }
  return ret < 0 ? ret : 0;
}

static inline const char* log_type_to_str(enum log_type type) {
  switch (type) {
    case LOG_CONN_INIT:
      return _("initializing connection");
    case LOG_CONN_ESTAB:
      return _("connection established");
    case LOG_CONN_DESTROY:
      return _("connection destroyed");
    case LOG_PKT_RECV_RST:
      return _("received RST");
    default:
      return "";
  }
}

static int _log_tcp(enum log_level level, bool recv, struct conn_tuple* conn, __u16 len,
                    __u16 flags, __u32 seq, __u32 ack_seq) {
  if (log_verbosity < level) return 0;
  char buf[12] = {};
  if (flags) {
    if (flags & SYN) strcat(buf, "SYN,");
    if (flags & RST) strcat(buf, "RST,");
    if (flags & ACK) strcat(buf, "ACK,");
  } else {
    strcpy(buf, "<None>");
  }
  if (recv) {
    log_conn(level, conn, _("recv, len=%u, %s seq=%08x, ack=%08x"), len, buf, seq, ack_seq);
  } else {
    log_conn(level, conn, _("sent, len=%u, %s seq=%08x, ack=%08x"), len, buf, seq, ack_seq);
  }
  return 0;
}

int log_tcp(enum log_level level, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len) {
  return _log_tcp(level, false, conn, len, tcp->syn * SYN | tcp->ack * ACK | tcp->rst * RST,
                  htonl(tcp->seq), htonl(tcp->ack_seq));
}

int handle_log_event(struct log_event* e) {
  if (e->type == LOG_MSG) {
    log_any(e->level, "%s", e->info.msg);
  } else {
    switch (e->type) {
      case LOG_PKT_SEND_TCP:
      case LOG_PKT_RECV_TCP:
        _log_tcp(e->level, e->type == LOG_PKT_RECV_TCP, &e->info.conn, e->info.len, e->info.flags,
                 e->info.seq, e->info.ack_seq);
        break;
      default:
        log_conn(e->level, &e->info.conn, "%s", log_type_to_str(e->type));
        break;
    }
  }
  return 0;
}
