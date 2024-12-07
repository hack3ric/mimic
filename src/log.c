#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "common/defs.h"
#include "common/log_impl.h"
#include "log.h"
#include "main.h"

void log_conn(int level, struct conn_tuple* conn, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (log_verbosity >= level) {
    char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
    ip_port_fmt(&conn->local, conn->local_port, from);
    ip_port_fmt(&conn->remote, conn->remote_port, to);
    fprintf(stderr, "%s%s " RESET, log_prefixes[level][0], gettext(log_prefixes[level][1]));
    if (level >= LOG_TRACE) fprintf(stderr, GRAY);
    fprintf(stderr, "%s => %s :: ", from, to);
    vfprintf(stderr, fmt, ap);
    if (level >= LOG_TRACE) fprintf(stderr, RESET);
    fprintf(stderr, "\n");
  }
  va_end(ap);
}

static void _log_tcp(enum log_level level, bool recv, struct conn_tuple* conn, __u16 len,
                     __u16 flags, __u32 seq, __u32 ack_seq) {
  if (log_verbosity < level) return;
  char buf[32] = {};
  if (flags) {
    __be32 flag_word = htonl(flags << 16);
    if (flag_word & TCP_FLAG_SYN) strcat(buf, "SYN,");
    if (flag_word & TCP_FLAG_RST) strcat(buf, "RST,");
    if (flag_word & TCP_FLAG_FIN) strcat(buf, "FIN,");
    if (flag_word & TCP_FLAG_PSH) strcat(buf, "PSH,");
    if (flag_word & TCP_FLAG_ACK) strcat(buf, "ACK,");
    if (flag_word & TCP_FLAG_CWR) strcat(buf, "CWR,");
    if (flag_word & TCP_FLAG_ECE) strcat(buf, "ECE,");
    if (flag_word & TCP_FLAG_URG) strcat(buf, "URG,");
  } else {
    strcpy(buf, "<None>");
  }
  if (recv)
    log_conn(level, conn, _("recv - len=%u, %s seq=%08x, ack=%08x"), len, buf, seq, ack_seq);
  else
    log_conn(level, conn, _("sent - len=%u, %s seq=%08x, ack=%08x"), len, buf, seq, ack_seq);
}

void log_tcp(enum log_level level, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len) {
  _log_tcp(level, false, conn, len, ntohl(tcp_flag_word(tcp)) >> 16, ntohl(tcp->seq),
           ntohl(tcp->ack_seq));
}

void log_destroy(enum log_level level, struct conn_tuple* conn, enum destroy_type type,
                 __u32 cooldown) {
  const char* reason;
  switch (type) {
    case DESTROY_RECV_RST:
      reason = _("received RST");
      break;
    case DESTROY_RECV_FIN:
      reason = _("received FIN");
      break;
    case DESTROY_TIMED_OUT:
      reason = _("timed out");
      break;
    case DESTROY_INVALID:
      reason = _("invalid TCP state");
      break;
    default:
      reason = _("unknown");
      break;
  }
  if (cooldown)
    log_conn(level, conn, _("connection destroyed (%s), retry in %u seconds"), reason, cooldown);
  else
    log_conn(level, conn, _("connection destroyed (%s)"), reason);
}

// TODO: filter other messages like:
// - turn 'libbpf: elf: skipping unrecognized data section' into Trace
// - turn 'libxdp: Error attaching XDP program ...' and 'XDP mode not supported; try using SKB mode' into Warn
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
        level = LOG_WARN;
        break;
      case LIBBPF_INFO:
        level = LOG_INFO;
        break;
      case LIBBPF_DEBUG:
        level = LOG_TRACE;
        break;
    }
    ret = fprintf(stderr, "%s%s " RESET, log_prefixes[level][0], gettext(log_prefixes[level][1]));
    if (level >= LOG_TRACE) ret = ret < 0 ? ret : fprintf(stderr, GRAY);
    ret = ret < 0 ? ret : vfprintf(stderr, format, args);
    if (level >= LOG_TRACE) ret = ret < 0 ? ret : fprintf(stderr, RESET);
  }
  return ret < 0 ? ret : 0;
}

static inline const char* log_type_to_str(enum log_type type) {
  switch (type) {
    case LOG_CONN_INIT:
      return _("initializing connection");
    case LOG_CONN_ACCEPT:
      return _("accepting connection");
    case LOG_CONN_ESTABLISH:
      return _("connection established");
    default:
      return "";
  }
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
      case LOG_CONN_DESTROY:
        log_destroy(e->level, &e->info.conn, e->info.destroy_type, e->info.cooldown);
        break;
      default:
        log_conn(e->level, &e->info.conn, "%s", log_type_to_str(e->type));
        break;
    }
  }
  return 0;
}
