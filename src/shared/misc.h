#ifndef _MIMIC_SHARED_MISC_H
#define _MIMIC_SHARED_MISC_H

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#else
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#endif

#include "util.h"

struct pkt_filter {
  enum pkt_origin { ORIGIN_LOCAL, ORIGIN_REMOTE } origin;
  enum ip_proto { PROTO_IPV4 = AF_INET, PROTO_IPV6 = AF_INET6 } protocol;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#ifndef _MIMIC_BPF

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

static inline void ip_port_fmt(enum ip_proto protocol, union ip_value ip, __be16 port, char* restrict dest) {
  *dest = '\0';
  if (protocol == PROTO_IPV6) strcat(dest, "[");
  inet_ntop(protocol, &ip, dest + strlen(dest), INET6_ADDRSTRLEN);
  if (protocol == PROTO_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", ntohs(port));
}

static inline struct sockaddr_storage ip_port_to_sockaddr(enum ip_proto protocol, union ip_value ip, __u16 port) {
  struct sockaddr_storage result = {};
  result.ss_family = protocol;
  if (protocol == PROTO_IPV4) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)&result;
    ipv4->sin_addr.s_addr = ntohl(ip.v4);
    ipv4->sin_port = port;
  } else {
    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&result;
    ipv6->sin6_addr = ip.v6;
    ipv6->sin6_port = port;
  }
  return result;
}

static inline void pkt_filter_ip_port_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  ip_port_fmt(filter->protocol, filter->ip, filter->port, dest);
}

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
static inline void pkt_filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  *dest = '\0';
  if (filter->origin == ORIGIN_LOCAL) {
    strcat(dest, "local=");
    dest += 6;
  } else if (filter->origin == ORIGIN_REMOTE) {
    strcat(dest, "remote=");
    dest += 7;
  }
  pkt_filter_ip_port_fmt(filter, dest);
}

#endif  // _MIMIC_BPF

struct conn_tuple {
  enum ip_proto protocol;
  __be16 local_port, remote_port;
  union ip_value local, remote;
};

struct connection {
  struct bpf_spin_lock lock;
  enum conn_state {
    STATE_IDLE,
    STATE_SYN_SENT,
    STATE_SYN_RECV,
    STATE_ESTABLISHED,
  } state;
  __u32 seq, ack_seq;
};

static inline const char* conn_state_to_str(enum conn_state s) {
  switch (s) {
    case STATE_IDLE:
      return "idle";
    case STATE_SYN_SENT:
      return "SYN sent";
    case STATE_SYN_RECV:
      return "SYN received";
    case STATE_ESTABLISHED:
      return "established";
  }
}

enum rst_result {
  RST_NONE,
  RST_ABORTED,
  RST_DESTROYED,
};

struct send_options {
  struct conn_tuple c;
  bool syn, ack, rst;
  __u32 seq, ack_seq;
};

// need to define `log_verbosity` besides including this file.
#define LOG_ALLOW_ERROR (log_verbosity >= LOG_LEVEL_ERROR)
#define LOG_ALLOW_WARN (log_verbosity >= LOG_LEVEL_WARN)
#define LOG_ALLOW_INFO (log_verbosity >= LOG_LEVEL_INFO)
#define LOG_ALLOW_DEBUG (log_verbosity >= LOG_LEVEL_DEBUG)
#define LOG_ALLOW_TRACE (log_verbosity >= LOG_LEVEL_TRACE)

struct log_event {
  enum log_level {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE,
  } level;
  bool ingress;
  enum log_type {
    LOG_TYPE_MATCHED,         // quartet
    LOG_TYPE_CONN_ESTABLISH,  // quartet
    LOG_TYPE_TCP_PKT,         // tcp (ignore state)
    LOG_TYPE_STATE,           // tcp
    LOG_TYPE_RST,             // quartet
    LOG_TYPE_CONN_DESTROY,    // quartet
    LOG_TYPE_QUICK_MSG,       // msg
  } type;
  union log_info {
    struct fake_tcp_info {
      enum conn_state state;
      __u32 seq, ack_seq;
    } tcp;
    struct conn_tuple quartet;
    char msg[40];
  } info;
};

// mimic_settings keys
enum settings_key {
  SETTINGS_LOG_VERBOSITY,
  SETTINGS_WHITELIST,  // not stored in mimic_settings map
};

struct rb_item {
  enum rb_item_type {
    RB_ITEM_LOG_EVENT,
    RB_ITEM_SEND_OPTIONS,
    RB_ITEM_STORE_PACKET,
  } type;
  union {
    struct log_event log_event;
    struct send_options send_options;
    struct {
      struct conn_tuple conn;
      bool l4_csum_partial;
    } store_packet;
  };
  // additional buffer follows
};

#ifdef _MIMIC_BPF

#define _log_a(_0, _1, _2, _3, N, ...) _##N
#define _log_b_0() (u64[0]){}, 0
#define _log_b_1(_a) (u64[1]){(u64)(_a)}, sizeof(u64)
#define _log_b_2(_a, _b) (u64[2]){(u64)(_a), (u64)(_b)}, 2 * sizeof(u64)
#define _log_b_3(_a, _b, _c) (u64[2]){(u64)(_a), (u64)(_b), (u64)(_c)}, 3 * sizeof(u64)
#define _log_c(...) _log_a(__VA_ARGS__, 3, 2, 1, 0)
#define _log_d(_x, _y) _x##_y
#define _log_e(_x, _y) _log_d(_x, _y)
#define _log_f(_str, _size, _fmt, ...) \
  bpf_snprintf((_str), (_size), (_fmt), _log_e(_log_b, _log_c(_0 __VA_OPT__(, ) __VA_ARGS__))(__VA_ARGS__))

#define _log_rbprintf(_l, _fmt, ...)                                                         \
  ({                                                                                         \
    struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);                 \
    if (item) {                                                                              \
      item->log_event.level = (_l);                                                          \
      item->log_event.type = LOG_TYPE_QUICK_MSG;                                             \
      _log_f(item->log_event.info.msg, sizeof(item->log_event.info.msg), _fmt, __VA_ARGS__); \
      bpf_ringbuf_submit(item, 0);                                                           \
    }                                                                                        \
  })

#define log_error(fmt, ...) \
  if (LOG_ALLOW_ERROR) _log_rbprintf(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (LOG_ALLOW_WARN) _log_rbprintf(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (LOG_ALLOW_INFO) _log_rbprintf(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) \
  if (LOG_ALLOW_DEBUG) _log_rbprintf(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define log_trace(fmt, ...) \
  if (LOG_ALLOW_TRACE) _log_rbprintf(LOG_LEVEL_TRACE, fmt, ##__VA_ARGS__)

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_MISC_H
