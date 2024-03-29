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
  } type;
  union log_info {
    struct fake_tcp_info {
      enum conn_state state;
      __u32 seq, ack_seq;
    } tcp;
    struct conn_tuple quartet;
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
  } type;
  union {
    struct log_event log_event;
    struct send_options send_options;
  };
};

#endif  // _MIMIC_SHARED_MISC_H
