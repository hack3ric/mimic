#ifndef _MIMIC_COMMON_DEFS_H
#define _MIMIC_COMMON_DEFS_H

#ifdef _MIMIC_BPF
// clang-format off
#include "../bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define cmp(x, y) ((x) > (y) - (x) < (y))

#define swap(x, y)   \
  ({                 \
    typeof(x) t = x; \
    x = y;           \
    y = t;           \
  })

#ifdef _MIMIC_BPF

// Some missing declaration of vmlinux.h

#define htons bpf_htons
#define htonl bpf_htonl
#define ntohs bpf_ntohs
#define ntohl bpf_ntohl

#define AF_INET 2
#define AF_INET6 10

// defined in linux/pkt_cls.h
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

// defined in linux/if_ether.h
#define ETH_HLEN 14       /* Total octets in header. */
#define ETH_DATA_LEN 1500 /* Max. octets in payload	*/
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook	*/

// defined in linux/tcp.h
#define tcp_flag_word(tp) (((union tcp_word_hdr*)(tp))->words[3])

#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_COMPLETE 2
#define CHECKSUM_PARTIAL 3

#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_MH 135

#else

#ifndef MIMIC_RUNTIME_DIR
#define MIMIC_RUNTIME_DIR "/run/mimic"
#endif

#endif  // _MIMIC_BPF

// Mainly used for limiting loop counts
#define MAX_PACKET_SIZE 9000

// Used for reading packet data in bulk
#define SEGMENT_SIZE 256

#define INIT_CWND 200
#define MIN_CWND 50
#define MAX_CWND 350
#define CWND_STEP 1
#define STABLE_FACTOR 0.2

#define SECOND 1000000000ul

// Reserved for gettext use in the future.
//
// On eBPF, these markers are just for convenience, so that I can get a comprehensive list of texts.
// In the future, logging should be rewritten so that eBPF should only send structurized information
// and let userspace call gettext.
#ifndef _MIMIC_BPF
// #define _(text) text
static inline __attribute__((__format_arg__(1))) const char* _(const char* text) { return text; }
#define gettext(text) _(text)
#endif
#define N_(text) text

struct pkt_filter {
  enum pkt_origin { ORIGIN_LOCAL, ORIGIN_REMOTE } origin;
  enum ip_proto { PROTO_IPV4 = AF_INET, PROTO_IPV6 = AF_INET6 } protocol;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

struct conn_tuple {
  enum ip_proto protocol;
  __be16 local_port, remote_port;
  union ip_value local, remote;
};

struct connection {
  struct bpf_spin_lock lock;
  enum conn_state {
    CONN_IDLE,
    CONN_SYN_SENT,
    CONN_SYN_RECV,
    CONN_ESTABLISHED,
  } state;
  __u32 seq, ack_seq;
  uintptr_t pktbuf;
  __u16 cwnd;
  __u64 retry_tstamp, reset_tstamp;
};

enum rst_result {
  RST_NONE,
  RST_ABORTED,
  RST_DESTROYED,
};

struct send_options {
  struct conn_tuple conn;
  bool syn, ack, rst;
  __u32 seq, ack_seq;
  __u16 cwnd;
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
    LOG_TYPE_MATCHED,         // conn
    LOG_TYPE_CONN_ESTABLISH,  // conn
    LOG_TYPE_TCP_PKT,         // tcp (ignore state)
    LOG_TYPE_STATE,           // tcp
    LOG_TYPE_RST,             // conn
    LOG_TYPE_CONN_DESTROY,    // conn
    LOG_TYPE_QUICK_MSG,       // msg
  } type;
  union log_info {
    struct fake_tcp_info {
      enum conn_state state;
      __u32 seq, ack_seq;
    } tcp;
    struct conn_tuple conn;
    char msg[40];
  } info;
};

struct rb_item {
  enum rb_item_type {
    RB_ITEM_LOG_EVENT,
    RB_ITEM_SEND_OPTIONS,
    RB_ITEM_STORE_PACKET,
    RB_ITEM_CONSUME_PKTBUF,
    RB_ITEM_FREE_PKTBUF,
  } type;
  union {
    struct log_event log_event;
    struct send_options send_options;
    struct {
      struct conn_tuple conn_key;
      __u16 len;
      bool l4_csum_partial;
    } store_packet;
    uintptr_t pktbuf;
  };
  // additional buffer follows
};

#ifndef _MIMIC_BPF

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

static inline void ip_port_fmt(enum ip_proto protocol, union ip_value ip, __be16 port,
                               char* restrict dest) {
  *dest = '\0';
  if (protocol == PROTO_IPV6) strcat(dest, "[");
  inet_ntop(protocol, &ip, dest + strlen(dest), INET6_ADDRSTRLEN);
  if (protocol == PROTO_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", ntohs(port));
}

static inline struct sockaddr_storage ip_port_to_sockaddr(enum ip_proto protocol, union ip_value ip,
                                                          __u16 port) {
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

static inline void pkt_filter_ip_port_fmt(const struct pkt_filter* restrict filter,
                                          char* restrict dest) {
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

static inline const char* conn_state_to_str(enum conn_state s) {
  switch (s) {
    case CONN_IDLE:
      return N_("idle");
    case CONN_SYN_SENT:
      return N_("SYN sent");
    case CONN_SYN_RECV:
      return N_("SYN received");
    case CONN_ESTABLISHED:
      return N_("established");
    default:
      return N_("(unknown)");
  }
}

// Cleanup utilities

static inline void cleanup_fd(int* fd) {
  if (*fd >= 0) close(*fd);
}
static inline void cleanup_file(FILE** file) {
  if (*file) fclose(*file);
}
static inline void cleanup_malloc(void** ptr) {
  if (*ptr) free(*ptr);
}

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))
#define _cleanup_malloc __attribute__((__cleanup__(cleanup_malloc)))

#endif  // _MIMIC_BPF

#endif  // _MIMIC_COMMON_DEFS_H
