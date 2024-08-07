#ifndef _MIMIC_COMMON_DEFS_H
#define _MIMIC_COMMON_DEFS_H

#ifdef _MIMIC_BPF
// clang-format off
#include "../bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
// clang-format on
#else
#include <linux/bpf.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#define fallthrough

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
#ifndef tcp_flag_word
#define tcp_flag_word(tp) (((union tcp_word_hdr*)(tp))->words[3])
#endif

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
static inline void cleanup_malloc_str(char** ptr) { cleanup_malloc((void*)ptr); }

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))
#define _cleanup_malloc __attribute__((__cleanup__(cleanup_malloc)))
#define _cleanup_malloc_str __attribute__((__cleanup__(cleanup_malloc_str)))

#endif  // _MIMIC_BPF

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

#define SYN 1
#define ACK (1 << 1)
#define RST (1 << 2)

// Mainly used for limiting loop counts
#define MAX_PACKET_SIZE 10000

// Used for reading packet data in bulk
#define SEGMENT_SIZE 64

#define INIT_CWND 0xffff
#define CWND_SCALE 7

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

struct filter {
  enum origin { O_LOCAL, O_REMOTE } origin;
  enum protocol { P_IPV4 = AF_INET, P_IPV6 = AF_INET6 } protocol;
  __u16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

struct filter_settings {
  int hi, hr;          // handshake interval, retry
  int kt, ki, kr, ks;  // keepalive time, interval, retry, stale
};

#define DEFAULT_HANDSHAKE_INTERVAL 2
#define DEFAULT_HANDSHAKE_RETRY 3
#define DEFAULT_KEEPALIVE_TIME 180
#define DEFAULT_KEEPALIVE_INTERVAL 10
#define DEFAULT_KEEPALIVE_RETRY 3
#define DEFAULT_KEEPALIVE_STALE 600
#define DEFAULT_FILTER_SETTINGS \
  ((struct filter_settings){    \
    DEFAULT_HANDSHAKE_INTERVAL, \
    DEFAULT_HANDSHAKE_RETRY,    \
    DEFAULT_KEEPALIVE_TIME,     \
    DEFAULT_KEEPALIVE_INTERVAL, \
    DEFAULT_KEEPALIVE_RETRY,    \
    DEFAULT_KEEPALIVE_STALE,    \
  })

#define _filter_settings_apply(_field) \
  if (local->_field < 0) local->_field = remote->_field;

static inline void filter_settings_apply(struct filter_settings* local,
                                         const struct filter_settings* remote) {
  _filter_settings_apply(hi);
  _filter_settings_apply(hr);
  _filter_settings_apply(kt);
  _filter_settings_apply(ki);
  _filter_settings_apply(kr);
  _filter_settings_apply(ks);
}

struct conn_tuple {
  enum protocol protocol;
  __u16 local_port, remote_port;
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
  __u64 pktbuf;
  __u32 cwnd;
  __u64 retry_tstamp, reset_tstamp, stale_tstamp;
  bool keepalive_sent;
  __u16 peer_mss;
  struct filter_settings settings;
};

struct send_options {
  struct conn_tuple conn;
  bool syn, ack, rst;
  __u32 seq, ack_seq;
  __u32 cwnd;
};

// need to define `log_verbosity` besides including this file.
#define LOG_ALLOW_ERROR (log_verbosity >= LOG_ERROR)
#define LOG_ALLOW_WARN (log_verbosity >= LOG_WARN)
#define LOG_ALLOW_INFO (log_verbosity >= LOG_INFO)
#define LOG_ALLOW_DEBUG (log_verbosity >= LOG_DEBUG)
#define LOG_ALLOW_TRACE (log_verbosity >= LOG_TRACE)

struct log_event {
  enum log_level {
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE,
  } level : 4;
  enum log_type {
    LOG_CONN_INIT,
    LOG_CONN_ACCEPT,
    LOG_CONN_ESTABLISH,
    LOG_CONN_DESTROY,
    LOG_PKT_SEND_TCP,
    LOG_PKT_RECV_TCP,
    LOG_MSG,
  } type : 4;
  union log_info {
    struct {
      struct conn_tuple conn;
      union {
        struct {
          __u16 len, flags;
          __u32 seq, ack_seq;
        };
        enum destroy_type {
          DESTROY_RECV_RST,
          DESTROY_TIMED_OUT,
          DESTROY_INVALID,
        } destroy_type;
      };
    };
    char msg[52];
  } info;
};

extern struct log_event _e;
_Static_assert(sizeof(_e.info) == sizeof(_e.info.msg),
               "Message length should match its parent union");

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
    __u64 pktbuf;
  };
  // additional buffer follows
};

#endif  // _MIMIC_COMMON_DEFS_H
