#ifndef _MIMIC_COMMON_DEFS_H
#define _MIMIC_COMMON_DEFS_H

#ifdef _MIMIC_BPF
// clang-format off
#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
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

#define sizeof_array(arr) (sizeof(arr) / sizeof(arr[0]))
#define round_to_mul(val, mul) ((val) % (mul) == 0) ? (val) : ((val) + ((mul) - (val) % (mul)))

#define swap(x, y)   \
  ({                 \
    typeof(x) t = x; \
    x = y;           \
    y = t;           \
  })

#if __GNUC__ >= 11 || __clang_major__ >= 17
#if __has_c_attribute(fallthrough)
#define fallthrough [[fallthrough]]
#elif __has_c_attribute(clang::fallthrough)
#define fallthrough [[clang::fallthrough]]
#else
#define fallthrough
#endif
#else
#define fallthrough
#endif

#define unlikely(expr) __builtin_expect(!!(expr), 0)
#define likely(expr) __builtin_expect(!!(expr), 1)

#if __clang_major__ >= 17
#if __has_c_attribute(clang::unlikely)
#define br_unlikely [[clang::unlikely]]
#else
#define br_unlikely
#endif
#if __has_c_attribute(clang::likely)
#define br_likely [[clang::likely]]
#else
#define br_likely
#endif
#else
#define br_unlikely
#define br_likely
#endif

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

#define s6_addr8 in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

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

// Mainly used for limiting loop counts
#define MAX_PACKET_SIZE 10000

#define MAX_PADDING_LEN 16
#define PADDING_RANDOM (-127)

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

// IP representation utilities

#define IP_ANY ((struct in6_addr){})

static inline int ip_proto(const struct in6_addr* ip) {
  if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 && ip->s6_addr32[2] == htonl(0xffff))
    return AF_INET;
  else
    return AF_INET6;
}

static inline void* ip_buf(struct in6_addr* ip) {
  if (ip_proto(ip) == AF_INET)
    return &ip->s6_addr32[3];
  else
    return ip;
}

static inline const void* ip_buf_const(const struct in6_addr* ip) {
  if (ip_proto(ip) == AF_INET)
    return &ip->s6_addr32[3];
  else
    return ip;
}

static inline struct in6_addr ipv4_mapped(__be32 ipv4) {
  return (struct in6_addr){.s6_addr32 = {0, 0, htonl(0xffff), ipv4}};
}

struct filter {
  enum { O_LOCAL, O_REMOTE } origin : 16;
  __u16 port;
  struct in6_addr ip;
};

// clang-format off
struct filter_settings {
  union {
    struct {
      union { struct filter_handshake {
        union {
          struct { __s16 interval, retry; };
          struct { __s16 i, r; };
          __s16 array[2];
        };
      } handshake, h; };
      union { struct filter_keepalive {
        union {
          struct { __s16 time, interval, retry, stale; };
          struct { __s16 t, i, r, s; };
          __s16 array[4];
        };
      } keepalive, k; };
      __s16 padding;
    };
    __s16 array[7];
  };
};
// clang-format on

struct filter_info {
  char host[128];
  struct filter_settings settings;
};

#define DEFAULT_COOLDOWN 5

static const struct filter_settings DEFAULT_SETTINGS = {
  .handshake.array = {2, 3},
  .keepalive.array = {180, 10, 3, 600},
  .padding = 0,
};

static const struct filter_settings FALLBACK_SETTINGS = {
  .array = {-1, -1, -1, -1, -1, -1, -1},
};

static inline void filter_settings_apply(struct filter_settings* local,
                                         const struct filter_settings* global) {
  for (int i = 0; i < sizeof_array(local->array); i++)
    if (local->array[i] == -1) local->array[i] = global->array[i];
}

struct conn_tuple {
  __u16 local_port, remote_port;
  struct in6_addr local, remote;
};

struct connection {
  struct bpf_spin_lock lock;
  __u32 seq, ack_seq;
  __u32 cwnd;

  struct {
    enum conn_state {
      CONN_IDLE,
      CONN_SYN_SENT,
      CONN_SYN_RECV,
      CONN_ESTABLISHED,
    } state : 3;
    __u8 cooldown_mul : 4;
    bool keepalive_sent : 1;
    bool initiator : 1;
    __u32 : 23;
  };
  struct {
    struct filter_settings settings;
    __u16 peer_mss;
  };

  __u64 retry_tstamp, reset_tstamp, stale_tstamp;
  __u64 pktbuf;
};

static __always_inline struct connection conn_init(struct filter_settings* settings, __u64 tstamp) {
  struct connection conn = {.cwnd = INIT_CWND};
  __builtin_memcpy(&conn.settings, settings, sizeof(*settings));
  conn.retry_tstamp = conn.reset_tstamp = conn.stale_tstamp = tstamp;
  return conn;
}

static __always_inline void conn_reset(struct connection* conn, __u64 tstamp) {
  conn->state = CONN_IDLE;
  conn->seq = conn->ack_seq = 0;
  // conn->pktbuf should be swapped out prior
  conn->cwnd = INIT_CWND;
  conn->peer_mss = 0;
  conn->keepalive_sent = false;
  if (conn->initiator && conn->cooldown_mul < 11) conn->cooldown_mul += 1;
  conn->retry_tstamp = conn->reset_tstamp = conn->stale_tstamp = tstamp;
}

static __always_inline __u32 conn_cooldown(struct connection* conn) {
  return conn->cooldown_mul ? DEFAULT_COOLDOWN * (1 << (conn->cooldown_mul - 1)) : 0;
}

static __always_inline __u32 conn_cooldown_display(struct connection* conn) {
  return conn->initiator ? conn_cooldown(conn) : 0;
}

static __always_inline int time_diff_sec(__u64 a, __u64 b) {
  if (a <= b) return 0;
  if ((a - b) % SECOND < SECOND / 2)
    return (a - b) / SECOND;
  else
    return (a - b) / SECOND + 1;
}

struct send_options {
  struct conn_tuple conn;
  __u16 flags;
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
        struct {
          enum destroy_type {
            DESTROY_RECV_RST,
            DESTROY_RECV_FIN,
            DESTROY_TIMED_OUT,
            DESTROY_INVALID,
          } destroy_type;
          __u32 cooldown;
        };
      };
    };
    char msg[52];
  } info;
};

extern struct log_event _e;
_Static_assert(sizeof(_e.info) == sizeof(_e.info.msg),
               "message length should match its parent union");

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
