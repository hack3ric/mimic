#ifndef MIMIC_COMMON_DEFS_H
#define MIMIC_COMMON_DEFS_H

#ifdef MIMIC_BPF
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

#define min(x, y)       \
  ({                    \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x < _y ? _x : _y;  \
  })
#define max(x, y)       \
  ({                    \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x < _y ? _y : _x;  \
  })
#define cmp(x, y)       \
  ({                    \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x > _y - _x < _y;  \
  })

#define sizeof_array(arr) (sizeof(arr) / sizeof(arr[0]))
#define round_to_mul(val, mul)                                \
  ({                                                          \
    typeof(val) _val = (val);                                 \
    typeof(mul) _mul = (mul);                                 \
    (_val % _mul == 0) ? _val : (_val + (_mul - _val % mul)); \
  })

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

#define UNUSED(x) (void)(x)

#ifdef MIMIC_BPF

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

static inline void closep(int* fd) {
  if (*fd >= 0) close(*fd);
}
static inline void fclosep(FILE** file) {
  if (*file) fclose(*file);
}
static inline void freep(void** ptr) {
  if (*ptr) free(*ptr);
}
static inline void freestrp(char** ptr) { freep((void*)ptr); }

#define raii(f) __attribute__((__cleanup__(f)))

#endif  // MIMIC_BPF

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

// Value of window size should be calculated from:
//   2 * 1000 * speed (MB/s) * latency (ms)
// This ensures window probe packets have time to reach to peer before the window fills up, even if
// the data flows completely *one-sided*. (Two-sided traffic such as TCP in a tunnel should
// constantly refresh the window)
//
// The default value is slightly larger than that of when speed = 1 Gb/s (125 MB/s) and latency =
// 200 ms. This is huge (~54.5 MB) and probably could be slower for a lot of other scenarios, but it
// should be a good default and works in most cases.
//
// TODO: make window configurable
#define INIT_WINDOW 0xffff
#define DEFAULT_WINDOW 0x3400000
#define WINDOW_SCALE 12
#define MAX_WINDOW_SCALE 14

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
enum {
  TCP_FLAGS_MASK = 0x00ff0000,
  TCP_GARBAGE_BYTE = 0x01000000,
  TCP_MAX_WINDOW = 0x02000000,
};
#else
enum {
  TCP_FLAGS_MASK = 0x0000ff00,
  TCP_GARBAGE_BYTE = 0x00000001,
  TCP_MAX_WINDOW = 0x00000002,
};
#endif

// Reserved for gettext use in the future.
//
// On eBPF, these markers are just for convenience, so that I can get a comprehensive list of texts.
// In the future, logging should be rewritten so that eBPF should only send structurized information
// and let userspace call gettext.
#ifndef MIMIC_BPF
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
      __s16 max_window;
    };
    __s16 array[8];
  };
};
// clang-format on

struct filter_info {
  char host[128];
  struct filter_settings settings;
};

#define DEFAULT_COOLDOWN 5
#define MAX_COOLDOWN_MUL 3  // max 5 << (3 + 1) = 40s

static const struct filter_settings DEFAULT_SETTINGS = {
  .handshake.array = {2, 3},
  .keepalive.array = {180, 10, 3, 600},
  .padding = 0,
  .max_window = false,
};

static const struct filter_settings FALLBACK_SETTINGS = {
  .array = {-1, -1, -1, -1, -1, -1, -1, -1},
};

static inline void filter_settings_apply(struct filter_settings* local,
                                         const struct filter_settings* global) {
  for (size_t i = 0; i < sizeof_array(local->array); i++)
    if (local->array[i] == -1) local->array[i] = global->array[i];
}

enum link_type {
  LINK_ETH,  // default value
  LINK_NONE,
};

static inline const char* link_type_str(enum link_type link) {
  switch (link) {
    case LINK_ETH:
      return "eth";
    case LINK_NONE:
      return "none";
    default:
      return "(unknown)";
  }
}

struct conn_tuple {
  __u16 local_port, remote_port;
  struct in6_addr local, remote;
};

struct connection {
  struct bpf_spin_lock lock;
  __u32 seq, ack_seq;
  __u32 window, peer_window;

  struct {
    enum conn_state {
      CONN_IDLE,
      CONN_SYN_SENT,
      CONN_SYN_RECV,
      CONN_ESTABLISHED,
    } state;
    __u8 cooldown_mul;
    bool keepalive_sent;
    bool initiator;
  };

  struct {
    struct filter_settings settings;
    __u16 peer_mss;
    __u8 peer_wscale;
  };

  __u64 retry_tstamp, reset_tstamp, stale_tstamp;
  __u64 wprobe_tstamp;
  __u64 pktbuf;
};

static __always_inline struct connection conn_init(struct filter_settings* settings, __u64 tstamp) {
  struct connection conn = {.window = 0xffff};
  __builtin_memcpy(&conn.settings, settings, sizeof(*settings));
  conn.retry_tstamp = conn.reset_tstamp = conn.stale_tstamp = tstamp;
  conn.wprobe_tstamp = 0;
  return conn;
}

static __always_inline void conn_reset(struct connection* conn, __u64 tstamp) {
  if (conn->initiator && conn->state != CONN_IDLE && conn->cooldown_mul < MAX_COOLDOWN_MUL)
    conn->cooldown_mul += 1;
  conn->state = CONN_IDLE;
  conn->seq = conn->ack_seq = 0;
  // conn->pktbuf should be swapped out prior
  conn->window = DEFAULT_WINDOW;
  conn->peer_mss = 0;
  conn->keepalive_sent = false;
  conn->retry_tstamp = conn->reset_tstamp = conn->stale_tstamp = tstamp;
  conn->wprobe_tstamp = 0;
}

static __always_inline __u32 conn_cooldown(struct connection* conn) {
  return conn->cooldown_mul ? DEFAULT_COOLDOWN * (1 << (conn->cooldown_mul - 1)) : 0;
}

static __always_inline __u32 conn_cooldown_display(struct connection* conn) {
  return conn->initiator ? conn_cooldown(conn) : 0;
}

static __always_inline __u32 conn_padding(struct connection* conn, __u32 seq, __u32 ack_seq) {
  return conn->settings.padding == PADDING_RANDOM ? (seq + ack_seq) % 11 : (__u32)conn->settings.padding;
}

static __always_inline __be32 conn_max_window(struct connection* conn) {
  return conn->settings.max_window ? TCP_MAX_WINDOW : 0;
}

#define SECOND 1000000000ul
#define MILISECOND 1000000ul

static __always_inline __u32 time_diff(__u64 unit, __u64 a, __u64 b) {
  if (a <= b) return 0;
  return (a - b) / unit + !!((a - b) % unit < unit / 2);
}

struct send_options {
  struct conn_tuple conn;
  __be32 flags;
  __u32 seq, ack_seq;
  __u32 window;
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

#endif  // MIMIC_COMMON_DEFS_H
