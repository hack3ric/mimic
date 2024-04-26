#ifndef _MIMIC_BPF_MIMIC_H
#define _MIMIC_BPF_MIMIC_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../common/defs.h"

extern struct mimic_whitelist_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, struct pkt_filter);
  __type(value, bool);
} mimic_whitelist;

extern struct mimic_conns_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, struct conn_tuple);
  __type(value, struct connection);
} mimic_conns;

extern struct mimic_settings_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u32);
} mimic_settings;

extern struct mimic_rb_map {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 12);
} mimic_rb;

#define IPV4_CSUM_OFF (offsetof(struct iphdr, check))
#define TCP_UDP_HEADER_DIFF (sizeof(struct tcphdr) - sizeof(struct udphdr))

struct ph_part {
  __u8 _pad;
  __u8 protocol;
  __be16 len;
} __attribute__((packed));

// clang-format off
#define QUARTET_DEF struct iphdr* ipv4, struct ipv6hdr* ipv6, struct udphdr* udp, struct tcphdr* tcp
#define QUARTET_UDP ipv4, ipv6, udp, NULL
#define QUARTET_TCP ipv4, ipv6, NULL, tcp
// clang-format on

bool matches_whitelist(QUARTET_DEF, bool ingress);

static __always_inline struct conn_tuple gen_conn_key(QUARTET_DEF, bool ingress) {
  struct conn_tuple key = {};
  if (udp) {
    key.local_port = udp->source;
    key.remote_port = udp->dest;
  } else if (tcp) {
    key.local_port = tcp->source;
    key.remote_port = tcp->dest;
  }
  if (ipv4) {
    key.protocol = PROTO_IPV4;
    key.local.v4 = ipv4->saddr;
    key.remote.v4 = ipv4->daddr;
  } else if (ipv6) {
    key.protocol = PROTO_IPV6;
    key.local.v6 = ipv6->saddr;
    key.remote.v6 = ipv6->daddr;
  }
  if (ingress) {
    swap(key.local, key.remote);
    swap(key.local_port, key.remote_port);
  }
  return key;
}

static inline struct connection* get_conn(struct conn_tuple* key) {
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, key);
  if (!conn) {
    struct connection conn_value = {.cwnd = INIT_CWND};
    if (bpf_map_update_elem(&mimic_conns, key, &conn_value, BPF_ANY)) return NULL;
    conn = bpf_map_lookup_elem(&mimic_conns, key);
    if (!conn) return NULL;
  }
  return conn;
}

int log_any(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
            union log_info* info);

static inline int log_conn(__u32 log_verbosity, enum log_level level, bool ingress,
                           enum log_type type, struct conn_tuple* conn) {
  if (!conn) return -1;
  return log_any(log_verbosity, level, ingress, type, &(union log_info){.conn = *conn});
}

static __always_inline int log_tcp(__u32 log_verbosity, enum log_level level, bool ingress,
                                   enum log_type type, enum conn_state state, __u32 seq,
                                   __u32 ack_seq) {
  return log_any(log_verbosity, level, ingress, type,
                 &(union log_info){.tcp = {.state = state, .seq = seq, .ack_seq = ack_seq}});
}

static __always_inline void change_cwnd(__u16* cwnd, __u32 r1, __u32 r2, __u32 r3, __u32 r4) {
  if (r4 > (__u32)(-1) * STABLE_FACTOR) {
    // Assuming r1, r2, r3 ~ U(0, U32_MAX), this performs Bernoulli trial 96 times, p = 1/2
    __s16 x = __builtin_popcount(r1) + __builtin_popcount(r2) + __builtin_popcount(r3) -
              3 * (sizeof(__u32) * 8) / 2;
    __u16 new = *cwnd + (x * CWND_STEP);
    if ((new >= MIN_CWND) && (new <= MAX_CWND)) {
      *cwnd = new;
    }
  }
}

#define SYN 1
#define ACK 1 << 1
#define RST 1 << 2

int send_ctrl_packet(struct conn_tuple* conn, __u32 flags, __u32 seq, __u32 ack_seq, __u16 cwnd);
int store_packet(struct __sk_buff* skb, __u32 pkt_off, struct conn_tuple* key);
int use_pktbuf(enum rb_item_type type, uintptr_t buf);

#define _log_a(_0, _1, _2, _3, N, ...) _##N
#define _log_b_0() (__u64[0]){}, 0
#define _log_b_1(_a) (__u64[1]){(__u64)(_a)}, sizeof(__u64)
#define _log_b_2(_a, _b) (__u64[2]){(__u64)(_a), (__u64)(_b)}, 2 * sizeof(__u64)
#define _log_b_3(_a, _b, _c) (__u64[2]){(__u64)(_a), (__u64)(_b), (__u64)(_c)}, 3 * sizeof(__u64)
#define _log_c(...) _log_a(__VA_ARGS__, 3, 2, 1, 0)
#define _log_d(_x, _y) _x##_y
#define _log_e(_x, _y) _log_d(_x, _y)
#define _log_f(_str, _size, _fmt, ...)  \
  bpf_snprintf((_str), (_size), (_fmt), \
               _log_e(_log_b, _log_c(_0 __VA_OPT__(, ) __VA_ARGS__))(__VA_ARGS__))

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

static inline bool ipv6_is_ext(__u8 nexthdr) {
  switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
      return true;
    default:
      return false;
  }
}

#endif  // _MIMIC_BPF_MIMIC_H
