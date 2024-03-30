#ifndef _MIMIC_BPF_MIMIC_H
#define _MIMIC_BPF_MIMIC_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../shared/misc.h"

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

struct ipv4_ph_part {
  __u8 _pad;
  __u8 protocol;
  __be16 len;
} __attribute__((packed));

struct ipv6_ph_part {
  __u8 _1[2];
  __be16 len;
  __u8 _2[3];
  __u8 nexthdr;
} __attribute__((packed));

struct sk_buff* mimic_inspect_skb(struct __sk_buff*) __ksym;
int mimic_change_csum_offset(struct __sk_buff*, __u16) __ksym;

// clang-format off
#define QUARTET_DEF struct iphdr* ipv4, struct ipv6hdr* ipv6, struct udphdr* udp, struct tcphdr* tcp
#define QUARTET_UDP ipv4, ipv6, udp, NULL
#define QUARTET_TCP ipv4, ipv6, NULL, tcp
// clang-format on

static inline bool matches_whitelist(QUARTET_DEF, bool ingress) {
  struct pkt_filter local = {.origin = ORIGIN_LOCAL}, remote = {.origin = ORIGIN_REMOTE};
  if (udp) {
    local.port = udp->source;
    remote.port = udp->dest;
  } else if (tcp) {
    local.port = tcp->source;
    remote.port = tcp->dest;
  }
  if (ipv4) {
    local.protocol = remote.protocol = PROTO_IPV4;
    local.ip.v4 = ipv4->saddr;
    remote.ip.v4 = ipv4->daddr;
  } else if (ipv6) {
    local.protocol = remote.protocol = PROTO_IPV6;
    local.ip.v6 = ipv6->saddr;
    remote.ip.v6 = ipv6->daddr;
  }
  if (ingress) {
    struct pkt_filter t = local;
    local = remote;
    remote = t;
    local.origin = ORIGIN_LOCAL;
    remote.origin = ORIGIN_REMOTE;
  }
  return bpf_map_lookup_elem(&mimic_whitelist, &local) || bpf_map_lookup_elem(&mimic_whitelist, &remote);
}

static inline struct conn_tuple gen_conn_key(QUARTET_DEF, bool ingress) {
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
    __be16 tp = key.local_port;
    key.local_port = key.remote_port;
    key.remote_port = tp;
    union ip_value ti = key.local;
    key.local = key.remote;
    key.remote = ti;
  }
  return key;
}

static inline struct connection* get_conn(struct conn_tuple* conn_key) {
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, conn_key);
  if (!conn) {
    struct connection conn_value = {};
    if (bpf_map_update_elem(&mimic_conns, conn_key, &conn_value, BPF_ANY)) return NULL;
    conn = bpf_map_lookup_elem(&mimic_conns, conn_key);
    if (!conn) return NULL;
  }
  return conn;
}

static inline void log_any(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                           union log_info info) {
  if (log_verbosity < level) return;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return;
  item->type = RB_ITEM_LOG_EVENT;
  item->log_event.level = level;
  item->log_event.type = type;
  item->log_event.ingress = ingress;
  item->log_event.info = info;
  bpf_ringbuf_submit(item, 0);
}

static inline void log_quartet(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                               struct conn_tuple quartet) {
  log_any(log_verbosity, level, ingress, type, (union log_info){.quartet = quartet});
}

static __always_inline void log_tcp(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                                    enum conn_state state, __u32 seq, __u32 ack_seq) {
  log_any(log_verbosity, level, ingress, type,
          (union log_info){.tcp = {.state = state, .seq = seq, .ack_seq = ack_seq}});
}

static __always_inline void send_ctrl_packet(struct conn_tuple c, bool syn, bool ack, bool rst, __u32 seq,
                                             __u32 ack_seq) {
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return;
  item->type = RB_ITEM_SEND_OPTIONS;
  item->send_options = (struct send_options){
    .c = c,
    .syn = syn,
    .ack = ack,
    .rst = rst,
    .seq = seq,
    .ack_seq = ack_seq,
  };
  bpf_ringbuf_submit(item, 0);
}

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

#endif  // _MIMIC_BPF_MIMIC_H
