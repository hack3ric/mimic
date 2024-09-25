#ifndef _MIMIC_BPF_MIMIC_H
#define _MIMIC_BPF_MIMIC_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "common/defs.h"

extern int log_verbosity;

extern struct mimic_whitelist_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, struct filter);
  __type(value, struct filter_info);
} mimic_whitelist;

extern struct mimic_conns_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, struct conn_tuple);
  __type(value, struct connection);
} mimic_conns;

extern struct mimic_rb_map {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
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

static __always_inline struct filter_settings* matches_whitelist(QUARTET_DEF) {
  struct filter local = {}, remote = {};
  local.origin = udp ? O_LOCAL : O_REMOTE;
  remote.origin = udp ? O_REMOTE : O_LOCAL;
  local.port = udp ? ntohs(udp->source) : tcp ? ntohs(tcp->source) : 0;
  remote.port = udp ? ntohs(udp->dest) : tcp ? ntohs(tcp->dest) : 0;
  local.ip = ipv4 ? ipv4_mapped(ipv4->saddr) : ipv6 ? ipv6->saddr : IP_ANY;
  remote.ip = ipv4 ? ipv4_mapped(ipv4->daddr) : ipv6 ? ipv6->daddr : IP_ANY;

  struct filter_info* result = bpf_map_lookup_elem(&mimic_whitelist, &local);
  result = result ?: bpf_map_lookup_elem(&mimic_whitelist, &remote);
  return result ? &result->settings : NULL;
}

static __always_inline struct conn_tuple gen_conn_key(QUARTET_DEF) {
  struct conn_tuple key = {};
  key.local_port = udp ? ntohs(udp->source) : tcp ? ntohs(tcp->dest) : 0;
  key.remote_port = udp ? ntohs(udp->dest) : tcp ? ntohs(tcp->source) : 0;
  key.local = ipv4 ? ipv4_mapped(ipv4->saddr) : ipv6 ? ipv6->saddr : IP_ANY;
  key.remote = ipv4 ? ipv4_mapped(ipv4->daddr) : ipv6 ? ipv6->daddr : IP_ANY;
  if (tcp) swap(key.local, key.remote);
  return key;
}

static void log_any(enum log_level level, enum log_type type, union log_info* info) {
  if (unlikely(!info)) return;
  if (log_verbosity < level) return;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (unlikely(!item)) return;
  item->type = RB_ITEM_LOG_EVENT;
  item->log_event = (struct log_event){.level = level, .type = type};
  __builtin_memcpy(&item->log_event.info, info, sizeof(*info));
  bpf_ringbuf_submit(item, 0);
  return;
}

// Log general connection information
static inline void log_conn(enum log_type type, struct conn_tuple* conn) {
  if (unlikely(!conn || !LOG_ALLOW_INFO)) return;
  log_any(LOG_INFO, type, &(union log_info){.conn = *conn});
}

// Log TCP packet trace
static inline void log_tcp(bool recv, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len) {
  if (likely(!conn || !LOG_ALLOW_TRACE)) return;
  union log_info info = {
    .conn = *conn,
    .len = len,
    .flags = ntohl(tcp_flag_word(tcp)) >> 16,
    .seq = htonl(tcp->seq),
    .ack_seq = htonl(tcp->ack_seq),
  };
  return log_any(LOG_TRACE, recv ? LOG_PKT_RECV_TCP : LOG_PKT_SEND_TCP, &info);
}

// Warn about connection destruction
static inline void log_destroy(struct conn_tuple* conn, enum destroy_type type, __u32 cooldown) {
  if (unlikely(!conn || !LOG_ALLOW_WARN)) return;
  log_any(LOG_WARN, LOG_CONN_DESTROY,
          &(union log_info){.conn = *conn, .destroy_type = type, .cooldown = cooldown});
}

int send_ctrl_packet(struct conn_tuple* conn, __be32 flags, __u32 seq, __u32 ack_seq, __u32 cwnd);
int store_packet(struct __sk_buff* skb, __u32 pkt_off, struct conn_tuple* key, int ip_summed);
int use_pktbuf(enum rb_item_type type, __u64 buf);

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
    if (likely(item)) {                                                                      \
      item->log_event.level = (_l);                                                          \
      item->log_event.type = LOG_MSG;                                                        \
      _log_f(item->log_event.info.msg, sizeof(item->log_event.info.msg), _fmt, __VA_ARGS__); \
      bpf_ringbuf_submit(item, 0);                                                           \
    }                                                                                        \
  })

#define log_error(fmt, ...) \
  if (likely(LOG_ALLOW_ERROR)) _log_rbprintf(LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (likely(LOG_ALLOW_WARN)) _log_rbprintf(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (likely(LOG_ALLOW_INFO)) _log_rbprintf(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) \
  if (unlikely(LOG_ALLOW_DEBUG)) _log_rbprintf(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_trace(fmt, ...) \
  if (unlikely(LOG_ALLOW_TRACE)) _log_rbprintf(LOG_TRACE, fmt, ##__VA_ARGS__)

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
