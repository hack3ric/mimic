#ifndef _MIMIC_BPF_LOG_H
#define _MIMIC_BPF_LOG_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../shared/log.h"
#include "mimic.h"

extern const volatile int log_verbosity;

extern struct mimic_log_rb_map {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LOG_RB_ITEM_LEN * 1024);
} mimic_log_rb;

#define _log_a(_0, _1, _2, _3, N, ...) _##N
#define _log_b_0() (u64[0]){}, 0
#define _log_b_1(_a) (u64[1]){(u64)(_a)}, sizeof(u64)
#define _log_b_2(_a, _b) (u64[2]){(u64)(_a), (u64)(_b)}, 2 * sizeof(u64)
#define _log_b_3(_a, _b, _c) (u64[2]){(u64)(_a), (u64)(_b), (u64)(_c)}, 3 * sizeof(u64)
#define _log_c(...) _log_a(__VA_ARGS__, 3, 2, 1, 0)
#define _log_d(_x, _y) _x##_y
#define _log_e(_x, _y) _log_d(_x, _y)
#define _log_f(_str, _size, _fmt, ...)  \
  bpf_snprintf((_str), (_size), (_fmt), \
               _log_e(_log_b, _log_c(_0 __VA_OPT__(, ) __VA_ARGS__))(__VA_ARGS__))

#define _log_rbprintf(_l, _fmt, ...)                                          \
  ({                                                                          \
    struct log_event* e = bpf_ringbuf_reserve(&mimic_log_rb, LOG_RB_ITEM_LEN, 0); \
    if (e) {                                                                  \
      e->level = (_l);                                                        \
      _log_f(e->inner.msg, LOG_RB_MSG_LEN, _fmt, __VA_ARGS__);                \
      bpf_ringbuf_submit(e, 0);                                               \
    }                                                                         \
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

static __always_inline void log_pkt(enum log_level level, char* msg, QUARTET_DEF) {
  if (log_verbosity < level) return;

  struct log_event* e = bpf_ringbuf_reserve(&mimic_log_rb, LOG_RB_ITEM_LEN, 0);
  if (!e) return;
  e->level = level;
  e->type = LOG_TYPE_PKT;
  struct pkt_info* pkt = &e->inner.pkt;

  if (udp) {
    pkt->from_port = udp->source;
    pkt->to_port = udp->dest;
  } else if (tcp) {
    pkt->from_port = tcp->source;
    pkt->to_port = tcp->dest;
  }

  if (ipv4) {
    pkt->protocol = PROTO_IPV4;
    pkt->from.v4 = ipv4->saddr;
    pkt->to.v4 = ipv4->daddr;
  } else if (ipv6) {
    pkt->protocol = PROTO_IPV6;
    pkt->from.v6 = ipv6->saddr;
    pkt->to.v6 = ipv6->daddr;
  }

  __builtin_strncpy(pkt->msg, msg, LOG_RB_PKT_MSG_LEN);
  bpf_ringbuf_submit(e, 0);
}

#endif  // _MIMIC_BPF_LOG_H
