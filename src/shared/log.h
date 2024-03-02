#ifndef _MIMIC_SHARED_LOG_H
#define _MIMIC_SHARED_LOG_H

#ifdef _MIMIC_BPF
// clang-format off
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#else
#include <bpf/libbpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdio.h>
#endif

#include "filter.h"

#ifdef _MIMIC_BPF
const volatile int log_verbosity = 0;
#else
static int log_verbosity = 2;
#endif

enum log_level {
  LOG_LEVEL_ERROR = 0,
  LOG_LEVEL_WARN = 1,
  LOG_LEVEL_INFO = 2,
  LOG_LEVEL_DEBUG = 3,
  LOG_LEVEL_TRACE = 4,
};

enum log_type {
  LOG_TYPE_MSG,
  LOG_TYPE_PKT,
};

#define LOG_ALLOW_ERROR (log_verbosity >= LOG_LEVEL_ERROR)
#define LOG_ALLOW_WARN (log_verbosity >= LOG_LEVEL_WARN)
#define LOG_ALLOW_INFO (log_verbosity >= LOG_LEVEL_INFO)
#define LOG_ALLOW_DEBUG (log_verbosity >= LOG_LEVEL_DEBUG)
#define LOG_ALLOW_TRACE (log_verbosity >= LOG_LEVEL_TRACE)

#define LOG_RB_ITEM_LEN 128
#define LOG_RB_MSG_LEN (LOG_RB_ITEM_LEN - 4)
#define LOG_RB_PKT_MSG_LEN 84

struct log_event {
  enum log_level level : 16;
  enum log_type type : 16;
  union {
    char msg[LOG_RB_MSG_LEN];
    struct pkt_info {
      char msg[LOG_RB_PKT_MSG_LEN];
      enum ip_proto protocol;
      __u16 from_port, to_port;
      union ip_value from, to;
    } pkt;
  } inner;
};

_Static_assert(sizeof(struct log_event) == LOG_RB_ITEM_LEN, "log_event length mismatch");

#ifdef _MIMIC_BPF

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LOG_RB_ITEM_LEN * 1024);
} mimic_rb SEC(".maps");

#define _log_a(_0, _1, _2, _3, N, ...) _##N
#define _log_b_0() (u64[0]){}, 0
#define _log_b_1(_a) (u64[1]){(u64)(_a)}, sizeof(u64)
#define _log_b_2(_a, _b) (u64[2]){(u64)(_a), (u64)(_b)}, 2 * sizeof(u64)
#define _log_b_3(_a, _b, _c) (u64[2]){(u64)(_a), (u64)(_b), (u64)(_c)}, 3 * sizeof(u64)
#define _log_c(...) _log_a(__VA_ARGS__, 3, 2, 1, 0)
#define _log_d(_x, _y) _x##_y
#define _log_e(_x, _y) _log_d(_x, _y)
#define _log_f(_str, _size, _fmt, ...)                                                          \
  bpf_snprintf(                                                                                 \
    (_str), (_size), (_fmt), _log_e(_log_b, _log_c(_0 __VA_OPT__(, ) __VA_ARGS__))(__VA_ARGS__) \
  )

#define _log_rbprintf(_l, _fmt, ...)                                          \
  ({                                                                          \
    struct log_event* e = bpf_ringbuf_reserve(&mimic_rb, LOG_RB_ITEM_LEN, 0); \
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

static __always_inline void log_pkt(
  enum log_level level, char* msg, struct iphdr* ipv4, struct ipv6hdr* ipv6, struct udphdr* udp,
  struct tcphdr* tcp
) {
  if (log_verbosity < level) return;

  struct log_event* e = bpf_ringbuf_reserve(&mimic_rb, LOG_RB_ITEM_LEN, 0);
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

#else

#define _LOG_ERROR_PREFIX "\r  \x1B[1;31merror:\x1B[0m "
#define _LOG_WARN_PREFIX "\r   \x1B[1;33mwarn:\x1B[0m "
#define _LOG_INFO_PREFIX "\r   \x1B[1;32minfo:\x1B[0m "
#define _LOG_DEBUG_PREFIX "\r  \x1B[1;34mdebug:\x1B[0m "
#define _LOG_TRACE_PREFIX "\r  \x1B[1;30mtrace:\x1B[0m "

static const char* _log_prefixes[] = {
  _LOG_ERROR_PREFIX, _LOG_WARN_PREFIX, _LOG_INFO_PREFIX, _LOG_DEBUG_PREFIX, _LOG_TRACE_PREFIX,
};

#define log(_l, fmt, ...) \
  if (log_verbosity >= (_l)) fprintf(stderr, "%s" fmt "\n", _log_prefixes[_l], ##__VA_ARGS__)

#define log_error(fmt, ...) \
  if (LOG_ALLOW_ERROR) fprintf(stderr, _LOG_ERROR_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (LOG_ALLOW_WARN) fprintf(stderr, _LOG_WARN_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (LOG_ALLOW_INFO) fprintf(stderr, _LOG_INFO_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) \
  if (LOG_ALLOW_DEBUG) fprintf(stderr, _LOG_DEBUG_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_trace(fmt, ...) \
  if (LOG_ALLOW_TRACE) fprintf(stderr, _LOG_TRACE_PREFIX fmt "\n", ##__VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  int result1;
  if (level == LIBBPF_WARN && LOG_ALLOW_WARN) {
    result1 = fprintf(stderr, _LOG_WARN_PREFIX);
  } else if (level == LIBBPF_INFO && LOG_ALLOW_INFO) {
    result1 = fprintf(stderr, _LOG_INFO_PREFIX);
  } else if (level == LIBBPF_DEBUG && LOG_ALLOW_DEBUG) {
    result1 = fprintf(stderr, _LOG_DEBUG_PREFIX);
  } else {
    return 0;
  }
  if (result1 < 0) return result1;
  int result2 = vfprintf(stderr, format, args);
  if (result2 < 0) return result2;
  return result1 + result2;
}

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_LOG_H
