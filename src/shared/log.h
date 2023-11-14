#ifndef _MIMIC_LOG_H
#define _MIMIC_LOG_H

#ifdef _MIMIC_BPF
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#else
#include <bpf/libbpf.h>
#include <stdio.h>
#endif

#ifdef _MIMIC_BPF
const volatile int log_verbosity = 0;
#else
static int log_verbosity = 2;
#endif

#define LOG_ALLOW_DEBUG (log_verbosity >= 3)
#define LOG_ALLOW_INFO (log_verbosity >= 2)
#define LOG_ALLOW_WARN (log_verbosity >= 1)
#define LOG_ALLOW_ERROR (1)

#define LOG_RB_ITEM_LEN 128
struct log_event {
  __u8 level;
  char buf[LOG_RB_ITEM_LEN - 1];
};
_Static_assert(sizeof(struct log_event) == LOG_RB_ITEM_LEN, "log_event length mismatch");

#ifdef _MIMIC_BPF

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LOG_RB_ITEM_LEN * 1024);
} mimic_rb SEC(".maps");

#define _log_a(_0, _1, _2, _3, N, ...) _##N
#define _log_b_0() (__u64[0]){}, 0
#define _log_b_1(_a) (__u64[1]){(__u64)(_a)}, sizeof(__u64)
#define _log_b_2(_a, _b) (__u64[2]){(__u64)(_a), (__u64)(_b)}, 2 * sizeof(__u64)
#define _log_b_3(_a, _b, _c) (__u64[2]){(__u64)(_a), (__u64)(_b), (__u64)(_c)}, 3 * sizeof(__u64)
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
      _log_f(e->buf, LOG_RB_ITEM_LEN - 1, _fmt, __VA_ARGS__);                 \
      bpf_ringbuf_submit(e, 0);                                               \
    }                                                                         \
  })

#define log_debug(fmt, ...) \
  if (LOG_ALLOW_DEBUG) _log_rbprintf(3, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (LOG_ALLOW_INFO) _log_rbprintf(2, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (LOG_ALLOW_WARN) _log_rbprintf(1, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) \
  if (LOG_ALLOW_ERROR) _log_rbprintf(0, fmt, ##__VA_ARGS__)

#else

#define _LOG_DEBUG_PREFIX "  \e[1;34mdebug:\e[0m "
#define _LOG_INFO_PREFIX "   \e[1;32minfo:\e[0m "
#define _LOG_WARN_PREFIX "   \e[1;33mwarn:\e[0m "
#define _LOG_ERROR_PREFIX "  \e[1;31merror:\e[0m "

#define log_debug(fmt, ...) \
  if (LOG_ALLOW_DEBUG) fprintf(stderr, _LOG_DEBUG_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...) \
  if (LOG_ALLOW_INFO) fprintf(stderr, _LOG_INFO_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) \
  if (LOG_ALLOW_WARN) fprintf(stderr, _LOG_WARN_PREFIX fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) \
  if (LOG_ALLOW_ERROR) fprintf(stderr, _LOG_ERROR_PREFIX fmt "\n", ##__VA_ARGS__)

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

#endif  // _MIMIC_LOG_H
