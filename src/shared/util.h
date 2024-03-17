#ifndef _MIMIC_SHARED_UTIL_H
#define _MIMIC_SHARED_UTIL_H

// clang-format off
#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#include "../bpf/log.h"
#else
#include <linux/pkt_cls.h>
#include <stdlib.h>
#include <unistd.h>
#include "../log.h"
#endif
// clang-format on

#ifndef MIMIC_RUNTIME_DIR
#define MIMIC_RUNTIME_DIR "/var/mimic"
#endif

#define redecl(_type, _name, _off, _ctx, _ret)                              \
  _name = ({                                                                \
    _type* _ptr = (void*)(__u64)(_ctx)->data + (_off);                      \
    if ((__u64)_ptr + sizeof(_type) > (__u64)(_ctx)->data_end) return _ret; \
    _ptr;                                                                   \
  })
#define redecl_ok(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_OK)
#define redecl_shot(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_SHOT)
#define redecl_pass(type, name, off, xdp) redecl(type, name, off, xdp, XDP_PASS)
#define redecl_drop(type, name, off, xdp) redecl(type, name, off, xdp, XDP_DROP)

#define decl(type, name, off, ctx, ret) type* redecl(type, name, off, ctx, ret)
#define decl_ok(type, name, off, skb) decl(type, name, off, skb, TC_ACT_OK)
#define decl_shot(type, name, off, skb) decl(type, name, off, skb, TC_ACT_SHOT)
#define decl_pass(type, name, off, xdp) decl(type, name, off, xdp, XDP_PASS)
#define decl_drop(type, name, off, xdp) decl(type, name, off, xdp, XDP_DROP)

#define _get_macro(_0, _1, _2, _3, _4, _5, NAME, ...) NAME

// Returns _ret while printing error.
#define ret(...) _get_macro(_0, ##__VA_ARGS__, _ret_fmt, _ret_fmt, _ret_fmt, _ret_fmt, _ret, )(__VA_ARGS__)
#define _ret(ret) return (ret)
#define _ret_fmt(ret, ...)  \
  ({                        \
    log_error(__VA_ARGS__); \
    return (ret);           \
  })

// Jumps to `cleanup`, returning _ret while printing error.
//
// Requires `cleanup` label, `retcode` to be defined inside function scope, and `retcode` to be
// returned after cleanup.
#define cleanup(...) \
  _get_macro(_0, ##__VA_ARGS__, _cleanup_fmt, _cleanup_fmt, _cleanup_fmt, _cleanup_fmt, _cleanup, )(__VA_ARGS__)
#define _cleanup(ret) \
  ({                  \
    retcode = (ret);  \
    goto cleanup;     \
  })
#define _cleanup_fmt(ret, ...) \
  ({                           \
    log_error(__VA_ARGS__);    \
    retcode = (ret);           \
    goto cleanup;              \
  })

#define _get_macro(_0, _1, _2, _3, _4, _5, NAME, ...) NAME

// Tests int return value from a function. Used for functions that returns non-zero error.
#define try(expr, ...)                      \
  ({                                        \
    int _ret = (expr);                      \
    if (_ret < 0) ret(_ret, ##__VA_ARGS__); \
    _ret;                                   \
  })

// Same as `try` with one arguments, but runs XDP subroutine
#define try_xdp(expr)                  \
  ({                                   \
    int _ret = (expr);                 \
    if (_ret != XDP_PASS) return _ret; \
    _ret;                              \
  })

// `try` but `cleanup`.
#define try2(expr, ...)                         \
  ({                                            \
    int _ret = (expr);                          \
    if (_ret < 0) cleanup(_ret, ##__VA_ARGS__); \
    _ret;                                       \
  })

// `errno` is not available in BPF
#ifndef _MIMIC_BPF

// Same as `try`, but returns -errno
#define try_e(expr, ...)          \
  ({                              \
    int _ret = (expr);            \
    if (_ret < 0) {               \
      _ret = -errno;              \
      ret(-errno, ##__VA_ARGS__); \
    }                             \
    _ret;                         \
  })

// `try_e` but `cleanup`.
#define try2_e(expr, ...)           \
  ({                                \
    int _ret = (expr);              \
    if (_ret < 0) {                 \
      _ret = -errno;                \
      cleanup(_ret, ##__VA_ARGS__); \
    }                               \
    _ret;                           \
  })

// Similar to `try_e`, but for function that returns a pointer.
#define try_p(expr, ...)        \
  ({                            \
    void* _ptr = (expr);        \
    if (!_ptr) {                \
      int _ret = -errno;        \
      ret(_ret, ##__VA_ARGS__); \
    }                           \
    _ptr;                       \
  })

// Similar to `try2_e`, but for function that returns a pointer.
#define try2_p(expr, ...)           \
  ({                                \
    void* _ptr = (expr);            \
    if (!_ptr) {                    \
      int _ret = -errno;            \
      cleanup(_ret, ##__VA_ARGS__); \
    }                               \
    _ptr;                           \
  })

#endif  // _MIMIC_BPF

// Tests int return value from a function, but return a different value when failed.
#define try_ret(expr, ret)    \
  ({                          \
    int _val = (expr);        \
    if (_val < 0) return ret; \
    _val;                     \
  })

#define try_ok(x) try_ret(x, TC_ACT_OK)
#define try_shot(x) try_ret(x, TC_ACT_SHOT)
#define try_pass(x) try_ret(x, XDP_PASS)
#define try_drop(x) try_ret(x, XDP_DROP)

// Tests pointer return value from a function, but return a different value when failed.
#define try_p_ret(expr, ret) \
  ({                         \
    void* _ptr = (expr);     \
    if (!_ptr) return ret;   \
    _ptr;                    \
  })

#define try_p_ok(x) try_p_ret(x, TC_ACT_OK)
#define try_p_shot(x) try_p_ret(x, TC_ACT_SHOT)
#define try_p_pass(x) try_p_ret(x, XDP_PASS)
#define try_p_drop(x) try_p_ret(x, XDP_DROP)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define cmp(x, y) ((x) > (y) - (x) < (y))

// Some missing declaration of vmlinux.h
#ifdef _MIMIC_BPF

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

#endif  // _MIMIC_BPF

// Cleanup utilities
#ifndef _MIMIC_BPF

static inline void cleanup_fd(int* fd) {
  if (*fd >= 0) close(*fd);
}
static inline void cleanup_file(FILE** file) {
  if (*file) fclose(*file);
}

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))

#endif  // _MIMIC_BPF

// mimic_settings keys
enum settings_key {
  SETTINGS_LOG_VERBOSITY,
  SETTINGS_WHITELIST,  // not stored in mimic_settings map
};

#endif  // _MIMIC_SHARED_UTIL_H
