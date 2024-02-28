#ifndef _MIMIC_SHARED_UTIL
#define _MIMIC_SHARED_UTIL

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#else
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#endif

#include "log.h"

#define strerrno strerror(errno)

#define redecl(_type, _name, _off, _ctx, _ret)                              \
  _name = ({                                                                \
    _type* _ptr = (void*)(__u64)(_ctx)->data + (_off);                      \
    if ((__u64)_ptr + sizeof(_type) > (__u64)(_ctx)->data_end) return _ret; \
    _ptr;                                                                   \
  })
#define redecl_or_ok(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_OK)
#define redecl_or_shot(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_SHOT)
#define redecl_or_pass(type, name, off, xdp) redecl(type, name, off, xdp, XDP_PASS)
#define redecl_or_drop(type, name, off, xdp) redecl(type, name, off, xdp, XDP_DROP)

#define decl(type, name, off, ctx, ret) type* redecl(type, name, off, ctx, ret)
#define decl_or_ok(type, name, off, skb) decl(type, name, off, skb, TC_ACT_OK)
#define decl_or_shot(type, name, off, skb) decl(type, name, off, skb, TC_ACT_SHOT)
#define decl_or_pass(type, name, off, xdp) decl(type, name, off, xdp, XDP_PASS)
#define decl_or_drop(type, name, off, xdp) decl(type, name, off, xdp, XDP_DROP)

// Returns _ret while printing error.
#define ret(ret, ...)       \
  ({                        \
    log_error(__VA_ARGS__); \
    return (ret);           \
  })

// Jumps to `cleanup`, returning _ret while printing error.
//
// Requires `cleanup` label, `retcode` to be defined inside function scope, and `retcode` to be
// returned after cleanup.
#define cleanup(ret, ...)   \
  ({                        \
    log_error(__VA_ARGS__); \
    retcode = (ret);        \
    goto cleanup;           \
  })

#define _get_macro(_0, _1, _2, _3, _4, _5, NAME, ...) NAME

// Tests int return value from a function. Used for functions that returns non-zero error.
#define try(...) \
  _get_macro(_0, ##__VA_ARGS__, _try_fmt, _try_fmt, _try_fmt, _try_fmt, _try, )(__VA_ARGS__)
#define _try(expr)             \
  ({                           \
    int _ret = (expr);         \
    if (_ret < 0) return _ret; \
    _ret;                      \
  })
#define _try_fmt(expr, ...)               \
  ({                                      \
    int _ret = (expr);                    \
    if (_ret < 0) ret(_ret, __VA_ARGS__); \
    _ret;                                 \
  })

// Same as `try` with one arguments, but runs XDP subroutine
#define try_xdp(expr)                  \
  ({                                   \
    int _ret = (expr);                 \
    if (_ret != XDP_PASS) return _ret; \
    _ret;                              \
  })

// Same as `try`, but returns -errno
#define try_errno(...)                                                                             \
  _get_macro(                                                                                      \
    _0, ##__VA_ARGS__, _try_errno_fmt, _try_errno_fmt, _try_errno_fmt, _try_errno_fmt, _try_errno, \
  )(__VA_ARGS__)
#define _try_errno(expr)     \
  ({                         \
    int _ret = (expr);       \
    if (_ret) return -errno; \
    _ret;                    \
  })
#define _try_errno_fmt(expr, ...)       \
  ({                                    \
    int _ret = (expr);                  \
    if (_ret) ret(-errno, __VA_ARGS__); \
    _ret;                               \
  })

// Similar to `try_errno`, but for function that returns a pointer.
#define try_ptr(...)                                                                     \
  _get_macro(                                                                            \
    _0, ##__VA_ARGS__, _try_ptr_fmt, _try_ptr_fmt, _try_ptr_fmt, _try_ptr_fmt, _try_ptr, \
  )(__VA_ARGS__)
#define _try_ptr(expr)        \
  ({                          \
    void* _ret = (expr);      \
    if (!_ret) return -errno; \
    _ret;                     \
  })
#define _try_ptr_fmt(expr, ...)          \
  ({                                     \
    void* _ret = (expr);                 \
    if (!_ret) ret(-errno, __VA_ARGS__); \
    _ret;                                \
  })

// Tests int return value from a function, but return a different value when failed.
#define try_ret(x, ret) \
  if (x) return ret

#define try_or_ok(x) try_ret(x, TC_ACT_OK)
#define try_or_shot(x) try_ret(x, TC_ACT_SHOT)
#define try_or_pass(x) try_ret(x, XDP_PASS)
#define try_or_drop(x) try_ret(x, XDP_DROP)

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

#endif  // _MIMIC_SHARED_UTIL
