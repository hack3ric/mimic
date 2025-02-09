#ifndef MIMIC_COMMON_TRY_H
#define MIMIC_COMMON_TRY_H

#ifdef MIMIC_BPF
#include "bpf/vmlinux.h"

#include <bpf/bpf_helpers.h>
#else
#include <errno.h>
#include <stddef.h>
#include <string.h>  // IWYU pragma: keep
#include "common/log.h"
#endif

#include "common/defs.h"

static __always_inline void* skb_data_end(const struct __sk_buff* ctx) {
  void* data_end;
  asm volatile("%[res] = *(u32 *)(%[base] + %[offset])"
               : [res] "=r"(data_end)
               : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data_end)), "m"(*ctx));
  return data_end;
}

static __always_inline void* xdp_data_end(const struct xdp_md* ctx) {
  void* data_end;
  asm volatile("%[res] = *(u32 *)(%[base] + %[offset])"
               : [res] "=r"(data_end)
               : [base] "r"(ctx), [offset] "i"(offsetof(struct xdp_md, data_end)), "m"(*ctx));
  return data_end;
}

#define redecl(_type, _name, _off, _ctx, _ret, _method)                            \
  _name = ({                                                                       \
    _type* _ptr = (void*)(__u64)(_ctx)->data + (_off);                             \
    if (unlikely((__u64)_ptr + sizeof(_type) > (__u64)_method(_ctx))) return _ret; \
    _ptr;                                                                          \
  })
#define redecl_skb(_type, _name, _off, _ctx, _ret) \
  redecl(_type, _name, _off, _ctx, _ret, skb_data_end)
#define redecl_xdp(_type, _name, _off, _ctx, _ret) \
  redecl(_type, _name, _off, _ctx, _ret, xdp_data_end)

#define redecl_ok(type, name, off, skb) redecl_skb(type, name, off, skb, TC_ACT_OK)
#define redecl_shot(type, name, off, skb) redecl_skb(type, name, off, skb, TC_ACT_SHOT)
#define redecl_pass(type, name, off, xdp) redecl_xdp(type, name, off, xdp, XDP_PASS)
#define redecl_drop(type, name, off, xdp) redecl_xdp(type, name, off, xdp, XDP_DROP)

#define decl_skb(type, name, off, ctx, ret) type* redecl_skb(type, name, off, ctx, ret)
#define decl_xdp(type, name, off, ctx, ret) type* redecl_xdp(type, name, off, ctx, ret)
#define decl_ok(type, name, off, skb) decl_skb(type, name, off, skb, TC_ACT_OK)
#define decl_shot(type, name, off, skb) decl_skb(type, name, off, skb, TC_ACT_SHOT)
#define decl_pass(type, name, off, xdp) decl_xdp(type, name, off, xdp, XDP_PASS)
#define decl_drop(type, name, off, xdp) decl_xdp(type, name, off, xdp, XDP_DROP)

#define _get_macro(_0, _1, _2, _3, _4, _5, NAME, ...) NAME

// Returns _ret while printing error.
#define ret(...) \
  _get_macro(_0, ##__VA_ARGS__, _ret_fmt, _ret_fmt, _ret_fmt, _ret_fmt, _ret, )(__VA_ARGS__)
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
#define cleanup(...)                                                                    \
  _get_macro(_0, ##__VA_ARGS__, _cleanup_fmt, _cleanup_fmt, _cleanup_fmt, _cleanup_fmt, \
             _cleanup, )(__VA_ARGS__)
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
#define try(expr, ...)                                \
  ({                                                  \
    long _ret = (expr);                               \
    if (unlikely(_ret < 0)) ret(_ret, ##__VA_ARGS__); \
    _ret;                                             \
  })

// Same as `try` with one arguments, but runs XDP subroutine
#define try_tc(expr)                              \
  ({                                              \
    long _ret = (expr);                           \
    if (unlikely(_ret != TC_ACT_OK)) return _ret; \
    _ret;                                         \
  })

// Same as `try` with one arguments, but runs XDP subroutine
#define try_xdp(expr)                            \
  ({                                             \
    long _ret = (expr);                          \
    if (unlikely(_ret != XDP_PASS)) return _ret; \
    _ret;                                        \
  })

// `try` but `cleanup`.
#define try2(expr, ...)                                   \
  ({                                                      \
    long _ret = (expr);                                   \
    if (unlikely(_ret < 0)) cleanup(_ret, ##__VA_ARGS__); \
    _ret;                                                 \
  })

// `errno` is not available in BPF
#ifndef MIMIC_BPF

// Same as `try`, but returns -errno
#define try_e(expr, ...)          \
  ({                              \
    long _ret = (expr);           \
    if (unlikely(_ret < 0)) {     \
      _ret = -errno;              \
      ret(-errno, ##__VA_ARGS__); \
    }                             \
    _ret;                         \
  })

// `try_e` but `cleanup`.
#define try2_e(expr, ...)           \
  ({                                \
    long _ret = (expr);             \
    if (unlikely(_ret < 0)) {       \
      _ret = -errno;                \
      cleanup(_ret, ##__VA_ARGS__); \
    }                               \
    _ret;                           \
  })

// Similar to `try_e`, but for function that returns a pointer.
#define try_p(expr, ...)        \
  ({                            \
    void* _ptr = (expr);        \
    if (unlikely(!_ptr)) {      \
      long _ret = -errno;       \
      ret(_ret, ##__VA_ARGS__); \
    }                           \
    _ptr;                       \
  })

// Similar to `try2_e`, but for function that returns a pointer.
#define try2_p(expr, ...)           \
  ({                                \
    void* _ptr = (expr);            \
    if (unlikely(!_ptr)) {          \
      long _ret = -errno;           \
      cleanup(_ret, ##__VA_ARGS__); \
    }                               \
    _ptr;                           \
  })

#endif  // MIMIC_BPF

// Tests int return value from a function, but return a different value when failed.
#define try_ret(expr, ret)              \
  ({                                    \
    int _val = (expr);                  \
    if (unlikely(_val < 0)) return ret; \
    _val;                               \
  })

#define try_ok(x) try_ret(x, TC_ACT_OK)
#define try_shot(x) try_ret(x, TC_ACT_SHOT)
#define try_pass(x) try_ret(x, XDP_PASS)
#define try_drop(x) try_ret(x, XDP_DROP)

// Tests pointer return value from a function, but return a different value when failed.
#define try_p_ret(expr, ret)         \
  ({                                 \
    void* _ptr = (expr);             \
    if (unlikely(!_ptr)) return ret; \
    _ptr;                            \
  })

#define try_p_ok(x) try_p_ret(x, TC_ACT_OK)
#define try_p_shot(x) try_p_ret(x, TC_ACT_SHOT)
#define try_p_pass(x) try_p_ret(x, XDP_PASS)
#define try_p_drop(x) try_p_ret(x, XDP_DROP)

#define strret strerror(-_ret)

#endif  // MIMIC_COMMON_TRY_H
