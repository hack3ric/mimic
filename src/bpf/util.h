#ifndef _MIMIC_BPF_UTIL_H
#define _MIMIC_BPF_UTIL_H

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define redecl(type, name, off, skb_xdp, ret)                     \
  name = ({                                                   \
    type* ptr = (void*)(size_t)skb_xdp->data + off;               \
    if ((size_t)ptr + sizeof(type) > (size_t)skb_xdp->data_end) { \
      bpf_printk("check decl failed");                        \
      return ret;                                             \
    }                                                         \
    ptr;                                                      \
  })

#define decl(type, name, off, skb_xdp, ret) type* redecl(type, name, off, skb_xdp, ret)

#define redecl_or_ok(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_OK)
#define redecl_or_shot(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_SHOT)
#define decl_or_ok(type, name, off, skb) decl(type, name, off, skb, TC_ACT_OK)
#define decl_or_shot(type, name, off, skb) decl(type, name, off, skb, TC_ACT_SHOT)

#define redecl_or_pass(type, name, off, xdp) redecl(type, name, off, xdp, XDP_PASS)
#define redecl_or_drop(type, name, off, xdp) redecl(type, name, off, xdp, XDP_DROP)
#define decl_or_pass(type, name, off, xdp) decl(type, name, off, xdp, XDP_PASS)
#define decl_or_drop(type, name, off, xdp) decl(type, name, off, xdp, XDP_DROP)

#define try(x)                 \
  ({                           \
    int result = x;            \
    if (result) return result; \
  })

#define try_xdp(x)                 \
  ({                           \
    int result = x;            \
    if (result != XDP_PASS) return result; \
  })

#define try_ret(x, ret) \
  if (x) return ret

#define try_or_shot(x) try_ret(x, TC_ACT_SHOT)
#define try_or_ok(x) try_ret(x, TC_ACT_OK)

#define try_or_drop(x) try_ret(x, XDP_DROP)
#define try_or_pass(x) try_ret(x, XDP_PASS)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define cmp(x, y) ((x) > (y) - (x) < (y))

#endif  // _MIMIC_BPF_UTIL_H
