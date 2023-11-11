#ifndef _MIMIC_BPF_UTIL_H
#define _MIMIC_BPF_UTIL_H

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define redecl(type, name, off, skb, ret)                     \
  name = ({                                                   \
    type* ptr = (void*)(size_t)skb->data + off;               \
    if ((size_t)ptr + sizeof(type) > (size_t)skb->data_end) { \
      bpf_printk("check decl failed");                        \
      return ret;                                             \
    }                                                         \
    ptr;                                                      \
  })

#define redecl_or_ok(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_OK)
#define redecl_or_shot(type, name, off, skb) redecl(type, name, off, skb, TC_ACT_SHOT)
#define decl(type, name, off, skb, ret) type* redecl(type, name, off, skb, ret)
#define decl_or_ok(type, name, off, skb) decl(type, name, off, skb, TC_ACT_OK)
#define decl_or_shot(type, name, off, skb) decl(type, name, off, skb, TC_ACT_SHOT)

#define try(x)                 \
  ({                           \
    int result = x;            \
    if (result) return result; \
  })

#define try_ret(x, ret) \
  if (x) return ret

#define try_or_shot(x) try_ret(x, TC_ACT_SHOT)
#define try_or_ok(x) try_ret(x, TC_ACT_OK)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define cmp(x, y) ((x) > (y) - (x) < (y))

#endif  // _MIMIC_BPF_UTIL_H
