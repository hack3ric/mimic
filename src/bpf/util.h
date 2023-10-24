#ifndef __MIMIC_UTIL_H__
#define __MIMIC_UTIL_H__

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define check_redecl(type, name, off, skb, ret)               \
  name = ({                                                   \
    type* ptr = (void*)(size_t)skb->data + off;               \
    if ((size_t)ptr + sizeof(type) > (size_t)skb->data_end) { \
      bpf_printk("check decl failed");                        \
      return ret;                                             \
    }                                                         \
    ptr;                                                      \
  })

#define check_redecl_ok(type, name, off, skb) \
  check_redecl(type, name, off, skb, TC_ACT_OK)

#define check_redecl_shot(type, name, off, skb) \
  check_redecl(type, name, off, skb, TC_ACT_SHOT)

#define check_decl(type, name, off, skb, ret) \
  type* check_redecl(type, name, off, skb, ret)

#define check_decl_ok(type, name, off, skb) \
  check_decl(type, name, off, skb, TC_ACT_OK)

#define check_decl_shot(type, name, off, skb) \
  check_decl(type, name, off, skb, TC_ACT_SHOT)

#define try(x)                 \
  ({                           \
    int result = x;            \
    if (result) return result; \
  })

#define try_ret(x, ret, msg) \
  ({                         \
    if (x) {                 \
      bpf_printk(msg);       \
      return ret;            \
    }                        \
  })

#define try_shot(x, msg) try_ret(x, TC_ACT_SHOT, msg)
#define try_ok(x) try_ret(x, TC_ACT_OK, msg)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))

#endif  // __MIMIC_UTIL_H__
