#ifndef __MIMIC_UTIL_H__
#define __MIMIC_UTIL_H__

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#define check_redecl(type, name, off, skb, ret)                         \
  name = ({                                                             \
    type* ptr = (void*)(size_t)skb->data + off;                         \
    if ((size_t)ptr + sizeof(type) > (size_t)skb->data_end) return ret; \
    ptr;                                                                \
  })

#define check_redecl_ok(type, name, off, skb) \
  check_redecl(type, name, off, skb, TC_ACT_OK)

#define check_redecl_unspec(type, name, off, skb) \
  check_redecl(type, name, off, skb, TC_ACT_UNSPEC)

#define check_decl(type, name, off, skb, ret) \
  type* check_redecl(type, name, off, skb, ret)

#define check_decl_ok(type, name, off, skb) \
  check_decl(type, name, off, skb, TC_ACT_OK)

#define check_decl_unspec(type, name, off, skb) \
  check_decl(type, name, off, skb, TC_ACT_UNSPEC)

#define try(x)                  \
  ({                            \
    int result = x;             \
    if (!result) return result; \
  })

#endif  // __MIMIC_UTIL_H__
