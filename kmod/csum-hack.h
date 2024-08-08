#ifndef _MIMIC_KMOD_CSUM_HACK_H
#define _MIMIC_KMOD_CSUM_HACK_H

#if defined(_MIMIC_KMOD)
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#elif defined(_MIMIC_BPF)
#include "../bpf/vmlinux.h"

#include <bpf/bpf_helpers.h>
#endif

#ifdef _MIMIC_KMOD
int csum_hack_init(void);
void csum_hack_exit(void);
#endif

#define MAGIC_FLAG1 0xfc9e39d58639b65a
#define MAGIC_FLAG2 0x4eb37b03751ff785

#ifdef _MIMIC_KMOD
static inline int change_csum_offset(struct sk_buff* skb, __u16 proto) {
  if (skb->ip_summed != CHECKSUM_PARTIAL) return -1;
  switch (proto) {
    case IPPROTO_TCP:
      skb->csum_offset = offsetof(struct tcphdr, check);
      break;
    case IPPROTO_UDP:
      skb->csum_offset = offsetof(struct udphdr, check);
      break;
    default:
      return -1;
  }
  return 0;
}
#endif

#ifdef _MIMIC_BPF
#if defined(MIMIC_CHECKSUM_HACK_kfunc)
static inline int mimic_skb_ip_summed(struct __sk_buff* skb) {
  struct sk_buff* mimic_inspect_skb(struct __sk_buff * skb) __ksym;
  return mimic_inspect_skb(skb)->ip_summed;
}
int mimic_change_csum_offset(struct __sk_buff* skb, __u16 protocol) __ksym;

#elif defined(MIMIC_CHECKSUM_HACK_kprobe)
static inline int mimic_skb_ip_summed(struct __sk_buff* skb) {
  return bpf_skb_change_proto(skb, 0, MAGIC_FLAG1);
}
static inline int mimic_change_csum_offset(struct __sk_buff* skb, __u16 protocol) {
  return bpf_skb_change_proto(skb, protocol, MAGIC_FLAG2);
}

#endif  // MIMIC_CHECKSUM_HACK_*
#endif  // _MIMIC_BPF
#endif  // _MIMIC_KMOD_CSUM_HACK_H
