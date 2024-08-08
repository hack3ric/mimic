#ifndef _MIMIC_KMOD_MIMIC_H
#define _MIMIC_KMOD_MIMIC_H

#ifdef _MIMIC_KMOD
#include <linux/bpf.h>
#include <linux/skbuff.h>
#elif defined _MIMIC_BPF
#include "../bpf/vmlinux.h"
#endif

#ifndef __ksym
#define __ksym
#endif

struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb) __ksym;
int mimic_change_csum_offset(struct __sk_buff* skb, __u16 protocol) __ksym;

#endif  // _MIMIC_KMOD_MIMIC_H
