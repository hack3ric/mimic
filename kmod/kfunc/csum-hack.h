#ifndef _MIMIC_KMOD_KFUNC_CSUM_HACK_H
#define _MIMIC_KMOD_KFUNC_CSUM_HACK_H

#include "common.h"

__bpf_kfunc_start_defs();

__bpf_kfunc struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb_bpf);
__bpf_kfunc int mimic_change_csum_offset(struct __sk_buff* skb_bpf, __u16 new_proto);

__bpf_kfunc_end_defs();

#endif  // _MIMIC_KMOD_KFUNC_CSUM_HACK_H
